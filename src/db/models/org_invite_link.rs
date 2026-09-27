use std::{collections::HashSet, str::FromStr};

use chrono::{NaiveDateTime, Utc};
use diesel::prelude::*;
use serde_json::Value;

use crate::{
    api::{ApiResult, EmptyResult},
    crypto,
    db::{DbConn, schema::org_invite_links},
    error::{Error, MapResult},
    util::format_date,
};

use super::OrganizationId;

/// A reusable link that lets users with an allowed email domain join an organization.
// https://github.com/bitwarden/server/blob/aa786fc9cd3803f48e79f15067e910e99d768b69/src/Core/AdminConsole/Entities/OrganizationInviteLink.cs
#[derive(Identifiable, Queryable)]
#[diesel(table_name = org_invite_links)]
#[diesel(primary_key(uuid))]
pub struct OrgInviteLink {
    pub uuid: OrgInviteLinkId,
    pub org_uuid: OrganizationId,
    /// Bearer secret of the link, always a UUID here and only stored encrypted. Only compare it with `code_matches`
    code: String,
    /// JSON list of the email domains which may use the link
    pub allowed_domains: String,
    /// Opaque data of the clients, the server only stores it
    pub invite: String,
    pub supports_confirmation: bool,
    pub creation_date: NaiveDateTime,
    pub revision_date: NaiveDateTime,
}

/// Local methods
impl OrgInviteLink {
    /// The largest valid list still fits in MySQL/MariaDB TEXT even if every domain is 253 ASCII bytes:
    /// `255 * (253 + JSON quotes/comma) + brackets == 65_281` bytes, below the 65_535-byte limit.
    pub const MAX_ALLOWED_DOMAINS: usize = 255;

    pub fn new(org_uuid: OrganizationId, allowed_domains: String, invite: String, supports_confirmation: bool) -> Self {
        let now = Utc::now().naive_utc();
        Self {
            uuid: OrgInviteLinkId(crate::util::get_uuid()),
            org_uuid,
            // A random v4 UUID like upstream, the clients expect the code to be a UUID
            code: crate::util::get_uuid(),
            allowed_domains,
            invite,
            supports_confirmation,
            creation_date: now,
            revision_date: now,
        }
    }

    /// Checks the domains an admin entered like upstream and returns them normalized, as the JSON list to store
    pub fn clean_domains(domains: Vec<String>) -> ApiResult<String> {
        if domains.len() > Self::MAX_ALLOWED_DOMAINS {
            err!(format!("No more than {} allowed domains may be provided.", Self::MAX_ALLOWED_DOMAINS))
        }

        let mut invalid = Vec::new();
        let mut cleaned = Vec::with_capacity(domains.len());
        let mut seen = HashSet::with_capacity(domains.len());
        for mut domain in domains {
            if !is_valid_domain_name(&domain) {
                invalid.push(format!("'{}'", domain.escape_debug()));
                continue;
            }

            domain.make_ascii_lowercase();
            if seen.insert(domain.clone()) {
                cleaned.push(domain);
            }
        }
        if !invalid.is_empty() {
            err!(format!("The following items are not valid: {}", invalid.join(", ")))
        }

        if cleaned.is_empty() {
            err!("At least one allowed domain is required.")
        }
        Ok(json!(cleaned).to_string())
    }

    pub fn allowed_domains(&self) -> ApiResult<Vec<String>> {
        serde_json::from_str(&self.allowed_domains)
            .map_res("Invalid allowed domains stored for organization invite link")
    }

    /// Constant time comparison with a code sent by a client, which like upstream may use any case
    pub fn code_matches(&self, code: &uuid::Uuid) -> bool {
        crypto::ct_eq(&self.code, code.to_string())
    }

    /// Whether the domain of the email address is one of the allowed domains, subdomains are not included.
    /// Like upstream, this only protects anything if the address is verified.
    pub fn allows_email(&self, email: &str) -> ApiResult<bool> {
        let Some(domain) = email_domain(email) else {
            return Ok(false);
        };
        Ok(self.allowed_domains()?.contains(&domain))
    }

    // https://github.com/bitwarden/server/blob/aa786fc9cd3803f48e79f15067e910e99d768b69/src/Api/AdminConsole/Models/Response/Organizations/OrganizationInviteLinkResponseModel.cs
    pub fn to_json(&self) -> ApiResult<Value> {
        Ok(json!({
            "id": self.uuid,
            "code": self.code,
            "organizationId": self.org_uuid,
            "allowedDomains": self.allowed_domains()?,
            "invite": self.invite,
            "supportsConfirmation": self.supports_confirmation,
            "creationDate": format_date(&self.creation_date),
            "object": "organizationInviteLink",
        }))
    }

    fn code_associated_data(&self) -> String {
        format!("OrganizationInviteLink.Code:{}", self.org_uuid)
    }

    fn protected_code(&self) -> ApiResult<String> {
        crypto::protect_database_field(&self.code, self.code_associated_data().as_bytes())
    }

    fn unprotect_code(mut self) -> ApiResult<Self> {
        // Branch builds before at-rest protection stored a plain UUID. Only that exact legacy shape is accepted;
        // a malformed or unknown envelope is corruption, not plaintext to silently trust.
        if crypto::is_protected_database_field(&self.code) {
            self.code = crypto::unprotect_database_field(&self.code, self.code_associated_data().as_bytes())?;
        }
        self.code = uuid::Uuid::parse_str(&self.code)
            .map_err(|_| Error::new_msg("Organization invite link contains an invalid protected code"))?
            .to_string();
        Ok(self)
    }
}

/// Upstream's `DomainNameValidatorAttribute`: ASCII labels of letters, digits and hyphens, at least one dot, a
/// top-level label of letters and no scheme or `www.` prefix. Internationalized domains need their `xn--` form.
fn is_valid_domain_name(domain: &str) -> bool {
    domain.len() <= 253
        && !domain.get(..4).is_some_and(|prefix| prefix.eq_ignore_ascii_case("www."))
        && domain.rsplit_once('.').is_some_and(|(labels, tld)| {
            tld.len() >= 2
                && tld.bytes().all(|b| b.is_ascii_alphabetic())
                && labels.split('.').all(|label| {
                    (1..=63).contains(&label.len())
                        && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                        && !label.starts_with('-')
                        && !label.ends_with('-')
                })
        })
}

/// The lowercase ASCII (`xn--`) form of the domain of an email address, the form allowed domains are entered in
fn email_domain(email: &str) -> Option<String> {
    let email = email_address::EmailAddress::from_str(email).ok()?;
    let url = url::Url::parse(&format!("https://{}", email.domain())).ok()?;
    url.domain().map(str::to_ascii_lowercase)
}

/// Database methods
impl OrgInviteLink {
    pub async fn find_by_org(org_uuid: &OrganizationId, conn: &DbConn) -> ApiResult<Option<Self>> {
        conn.run(move |conn| {
            org_invite_links::table
                .filter(org_invite_links::org_uuid.eq(org_uuid))
                .first::<Self>(conn)
                .optional()
                .map_res("Error finding organization invite link")
        })
        .await?
        .map(Self::unprotect_code)
        .transpose()
    }

    /// Fails if the organization already has a link, the unique index also covers concurrent requests
    pub async fn insert(&self, conn: &DbConn) -> EmptyResult {
        let protected_code = self.protected_code()?;
        conn.run(move |conn| {
            diesel::insert_into(org_invite_links::table)
                .values((
                    org_invite_links::uuid.eq(&self.uuid),
                    org_invite_links::org_uuid.eq(&self.org_uuid),
                    org_invite_links::code.eq(&protected_code),
                    org_invite_links::allowed_domains.eq(&self.allowed_domains),
                    org_invite_links::invite.eq(&self.invite),
                    org_invite_links::supports_confirmation.eq(self.supports_confirmation),
                    org_invite_links::creation_date.eq(self.creation_date),
                    org_invite_links::revision_date.eq(self.revision_date),
                ))
                .execute(conn)
                .map_res("Error saving invite link")
        })
        .await
    }

    /// Stores the allowed domains, returns `false` if the link was refreshed or deleted meanwhile
    pub async fn update_allowed_domains(&self, conn: &DbConn) -> ApiResult<bool> {
        let protected_code = self.protected_code()?;
        conn.run(move |conn| {
            diesel::update(org_invite_links::table.filter(org_invite_links::uuid.eq(&self.uuid)))
                .set((
                    org_invite_links::code.eq(&protected_code),
                    org_invite_links::allowed_domains.eq(&self.allowed_domains),
                    org_invite_links::revision_date.eq(self.revision_date),
                ))
                .execute(conn)
                .map(|rows| rows == 1)
                .map_res("Error saving invite link")
        })
        .await
    }

    /// Stores this link in place of the link with `uuid`, apart from the allowed domains which stay as they are.
    /// A refreshed link gets a new uuid and code here, which invalidates the old code in the same statement.
    /// Returns `false` if the link with `uuid` was refreshed or deleted meanwhile.
    pub async fn replace(&self, uuid: &OrgInviteLinkId, conn: &DbConn) -> ApiResult<bool> {
        let protected_code = self.protected_code()?;
        conn.run(move |conn| {
            diesel::update(org_invite_links::table.filter(org_invite_links::uuid.eq(uuid)))
                .set((
                    org_invite_links::uuid.eq(&self.uuid),
                    org_invite_links::code.eq(&protected_code),
                    org_invite_links::invite.eq(&self.invite),
                    org_invite_links::supports_confirmation.eq(self.supports_confirmation),
                    org_invite_links::creation_date.eq(self.creation_date),
                    org_invite_links::revision_date.eq(self.revision_date),
                ))
                .execute(conn)
                .map(|rows| rows == 1)
                .map_res("Error saving invite link")
        })
        .await
    }

    pub async fn delete_all_by_organization(org_uuid: &OrganizationId, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::delete(org_invite_links::table.filter(org_invite_links::org_uuid.eq(org_uuid)))
                .execute(conn)
                .map_res("Error deleting invite link")
        })
        .await
    }
}

#[derive(Debug, DieselNewType, Hash, PartialEq, Eq, Serialize)]
pub struct OrgInviteLinkId(String);

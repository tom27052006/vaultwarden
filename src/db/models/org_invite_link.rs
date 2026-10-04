use std::future::Future;

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
    /// Bearer secret of the link, a random UUID as in Bitwarden. Only compare it with `code_matches`.
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

    /// Link use by an existing verified account does not require an SMTP server.
    pub fn is_available() -> bool {
        true
    }

    /// Keep the asynchronous call shape used by organization responses without requiring a database query.
    pub fn is_available_for_org(_org_uuid: &OrganizationId, _conn: &DbConn) -> impl Future<Output = bool> {
        std::future::ready(Self::is_available())
    }

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
        for domain in domains {
            let domain = domain.trim().to_ascii_lowercase();
            if domain.is_empty() {
                continue;
            }
            if !is_valid_domain_name(&domain) {
                invalid.push(format!("'{}'", domain.escape_debug()));
                continue;
            }

            cleaned.push(domain);
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

    fn unprotect_code(&mut self) -> EmptyResult {
        // Earlier feature-branch builds stored an RSA-derived AES-GCM envelope. New links use Bitwarden's UUID
        // representation, and startup migrates decryptable envelopes before an RSA key can be rotated.
        if crypto::is_protected_database_field(&self.code) {
            self.code = crypto::unprotect_database_field(&self.code, self.code_associated_data().as_bytes())?;
        }
        self.code = uuid::Uuid::parse_str(&self.code)
            .map_err(|_| Error::new_msg("Organization invite link contains an invalid protected code"))?
            .to_string();
        Ok(())
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

/// The lowercase domain of an email address, compared literally like upstream's `EmailValidation.GetDomain`. Only a
/// plain address counts, no display name. Allowed domains are plain DNS names, so a domain with other characters the
/// parser accepts, like `example.com#x` or `example.com/x`, never matches one.
fn email_domain(email: &str) -> Option<String> {
    let options = email_address::Options::default().without_display_text();
    let email = email_address::EmailAddress::parse_with_options(email, options).ok()?;
    Some(email.domain().to_ascii_lowercase())
}

/// Database methods
impl OrgInviteLink {
    /// The link of the organization. A legacy envelope whose RSA key is already lost counts as missing.
    pub async fn find_by_org(org_uuid: &OrganizationId, conn: &DbConn) -> ApiResult<Option<Self>> {
        Ok(Self::find_stored_by_org(org_uuid, conn).await?.and_then(Result::ok))
    }

    /// Like `find_by_org`, but for a link whose code can't be decrypted returns its id as the error
    pub async fn find_stored_by_org(
        org_uuid: &OrganizationId,
        conn: &DbConn,
    ) -> ApiResult<Option<Result<Self, OrgInviteLinkId>>> {
        let link = Self::find_protected_by_org(org_uuid, conn).await?;
        Ok(link.map(|mut link| match link.unprotect_code() {
            Ok(()) => Ok(link),
            Err(e) => {
                error!(
                    "The code of the invite link of organization {org_uuid} can't be decrypted ({e:?}). It was probably \
                    protected with a different rsa_key.pem. The link can't be used and counts as missing; creating a \
                    new one replaces it."
                );
                Err(link.uuid)
            }
        }))
    }

    /// The link of the organization with its code as stored
    async fn find_protected_by_org(org_uuid: &OrganizationId, conn: &DbConn) -> ApiResult<Option<Self>> {
        conn.run(move |conn| {
            org_invite_links::table
                .filter(org_invite_links::org_uuid.eq(org_uuid))
                .first::<Self>(conn)
                .optional()
                .map_res("Error finding organization invite link")
        })
        .await
    }

    /// Current locking read inside the organization and user transaction. DELETE, refresh and support-confirm
    /// update the same row, so they cannot complete between this read and the membership write.
    pub async fn find_by_org_for_update(org_uuid: &OrganizationId, conn: &DbConn) -> ApiResult<Option<Self>> {
        let conn_ref = conn;
        let link = db_run! { conn_ref:
            sqlite {
                org_invite_links::table.filter(org_invite_links::org_uuid.eq(org_uuid)).first::<Self>(conn_ref).optional()
            }
            mysql, postgresql {
                org_invite_links::table.filter(org_invite_links::org_uuid.eq(org_uuid)).for_update().first::<Self>(conn_ref).optional()
            }
        }
        .map_res("Error locking organization invite link")?;
        Ok(link.and_then(|mut link| link.unprotect_code().ok().map(|()| link)))
    }

    /// One-time, idempotent conversion while the old RSA key is still present. Rows encrypted under an already
    /// lost key remain replaceable or deletable through the existing admin endpoints.
    pub async fn migrate_legacy_codes(conn: &DbConn) -> ApiResult<()> {
        let conn_ref = conn;
        let links = db_run! { conn_ref:
            sqlite, mysql, postgresql {
                org_invite_links::table.load::<Self>(conn_ref).map_res("Error loading invite links")
            }
        }?;
        for mut link in links {
            if !crypto::is_protected_database_field(&link.code) {
                continue;
            }
            let old_code = link.code.clone();
            if let Err(e) = link.unprotect_code() {
                error!("Could not migrate invite link {}: {e:?}", link.uuid.0);
                continue;
            }
            let conn_ref = conn;
            db_run! { conn_ref:
                sqlite, mysql, postgresql {
                diesel::update(
                    org_invite_links::table
                        .filter(org_invite_links::uuid.eq(&link.uuid))
                        .filter(org_invite_links::code.eq(old_code)),
                )
                .set(org_invite_links::code.eq(link.code))
                .execute(conn_ref)
                .map(|_| ())
                .map_res("Error migrating invite link code")
                }
            }?;
        }
        Ok(())
    }

    /// Fails if the organization already has a link, the unique index also covers concurrent requests
    pub async fn insert(&self, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::insert_into(org_invite_links::table)
                .values((
                    org_invite_links::uuid.eq(&self.uuid),
                    org_invite_links::org_uuid.eq(&self.org_uuid),
                    org_invite_links::code.eq(&self.code),
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
        conn.run(move |conn| {
            diesel::update(org_invite_links::table.filter(org_invite_links::uuid.eq(&self.uuid)))
                .set((
                    org_invite_links::code.eq(&self.code),
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
        conn.run(move |conn| {
            diesel::update(org_invite_links::table.filter(org_invite_links::uuid.eq(uuid)))
                .set((
                    org_invite_links::uuid.eq(&self.uuid),
                    org_invite_links::code.eq(&self.code),
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

    /// Stores this new link in place of the link with `uuid` whose code can't be decrypted, in one statement so only
    /// one of concurrent requests replaces it. Returns `false` if that link was replaced or deleted meanwhile.
    pub async fn replace_undecryptable(&self, uuid: &OrgInviteLinkId, conn: &DbConn) -> ApiResult<bool> {
        conn.run(move |conn| {
            diesel::update(org_invite_links::table.filter(org_invite_links::uuid.eq(uuid)))
                .set((
                    org_invite_links::uuid.eq(&self.uuid),
                    org_invite_links::code.eq(&self.code),
                    org_invite_links::allowed_domains.eq(&self.allowed_domains),
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

    /// Deletes the link without decrypting its code, returns whether there was one
    pub async fn delete_all_by_organization(org_uuid: &OrganizationId, conn: &DbConn) -> ApiResult<bool> {
        conn.run(move |conn| {
            diesel::delete(org_invite_links::table.filter(org_invite_links::org_uuid.eq(org_uuid)))
                .execute(conn)
                .map(|rows| rows > 0)
                .map_res("Error deleting invite link")
        })
        .await
    }
}

#[derive(Debug, DieselNewType, Hash, PartialEq, Eq, Serialize)]
pub struct OrgInviteLinkId(String);

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
    /// Bearer secret of the link, only compare it with `code_matches`
    pub code: String,
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

    pub fn new(org_uuid: OrganizationId, invite: String, supports_confirmation: bool) -> Self {
        let now = Utc::now().naive_utc();
        Self {
            uuid: OrgInviteLinkId(crate::util::get_uuid()),
            org_uuid,
            // A random v4 UUID like upstream, the clients expect the code to be a UUID
            code: crate::util::get_uuid(),
            allowed_domains: String::from("[]"),
            invite,
            supports_confirmation,
            creation_date: now,
            revision_date: now,
        }
    }

    /// Checks the domains an admin entered like upstream and returns them normalized
    pub fn clean_domains(domains: Vec<String>) -> ApiResult<Vec<String>> {
        if domains.len() > Self::MAX_ALLOWED_DOMAINS {
            err!(format!("No more than {} allowed domains may be provided.", Self::MAX_ALLOWED_DOMAINS))
        }

        let mut invalid = Vec::new();
        let mut cleaned = Vec::with_capacity(domains.len());
        let mut seen = HashSet::with_capacity(domains.len());
        for domain in domains {
            if !is_valid_domain_name(&domain) {
                invalid.push(format!("'{}'", domain.escape_debug()));
                continue;
            }

            let domain = domain.to_ascii_lowercase();
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
        Ok(cleaned)
    }

    pub fn allowed_domains(&self) -> ApiResult<Vec<String>> {
        serde_json::from_str(&self.allowed_domains)
            .map_res("Invalid allowed domains stored for organization invite link")
    }

    pub fn set_allowed_domains(&mut self, domains: &[String]) {
        self.allowed_domains = json!(domains).to_string();
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
        let code = uuid::Uuid::parse_str(&self.code)
            .map_err(|_| Error::new_msg("Organization invite link contains an invalid code"))?
            .to_string();
        crypto::protect_database_field(&code, self.code_associated_data().as_bytes())
    }

    fn unprotect_code(&mut self) -> EmptyResult {
        let code = if crypto::is_protected_database_field(&self.code) {
            crypto::unprotect_database_field(&self.code, self.code_associated_data().as_bytes())?
        } else {
            // Branch builds before at-rest protection stored a plain UUID. Only that exact legacy shape is accepted;
            // a malformed or unknown envelope is corruption, not plaintext to silently trust.
            self.code.clone()
        };
        self.code = uuid::Uuid::parse_str(&code)
            .map_err(|_| Error::new_msg("Organization invite link contains an invalid protected code"))?
            .to_string();
        Ok(())
    }
}

/// Upstream's `DomainNameValidatorAttribute`: ASCII labels of letters, digits and hyphens, at least one dot, a
/// top-level label of letters and no scheme or `www.` prefix. Internationalized domains need their `xn--` form.
fn is_valid_domain_name(domain: &str) -> bool {
    let mut labels: Vec<&str> = domain.split('.').collect();
    let tld = labels.pop().unwrap_or_default();

    domain.len() <= 253
        && !domain.to_ascii_lowercase().starts_with("www.")
        && !labels.is_empty()
        && tld.len() >= 2
        && tld.bytes().all(|b| b.is_ascii_alphabetic())
        && labels.iter().all(|label| {
            (1..=63).contains(&label.len())
                && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
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
        let mut link = conn
            .run(move |conn| {
                org_invite_links::table
                    .filter(org_invite_links::org_uuid.eq(org_uuid))
                    .first::<Self>(conn)
                    .optional()
                    .map_res("Error finding organization invite link")
            })
            .await?;
        if let Some(link) = &mut link {
            link.unprotect_code()?;
        }
        Ok(link)
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

#[cfg(test)]
mod tests {
    use std::sync::Once;

    use super::*;

    static INIT_DATABASE_FIELD_KEY: Once = Once::new();

    fn initialize_database_field_key() {
        INIT_DATABASE_FIELD_KEY.call_once(|| {
            crypto::initialize_database_field_key(b"org-invite-link-test-installation-key").unwrap();
        });
    }

    fn link(domains: &[&str]) -> OrgInviteLink {
        let mut link = OrgInviteLink::new(String::from("org").into(), String::new(), false);
        link.set_allowed_domains(&domains.iter().map(|d| (*d).to_owned()).collect::<Vec<_>>());
        link
    }

    fn clean(domains: &[&str]) -> ApiResult<Vec<String>> {
        OrgInviteLink::clean_domains(domains.iter().map(|d| (*d).to_owned()).collect())
    }

    #[test]
    fn valid_domains_are_normalized() {
        assert_eq!(
            clean(&["Example.COM", "sub.example.co.uk", "xn--bcher-kva.de", "example.com"]).unwrap(),
            ["example.com", "sub.example.co.uk", "xn--bcher-kva.de"]
        );
    }

    #[test]
    fn oversized_domain_lists_are_rejected_before_processing() {
        let domains = (0..100_000).map(|i| format!("{i}.example.com")).collect();
        assert!(OrgInviteLink::clean_domains(domains).is_err());
    }

    #[test]
    fn maximum_domain_list_fits_mysql_text() {
        let domains: Vec<String> = (0..OrgInviteLink::MAX_ALLOWED_DOMAINS)
            .map(|i| format!("{i:03}{}.{}.{}.{}.de", "a".repeat(60), "b".repeat(63), "c".repeat(63), "d".repeat(58),))
            .collect();
        assert!(domains.iter().all(|domain| domain.len() == 253));

        let cleaned = OrgInviteLink::clean_domains(domains).unwrap();
        let serialized = serde_json::to_string(&cleaned).unwrap();
        assert_eq!(serialized.len(), 65_281);
        assert!(serialized.len() <= u16::MAX as usize);
    }

    #[test]
    fn invalid_domains_are_rejected() {
        for domain in [
            "",
            " example.com",
            "example.com ",
            "exa mple.com",
            "example",
            "example.c",
            "example.c0m",
            "-example.com",
            "example-.com",
            "exa_mple.com",
            "example..com",
            ".example.com",
            "example.com.",
            "www.example.com",
            "WWW.example.com",
            "https://example.com",
            "user@example.com",
            "bücher.de",
            "<script>.com",
            "*.example.com",
            &format!("{}.com", "a".repeat(64)),
        ] {
            assert!(clean(&["example.com", domain]).is_err(), "{domain:?} must be rejected");
        }
        assert!(clean(&[]).is_err());
    }

    #[test]
    fn only_exact_email_domains_are_allowed() {
        let link = link(&["example.com", "xn--bcher-kva.de"]);
        for email in ["user@example.com", "User@EXAMPLE.com", "\"user@evil.com\"@example.com", "user@bücher.de"] {
            assert!(link.allows_email(email).unwrap(), "{email:?} must be allowed");
        }
        for email in [
            "user@evil-example.com",
            "user@example.com.evil.com",
            "user@sub.example.com",
            "user@example.com@evil.com",
            "\"user@example.com\"@evil.com",
            "user@example.co",
            "user@example.com.",
            "user@[127.0.0.1]",
            "example.com",
            "",
        ] {
            assert!(!link.allows_email(email).unwrap(), "{email:?} must not be allowed");
        }
        assert!(!self::link(&[]).allows_email("user@example.com").unwrap());
    }

    #[test]
    fn codes_are_compared_case_insensitively() {
        let link = link(&[]);
        let code = uuid::Uuid::parse_str(&link.code).unwrap();
        let uppercase_code = uuid::Uuid::parse_str(&link.code.to_uppercase()).unwrap();
        let wrong_code = uuid::Uuid::new_v4();
        assert!(link.code_matches(&code));
        assert!(link.code_matches(&uppercase_code));
        assert!(!link.code_matches(&wrong_code));
    }

    #[test]
    fn invalid_allowed_domains_json_is_not_silently_treated_as_empty() {
        let mut link = link(&["example.com"]);
        link.allowed_domains = "[truncated".to_owned();
        assert!(link.allowed_domains().is_err());
        assert!(link.allows_email("user@example.com").is_err());
        assert!(link.to_json().is_err());
    }

    #[test]
    fn protected_code_round_trips_and_is_bound_to_the_organization() {
        initialize_database_field_key();
        let org_id = crate::util::get_uuid();
        let mut link = OrgInviteLink::new(org_id.clone().into(), String::new(), false);
        let plaintext = link.code.clone();
        let protected = link.protected_code().unwrap();
        assert_ne!(protected, plaintext);
        assert!(protected.starts_with("P|1|"));

        link.code = protected.clone();
        link.unprotect_code().unwrap();
        assert_eq!(link.code, plaintext);

        let mut moved = OrgInviteLink::new(crate::util::get_uuid().into(), String::new(), false);
        moved.code = protected;
        assert!(moved.unprotect_code().is_err());
    }

    #[test]
    fn only_valid_plaintext_uuid_is_accepted_for_legacy_rows() {
        let mut legacy = OrgInviteLink::new(crate::util::get_uuid().into(), String::new(), false);
        let code = legacy.code.clone();
        legacy.unprotect_code().unwrap();
        assert_eq!(legacy.code, code);

        legacy.code = "not-a-legacy-uuid".to_owned();
        assert!(legacy.unprotect_code().is_err());

        legacy.code = "P|unknown-format".to_owned();
        assert!(legacy.unprotect_code().is_err());
    }
}

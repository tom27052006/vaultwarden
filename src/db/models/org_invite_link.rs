use std::str::FromStr;

use chrono::{NaiveDateTime, Utc};
use diesel::prelude::*;
use serde_json::Value;

use crate::{
    api::{ApiResult, EmptyResult},
    db::{DbConn, schema::org_invite_links},
    error::MapResult,
    util::format_date,
};

use super::OrganizationId;

/// A reusable link that lets users with an allowed email domain join an organization.
// https://github.com/bitwarden/server/blob/aa786fc9cd3803f48e79f15067e910e99d768b69/src/Core/AdminConsole/Entities/OrganizationInviteLink.cs
#[derive(Identifiable, Queryable, Insertable)]
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
        let invalid: Vec<String> =
            domains.iter().filter(|d| !is_valid_domain_name(d)).map(|d| format!("'{}'", d.escape_debug())).collect();
        if !invalid.is_empty() {
            err!(format!("The following items are not valid: {}", invalid.join(", ")))
        }

        let mut cleaned: Vec<String> = Vec::with_capacity(domains.len());
        for domain in domains.into_iter().map(|d| d.to_ascii_lowercase()) {
            if !cleaned.contains(&domain) {
                cleaned.push(domain);
            }
        }
        if cleaned.is_empty() {
            err!("At least one allowed domain is required.")
        }
        Ok(cleaned)
    }

    pub fn allowed_domains(&self) -> Vec<String> {
        serde_json::from_str(&self.allowed_domains).unwrap_or_default()
    }

    pub fn set_allowed_domains(&mut self, domains: &[String]) {
        self.allowed_domains = json!(domains).to_string();
    }

    /// Constant time comparison with a code sent by a client, which like upstream may use any case
    pub fn code_matches(&self, code: &str) -> bool {
        crate::crypto::ct_eq(&self.code, code.to_ascii_lowercase())
    }

    /// Whether the domain of the email address is one of the allowed domains, subdomains are not included.
    /// Like upstream, this only protects anything if the address is verified.
    pub fn allows_email(&self, email: &str) -> bool {
        email_domain(email).is_some_and(|domain| self.allowed_domains().contains(&domain))
    }

    // https://github.com/bitwarden/server/blob/aa786fc9cd3803f48e79f15067e910e99d768b69/src/Api/AdminConsole/Models/Response/Organizations/OrganizationInviteLinkResponseModel.cs
    pub fn to_json(&self) -> Value {
        json!({
            "id": self.uuid,
            "code": self.code,
            "organizationId": self.org_uuid,
            "allowedDomains": self.allowed_domains(),
            "invite": self.invite,
            "supportsConfirmation": self.supports_confirmation,
            "creationDate": format_date(&self.creation_date),
            "object": "organizationInviteLink",
        })
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
    pub async fn find_by_org(org_uuid: &OrganizationId, conn: &DbConn) -> Option<Self> {
        conn.run(move |conn| {
            org_invite_links::table.filter(org_invite_links::org_uuid.eq(org_uuid)).first::<Self>(conn).ok()
        })
        .await
    }

    /// Fails if the organization already has a link, the unique index also covers concurrent requests
    pub async fn insert(&self, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::insert_into(org_invite_links::table).values(self).execute(conn).map_res("Error saving invite link")
        })
        .await
    }

    /// Stores the allowed domains, returns `false` if the link was refreshed or deleted meanwhile
    pub async fn update_allowed_domains(&self, conn: &DbConn) -> ApiResult<bool> {
        conn.run(move |conn| {
            diesel::update(org_invite_links::table.filter(org_invite_links::uuid.eq(&self.uuid)))
                .set((
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
    use super::*;

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
            assert!(link.allows_email(email), "{email:?} must be allowed");
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
            assert!(!link.allows_email(email), "{email:?} must not be allowed");
        }
        assert!(!self::link(&[]).allows_email("user@example.com"));
    }

    #[test]
    fn codes_are_compared_case_insensitively() {
        let link = link(&[]);
        assert!(link.code_matches(&link.code));
        assert!(link.code_matches(&link.code.to_uppercase()));
        assert!(!link.code_matches(&crate::util::get_uuid()));
        assert!(!link.code_matches(""));
        assert!(!link.code_matches(&link.code[..35]));
    }
}

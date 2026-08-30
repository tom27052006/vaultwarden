//! Mapping between SCIM resources and Vaultwarden's own model.
//!
//! SCIM ids are existing Vaultwarden ids -- a SCIM `User.id` is a `MembershipId` and a SCIM
//! `Group.id` is a `GroupId` -- so no SCIM-specific mapping table is needed and every lookup can
//! bind the organization id alongside the resource id.
//!
//! The inbound structs here deliberately have **no field that maps to a membership type,
//! permission or policy**. That is the structural reason SCIM cannot be used to escalate
//! privileges: there is nowhere for a role to be assigned from, whatever the request body says.

use chrono::NaiveDateTime;
use serde_json::Value;

use crate::{
    db::models::{Group, GroupId, Membership, MembershipId, MembershipStatus, MembershipType, User},
    util::{format_date, is_valid_email},
};

use super::{
    GROUP_SCHEMA, USER_SCHEMA,
    error::{ScimError, ScimResult},
    filter::{FilterResource, FilterValue},
};

/// Upper bound on a `userName`, matching what any sane mail system accepts.
const MAX_USER_NAME_LEN: usize = 255;
/// Upper bound on an `externalId`. The column is `TEXT`/`VARCHAR(300)` depending on the backend.
const MAX_EXTERNAL_ID_LEN: usize = 255;
/// Upper bound on a group `displayName`. MySQL stores `groups.name` as `VARCHAR(100)`.
const MAX_DISPLAY_NAME_LEN: usize = 100;
/// Most members a single request may reference.
pub const MAX_MEMBERS_PER_REQUEST: usize = 5000;

// ---------------------------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------------------------

/// Normalise a SCIM `userName` into the form Vaultwarden stores emails in.
///
/// Vaultwarden lower-cases every account email (`User::new`, `User::find_by_mail`), so SCIM must
/// do the same or the same person would resolve to two different accounts depending on how the
/// identity provider happened to capitalise them.
pub fn normalize_user_name(raw: &str) -> ScimResult<String> {
    let trimmed = raw.trim();

    if trimmed.is_empty() {
        return Err(ScimError::invalid_value("'userName' must not be empty."));
    }
    if trimmed.len() > MAX_USER_NAME_LEN {
        return Err(ScimError::invalid_value(format!("'userName' must be at most {MAX_USER_NAME_LEN} characters.")));
    }
    if !is_valid_email(trimmed) {
        return Err(ScimError::invalid_value("'userName' must be a valid email address."));
    }

    Ok(trimmed.to_lowercase())
}

/// Validate an `externalId`, mapping empty to `None`.
///
/// Vaultwarden's `set_external_id` already collapses empty strings to `NULL`; doing the same here
/// means a client cannot create two "different" external ids that are both stored as `NULL`.
pub fn normalize_external_id(raw: Option<&str>) -> ScimResult<Option<String>> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let trimmed = raw.trim();

    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed.len() > MAX_EXTERNAL_ID_LEN {
        return Err(ScimError::invalid_value(format!(
            "'externalId' must be at most {MAX_EXTERNAL_ID_LEN} characters."
        )));
    }

    Ok(Some(trimmed.to_owned()))
}

pub fn normalize_display_name(raw: &str) -> ScimResult<String> {
    let trimmed = raw.trim();

    if trimmed.is_empty() {
        return Err(ScimError::invalid_value("'displayName' must not be empty."));
    }
    if trimmed.chars().count() > MAX_DISPLAY_NAME_LEN {
        return Err(ScimError::invalid_value(format!(
            "'displayName' must be at most {MAX_DISPLAY_NAME_LEN} characters."
        )));
    }

    Ok(trimmed.to_owned())
}

// ---------------------------------------------------------------------------------------------
// Outbound: User
// ---------------------------------------------------------------------------------------------

/// A membership rendered as the data a SCIM `User` needs.
///
/// Keeping this separate from the JSON means filtering, PATCH planning and the privilege checks
/// all operate on plain data that can be constructed in a test without a database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserView {
    pub id: MembershipId,
    pub external_id: Option<String>,
    /// The account email, already lower-cased.
    pub user_name: String,
    pub display_name: String,
    pub active: bool,
    /// The underlying `MembershipType`, used to refuse writes to privileged memberships.
    pub membership_type: i32,
}

impl UserView {
    pub fn from_membership(member: &Membership, user: &User) -> Self {
        Self {
            id: member.uuid.clone(),
            external_id: member.external_id.clone(),
            user_name: user.email.to_lowercase(),
            // Shell accounts created by an invite get `name == email`; showing that is more
            // useful than showing nothing.
            display_name: if user.name.trim().is_empty() {
                user.email.clone()
            } else {
                user.name.clone()
            },
            active: member.status > MembershipStatus::Revoked as i32,
            membership_type: member.atype,
        }
    }

    /// Is this membership one SCIM is allowed to modify?
    ///
    /// Only plain `User` memberships are writable. Owners, Admins and Managers are refused, which
    /// is what makes "SCIM cannot create, demote, restore or remove a privileged member" true by
    /// construction rather than by a list of special cases.
    pub fn is_scim_manageable(&self) -> bool {
        self.membership_type == MembershipType::User as i32
    }

    pub fn to_json(&self, location: &str) -> Value {
        // `meta.created` / `meta.lastModified` are deliberately absent: `users_organizations` has
        // no timestamps, and reporting the *account's* timestamps would be misleading. Both are
        // optional in RFC 7643 section 3.1. See docs/scim/design.md section 6.
        json!({
            "schemas": [USER_SCHEMA],
            "id": self.id,
            "externalId": self.external_id,
            "userName": self.user_name,
            "displayName": self.display_name,
            "active": self.active,
            "emails": [{
                "value": self.user_name,
                "type": "work",
                "primary": true,
            }],
            "meta": {
                "resourceType": "User",
                "location": location,
            },
        })
    }

    /// Flatten into the shape the filter evaluator understands.
    pub fn to_filter_resource(&self) -> FilterResource {
        let mut resource = FilterResource::new();
        resource
            .set("id", Some(FilterValue::str(self.id.to_string())))
            .set("username", Some(FilterValue::str(&self.user_name)))
            .set("displayname", Some(FilterValue::str(&self.display_name)))
            .set("active", Some(FilterValue::Bool(self.active)))
            .set("meta.resourcetype", Some(FilterValue::str("User")))
            .set("externalid", self.external_id.as_ref().map(FilterValue::str));

        let mut email = FilterResource::new();
        email
            .set("emails.value", Some(FilterValue::str(&self.user_name)))
            .set("emails.type", Some(FilterValue::str("work")))
            .set("emails.primary", Some(FilterValue::Bool(true)));
        resource.push_element("emails", email);

        resource
    }
}

// ---------------------------------------------------------------------------------------------
// Outbound: Group
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupView {
    pub id: GroupId,
    pub external_id: Option<String>,
    pub display_name: String,
    pub created: NaiveDateTime,
    pub last_modified: NaiveDateTime,
    /// `None` when the caller excluded `members` and the membership was never loaded.
    pub members: Option<Vec<MembershipId>>,
}

impl GroupView {
    pub fn from_group(group: &Group, members: Option<Vec<MembershipId>>) -> Self {
        Self {
            id: group.uuid.clone(),
            external_id: group.external_id.clone(),
            display_name: group.name.clone(),
            created: group.creation_date,
            last_modified: group.revision_date,
            members,
        }
    }

    pub fn to_json(&self, location: &str, base_url: &str) -> Value {
        let mut body = json!({
            "schemas": [GROUP_SCHEMA],
            "id": self.id,
            "externalId": self.external_id,
            "displayName": self.display_name,
            "meta": {
                "resourceType": "Group",
                "created": format_date(&self.created),
                "lastModified": format_date(&self.last_modified),
                "location": location,
            },
        });

        if let Some(members) = &self.members {
            // `display` is omitted on purpose: it is optional in RFC 7643, no identity provider
            // consumes it, and producing it would cost one account lookup per member.
            body["members"] = Value::Array(
                members
                    .iter()
                    .map(|m| {
                        json!({
                            "value": m,
                            "$ref": format!("{base_url}/Users/{m}"),
                            "type": "User",
                        })
                    })
                    .collect(),
            );
        }

        body
    }

    pub fn to_filter_resource(&self) -> FilterResource {
        let mut resource = FilterResource::new();
        resource
            .set("id", Some(FilterValue::str(self.id.to_string())))
            .set("displayname", Some(FilterValue::str(&self.display_name)))
            .set("meta.resourcetype", Some(FilterValue::str("Group")))
            .set("externalid", self.external_id.as_ref().map(FilterValue::str));

        for member in self.members.iter().flatten() {
            let mut element = FilterResource::new();
            element.set("members.value", Some(FilterValue::str(member.to_string())));
            resource.push_element("members", element);
        }

        resource
    }
}

// ---------------------------------------------------------------------------------------------
// Inbound
// ---------------------------------------------------------------------------------------------

/// Validate a resource document's `schemas` array.
///
/// Deliberately lenient: an absent or empty array is accepted, and additional URNs (an identity
/// provider announcing an extension this server does not implement) are fine. Only a document
/// that announces schemas and omits the core one is rejected, because that is a genuine
/// client/server mismatch rather than a difference in optional features.
pub fn ensure_schema(schemas: Option<&Vec<String>>, expected: &str) -> ScimResult<()> {
    let Some(schemas) = schemas.filter(|s| !s.is_empty()) else {
        return Ok(());
    };

    if schemas.iter().any(|s| s.eq_ignore_ascii_case(expected)) {
        return Ok(());
    }

    Err(ScimError::invalid_syntax(format!("Request 'schemas' must include '{expected}'.")))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimEmail {
    pub value: Option<String>,
    pub primary: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimName {
    pub formatted: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
}

/// The `User` document accepted by `POST` and `PUT`.
///
/// Unknown attributes are ignored rather than rejected. Identity providers routinely send
/// attributes a server does not implement -- `title`, `addresses`, `phoneNumbers`, the
/// `EnterpriseUser` extension -- and rejecting them would break provisioning outright. Ignoring
/// them is safe precisely because this struct has no privileged field to be filled in.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimUserRequest {
    pub schemas: Option<Vec<String>>,
    pub external_id: Option<String>,
    pub user_name: Option<String>,
    pub display_name: Option<String>,
    pub name: Option<ScimName>,
    pub emails: Option<Vec<ScimEmail>>,
    pub active: Option<bool>,
}

impl ScimUserRequest {
    /// The email this document identifies, preferring `userName` and falling back to the primary
    /// (or first) email, which is what identity providers that omit `userName` expect.
    pub fn resolve_user_name(&self) -> ScimResult<String> {
        if let Some(user_name) = self.user_name.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            return normalize_user_name(user_name);
        }

        let emails = self.emails.as_deref().unwrap_or_default();
        let candidate = emails
            .iter()
            .find(|e| e.primary == Some(true) && e.value.is_some())
            .or_else(|| emails.iter().find(|e| e.value.is_some()));

        match candidate.and_then(|e| e.value.as_deref()) {
            Some(value) => normalize_user_name(value),
            None => Err(ScimError::invalid_value("'userName' is required.")),
        }
    }

    /// A human-readable name for an account this request is about to create.
    ///
    /// Only ever applied to a brand-new shell account. An account that already exists keeps its
    /// name: that name is global, and one organization's identity provider must not rewrite what
    /// every other organization sees.
    pub fn resolve_display_name(&self) -> Option<String> {
        let from_display = self.display_name.as_deref().map(str::trim).filter(|s| !s.is_empty());
        if let Some(name) = from_display {
            return Some(name.to_owned());
        }

        let name = self.name.as_ref()?;
        if let Some(formatted) = name.formatted.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            return Some(formatted.to_owned());
        }

        let given = name.given_name.as_deref().map(str::trim).filter(|s| !s.is_empty());
        let family = name.family_name.as_deref().map(str::trim).filter(|s| !s.is_empty());
        match (given, family) {
            (Some(given), Some(family)) => Some(format!("{given} {family}")),
            (Some(part), None) | (None, Some(part)) => Some(part.to_owned()),
            (None, None) => None,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimMemberRef {
    pub value: Option<String>,
}

/// The `Group` document accepted by `POST` and `PUT`.
///
/// `members` is `Option` on purpose. An absent key means "leave membership alone"; an explicit
/// empty array means "remove every member". A strict reading of RFC 7644 section 3.5.1 would
/// treat both as "remove every member", which turns a sparse client payload into a silent
/// mass-deprovisioning. See docs/scim/design.md section 8.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimGroupRequest {
    pub schemas: Option<Vec<String>>,
    pub external_id: Option<String>,
    pub display_name: Option<String>,
    pub members: Option<Vec<ScimMemberRef>>,
}

impl ScimGroupRequest {
    /// Extract the referenced membership ids, without yet checking that they exist or belong to
    /// this organization -- the caller does that against the database before mutating anything.
    pub fn member_ids(&self) -> ScimResult<Option<Vec<MembershipId>>> {
        let Some(members) = &self.members else {
            return Ok(None);
        };

        if members.len() > MAX_MEMBERS_PER_REQUEST {
            return Err(ScimError::bad_request(
                super::error::ScimType::TooMany,
                format!("At most {MAX_MEMBERS_PER_REQUEST} members may be sent in one request."),
            ));
        }

        let mut ids = Vec::with_capacity(members.len());
        for member in members {
            let Some(value) = member.value.as_deref().map(str::trim).filter(|v| !v.is_empty()) else {
                return Err(ScimError::invalid_value("Each 'members' entry requires a 'value'."));
            };
            ids.push(MembershipId::from(value.to_owned()));
        }

        Ok(Some(ids))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- userName normalisation ----------------------------------------------------------------

    #[test]
    fn user_names_are_lower_cased_and_trimmed() {
        assert_eq!(normalize_user_name("  Alice@Example.TEST  ").unwrap(), "alice@example.test");
    }

    #[test]
    fn user_names_must_be_email_addresses() {
        // Vaultwarden identifies accounts by email; anything else cannot be provisioned.
        for bad in ["alice", "alice@", "@example.test", "alice example.test", "alice@exam ple.test"] {
            assert!(normalize_user_name(bad).is_err(), "{bad} should be rejected");
        }
    }

    #[test]
    fn empty_user_names_are_rejected() {
        assert!(normalize_user_name("").is_err());
        assert!(normalize_user_name("   ").is_err());
    }

    #[test]
    fn over_long_user_names_are_rejected() {
        let long = format!("{}@example.test", "a".repeat(MAX_USER_NAME_LEN));
        assert!(normalize_user_name(&long).is_err());
    }

    // -- externalId normalisation --------------------------------------------------------------

    #[test]
    fn external_ids_collapse_empty_to_none() {
        // Matches Membership::set_external_id, so two "different" empty ids cannot both be stored.
        assert_eq!(normalize_external_id(None).unwrap(), None);
        assert_eq!(normalize_external_id(Some("")).unwrap(), None);
        assert_eq!(normalize_external_id(Some("   ")).unwrap(), None);
    }

    #[test]
    fn external_ids_are_trimmed_but_case_preserved() {
        assert_eq!(normalize_external_id(Some("  AbC-123  ")).unwrap(), Some("AbC-123".to_owned()));
    }

    #[test]
    fn over_long_external_ids_are_rejected() {
        let long = "x".repeat(MAX_EXTERNAL_ID_LEN + 1);
        assert!(normalize_external_id(Some(&long)).is_err());
    }

    // -- displayName normalisation -------------------------------------------------------------

    #[test]
    fn group_display_names_are_bounded() {
        assert_eq!(normalize_display_name("  Engineering  ").unwrap(), "Engineering");
        assert!(normalize_display_name("").is_err());
        assert!(normalize_display_name(&"x".repeat(MAX_DISPLAY_NAME_LEN + 1)).is_err());
        // The limit is characters, not bytes, so multi-byte names are not unfairly rejected.
        assert!(normalize_display_name(&"é".repeat(MAX_DISPLAY_NAME_LEN)).is_ok());
    }

    // -- inbound user documents ----------------------------------------------------------------

    fn parse_user(body: Value) -> ScimUserRequest {
        serde_json::from_value(body).expect("should deserialize")
    }

    #[test]
    fn parses_the_document_entra_sends_on_create() {
        let request = parse_user(json!({
            "schemas": [USER_SCHEMA],
            "externalId": "8a7b6c5d",
            "userName": "alice@example.test",
            "displayName": "Alice Example",
            "name": {"givenName": "Alice", "familyName": "Example"},
            "emails": [{"primary": true, "type": "work", "value": "alice@example.test"}],
            "active": true,
        }));

        assert_eq!(request.resolve_user_name().unwrap(), "alice@example.test");
        assert_eq!(request.external_id.as_deref(), Some("8a7b6c5d"));
        assert_eq!(request.active, Some(true));
    }

    #[test]
    fn falls_back_to_the_primary_email_when_user_name_is_absent() {
        let request = parse_user(json!({
            "emails": [
                {"value": "secondary@example.test", "primary": false},
                {"value": "Primary@Example.test", "primary": true},
            ],
        }));

        assert_eq!(request.resolve_user_name().unwrap(), "primary@example.test");
    }

    #[test]
    fn falls_back_to_the_first_email_when_none_is_primary() {
        let request = parse_user(json!({"emails": [{"value": "only@example.test"}]}));
        assert_eq!(request.resolve_user_name().unwrap(), "only@example.test");
    }

    #[test]
    fn a_document_with_no_identifier_is_rejected() {
        assert!(parse_user(json!({})).resolve_user_name().is_err());
        assert!(parse_user(json!({"emails": []})).resolve_user_name().is_err());
    }

    #[test]
    fn unknown_attributes_are_ignored_not_rejected() {
        // Entra sends the EnterpriseUser extension and various optional core attributes.
        let request = parse_user(json!({
            "userName": "alice@example.test",
            "title": "Engineer",
            "phoneNumbers": [{"value": "+1-555-0100"}],
            "addresses": [{"country": "US"}],
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {"department": "R&D"},
        }));

        assert_eq!(request.resolve_user_name().unwrap(), "alice@example.test");
    }

    #[test]
    fn there_is_no_way_to_ask_for_a_privileged_role() {
        // The inbound struct has no role/type/permission field at all, so these are dropped.
        // This is the structural guarantee behind "SCIM cannot create an Owner or Admin".
        let request = parse_user(json!({
            "userName": "attacker@example.test",
            "type": 0,
            "atype": 0,
            "role": "Owner",
            "membershipType": "Owner",
            "accessAll": true,
            "permissions": {"manageUsers": true},
        }));

        assert_eq!(request.resolve_user_name().unwrap(), "attacker@example.test");
        // Nothing above survived parsing; the only fields that exist are the benign ones.
        assert_eq!(request.display_name, None);
        assert_eq!(request.active, None);
    }

    // -- inbound group documents ---------------------------------------------------------------

    fn parse_group(body: Value) -> ScimGroupRequest {
        serde_json::from_value(body).expect("should deserialize")
    }

    #[test]
    fn absent_members_is_distinguishable_from_empty_members() {
        // This distinction is what stops a sparse PUT from emptying a group.
        assert_eq!(parse_group(json!({"displayName": "Eng"})).member_ids().unwrap(), None);
        assert_eq!(parse_group(json!({"displayName": "Eng", "members": []})).member_ids().unwrap(), Some(vec![]));
    }

    #[test]
    fn member_ids_are_extracted_in_order() {
        let request = parse_group(json!({
            "displayName": "Eng",
            "members": [{"value": "m1"}, {"value": "m2", "display": "ignored"}],
        }));

        let ids = request.member_ids().unwrap().unwrap();
        assert_eq!(ids.len(), 2);
        assert_eq!(*ids[0], "m1");
        assert_eq!(*ids[1], "m2");
    }

    #[test]
    fn member_entries_without_a_value_are_rejected() {
        let request = parse_group(json!({"members": [{"display": "no value here"}]}));
        assert!(request.member_ids().is_err());

        let request = parse_group(json!({"members": [{"value": "  "}]}));
        assert!(request.member_ids().is_err());
    }

    #[test]
    fn over_long_member_lists_are_rejected() {
        let members: Vec<Value> = (0..=MAX_MEMBERS_PER_REQUEST).map(|i| json!({"value": format!("m{i}")})).collect();
        let request = parse_group(json!({"members": members}));

        let err = request.member_ids().unwrap_err();
        assert_eq!(err.scim_type, Some(super::super::error::ScimType::TooMany));
    }

    // -- outbound rendering --------------------------------------------------------------------

    fn view(active: bool, membership_type: MembershipType) -> UserView {
        UserView {
            id: MembershipId::from("member-1".to_owned()),
            external_id: Some("ext-1".to_owned()),
            user_name: "alice@example.test".to_owned(),
            display_name: "Alice".to_owned(),
            active,
            membership_type: membership_type as i32,
        }
    }

    #[test]
    fn user_json_matches_the_core_schema() {
        let body = view(true, MembershipType::User).to_json("https://vault.test/scim/v2/org/Users/member-1");

        assert_eq!(body["schemas"], json!([USER_SCHEMA]));
        assert_eq!(body["id"], json!("member-1"));
        assert_eq!(body["userName"], json!("alice@example.test"));
        assert_eq!(body["externalId"], json!("ext-1"));
        assert_eq!(body["active"], json!(true));
        assert_eq!(body["emails"][0]["value"], json!("alice@example.test"));
        assert_eq!(body["emails"][0]["primary"], json!(true));
        assert_eq!(body["meta"]["resourceType"], json!("User"));
        assert_eq!(body["meta"]["location"], json!("https://vault.test/scim/v2/org/Users/member-1"));
    }

    #[test]
    fn user_json_never_exposes_the_membership_type() {
        // The role is an internal authorization attribute; SCIM neither accepts nor reports it.
        let body = view(true, MembershipType::Owner).to_json("https://vault.test/x");
        let rendered = body.to_string();

        assert!(!rendered.contains("Owner"), "{rendered}");
        assert!(body.get("type").is_none());
        assert!(body.get("membershipType").is_none());
    }

    #[test]
    fn only_plain_user_memberships_are_scim_manageable() {
        assert!(view(true, MembershipType::User).is_scim_manageable());
        assert!(!view(true, MembershipType::Owner).is_scim_manageable());
        assert!(!view(true, MembershipType::Admin).is_scim_manageable());
        assert!(!view(true, MembershipType::Manager).is_scim_manageable());
    }

    #[test]
    fn revoked_memberships_render_as_inactive() {
        assert!(view(true, MembershipType::User).to_json("l")["active"].as_bool().unwrap());
        assert!(!view(false, MembershipType::User).to_json("l")["active"].as_bool().unwrap());
    }

    #[test]
    fn group_json_matches_the_core_schema() {
        let group = GroupView {
            id: GroupId::from("group-1".to_owned()),
            external_id: Some("g-ext".to_owned()),
            display_name: "Engineering".to_owned(),
            created: chrono::DateTime::UNIX_EPOCH.naive_utc(),
            last_modified: chrono::DateTime::UNIX_EPOCH.naive_utc(),
            members: Some(vec![MembershipId::from("member-1".to_owned())]),
        };

        let body = group.to_json("https://vault.test/scim/v2/org/Groups/group-1", "https://vault.test/scim/v2/org");

        assert_eq!(body["schemas"], json!([GROUP_SCHEMA]));
        assert_eq!(body["displayName"], json!("Engineering"));
        assert_eq!(body["externalId"], json!("g-ext"));
        assert_eq!(body["members"][0]["value"], json!("member-1"));
        assert_eq!(body["members"][0]["$ref"], json!("https://vault.test/scim/v2/org/Users/member-1"));
        assert_eq!(body["meta"]["resourceType"], json!("Group"));
        assert!(body["meta"]["created"].is_string());
        assert!(body["meta"]["lastModified"].is_string());
    }

    #[test]
    fn group_json_omits_members_when_they_were_not_loaded() {
        let group = GroupView {
            id: GroupId::from("group-1".to_owned()),
            external_id: None,
            display_name: "Engineering".to_owned(),
            created: chrono::DateTime::UNIX_EPOCH.naive_utc(),
            last_modified: chrono::DateTime::UNIX_EPOCH.naive_utc(),
            members: None,
        };

        let body = group.to_json("l", "b");
        assert!(body.get("members").is_none(), "excluded members must not appear as an empty array");
    }
}

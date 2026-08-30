//! SCIM `PATCH` support, per RFC 7644 section 3.5.2.
//!
//! A `PatchOp` document is turned into a fully validated *change set* before anything is written.
//! Vaultwarden's database layer runs one statement per `conn.run(...)` call and its model methods
//! are `async`, so a transaction cannot span several of them; planning the whole request first is
//! what makes a partially-applied `PATCH` impossible. See `docs/scim/design.md` section 8.
//!
//! The parsing here is deliberately tolerant of the two things Microsoft Entra ID does that a
//! strict reading of the RFC does not require -- capitalised `op` names and booleans sent as
//! strings -- and strict about everything else. An unsupported path is an error, never a silent
//! no-op, because silently ignoring an operation makes a broken mapping look like a working one.

use serde_json::Value;

use crate::db::models::MembershipId;

use super::{
    PATCH_OP_SCHEMA,
    error::{ScimError, ScimResult, ScimType},
    filter::{CompValue, CompareOp, Filter, GROUP_ATTRS},
    resource::{MAX_MEMBERS_PER_REQUEST, normalize_display_name, normalize_external_id, normalize_user_name},
};

/// Most operations a single `PatchOp` document may contain.
pub const MAX_PATCH_OPERATIONS: usize = 1000;

// ---------------------------------------------------------------------------------------------
// Wire format
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct PatchRequest {
    pub schemas: Option<Vec<String>>,
    /// RFC 7644 spells this `Operations`; some clients use `operations`.
    #[serde(rename = "Operations", alias = "operations")]
    pub operations: Vec<PatchOperation>,
}

#[derive(Debug, Deserialize)]
pub struct PatchOperation {
    pub op: String,
    pub path: Option<String>,
    pub value: Option<Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatchOp {
    Add,
    Replace,
    Remove,
}

impl PatchOp {
    /// Entra ID sends `"Add"`, `"Replace"` and `"Remove"`; the RFC uses lower case. Accept both.
    fn parse(raw: &str) -> ScimResult<Self> {
        match raw.trim().to_lowercase().as_str() {
            "add" => Ok(Self::Add),
            "replace" => Ok(Self::Replace),
            "remove" => Ok(Self::Remove),
            other => Err(ScimError::invalid_syntax(format!(
                "Unsupported PATCH operation '{other}'; expected add, replace or remove."
            ))),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Path parsing
// ---------------------------------------------------------------------------------------------

/// A parsed `path` from a PATCH operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchPath {
    /// Lower-case base attribute, e.g. `active`, `members`.
    pub attr: String,
    /// Lower-case sub-attribute, from either `attr.sub` or `attr[...].sub`.
    pub sub: Option<String>,
    /// Raw filter text from `attr[...]`, if present.
    pub filter: Option<String>,
}

impl PatchPath {
    pub fn parse(raw: &str) -> ScimResult<Self> {
        let raw = raw.trim();
        if raw.is_empty() {
            return Err(ScimError::invalid_path("PATCH 'path' must not be empty."));
        }

        let (head, filter, tail) = match (raw.find('['), raw.rfind(']')) {
            (Some(open), Some(close)) if close > open => {
                (&raw[..open], Some(raw[open + 1..close].trim().to_owned()), &raw[close + 1..])
            }
            (None, None) => (raw, None, ""),
            _ => return Err(ScimError::invalid_path(format!("Malformed PATCH path '{raw}'."))),
        };

        // Strip a schema URN prefix: `urn:...:User:userName` -> `userName`.
        let head = head.rsplit(':').next().unwrap_or(head);

        // Without a filter the path may be `attr` or `attr.sub`; with one, any sub-attribute
        // follows the bracket as `.sub`.
        let (attr, mut sub) = match head.split_once('.') {
            Some((attr, sub)) => (attr, Some(sub.to_lowercase())),
            None => (head, None),
        };

        if !tail.is_empty() {
            let tail = tail.strip_prefix('.').ok_or_else(|| {
                ScimError::invalid_path(format!("Malformed PATCH path '{raw}'; expected '.' after ']'."))
            })?;
            if tail.is_empty() || sub.is_some() {
                return Err(ScimError::invalid_path(format!("Malformed PATCH path '{raw}'.")));
            }
            sub = Some(tail.to_lowercase());
        }

        let attr = attr.trim().to_lowercase();
        // SCIM has exactly one level of sub-attribute, so neither part may contain another dot.
        if attr.is_empty() || attr.contains('.') || sub.as_ref().is_some_and(|s| s.contains('.')) {
            return Err(ScimError::invalid_path(format!("Malformed PATCH path '{raw}'.")));
        }

        Ok(Self {
            attr,
            sub,
            filter,
        })
    }
}

// ---------------------------------------------------------------------------------------------
// Value coercion
// ---------------------------------------------------------------------------------------------

/// Read a boolean, tolerating the string form.
///
/// Entra ID sends `"active": "False"` as a JSON string in some flows. Refusing it would make
/// deprovisioning fail for a purely cosmetic reason.
fn as_bool(value: &Value) -> Option<bool> {
    match value {
        Value::Bool(b) => Some(*b),
        Value::String(s) if s.eq_ignore_ascii_case("true") => Some(true),
        Value::String(s) if s.eq_ignore_ascii_case("false") => Some(false),
        _ => None,
    }
}

fn as_string(value: &Value) -> Option<&str> {
    value.as_str()
}

/// Extract membership ids from a PATCH `value`.
///
/// Accepts the three shapes seen in the wild: an array of `{"value": id}` objects, a single such
/// object, and a bare array of id strings.
fn member_ids_from_value(value: &Value) -> ScimResult<Vec<MembershipId>> {
    fn one(entry: &Value) -> ScimResult<MembershipId> {
        let raw = match entry {
            Value::String(s) => s.as_str(),
            Value::Object(map) => map
                .get("value")
                .and_then(Value::as_str)
                .ok_or_else(|| ScimError::invalid_value("Each member entry requires a 'value'."))?,
            _ => return Err(ScimError::invalid_value("Member entries must be objects or strings.")),
        };

        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(ScimError::invalid_value("Member 'value' must not be empty."));
        }
        Ok(MembershipId::from(trimmed.to_owned()))
    }

    match value {
        Value::Array(entries) => {
            if entries.len() > MAX_MEMBERS_PER_REQUEST {
                return Err(ScimError::bad_request(
                    ScimType::TooMany,
                    format!("At most {MAX_MEMBERS_PER_REQUEST} members may be sent in one request."),
                ));
            }
            entries.iter().map(one).collect()
        }
        other => Ok(vec![one(other)?]),
    }
}

// ---------------------------------------------------------------------------------------------
// User change sets
// ---------------------------------------------------------------------------------------------

/// How a request wants an optional attribute changed.
///
/// SCIM distinguishes three cases that a bare `Option` cannot: the request did not mention the
/// attribute, the request set it, and the request asked for it to be removed.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub enum FieldChange {
    /// The request did not mention this attribute, so it keeps its current value.
    #[default]
    Unchanged,
    /// Set the attribute to this value.
    Set(String),
    /// Remove the attribute.
    Clear,
}

impl FieldChange {
    /// Build from a normalised value, where `None` means "the client sent an empty value", which
    /// Vaultwarden stores as `NULL`.
    pub fn from_normalized(value: Option<String>) -> Self {
        match value {
            Some(value) => Self::Set(value),
            None => Self::Clear,
        }
    }

    pub const fn is_unchanged(&self) -> bool {
        matches!(self, Self::Unchanged)
    }

    /// The value to store, or `None` to store `NULL`. Only meaningful when not `Unchanged`.
    pub fn to_stored(&self) -> Option<String> {
        match self {
            Self::Set(value) => Some(value.clone()),
            Self::Unchanged | Self::Clear => None,
        }
    }
}

/// Everything a `PATCH /Users/<id>` asks to change, validated but not yet applied.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct UserChanges {
    /// `Some(true)` restores the membership, `Some(false)` revokes it.
    pub active: Option<bool>,
    pub external_id: FieldChange,
    /// A `userName` the client asserted. Vaultwarden never renames an account through SCIM, so
    /// the caller compares this against the stored email and rejects a genuine change.
    pub user_name_assertion: Option<String>,
}

/// Attributes a client may send on a user that this server knowingly does not store.
///
/// They are accepted and dropped rather than rejected: they are cosmetic, and failing the whole
/// operation over them would break provisioning. See `docs/scim/design.md` section 7.
const USER_IGNORED_ATTRS: &[&str] = &[
    "displayname",
    "name",
    "nickname",
    "title",
    "usertype",
    "preferredlanguage",
    "locale",
    "timezone",
    "phonenumbers",
    "addresses",
    "photos",
    "ims",
    "entitlements",
    "roles",
    "x509certificates",
    "profileurl",
    "password",
    "groups",
];

pub fn plan_user_patch(request: &PatchRequest) -> ScimResult<UserChanges> {
    validate_patch_envelope(request)?;

    let mut changes = UserChanges::default();
    for operation in &request.operations {
        let op = PatchOp::parse(&operation.op)?;
        apply_user_operation(&mut changes, op, operation)?;
    }

    Ok(changes)
}

fn apply_user_operation(changes: &mut UserChanges, op: PatchOp, operation: &PatchOperation) -> ScimResult<()> {
    let Some(raw_path) = operation.path.as_deref().map(str::trim).filter(|p| !p.is_empty()) else {
        // A pathless operation carries an object whose keys are the attributes to change.
        if op == PatchOp::Remove {
            // RFC 7644 section 3.5.2.2 requires a path for `remove`.
            return Err(ScimError::no_target("A 'remove' operation requires a 'path'."));
        }

        let Some(Value::Object(map)) = operation.value.as_ref() else {
            return Err(ScimError::invalid_value("A PATCH operation without a 'path' requires an object 'value'."));
        };

        for (key, value) in map {
            let path = PatchPath::parse(key)?;
            apply_user_attribute(changes, op, &path, Some(value))?;
        }
        return Ok(());
    };

    let path = PatchPath::parse(raw_path)?;
    apply_user_attribute(changes, op, &path, operation.value.as_ref())
}

fn apply_user_attribute(
    changes: &mut UserChanges,
    op: PatchOp,
    path: &PatchPath,
    value: Option<&Value>,
) -> ScimResult<()> {
    if path.filter.is_some() && path.attr != "emails" {
        return Err(ScimError::invalid_path(format!(
            "Value filters are not supported on '{}' for User resources.",
            path.attr
        )));
    }

    match path.attr.as_str() {
        "active" => {
            if op == PatchOp::Remove {
                return Err(ScimError::invalid_path("'active' cannot be removed."));
            }
            let Some(active) = value.and_then(as_bool) else {
                return Err(ScimError::invalid_value("'active' must be a boolean."));
            };
            changes.active = Some(active);
            Ok(())
        }

        "externalid" => {
            if op == PatchOp::Remove {
                changes.external_id = FieldChange::Clear;
                return Ok(());
            }
            let Some(raw) = value.and_then(as_string) else {
                return Err(ScimError::invalid_value("'externalId' must be a string."));
            };
            changes.external_id = FieldChange::from_normalized(normalize_external_id(Some(raw))?);
            Ok(())
        }

        "username" => {
            if op == PatchOp::Remove {
                return Err(ScimError::immutable("'userName' cannot be removed."));
            }
            let Some(raw) = value.and_then(as_string) else {
                return Err(ScimError::invalid_value("'userName' must be a string."));
            };
            // Validated now so a malformed address fails before anything is written; whether the
            // value is actually a *change* is decided by the caller against the stored account.
            changes.user_name_assertion = Some(normalize_user_name(raw)?);
            Ok(())
        }

        // `emails` is derived from the account email, which SCIM does not rename. Accept a write
        // that matches, so that an identity provider sending the full resource does not fail.
        "emails" => {
            if op == PatchOp::Remove {
                return Err(ScimError::immutable("'emails' is derived from the account and cannot be removed."));
            }
            let asserted = match value {
                Some(Value::String(s)) => Some(s.as_str()),
                Some(Value::Array(entries)) => entries.iter().find_map(|e| e.get("value").and_then(Value::as_str)),
                Some(Value::Object(map)) => map.get("value").and_then(Value::as_str),
                _ => None,
            };
            if let Some(asserted) = asserted {
                changes.user_name_assertion = Some(normalize_user_name(asserted)?);
            }
            Ok(())
        }

        attr if USER_IGNORED_ATTRS.contains(&attr) => Ok(()),

        other => Err(ScimError::invalid_path(format!("Unsupported PATCH path '{other}' for User resources."))),
    }
}

// ---------------------------------------------------------------------------------------------
// Group change sets
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemberOp {
    Add(Vec<MembershipId>),
    Remove(Vec<MembershipId>),
    /// Set the membership to exactly this list.
    Replace(Vec<MembershipId>),
    /// `{"op": "remove", "path": "members"}` with no value.
    RemoveAll,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct GroupChanges {
    pub display_name: Option<String>,
    pub external_id: FieldChange,
    /// Applied in order by [`apply_member_ops`].
    pub member_ops: Vec<MemberOp>,
}

impl GroupChanges {
    /// Does this change set touch membership at all?
    pub fn touches_members(&self) -> bool {
        !self.member_ops.is_empty()
    }

    /// Every membership id this change set references, so the caller can validate them all
    /// against the organization before writing anything.
    pub fn referenced_members(&self) -> Vec<MembershipId> {
        let mut ids = Vec::new();
        for op in &self.member_ops {
            match op {
                MemberOp::Add(m) | MemberOp::Remove(m) | MemberOp::Replace(m) => ids.extend(m.iter().cloned()),
                MemberOp::RemoveAll => {}
            }
        }
        ids
    }
}

pub fn plan_group_patch(request: &PatchRequest) -> ScimResult<GroupChanges> {
    validate_patch_envelope(request)?;

    let mut changes = GroupChanges::default();
    for operation in &request.operations {
        let op = PatchOp::parse(&operation.op)?;
        apply_group_operation(&mut changes, op, operation)?;
    }

    Ok(changes)
}

fn apply_group_operation(changes: &mut GroupChanges, op: PatchOp, operation: &PatchOperation) -> ScimResult<()> {
    let Some(raw_path) = operation.path.as_deref().map(str::trim).filter(|p| !p.is_empty()) else {
        if op == PatchOp::Remove {
            return Err(ScimError::no_target("A 'remove' operation requires a 'path'."));
        }

        let Some(Value::Object(map)) = operation.value.as_ref() else {
            return Err(ScimError::invalid_value("A PATCH operation without a 'path' requires an object 'value'."));
        };

        for (key, value) in map {
            let path = PatchPath::parse(key)?;
            apply_group_attribute(changes, op, &path, Some(value))?;
        }
        return Ok(());
    };

    let path = PatchPath::parse(raw_path)?;
    apply_group_attribute(changes, op, &path, operation.value.as_ref())
}

fn apply_group_attribute(
    changes: &mut GroupChanges,
    op: PatchOp,
    path: &PatchPath,
    value: Option<&Value>,
) -> ScimResult<()> {
    match path.attr.as_str() {
        "displayname" => {
            if path.filter.is_some() {
                return Err(ScimError::invalid_path("Value filters are not supported on 'displayName'."));
            }
            if op == PatchOp::Remove {
                return Err(ScimError::invalid_value("'displayName' is required and cannot be removed."));
            }
            let Some(raw) = value.and_then(as_string) else {
                return Err(ScimError::invalid_value("'displayName' must be a string."));
            };
            changes.display_name = Some(normalize_display_name(raw)?);
            Ok(())
        }

        "externalid" => {
            if path.filter.is_some() {
                return Err(ScimError::invalid_path("Value filters are not supported on 'externalId'."));
            }
            if op == PatchOp::Remove {
                changes.external_id = FieldChange::Clear;
                return Ok(());
            }
            let Some(raw) = value.and_then(as_string) else {
                return Err(ScimError::invalid_value("'externalId' must be a string."));
            };
            changes.external_id = FieldChange::from_normalized(normalize_external_id(Some(raw))?);
            Ok(())
        }

        "members" => apply_member_operation(changes, op, path, value),

        other => Err(ScimError::invalid_path(format!("Unsupported PATCH path '{other}' for Group resources."))),
    }
}

fn apply_member_operation(
    changes: &mut GroupChanges,
    op: PatchOp,
    path: &PatchPath,
    value: Option<&Value>,
) -> ScimResult<()> {
    // `members[value eq "..."]` selects one member. Older Azure AD connectors remove members
    // this way instead of sending the id in the body.
    if let Some(filter_text) = &path.filter {
        if path.sub.is_some() {
            return Err(ScimError::invalid_path("Sub-attributes of a selected member cannot be modified."));
        }

        let selected = member_id_from_value_filter(&path.attr, filter_text)?;
        return match op {
            PatchOp::Remove => {
                changes.member_ops.push(MemberOp::Remove(vec![selected]));
                Ok(())
            }
            PatchOp::Add | PatchOp::Replace => {
                Err(ScimError::invalid_path("A member value filter is only supported with 'remove'."))
            }
        };
    }

    if path.sub.is_some() {
        return Err(ScimError::invalid_path("Sub-attributes of 'members' cannot be modified directly."));
    }

    match op {
        PatchOp::Add => {
            let Some(value) = value else {
                return Err(ScimError::invalid_value("An 'add' on 'members' requires a value."));
            };
            changes.member_ops.push(MemberOp::Add(member_ids_from_value(value)?));
            Ok(())
        }
        PatchOp::Replace => {
            let Some(value) = value else {
                return Err(ScimError::invalid_value("A 'replace' on 'members' requires a value."));
            };
            changes.member_ops.push(MemberOp::Replace(member_ids_from_value(value)?));
            Ok(())
        }
        PatchOp::Remove => match value {
            // `remove` on `members` with no value clears the whole membership.
            None | Some(Value::Null) => {
                changes.member_ops.push(MemberOp::RemoveAll);
                Ok(())
            }
            Some(value) => {
                changes.member_ops.push(MemberOp::Remove(member_ids_from_value(value)?));
                Ok(())
            }
        },
    }
}

/// Parse `members[value eq "<id>"]` and return the selected id.
///
/// The filter text is untrusted, so it goes through the same validated parser the query filters
/// use rather than any ad-hoc string handling.
fn member_id_from_value_filter(attr: &str, filter_text: &str) -> ScimResult<MembershipId> {
    let parsed = Filter::parse(&format!("{attr}[{filter_text}]"), GROUP_ATTRS)
        .map_err(|e| ScimError::invalid_path(format!("Unsupported member selection: {}", e.detail)))?;

    match parsed {
        Filter::ValuePath {
            filter,
            ..
        } => match *filter {
            Filter::Compare {
                path,
                op: CompareOp::Eq,
                value: CompValue::Str(id),
            } if path.path == "members.value" => {
                let trimmed = id.trim();
                if trimmed.is_empty() {
                    return Err(ScimError::invalid_value("Member 'value' must not be empty."));
                }
                Ok(MembershipId::from(trimmed.to_owned()))
            }
            _ => Err(ScimError::invalid_path(
                "Only 'members[value eq \"<id>\"]' member selection is supported.".to_owned(),
            )),
        },
        _ => Err(ScimError::invalid_path("Malformed member selection in PATCH path.")),
    }
}

/// Apply a planned sequence of member operations to the current membership.
///
/// Order is preserved and duplicates are collapsed, so re-adding an existing member is a no-op
/// rather than a second row.
pub fn apply_member_ops(current: &[MembershipId], ops: &[MemberOp]) -> Vec<MembershipId> {
    let mut result: Vec<MembershipId> = current.to_vec();

    for op in ops {
        match op {
            MemberOp::Add(ids) => {
                for id in ids {
                    if !result.contains(id) {
                        result.push(id.clone());
                    }
                }
            }
            MemberOp::Remove(ids) => {
                result.retain(|existing| !ids.contains(existing));
            }
            MemberOp::Replace(ids) => {
                let mut replacement: Vec<MembershipId> = Vec::with_capacity(ids.len());
                for id in ids {
                    if !replacement.contains(id) {
                        replacement.push(id.clone());
                    }
                }
                result = replacement;
            }
            MemberOp::RemoveAll => result.clear(),
        }
    }

    result
}

fn validate_patch_envelope(request: &PatchRequest) -> ScimResult<()> {
    // Lenient, like the resource documents: an absent or empty `schemas` is accepted, and extra
    // URNs are fine. Only a document that announces schemas without the PatchOp one is refused.
    if let Some(schemas) = request.schemas.as_ref().filter(|s| !s.is_empty())
        && !schemas.iter().any(|s| s.eq_ignore_ascii_case(PATCH_OP_SCHEMA))
    {
        return Err(ScimError::invalid_syntax(format!("PATCH 'schemas' must include '{PATCH_OP_SCHEMA}'.")));
    }

    if request.operations.is_empty() {
        return Err(ScimError::invalid_value("A PATCH request requires at least one operation."));
    }
    if request.operations.len() > MAX_PATCH_OPERATIONS {
        return Err(ScimError::bad_request(
            ScimType::TooMany,
            format!("At most {MAX_PATCH_OPERATIONS} operations may be sent in one PATCH request."),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn patch(body: Value) -> PatchRequest {
        serde_json::from_value(body).expect("should deserialize")
    }

    fn ids(raw: &[&str]) -> Vec<MembershipId> {
        raw.iter().map(|r| MembershipId::from((*r).to_owned())).collect()
    }

    // -- op parsing ----------------------------------------------------------------------------

    #[test]
    fn op_names_are_case_insensitive() {
        // Entra ID capitalises them; the RFC does not.
        assert_eq!(PatchOp::parse("add").unwrap(), PatchOp::Add);
        assert_eq!(PatchOp::parse("Add").unwrap(), PatchOp::Add);
        assert_eq!(PatchOp::parse("ADD").unwrap(), PatchOp::Add);
        assert_eq!(PatchOp::parse(" Replace ").unwrap(), PatchOp::Replace);
        assert_eq!(PatchOp::parse("Remove").unwrap(), PatchOp::Remove);
    }

    #[test]
    fn unknown_ops_are_rejected() {
        let err = PatchOp::parse("upsert").unwrap_err();
        assert_eq!(err.scim_type, Some(ScimType::InvalidSyntax));
    }

    #[test]
    fn operations_key_is_accepted_in_both_spellings() {
        let upper = patch(json!({"Operations": [{"op": "replace", "path": "active", "value": false}]}));
        let lower = patch(json!({"operations": [{"op": "replace", "path": "active", "value": false}]}));

        assert_eq!(plan_user_patch(&upper).unwrap().active, Some(false));
        assert_eq!(plan_user_patch(&lower).unwrap().active, Some(false));
    }

    // -- path parsing --------------------------------------------------------------------------

    #[test]
    fn parses_simple_paths() {
        let path = PatchPath::parse("active").unwrap();
        assert_eq!(path.attr, "active");
        assert_eq!(path.sub, None);
        assert_eq!(path.filter, None);
    }

    #[test]
    fn parses_sub_attribute_paths() {
        let path = PatchPath::parse("name.givenName").unwrap();
        assert_eq!(path.attr, "name");
        assert_eq!(path.sub.as_deref(), Some("givenname"));
    }

    #[test]
    fn parses_value_filter_paths() {
        let path = PatchPath::parse(r#"members[value eq "abc"]"#).unwrap();
        assert_eq!(path.attr, "members");
        assert_eq!(path.filter.as_deref(), Some(r#"value eq "abc""#));
        assert_eq!(path.sub, None);
    }

    #[test]
    fn parses_value_filter_paths_with_a_sub_attribute() {
        let path = PatchPath::parse(r#"emails[type eq "work"].value"#).unwrap();
        assert_eq!(path.attr, "emails");
        assert_eq!(path.filter.as_deref(), Some(r#"type eq "work""#));
        assert_eq!(path.sub.as_deref(), Some("value"));
    }

    #[test]
    fn strips_a_schema_urn_from_a_path() {
        let path = PatchPath::parse("urn:ietf:params:scim:schemas:core:2.0:User:active").unwrap();
        assert_eq!(path.attr, "active");
    }

    #[test]
    fn rejects_malformed_paths() {
        assert!(PatchPath::parse("").is_err());
        assert!(PatchPath::parse("   ").is_err());
        assert!(PatchPath::parse("members[value eq \"a\"").is_err(), "unbalanced bracket");
        assert!(PatchPath::parse("members]value[").is_err(), "reversed brackets");
        assert!(PatchPath::parse("a.b.c").is_err(), "two levels of sub-attribute");
        assert!(PatchPath::parse(r#"members[value eq "a"]x"#).is_err(), "junk after the bracket");
    }

    // -- user patches --------------------------------------------------------------------------

    #[test]
    fn entra_disable_shape_is_understood() {
        let request = patch(json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "Replace", "path": "active", "value": false}],
        }));

        assert_eq!(plan_user_patch(&request).unwrap().active, Some(false));
    }

    #[test]
    fn entra_string_boolean_is_accepted() {
        // Entra sends `"False"` as a JSON string in some flows; rejecting it would break
        // deprovisioning for a purely cosmetic reason.
        for raw in ["False", "false", "FALSE"] {
            let request = patch(json!({"Operations": [{"op": "Replace", "path": "active", "value": raw}]}));
            assert_eq!(plan_user_patch(&request).unwrap().active, Some(false), "{raw}");
        }
        for raw in ["True", "true"] {
            let request = patch(json!({"Operations": [{"op": "Replace", "path": "active", "value": raw}]}));
            assert_eq!(plan_user_patch(&request).unwrap().active, Some(true), "{raw}");
        }
    }

    #[test]
    fn pathless_replace_with_an_object_value_is_understood() {
        let request = patch(json!({
            "Operations": [{"op": "Replace", "value": {"active": false, "externalId": "ext-9"}}],
        }));

        let changes = plan_user_patch(&request).unwrap();
        assert_eq!(changes.active, Some(false));
        assert_eq!(changes.external_id, FieldChange::Set("ext-9".to_owned()));
    }

    #[test]
    fn external_id_can_be_set_and_cleared() {
        let set = patch(json!({"Operations": [{"op": "add", "path": "externalId", "value": "ext-1"}]}));
        assert_eq!(plan_user_patch(&set).unwrap().external_id, FieldChange::Set("ext-1".to_owned()));

        let cleared = patch(json!({"Operations": [{"op": "remove", "path": "externalId"}]}));
        assert_eq!(plan_user_patch(&cleared).unwrap().external_id, FieldChange::Clear);

        let blanked = patch(json!({"Operations": [{"op": "replace", "path": "externalId", "value": "  "}]}));
        assert_eq!(plan_user_patch(&blanked).unwrap().external_id, FieldChange::Clear);
    }

    #[test]
    fn user_name_is_captured_as_an_assertion_not_a_rename() {
        // The planner records what was asserted; the caller compares it to the stored account and
        // rejects a genuine change. This keeps the "no account rename via SCIM" rule in one place.
        let request = patch(json!({"Operations": [{"op": "replace", "path": "userName", "value": "A@Example.test"}]}));
        let changes = plan_user_patch(&request).unwrap();

        assert_eq!(changes.user_name_assertion.as_deref(), Some("a@example.test"));
        assert_eq!(changes.active, None, "asserting a userName must not imply anything else");
    }

    #[test]
    fn a_malformed_user_name_fails_planning_before_anything_is_written() {
        let request = patch(json!({"Operations": [{"op": "replace", "path": "userName", "value": "not-an-email"}]}));
        assert!(plan_user_patch(&request).is_err());
    }

    #[test]
    fn cosmetic_attributes_are_accepted_and_dropped() {
        let request = patch(json!({
            "Operations": [
                {"op": "Replace", "path": "displayName", "value": "New Name"},
                {"op": "Replace", "path": "name.givenName", "value": "New"},
                {"op": "Replace", "path": "title", "value": "Staff Engineer"},
                {"op": "Replace", "path": "active", "value": true},
            ],
        }));

        let changes = plan_user_patch(&request).unwrap();
        assert_eq!(changes.active, Some(true));
        assert!(changes.external_id.is_unchanged());
        assert_eq!(changes.user_name_assertion, None);
    }

    #[test]
    fn unsupported_user_paths_are_rejected_not_ignored() {
        // Silently accepting these would make a broken attribute mapping look like it works.
        for path in ["members", "id", "meta.location", "somethingMadeUp"] {
            let request = patch(json!({"Operations": [{"op": "replace", "path": path, "value": "x"}]}));
            let err = plan_user_patch(&request).unwrap_err();
            assert_eq!(err.scim_type, Some(ScimType::InvalidPath), "path {path} should be rejected");
        }
    }

    #[test]
    fn remove_without_a_path_is_a_no_target_error() {
        let request = patch(json!({"Operations": [{"op": "remove"}]}));
        let err = plan_user_patch(&request).unwrap_err();
        assert_eq!(err.scim_type, Some(ScimType::NoTarget));
    }

    #[test]
    fn a_bad_value_type_is_rejected() {
        let request = patch(json!({"Operations": [{"op": "replace", "path": "active", "value": 42}]}));
        assert_eq!(plan_user_patch(&request).unwrap_err().scim_type, Some(ScimType::InvalidValue));

        let request = patch(json!({"Operations": [{"op": "replace", "path": "externalId", "value": 42}]}));
        assert_eq!(plan_user_patch(&request).unwrap_err().scim_type, Some(ScimType::InvalidValue));
    }

    #[test]
    fn an_empty_operation_list_is_rejected() {
        let request = patch(json!({"Operations": []}));
        assert!(plan_user_patch(&request).is_err());
    }

    #[test]
    fn too_many_operations_are_rejected() {
        let ops: Vec<Value> =
            (0..=MAX_PATCH_OPERATIONS).map(|_| json!({"op": "replace", "path": "active", "value": true})).collect();
        let request = patch(json!({"Operations": ops}));

        assert_eq!(plan_user_patch(&request).unwrap_err().scim_type, Some(ScimType::TooMany));
    }

    #[test]
    fn a_failing_operation_aborts_the_whole_plan() {
        // The second operation is invalid, so nothing at all is planned -- this is what makes
        // PATCH atomic without a database transaction.
        let request = patch(json!({
            "Operations": [
                {"op": "replace", "path": "active", "value": false},
                {"op": "replace", "path": "totallyUnknown", "value": "x"},
            ],
        }));

        assert!(plan_user_patch(&request).is_err());
    }

    #[test]
    fn later_operations_win_over_earlier_ones() {
        let request = patch(json!({
            "Operations": [
                {"op": "replace", "path": "active", "value": false},
                {"op": "replace", "path": "active", "value": true},
            ],
        }));

        assert_eq!(plan_user_patch(&request).unwrap().active, Some(true));
    }

    // -- group patches -------------------------------------------------------------------------

    #[test]
    fn entra_add_member_shape_is_understood() {
        let request = patch(json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "Add", "path": "members", "value": [{"value": "member-1"}]}],
        }));

        let changes = plan_group_patch(&request).unwrap();
        assert_eq!(changes.member_ops, vec![MemberOp::Add(ids(&["member-1"]))]);
    }

    #[test]
    fn entra_remove_member_shapes_are_understood() {
        // Newer connectors send the id in the body...
        let by_value = patch(json!({
            "Operations": [{"op": "Remove", "path": "members", "value": [{"value": "member-1"}]}],
        }));
        assert_eq!(plan_group_patch(&by_value).unwrap().member_ops, vec![MemberOp::Remove(ids(&["member-1"]))]);

        // ...older ones select it with a value filter in the path.
        let by_filter = patch(json!({
            "Operations": [{"op": "Remove", "path": r#"members[value eq "member-1"]"#}],
        }));
        assert_eq!(plan_group_patch(&by_filter).unwrap().member_ops, vec![MemberOp::Remove(ids(&["member-1"]))]);
    }

    #[test]
    fn replace_members_is_understood() {
        let request = patch(json!({
            "Operations": [{"op": "Replace", "path": "members", "value": [{"value": "a"}, {"value": "b"}]}],
        }));

        assert_eq!(plan_group_patch(&request).unwrap().member_ops, vec![MemberOp::Replace(ids(&["a", "b"]))]);
    }

    #[test]
    fn removing_members_without_a_value_clears_the_group() {
        let request = patch(json!({"Operations": [{"op": "Remove", "path": "members"}]}));
        assert_eq!(plan_group_patch(&request).unwrap().member_ops, vec![MemberOp::RemoveAll]);
    }

    #[test]
    fn bare_string_member_values_are_accepted() {
        let request = patch(json!({"Operations": [{"op": "Add", "path": "members", "value": ["a", "b"]}]}));
        assert_eq!(plan_group_patch(&request).unwrap().member_ops, vec![MemberOp::Add(ids(&["a", "b"]))]);
    }

    #[test]
    fn a_single_member_object_is_accepted() {
        let request = patch(json!({"Operations": [{"op": "Add", "path": "members", "value": {"value": "a"}}]}));
        assert_eq!(plan_group_patch(&request).unwrap().member_ops, vec![MemberOp::Add(ids(&["a"]))]);
    }

    #[test]
    fn group_rename_shapes_are_understood() {
        let with_path = patch(json!({
            "Operations": [{"op": "Replace", "path": "displayName", "value": "Platform"}],
        }));
        assert_eq!(plan_group_patch(&with_path).unwrap().display_name.as_deref(), Some("Platform"));

        let without_path = patch(json!({
            "Operations": [{"op": "Replace", "value": {"displayName": "Platform"}}],
        }));
        assert_eq!(plan_group_patch(&without_path).unwrap().display_name.as_deref(), Some("Platform"));
    }

    #[test]
    fn unsupported_group_paths_are_rejected() {
        for path in ["userName", "active", "owner", "members.display"] {
            let request = patch(json!({"Operations": [{"op": "replace", "path": path, "value": "x"}]}));
            assert!(plan_group_patch(&request).is_err(), "path {path} should be rejected");
        }
    }

    #[test]
    fn member_value_filters_only_work_with_remove() {
        let request = patch(json!({
            "Operations": [{"op": "Add", "path": r#"members[value eq "a"]"#, "value": [{"value": "a"}]}],
        }));
        assert_eq!(plan_group_patch(&request).unwrap_err().scim_type, Some(ScimType::InvalidPath));
    }

    #[test]
    fn unsupported_member_selections_are_rejected() {
        for path in
            [r#"members[value co "a"]"#, r#"members[display eq "a"]"#, r#"members[value eq "a" and value eq "b"]"#]
        {
            let request = patch(json!({"Operations": [{"op": "Remove", "path": path}]}));
            assert!(plan_group_patch(&request).is_err(), "selection {path} should be rejected");
        }
    }

    #[test]
    fn referenced_members_lists_everything_that_needs_validating() {
        let request = patch(json!({
            "Operations": [
                {"op": "Add", "path": "members", "value": [{"value": "a"}]},
                {"op": "Remove", "path": "members", "value": [{"value": "b"}]},
                {"op": "Replace", "path": "members", "value": [{"value": "c"}]},
            ],
        }));

        let changes = plan_group_patch(&request).unwrap();
        assert_eq!(changes.referenced_members(), ids(&["a", "b", "c"]));
        assert!(changes.touches_members());
    }

    #[test]
    fn a_rename_only_patch_does_not_touch_members() {
        let request = patch(json!({"Operations": [{"op": "Replace", "path": "displayName", "value": "X"}]}));
        let changes = plan_group_patch(&request).unwrap();

        assert!(!changes.touches_members(), "a rename must never rewrite the membership list");
        assert!(changes.referenced_members().is_empty());
    }

    // -- member op application ------------------------------------------------------------------

    #[test]
    fn add_appends_without_duplicating() {
        let current = ids(&["a", "b"]);
        let result = apply_member_ops(&current, &[MemberOp::Add(ids(&["b", "c"]))]);
        assert_eq!(result, ids(&["a", "b", "c"]));
    }

    #[test]
    fn remove_takes_members_out_and_ignores_absent_ones() {
        let current = ids(&["a", "b", "c"]);
        let result = apply_member_ops(&current, &[MemberOp::Remove(ids(&["b", "zzz"]))]);
        assert_eq!(result, ids(&["a", "c"]));
    }

    #[test]
    fn replace_sets_the_membership_exactly() {
        let current = ids(&["a", "b", "c"]);
        let result = apply_member_ops(&current, &[MemberOp::Replace(ids(&["x", "y"]))]);
        assert_eq!(result, ids(&["x", "y"]));
    }

    #[test]
    fn replace_deduplicates_its_input() {
        let result = apply_member_ops(&[], &[MemberOp::Replace(ids(&["a", "a", "b"]))]);
        assert_eq!(result, ids(&["a", "b"]));
    }

    #[test]
    fn remove_all_clears_the_membership() {
        let current = ids(&["a", "b"]);
        assert!(apply_member_ops(&current, &[MemberOp::RemoveAll]).is_empty());
    }

    #[test]
    fn operations_apply_in_order() {
        let current = ids(&["a"]);
        let result = apply_member_ops(
            &current,
            &[MemberOp::Add(ids(&["b", "c"])), MemberOp::Remove(ids(&["a"])), MemberOp::Add(ids(&["d"]))],
        );
        assert_eq!(result, ids(&["b", "c", "d"]));
    }

    #[test]
    fn a_replace_after_an_add_wins() {
        let current = ids(&["a"]);
        let result = apply_member_ops(&current, &[MemberOp::Add(ids(&["b"])), MemberOp::Replace(ids(&["z"]))]);
        assert_eq!(result, ids(&["z"]));
    }

    #[test]
    fn applying_no_operations_leaves_the_membership_alone() {
        let current = ids(&["a", "b"]);
        assert_eq!(apply_member_ops(&current, &[]), current);
    }
}

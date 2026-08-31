//! SCIM 2.0 provisioning endpoints (RFC 7643 / RFC 7644).
//!
//! Mounted at `<basepath>/scim/v2`, so an organization's SCIM base URL is
//! `https://vault.example.com/scim/v2/<organization_uuid>`. The organization id is part of every
//! path and is bound into every database lookup, which is what keeps one tenant's identity
//! provider from ever seeing or touching another tenant's members and groups.
//!
//! See `docs/scim/design.md` for the architecture and the security decisions, and
//! `docs/scim/README.md` for operator documentation.

mod auth;
mod discovery;
#[cfg(test)]
mod e2e;
mod error;
mod filter;
mod groups;
mod json;
mod patch;
mod resource;
mod settings;
mod users;

use std::sync::LazyLock;

use rocket::{Catcher, Request, Route, form::FromForm, http::ContentType};
use serde_json::Value;

use crate::{CONFIG, db::models::OrganizationId};

pub use auth::ScimToken;
use error::{ScimError, ScimResult};

/// The media type every SCIM response uses.
pub static SCIM_CONTENT_TYPE: LazyLock<ContentType> = LazyLock::new(|| ContentType::new("application", "scim+json"));

pub const USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
pub const GROUP_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
pub const LIST_RESPONSE_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
pub const PATCH_OP_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
pub const SERVICE_PROVIDER_CONFIG_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig";
pub const RESOURCE_TYPE_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:ResourceType";
pub const SCHEMA_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Schema";

/// The enterprise extension Microsoft Entra ID maps attributes from by default.
///
/// Vaultwarden stores none of it. It is named here so those attributes can be *recognised* as
/// extension attributes and ignored deliberately, rather than falling through to an error.
pub const ENTERPRISE_USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";

/// An attribute name that may carry a schema URN prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QualifiedAttr<'a> {
    /// An attribute of the resource type's own core schema.
    Core(&'a str),
    /// An attribute belonging to some other schema namespace.
    Extension {
        urn: &'a str,
        attr: &'a str,
    },
}

/// Split a possibly schema-qualified attribute name into its namespace and its name.
///
/// This exists because discarding everything before the last `:` -- the obvious shortcut -- lets
/// an arbitrary extension attribute impersonate a core one. A client sending
/// `urn:example:Whatever:active` must not end up toggling the core `active` attribute, and
/// `urn:example:Whatever:members` must not rewrite a group's membership.
///
/// A name with no `:` is a core attribute. A name with one is core only when its prefix is
/// exactly this resource type's core schema; anything else is an extension.
///
/// Callers that deal with value paths (`members[value eq "urn:x"]`) must strip the bracketed part
/// before calling this, so a colon inside a filter literal cannot be mistaken for a namespace
/// separator.
pub fn qualify<'a>(raw: &'a str, core_schema: &str) -> QualifiedAttr<'a> {
    let Some(idx) = raw.rfind(':') else {
        return QualifiedAttr::Core(raw);
    };

    let (urn, attr) = (&raw[..idx], &raw[idx + 1..]);

    if urn.eq_ignore_ascii_case(core_schema) {
        QualifiedAttr::Core(attr)
    } else {
        QualifiedAttr::Extension {
            urn,
            attr,
        }
    }
}

/// Is this name itself a schema URN rather than an attribute within one?
///
/// A pathless `PATCH` may carry a whole extension object keyed by its URN, as Entra ID does with
/// `{"urn:...:extension:enterprise:2.0:User": {"department": "..."}}`.
pub fn is_schema_urn(raw: &str, core_schema: &str) -> bool {
    raw.eq_ignore_ascii_case(core_schema) || raw.eq_ignore_ascii_case(ENTERPRISE_USER_SCHEMA)
}

/// Where the SCIM routes are mounted, relative to the configured domain path.
pub const SCIM_BASE_PATH: &str = "/scim/v2";

/// Synthetic actor recorded for SCIM-initiated organization events.
///
/// Mirrors the `ACTING_ADMIN_USER` pattern in `src/api/admin.rs`, so the event log never claims a
/// real person performed an automated change.
pub const ACTING_SCIM_USER: &str = "vaultwarden-scim-000000-000000000000";

/// `DeviceType::UnknownBrowser`, the value `/admin` already uses for non-interactive actions.
pub const SCIM_DEVICE_TYPE: i32 = 14;

pub fn routes() -> Vec<Route> {
    let mut routes = Vec::new();
    routes.append(&mut discovery::routes());
    routes.append(&mut users::routes());
    routes.append(&mut groups::routes());
    routes
}

/// Catchers scoped to the SCIM mount point.
///
/// Request-guard failures (a rejected bearer token, a disabled server) and unmatched paths are
/// turned into responses by Rocket's catchers rather than by a handler, so without these a SCIM
/// client would receive Vaultwarden's HTML or Bitwarden-JSON error pages.
pub fn catchers() -> Vec<Catcher> {
    catchers![
        scim_bad_request,
        scim_unauthorized,
        scim_forbidden,
        scim_not_found,
        scim_method_not_allowed,
        scim_payload_too_large,
        scim_unsupported_media_type,
        scim_unprocessable_entity,
        scim_too_many_requests,
        scim_internal_error,
    ]
}

#[catch(400)]
fn scim_bad_request() -> ScimError {
    ScimError::invalid_syntax("The request could not be understood.")
}

#[catch(401)]
fn scim_unauthorized() -> ScimError {
    ScimError::unauthorized()
}

#[catch(403)]
fn scim_forbidden() -> ScimError {
    ScimError::forbidden("The request was refused.")
}

#[catch(404)]
fn scim_not_found() -> ScimError {
    ScimError::not_found("Resource not found.")
}

#[catch(405)]
fn scim_method_not_allowed() -> ScimError {
    ScimError::new(rocket::http::Status::MethodNotAllowed, None, "Method not allowed for this resource.")
}

#[catch(413)]
fn scim_payload_too_large() -> ScimError {
    ScimError::payload_too_large("Request body is too large.")
}

#[catch(415)]
fn scim_unsupported_media_type() -> ScimError {
    ScimError::new(
        rocket::http::Status::UnsupportedMediaType,
        None,
        "Expected application/scim+json or application/json.",
    )
}

#[catch(422)]
fn scim_unprocessable_entity() -> ScimError {
    ScimError::invalid_syntax("The request could not be processed.")
}

#[catch(429)]
fn scim_too_many_requests() -> ScimError {
    ScimError::too_many_requests()
}

#[catch(500)]
fn scim_internal_error(req: &Request<'_>) -> ScimError {
    error!(target: "scim", "Unhandled error while serving {}", req.uri());
    ScimError::new(rocket::http::Status::InternalServerError, None, "The request could not be completed.")
}

// ---------------------------------------------------------------------------------------------
// Tenant context
// ---------------------------------------------------------------------------------------------

/// A SCIM request that has been authenticated for one specific organization.
///
/// Built by [`ScimContext::resolve`], which re-checks the authenticated organization against the
/// one in the URL. The guard already performs that check; doing it again here means a mistake in
/// the guard's path handling cannot become a cross-tenant bug.
pub struct ScimContext {
    pub org_id: OrganizationId,
}

impl ScimContext {
    pub fn resolve(token: &ScimToken, path_org_id: &str) -> ScimResult<Self> {
        if !crate::crypto::ct_eq(token.org_id.as_ref(), path_org_id) {
            // Same uniform 401 as any other authentication failure: a client must not be able to
            // tell "wrong organization" apart from "wrong token".
            return Err(ScimError::unauthorized());
        }

        Ok(Self {
            org_id: token.org_id.clone(),
        })
    }

    /// This organization's SCIM base URL, used for `meta.location` and the `Location` header.
    pub fn base_url(&self) -> String {
        format!("{}{SCIM_BASE_PATH}/{}", CONFIG.domain(), self.org_id)
    }

    pub fn resource_location(&self, resource_type: &str, id: &str) -> String {
        format!("{}/{resource_type}s/{id}", self.base_url())
    }
}

// ---------------------------------------------------------------------------------------------
// List queries: pagination and attribute projection
// ---------------------------------------------------------------------------------------------

/// Default number of resources returned when the client does not ask for a specific `count`.
pub const DEFAULT_PAGE_SIZE: usize = 100;
/// Hard cap on `count`, so a client cannot request an unbounded response.
pub const MAX_PAGE_SIZE: usize = 500;

/// The projection parameters, which RFC 7644 section 3.9 allows on **every** operation that
/// returns a resource representation -- `POST` and `PUT` and `PATCH` as much as `GET`.
///
/// Kept separate from [`ListQuery`] because `filter`, `startIndex` and `count` mean nothing on a
/// write, so there is nothing for a write handler to read them into.
///
/// That is a statement about what the handler *uses*, not about what the server rejects. Rocket
/// 0.5 parses query strings leniently: a field this struct does not declare is skipped, so
/// `POST /Users?filter=x&count=99` is accepted and the two unknown parameters are ignored. That is
/// also the RFC's position -- section 3.4.2 defines no error for an unrecognised query parameter,
/// and identity providers do append their own -- so nothing here tries to be stricter. The
/// behaviour is pinned by a route-level test in `e2e.rs` rather than left to be rediscovered.
#[derive(FromForm)]
pub struct ProjectionQuery {
    pub attributes: Option<String>,
    #[field(name = "excludedAttributes")]
    pub excluded_attributes: Option<String>,
}

impl ProjectionQuery {
    pub fn projection(&self, core_schema: &str) -> ScimResult<AttributeProjection> {
        AttributeProjection::parse(self.attributes.as_deref(), self.excluded_attributes.as_deref(), core_schema)
    }
}

/// Query parameters shared by the two list endpoints.
///
/// Everything is taken as a string and parsed by hand: Rocket's own numeric parsing would fail
/// the request before a handler runs, producing a Rocket error page instead of a SCIM one.
#[derive(FromForm)]
pub struct ListQuery {
    pub filter: Option<String>,
    #[field(name = "startIndex")]
    pub start_index: Option<String>,
    pub count: Option<String>,
    pub attributes: Option<String>,
    #[field(name = "excludedAttributes")]
    pub excluded_attributes: Option<String>,
}

impl ListQuery {
    pub fn projection(&self, core_schema: &str) -> ScimResult<AttributeProjection> {
        AttributeProjection::parse(self.attributes.as_deref(), self.excluded_attributes.as_deref(), core_schema)
    }

    pub fn pagination(&self) -> ScimResult<Pagination> {
        Pagination::parse(self.start_index.as_deref(), self.count.as_deref())
    }
}

/// A validated, 1-based SCIM page request.
#[derive(Debug, PartialEq, Eq)]
pub struct Pagination {
    /// 1-based index of the first resource to return.
    pub start_index: usize,
    /// Maximum number of resources to return.
    pub count: usize,
}

impl Pagination {
    pub fn parse(start_index: Option<&str>, count: Option<&str>) -> ScimResult<Self> {
        // RFC 7644 section 3.4.2.4: "A value less than 1 SHALL be interpreted as 1."
        let start_index = match start_index {
            None => 1,
            Some(raw) => {
                let parsed: i64 = raw
                    .trim()
                    .parse()
                    .map_err(|_| ScimError::invalid_value(format!("'startIndex' must be an integer, got '{raw}'.")))?;
                usize::try_from(parsed.max(1)).unwrap_or(1)
            }
        };

        // "A negative value SHALL be interpreted as 0." A count of 0 is a legitimate way to ask
        // for `totalResults` without any resources.
        let count = match count {
            None => DEFAULT_PAGE_SIZE,
            Some(raw) => {
                let parsed: i64 = raw
                    .trim()
                    .parse()
                    .map_err(|_| ScimError::invalid_value(format!("'count' must be an integer, got '{raw}'.")))?;
                usize::try_from(parsed.max(0)).unwrap_or(0).min(MAX_PAGE_SIZE)
            }
        };

        Ok(Self {
            start_index,
            count,
        })
    }

    /// Convert the 1-based window into a 0-based slice range over `total` resources.
    pub fn slice_range(&self, total: usize) -> std::ops::Range<usize> {
        let offset = self.start_index.saturating_sub(1).min(total);
        let end = offset.saturating_add(self.count).min(total);
        offset..end
    }
}

/// One entry of an `attributes` / `excludedAttributes` list.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AttrRef {
    /// Lower-case top-level attribute.
    attr: String,
    /// Lower-case sub-attribute, when the client named one (`emails.value`).
    sub: Option<String>,
}

/// `attributes` / `excludedAttributes` handling (RFC 7644 section 3.9).
///
/// The two are mutually exclusive; supplying both is a client error rather than something to
/// silently reconcile.
///
/// `id` and `schemas` are the minimum response set and always survive. `meta` does **not**: RFC
/// 7643 gives it `returned: default`, so `attributes=userName` legitimately omits it.
///
/// A projection is parsed **against the resource type being served**, never against both core
/// schemas at once. `GET /Users?attributes=urn:...:core:2.0:Group:externalId` names an attribute
/// of a schema the `User` resource does not have, so it selects nothing -- it must not be allowed
/// to reach through to the User's own `externalId`.
#[derive(Debug)]
pub struct AttributeProjection {
    include: Option<Vec<AttrRef>>,
    exclude: Vec<AttrRef>,
}

/// The minimum response set. RFC 7644 section 3.9 keeps `id` and the `schemas` declaration in
/// every representation regardless of what the client asked for.
const MINIMUM_RETURNED: [&str; 2] = ["id", "schemas"];

impl AttributeProjection {
    /// Parse a projection for one resource type.
    ///
    /// `core_schema` is that resource type's own schema URN ([`USER_SCHEMA`] or [`GROUP_SCHEMA`]).
    /// An unqualified name is one of its core attributes; a name qualified with `core_schema` is
    /// the same attribute spelled out; anything else is an extension attribute in some other
    /// namespace, which this server does not render and which therefore selects nothing.
    pub fn parse(attributes: Option<&str>, excluded: Option<&str>, core_schema: &str) -> ScimResult<Self> {
        /// Parse one comma-separated list.
        ///
        /// Returns `None` only when the parameter was absent or blank. A list that names nothing
        /// this server renders -- only extension attributes, say -- yields `Some(vec![])`, so
        /// `attributes=urn:example:Custom:foo` correctly narrows the response to the minimum set
        /// instead of being mistaken for "no projection requested".
        fn split(raw: Option<&str>, core_schema: &str) -> Option<Vec<AttrRef>> {
            let raw = raw?;
            if raw.trim().is_empty() {
                return None;
            }

            let refs: Vec<AttrRef> = raw
                .split(',')
                .filter_map(|entry| {
                    // Namespace-aware: an extension attribute must not be mistaken for the core
                    // attribute that happens to share its final name.
                    let name = match qualify(entry.trim(), core_schema) {
                        QualifiedAttr::Core(name) => name,
                        // Nothing in an extension namespace is ever rendered, so naming one in
                        // either list has no effect.
                        QualifiedAttr::Extension {
                            ..
                        } => return None,
                    };

                    let (attr, sub) = match name.split_once('.') {
                        Some((attr, sub)) => (attr, Some(sub.to_lowercase())),
                        None => (name, None),
                    };

                    let attr = attr.trim().to_lowercase();
                    if attr.is_empty() {
                        return None;
                    }
                    Some(AttrRef {
                        attr,
                        sub,
                    })
                })
                .collect();

            Some(refs)
        }

        let has_attributes = attributes.is_some_and(|a| !a.trim().is_empty());
        let has_excluded = excluded.is_some_and(|a| !a.trim().is_empty());
        if has_attributes && has_excluded {
            return Err(ScimError::invalid_value(
                "'attributes' and 'excludedAttributes' are mutually exclusive; send at most one.",
            ));
        }

        Ok(Self {
            include: split(attributes, core_schema),
            exclude: split(excluded, core_schema).unwrap_or_default(),
        })
    }

    /// The projection a client asked for nothing with: every attribute is returned.
    ///
    /// Only used by tests now that every handler parses the client's own parameters. Production
    /// code reaches the same state through `parse(None, None, ..)`.
    #[cfg(test)]
    pub fn none() -> Self {
        Self {
            include: None,
            exclude: Vec::new(),
        }
    }

    /// Could this attribute appear in the response at all?
    ///
    /// Used to skip work as well as output: when `members` is excluded outright there is no reason
    /// to load a group's membership from the database. An exclusion that only names a
    /// *sub*-attribute still needs the attribute loaded, so it does not suppress the work.
    pub fn wants(&self, attribute: &str) -> bool {
        let attribute = attribute.to_lowercase();
        if MINIMUM_RETURNED.contains(&attribute.as_str()) {
            return true;
        }
        if self.exclude.iter().any(|e| e.attr == attribute && e.sub.is_none()) {
            return false;
        }
        match &self.include {
            Some(include) => include.iter().any(|i| i.attr == attribute),
            None => true,
        }
    }

    /// Apply a sub-attribute projection to a complex value, in place.
    ///
    /// Handles both a single object and an array of objects, which is what SCIM's multi-valued
    /// complex attributes look like on the wire.
    fn project_complex(value: &mut Value, keep: Option<&[String]>, drop: &[String]) {
        fn project_object(object: &mut Value, keep: Option<&[String]>, drop: &[String]) {
            let Value::Object(map) = object else {
                return;
            };
            map.retain(|key, _| {
                let key = key.to_lowercase();
                if drop.contains(&key) {
                    return false;
                }
                match keep {
                    Some(keep) => keep.contains(&key),
                    None => true,
                }
            });
        }

        match value {
            Value::Array(items) => {
                for item in items {
                    project_object(item, keep, drop);
                }
            }
            other => project_object(other, keep, drop),
        }
    }

    pub fn apply(&self, resource: Value) -> Value {
        let Value::Object(mut map) = resource else {
            return resource;
        };

        map.retain(|key, _| self.wants(key));

        // Now narrow the complex attributes that survived. Excluding one sub-attribute removes
        // only that sub-attribute; it must not take the whole parent with it.
        let keys: Vec<String> = map.keys().cloned().collect();
        for key in keys {
            let lower = key.to_lowercase();
            if MINIMUM_RETURNED.contains(&lower.as_str()) {
                continue;
            }

            let drop: Vec<String> =
                self.exclude.iter().filter(|e| e.attr == lower).filter_map(|e| e.sub.clone()).collect();

            let keep: Option<Vec<String>> = self.include.as_ref().and_then(|include| {
                let subs: Vec<String> =
                    include.iter().filter(|i| i.attr == lower).filter_map(|i| i.sub.clone()).collect();
                // `attributes=emails` asks for the whole attribute, so only narrow when every
                // reference to it named a sub-attribute.
                let named_whole = include.iter().any(|i| i.attr == lower && i.sub.is_none());
                if subs.is_empty() || named_whole {
                    None
                } else {
                    Some(subs)
                }
            });

            if drop.is_empty() && keep.is_none() {
                continue;
            }
            if let Some(value) = map.get_mut(&key) {
                Self::project_complex(value, keep.as_deref(), &drop);
            }
        }

        Value::Object(map)
    }
}

/// Build a SCIM `ListResponse`.
pub fn list_response(total_results: usize, pagination: &Pagination, resources: Vec<Value>) -> Value {
    json!({
        "schemas": [LIST_RESPONSE_SCHEMA],
        "totalResults": total_results,
        "startIndex": pagination.start_index,
        "itemsPerPage": resources.len(),
        "Resources": Value::Array(resources),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- pagination ----------------------------------------------------------------------------

    #[test]
    fn pagination_defaults_are_one_based() {
        let p = Pagination::parse(None, None).unwrap();
        assert_eq!(p.start_index, 1, "SCIM indices start at 1, not 0");
        assert_eq!(p.count, DEFAULT_PAGE_SIZE);
    }

    #[test]
    fn start_index_below_one_is_clamped_to_one() {
        // RFC 7644 section 3.4.2.4.
        assert_eq!(Pagination::parse(Some("0"), None).unwrap().start_index, 1);
        assert_eq!(Pagination::parse(Some("-5"), None).unwrap().start_index, 1);
    }

    #[test]
    fn count_is_capped_and_never_negative() {
        assert_eq!(Pagination::parse(None, Some("10")).unwrap().count, 10);
        assert_eq!(Pagination::parse(None, Some("-1")).unwrap().count, 0);
        assert_eq!(Pagination::parse(None, Some("100000")).unwrap().count, MAX_PAGE_SIZE);
    }

    #[test]
    fn count_zero_is_a_valid_count_only_request() {
        let p = Pagination::parse(None, Some("0")).unwrap();
        assert_eq!(p.count, 0);
        assert_eq!(p.slice_range(42), 0..0, "no resources, but totalResults still reported");
    }

    #[test]
    fn non_numeric_pagination_is_a_scim_error_not_a_panic() {
        let err = Pagination::parse(Some("abc"), None).unwrap_err();
        assert_eq!(err.scim_type, Some(error::ScimType::InvalidValue));

        let err = Pagination::parse(None, Some("lots")).unwrap_err();
        assert_eq!(err.scim_type, Some(error::ScimType::InvalidValue));
    }

    #[test]
    fn slice_range_walks_pages_without_gaps_or_overlap() {
        let total = 10;

        let first = Pagination {
            start_index: 1,
            count: 4,
        };
        let second = Pagination {
            start_index: 5,
            count: 4,
        };
        let third = Pagination {
            start_index: 9,
            count: 4,
        };

        assert_eq!(first.slice_range(total), 0..4);
        assert_eq!(second.slice_range(total), 4..8);
        assert_eq!(third.slice_range(total), 8..10, "last page is short, not out of bounds");
    }

    #[test]
    fn slice_range_past_the_end_is_empty() {
        let p = Pagination {
            start_index: 100,
            count: 10,
        };
        assert_eq!(p.slice_range(5), 5..5);
        assert!(p.slice_range(5).is_empty());
    }

    #[test]
    fn slice_range_handles_an_empty_collection() {
        let p = Pagination {
            start_index: 1,
            count: 10,
        };
        assert_eq!(p.slice_range(0), 0..0);
    }

    #[test]
    fn huge_start_index_does_not_overflow() {
        let p = Pagination::parse(Some(&i64::MAX.to_string()), Some("500")).unwrap();
        assert!(p.slice_range(10).is_empty());
    }

    // -- list response -------------------------------------------------------------------------

    #[test]
    fn list_response_reports_the_page_it_actually_returned() {
        let p = Pagination {
            start_index: 5,
            count: 100,
        };
        let body = list_response(42, &p, vec![json!({"id": "a"}), json!({"id": "b"})]);

        assert_eq!(body["schemas"], json!([LIST_RESPONSE_SCHEMA]));
        assert_eq!(body["totalResults"], json!(42));
        assert_eq!(body["startIndex"], json!(5));
        assert_eq!(body["itemsPerPage"], json!(2), "itemsPerPage is the page size actually returned");
        assert_eq!(body["Resources"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn empty_list_response_is_still_well_formed() {
        let p = Pagination::parse(None, None).unwrap();
        let body = list_response(0, &p, Vec::new());

        assert_eq!(body["totalResults"], json!(0));
        assert_eq!(body["itemsPerPage"], json!(0));
        assert_eq!(body["Resources"], json!([]));
    }

    // -- attribute projection ------------------------------------------------------------------

    fn group() -> Value {
        json!({
            "schemas": [GROUP_SCHEMA],
            "id": "group-1",
            "externalId": "ext-1",
            "displayName": "Engineering",
            "members": [{"value": "member-1"}],
            "meta": {"resourceType": "Group"},
        })
    }

    fn user() -> Value {
        json!({
            "schemas": [USER_SCHEMA],
            "id": "member-1",
            "externalId": "ext-1",
            "userName": "alice@example.test",
            "displayName": "Alice",
            "active": true,
            "emails": [{"value": "alice@example.test", "type": "work", "primary": true}],
            "meta": {"resourceType": "User", "location": "https://vault.test/x"},
        })
    }

    /// A Group projection, which is what most of these tests exercise.
    fn projection(attributes: Option<&str>, excluded: Option<&str>) -> AttributeProjection {
        AttributeProjection::parse(attributes, excluded, GROUP_SCHEMA).expect("valid projection")
    }

    fn user_projection(attributes: Option<&str>, excluded: Option<&str>) -> AttributeProjection {
        AttributeProjection::parse(attributes, excluded, USER_SCHEMA).expect("valid projection")
    }

    #[test]
    fn projection_defaults_to_returning_everything() {
        assert_eq!(AttributeProjection::none().apply(group()), group());
    }

    #[test]
    fn excluded_attributes_are_dropped() {
        // This is the request Entra ID makes when it looks a group up by name.
        let projection = projection(None, Some("members"));

        assert!(!projection.wants("members"), "excluding it outright also skips loading it");
        let projected = projection.apply(group());
        assert!(projected.get("members").is_none());
        assert_eq!(projected["displayName"], json!("Engineering"));
    }

    #[test]
    fn requested_attributes_are_the_only_optional_ones_returned() {
        let projected = projection(Some("displayName"), None).apply(group());

        assert_eq!(projected["displayName"], json!("Engineering"));
        assert!(projected.get("externalId").is_none());
        assert!(projected.get("members").is_none());
    }

    #[test]
    fn id_and_schemas_survive_any_projection() {
        // RFC 7644 section 3.9 keeps these in the minimum response set.
        let projected = projection(Some("displayName"), None).apply(group());

        assert_eq!(projected["id"], json!("group-1"));
        assert_eq!(projected["schemas"], json!([GROUP_SCHEMA]));
    }

    #[test]
    fn meta_is_returned_by_default_but_is_not_mandatory() {
        // RFC 7643 gives `meta` `returned: default`, not `returned: always`, so asking for a
        // specific attribute list legitimately leaves it out.
        assert!(AttributeProjection::none().apply(user()).get("meta").is_some());
        assert!(user_projection(Some("userName"), None).apply(user()).get("meta").is_none());
        assert!(user_projection(None, Some("meta")).apply(user()).get("meta").is_none());
        assert!(user_projection(Some("userName,meta"), None).apply(user()).get("meta").is_some());
    }

    #[test]
    fn a_sub_attribute_can_be_selected() {
        let projected = user_projection(Some("emails.value"), None).apply(user());

        let email = &projected["emails"][0];
        assert_eq!(email["value"], json!("alice@example.test"));
        assert!(email.get("type").is_none(), "only the named sub-attribute is kept");
        assert!(email.get("primary").is_none());
    }

    #[test]
    fn excluding_a_sub_attribute_keeps_the_parent() {
        let projected = user_projection(None, Some("emails.type")).apply(user());

        let email = &projected["emails"][0];
        assert!(email.get("type").is_none(), "the named sub-attribute is gone");
        assert_eq!(email["value"], json!("alice@example.test"), "the rest of the parent survives");
        assert_eq!(email["primary"], json!(true));
    }

    #[test]
    fn naming_the_whole_attribute_wins_over_a_sub_attribute() {
        let projected = user_projection(Some("emails,emails.value"), None).apply(user());

        assert!(projected["emails"][0].get("type").is_some(), "asking for `emails` asks for all of it");
    }

    #[test]
    fn attributes_and_excluded_attributes_are_mutually_exclusive() {
        // RFC 7644 section 3.9. Reconciling them silently would guess at the client's intent.
        let err = AttributeProjection::parse(Some("userName"), Some("emails"), USER_SCHEMA).unwrap_err();
        assert_eq!(err.status, rocket::http::Status::BadRequest);
        assert_eq!(err.scim_type, Some(error::ScimType::InvalidValue));
    }

    #[test]
    fn a_qualified_core_attribute_is_recognised() {
        let projection = projection(None, Some("urn:ietf:params:scim:schemas:core:2.0:Group:members"));
        assert!(!projection.wants("members"));
    }

    #[test]
    fn an_extension_attribute_never_projects_a_core_one() {
        // The final segment is `members`, but the namespace is not the Group core schema, so it
        // must not act on the core `members`.
        let projection = projection(None, Some("urn:example:Custom:members"));
        assert!(projection.wants("members"), "an extension attribute must not exclude the core one");
        assert!(projection.apply(group()).get("members").is_some());
    }

    #[test]
    fn asking_only_for_extension_attributes_returns_the_minimum_set() {
        // The list named nothing this server renders. That is not the same as naming nothing at
        // all, so the response narrows to `id` and `schemas` rather than returning everything.
        let projected = projection(Some("urn:example:Custom:foo"), None).apply(group());

        assert_eq!(projected["id"], json!("group-1"));
        assert_eq!(projected["schemas"], json!([GROUP_SCHEMA]));
        assert!(projected.get("displayName").is_none(), "an unsatisfiable list must not return everything");
        assert!(projected.get("members").is_none());
    }

    // -- cross-resource namespace isolation --------------------------------------------------------
    //
    // A projection is parsed against the resource type being served. Parsing it against both core
    // schemas and keeping the union -- what an earlier revision did -- means a Group-qualified name
    // selects the User attribute that happens to share its last segment, and vice versa.

    #[test]
    fn a_group_qualified_name_does_not_select_a_user_attribute() {
        // `GET /Users?attributes=urn:...:Group:externalId` names an attribute of a schema the User
        // resource does not have. It selects nothing, so the response narrows to the minimum set;
        // it must not reach through to the User's own `externalId`.
        let projection = user_projection(Some("urn:ietf:params:scim:schemas:core:2.0:Group:externalId"), None);

        assert!(!projection.wants("externalid"), "a Group-qualified name is foreign to a User");
        let projected = projection.apply(user());
        assert!(projected.get("externalId").is_none());
        assert_eq!(projected["id"], json!("member-1"), "the minimum response set survives");
    }

    #[test]
    fn a_group_qualified_name_does_not_exclude_a_user_attribute() {
        let projection = user_projection(None, Some("urn:ietf:params:scim:schemas:core:2.0:Group:externalId"));

        assert!(projection.wants("externalid"), "excluding a foreign attribute excludes nothing");
        assert_eq!(projection.apply(user())["externalId"], json!("ext-1"));
    }

    #[test]
    fn a_user_qualified_name_does_not_select_a_group_attribute() {
        let projection = projection(Some("urn:ietf:params:scim:schemas:core:2.0:User:externalId"), None);

        assert!(!projection.wants("externalid"));
        let projected = projection.apply(group());
        assert!(projected.get("externalId").is_none());
        assert!(projected.get("displayName").is_none());
    }

    #[test]
    fn a_user_qualified_name_does_not_exclude_a_group_attribute() {
        let projection = projection(None, Some("urn:ietf:params:scim:schemas:core:2.0:User:displayName"));

        assert!(projection.wants("displayname"));
        assert_eq!(projection.apply(group())["displayName"], json!("Engineering"));
    }

    #[test]
    fn a_user_qualified_members_cannot_hide_a_groups_membership() {
        // The optimisation that skips loading membership keys off `wants("members")`, so a
        // foreign-namespace `members` must not be able to trigger it either.
        let projection = projection(None, Some("urn:ietf:params:scim:schemas:core:2.0:User:members"));

        assert!(projection.wants("members"), "only the Group's own `members` may skip the membership load");
        assert!(projection.apply(group()).get("members").is_some());
    }

    #[test]
    fn each_resource_type_honours_its_own_qualified_names() {
        // The other half of the rule: a name qualified with the *active* core schema still works.
        assert!(projection(Some("urn:ietf:params:scim:schemas:core:2.0:Group:displayName"), None).wants("displayname"));
        assert!(user_projection(Some("urn:ietf:params:scim:schemas:core:2.0:User:userName"), None).wants("username"));
    }

    #[test]
    fn an_arbitrary_extension_attribute_never_projects_a_core_one() {
        // Not just the other resource type: any third namespace is foreign too.
        for name in ["active", "externalId", "members", "displayName", "userName"] {
            let excluded = user_projection(None, Some(&format!("urn:example:Custom:{name}")));
            assert!(excluded.wants(&name.to_lowercase()), "urn:example:Custom:{name} must not exclude the core one");

            let included = user_projection(Some(&format!("urn:example:Custom:{name}")), None);
            assert!(!included.wants(&name.to_lowercase()), "urn:example:Custom:{name} must not select the core one");
        }
    }

    #[test]
    fn projection_is_case_insensitive() {
        let projection = projection(None, Some("MEMBERS"));
        assert!(!projection.wants("members"));
        assert!(!projection.wants("Members"));
    }

    #[test]
    fn empty_projection_strings_are_ignored() {
        let projection = projection(Some(""), Some(" , "));
        assert!(projection.wants("displayName"), "an empty attributes list must not hide everything");
    }

    // -- namespace awareness ---------------------------------------------------------------------

    #[test]
    fn qualify_recognises_the_core_schema() {
        assert_eq!(qualify("active", USER_SCHEMA), QualifiedAttr::Core("active"));
        assert_eq!(
            qualify("urn:ietf:params:scim:schemas:core:2.0:User:active", USER_SCHEMA),
            QualifiedAttr::Core("active")
        );
        // The URN comparison is case-insensitive, as URNs are.
        assert_eq!(
            qualify("URN:IETF:PARAMS:SCIM:SCHEMAS:CORE:2.0:USER:active", USER_SCHEMA),
            QualifiedAttr::Core("active")
        );
    }

    #[test]
    fn qualify_never_aliases_an_extension_onto_a_core_attribute() {
        // This is the whole point: an extension attribute whose final name collides with a core
        // one must stay an extension.
        for name in ["active", "userName", "externalId", "members", "id"] {
            let raw = format!("urn:example:Custom:{name}");
            assert_eq!(
                qualify(&raw, USER_SCHEMA),
                QualifiedAttr::Extension {
                    urn: "urn:example:Custom",
                    attr: name,
                },
                "{raw} must not be treated as core"
            );
        }
    }

    #[test]
    fn the_group_schema_is_not_the_user_schema() {
        // A Group-qualified attribute is an extension from the User resource's point of view.
        assert!(matches!(
            qualify("urn:ietf:params:scim:schemas:core:2.0:Group:members", USER_SCHEMA),
            QualifiedAttr::Extension { .. }
        ));
    }

    #[test]
    fn enterprise_extension_objects_are_recognised_as_schema_urns() {
        assert!(is_schema_urn(ENTERPRISE_USER_SCHEMA, USER_SCHEMA));
        assert!(is_schema_urn(USER_SCHEMA, USER_SCHEMA));
        assert!(!is_schema_urn("urn:example:Custom", USER_SCHEMA));
        assert!(!is_schema_urn("active", USER_SCHEMA));
    }
}

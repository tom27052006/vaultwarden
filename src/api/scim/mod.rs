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

use std::{collections::HashSet, sync::LazyLock};

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

/// `attributes` / `excludedAttributes` handling (RFC 7644 section 3.9).
///
/// Only top-level attributes are supported, which is what identity providers actually use --
/// Entra ID asks for groups with `excludedAttributes=members` so it does not have to receive a
/// membership list it is about to overwrite.
pub struct AttributeProjection {
    include: Option<HashSet<String>>,
    exclude: HashSet<String>,
}

/// Attributes that are always returned, whatever the client asks for. RFC 7644 section 3.9 makes
/// `id`, `schemas` and `meta` non-excludable.
const ALWAYS_RETURNED: [&str; 3] = ["id", "schemas", "meta"];

impl AttributeProjection {
    pub fn parse(attributes: Option<&str>, excluded: Option<&str>) -> Self {
        fn split(raw: Option<&str>) -> Option<HashSet<String>> {
            let set: HashSet<String> = raw?
                .split(',')
                .map(|a| {
                    // Tolerate a fully-qualified name: `urn:...:User:userName` -> `username`.
                    let a = a.trim();
                    let a = a.rsplit(':').next().unwrap_or(a);
                    // Only top-level attributes are honoured, so drop any sub-attribute.
                    a.split('.').next().unwrap_or(a).to_lowercase()
                })
                .filter(|a| !a.is_empty())
                .collect();

            if set.is_empty() {
                None
            } else {
                Some(set)
            }
        }

        Self {
            include: split(attributes),
            exclude: split(excluded).unwrap_or_default(),
        }
    }

    pub fn none() -> Self {
        Self {
            include: None,
            exclude: HashSet::new(),
        }
    }

    /// Does the caller want this attribute rendered at all?
    ///
    /// Used to skip work as well as output: when `members` is excluded there is no reason to load
    /// a group's membership from the database.
    pub fn wants(&self, attribute: &str) -> bool {
        let attribute = attribute.to_lowercase();
        if ALWAYS_RETURNED.contains(&attribute.as_str()) {
            return true;
        }
        if self.exclude.contains(&attribute) {
            return false;
        }
        match &self.include {
            Some(include) => include.contains(&attribute),
            None => true,
        }
    }

    pub fn apply(&self, resource: Value) -> Value {
        let Value::Object(map) = resource else {
            return resource;
        };

        Value::Object(map.into_iter().filter(|(key, _)| self.wants(key)).collect())
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

    #[test]
    fn projection_defaults_to_returning_everything() {
        let projection = AttributeProjection::none();
        assert_eq!(projection.apply(group()), group());
    }

    #[test]
    fn excluded_attributes_are_dropped() {
        // This is the request Entra ID makes when it looks a group up by name.
        let projection = AttributeProjection::parse(None, Some("members"));

        assert!(!projection.wants("members"));
        let projected = projection.apply(group());
        assert!(projected.get("members").is_none());
        assert_eq!(projected["displayName"], json!("Engineering"));
    }

    #[test]
    fn requested_attributes_are_the_only_optional_ones_returned() {
        let projection = AttributeProjection::parse(Some("displayName"), None);

        let projected = projection.apply(group());
        assert_eq!(projected["displayName"], json!("Engineering"));
        assert!(projected.get("externalId").is_none());
        assert!(projected.get("members").is_none());
    }

    #[test]
    fn id_schemas_and_meta_survive_any_projection() {
        // RFC 7644 section 3.9 makes these non-excludable.
        let projection = AttributeProjection::parse(Some("displayName"), Some("id,schemas,meta"));
        let projected = projection.apply(group());

        assert_eq!(projected["id"], json!("group-1"));
        assert_eq!(projected["schemas"], json!([GROUP_SCHEMA]));
        assert_eq!(projected["meta"]["resourceType"], json!("Group"));
    }

    #[test]
    fn projection_accepts_qualified_and_sub_attribute_names() {
        let projection =
            AttributeProjection::parse(None, Some("urn:ietf:params:scim:schemas:core:2.0:Group:members.value"));
        assert!(!projection.wants("members"), "a sub-attribute exclusion drops the whole attribute");
    }

    #[test]
    fn projection_is_case_insensitive() {
        let projection = AttributeProjection::parse(None, Some("MEMBERS"));
        assert!(!projection.wants("members"));
        assert!(!projection.wants("Members"));
    }

    #[test]
    fn empty_projection_strings_are_ignored() {
        let projection = AttributeProjection::parse(Some(""), Some(" , "));
        assert!(projection.wants("displayName"), "an empty attributes list must not hide everything");
    }
}

//! SCIM discovery endpoints (RFC 7644 section 4).
//!
//! These describe what this server actually does. Every capability reported here is one the
//! implementation genuinely has: bulk, sort, ETag and change-password are advertised as
//! unsupported because they are, and the `Group` resource type disappears entirely when
//! `ORG_GROUPS_ENABLED` is off rather than being advertised and then failing.
//!
//! They are mounted under the organization's base path and require the same bearer token as every
//! other SCIM request. RFC 7644 permits them to be anonymous, but they are tenant-scoped here and
//! identity providers always send the token, so there is nothing to gain by opening them up.

use rocket::Route;
use serde_json::Value;

use super::{
    GROUP_SCHEMA, MAX_PAGE_SIZE, Pagination, RESOURCE_TYPE_SCHEMA, SCHEMA_SCHEMA, SERVICE_PROVIDER_CONFIG_SCHEMA,
    ScimContext, ScimToken, USER_SCHEMA,
    error::{ScimError, ScimResult},
    json::ScimResponse,
    list_response,
};

pub fn routes() -> Vec<Route> {
    routes![service_provider_config, resource_types, resource_type, schemas, schema]
}

#[get("/<org_id>/ServiceProviderConfig")]
#[expect(clippy::needless_pass_by_value, reason = "Rocket request guards are taken by value")]
fn service_provider_config(org_id: &str, token: ScimToken) -> ScimResult<ScimResponse> {
    let ctx = ScimContext::resolve(&token, org_id)?;
    let location = format!("{}/ServiceProviderConfig", ctx.base_url());

    Ok(ScimResponse::resource(
        json!({
        "schemas": [SERVICE_PROVIDER_CONFIG_SCHEMA],
        "documentationUri": "https://github.com/dani-garcia/vaultwarden/blob/main/docs/scim/README.md",
        "patch": { "supported": true },
        // Vaultwarden has no /Bulk endpoint. Reporting maxOperations/maxPayloadSize alongside an
        // unsupported feature would be meaningless, so they are omitted.
        "bulk": { "supported": false, "maxOperations": 0, "maxPayloadSize": 0 },
        "filter": { "supported": true, "maxResults": MAX_PAGE_SIZE },
        "changePassword": { "supported": false },
        "sort": { "supported": false },
        "etag": { "supported": false },
        "authenticationSchemes": [{
            "type": "oauthbearertoken",
            "name": "OAuth Bearer Token",
            "description": "Authentication using an organization SCIM token issued from the Vaultwarden admin panel.",
            "specUri": "https://www.rfc-editor.org/rfc/rfc6750",
            "primary": true,
        }],
        "meta": {
            "resourceType": "ServiceProviderConfig",
            "location": location,
        },
        }),
        location,
    ))
}

/// Wrap a single discovery resource, mirroring its own `meta.location` into `Content-Location`.
fn single_resource(body: Value) -> ScimResponse {
    let location = body["meta"]["location"].as_str().unwrap_or_default().to_owned();
    ScimResponse::resource(body, location)
}

/// Resource types this server exposes.
///
/// `Group` is present only when organization groups are enabled, because that is the only case in
/// which the `/Groups` endpoints work.
fn resource_type_definitions(ctx: &ScimContext) -> Vec<Value> {
    let base_url = ctx.base_url();
    let mut types = vec![json!({
        "schemas": [RESOURCE_TYPE_SCHEMA],
        "id": "User",
        "name": "User",
        "endpoint": "/Users",
        "description": "Organization member",
        "schema": USER_SCHEMA,
        "schemaExtensions": [],
        "meta": {
            "resourceType": "ResourceType",
            "location": format!("{base_url}/ResourceTypes/User"),
        },
    })];

    if super::settings::groups_enabled() {
        types.push(json!({
            "schemas": [RESOURCE_TYPE_SCHEMA],
            "id": "Group",
            "name": "Group",
            "endpoint": "/Groups",
            "description": "Organization group",
            "schema": GROUP_SCHEMA,
            "schemaExtensions": [],
            "meta": {
                "resourceType": "ResourceType",
                "location": format!("{base_url}/ResourceTypes/Group"),
            },
        }));
    }

    types
}

#[get("/<org_id>/ResourceTypes")]
#[expect(clippy::needless_pass_by_value, reason = "Rocket request guards are taken by value")]
fn resource_types(org_id: &str, token: ScimToken) -> ScimResult<ScimResponse> {
    let ctx = ScimContext::resolve(&token, org_id)?;
    let types = resource_type_definitions(&ctx);

    let pagination = Pagination {
        start_index: 1,
        count: types.len().max(1),
    };
    Ok(ScimResponse::ok(list_response(types.len(), &pagination, types)))
}

#[get("/<org_id>/ResourceTypes/<type_id>")]
#[expect(clippy::needless_pass_by_value, reason = "Rocket request guards are taken by value")]
fn resource_type(org_id: &str, type_id: &str, token: ScimToken) -> ScimResult<ScimResponse> {
    let ctx = ScimContext::resolve(&token, org_id)?;

    resource_type_definitions(&ctx)
        .into_iter()
        .find(|t| t["id"].as_str().is_some_and(|id| id.eq_ignore_ascii_case(type_id)))
        .map(single_resource)
        .ok_or_else(|| ScimError::not_found(format!("Resource type '{type_id}' is not supported.")))
}

/// Build one attribute definition for a schema document.
fn attribute(
    name: &str,
    attr_type: &str,
    multi_valued: bool,
    required: bool,
    mutability: &str,
    uniqueness: &str,
    case_exact: bool,
) -> Value {
    json!({
        "name": name,
        "type": attr_type,
        "multiValued": multi_valued,
        "required": required,
        "caseExact": case_exact,
        "mutability": mutability,
        "returned": "default",
        "uniqueness": uniqueness,
    })
}

fn user_schema(ctx: &ScimContext) -> Value {
    json!({
        "schemas": [SCHEMA_SCHEMA],
        "id": USER_SCHEMA,
        "name": "User",
        "description": "Organization member",
        // The mutability values here are what the implementation actually enforces, not what a
        // stock Core User schema would say. Three deliberate deviations, all documented in
        // docs/scim/design.md:
        //
        // * `userName` is `immutable` rather than `readWrite`. It maps to the account's global
        //   email address -- the login identity every other organization resolves through -- so
        //   SCIM sets it at creation and refuses any later change.
        // * `displayName` is `immutable` rather than `readWrite`. It names a brand-new account
        //   this request creates; an existing account keeps its own name, because that name is
        //   visible in every organization it belongs to. Re-sending the stored value is a no-op;
        //   sending a different one is refused with `scimType: mutability`.
        // * `emails` is `immutable` rather than `readOnly`, because `POST /Users` genuinely
        //   accepts `emails[].value` as the identity when `userName` is absent. Advertising it
        //   `readOnly` while letting it decide creation state would be describing a different
        //   server. `emails.value` is the same global account email as `userName` and follows
        //   exactly the same rule; `type` and `primary` really are server-derived, so those two
        //   stay `readOnly` rather than being levelled up to match their parent.
        "attributes": [
            attribute("userName", "string", false, true, "immutable", "server", false),
            attribute("externalId", "string", false, false, "readWrite", "none", true),
            attribute("displayName", "string", false, false, "immutable", "none", false),
            attribute("active", "boolean", false, false, "readWrite", "none", false),
            json!({
                "name": "emails",
                "type": "complex",
                "multiValued": true,
                "required": false,
                "mutability": "immutable",
                "returned": "default",
                "subAttributes": [
                    attribute("value", "string", false, false, "immutable", "server", false),
                    attribute("type", "string", false, false, "readOnly", "none", false),
                    attribute("primary", "boolean", false, false, "readOnly", "none", false),
                ],
            }),
        ],
        "meta": {
            "resourceType": "Schema",
            "location": format!("{}/Schemas/{USER_SCHEMA}", ctx.base_url()),
        },
    })
}

fn group_schema(ctx: &ScimContext) -> Value {
    json!({
        "schemas": [SCHEMA_SCHEMA],
        "id": GROUP_SCHEMA,
        "name": "Group",
        "description": "Organization group",
        // `displayName` is advertised `uniqueness: "none"`, even though SCIM refuses to create or
        // rename a group into a name another group in the organization already has.
        //
        // The two are not the same claim. `uniqueness: "server"` says the value *is* unique across
        // this service provider, and Vaultwarden cannot promise that: `groups.name` has no unique
        // constraint, and an installation may already hold duplicates created by hand or by the
        // Directory Connector. The SCIM layer only refuses to introduce *new* collisions. Saying
        // "server" would be describing an invariant the storage does not hold, and a client that
        // believed it could resolve a group by name and get one row.
        //
        // See docs/scim/design.md section 12.
        "attributes": [
            attribute("displayName", "string", false, true, "readWrite", "none", false),
            attribute("externalId", "string", false, false, "readWrite", "none", true),
            json!({
                "name": "members",
                "type": "complex",
                "multiValued": true,
                "required": false,
                "mutability": "readWrite",
                "returned": "default",
                "subAttributes": [
                    attribute("value", "string", false, false, "immutable", "none", true),
                    attribute("$ref", "reference", false, false, "immutable", "none", true),
                    attribute("type", "string", false, false, "immutable", "none", false),
                ],
            }),
        ],
        "meta": {
            "resourceType": "Schema",
            "location": format!("{}/Schemas/{GROUP_SCHEMA}", ctx.base_url()),
        },
    })
}

fn schema_definitions(ctx: &ScimContext) -> Vec<Value> {
    let mut schemas = vec![user_schema(ctx)];
    if super::settings::groups_enabled() {
        schemas.push(group_schema(ctx));
    }
    schemas
}

#[get("/<org_id>/Schemas")]
#[expect(clippy::needless_pass_by_value, reason = "Rocket request guards are taken by value")]
fn schemas(org_id: &str, token: ScimToken) -> ScimResult<ScimResponse> {
    let ctx = ScimContext::resolve(&token, org_id)?;
    let definitions = schema_definitions(&ctx);

    let pagination = Pagination {
        start_index: 1,
        count: definitions.len().max(1),
    };
    Ok(ScimResponse::ok(list_response(definitions.len(), &pagination, definitions)))
}

#[get("/<org_id>/Schemas/<schema_id>")]
#[expect(clippy::needless_pass_by_value, reason = "Rocket request guards are taken by value")]
fn schema(org_id: &str, schema_id: &str, token: ScimToken) -> ScimResult<ScimResponse> {
    let ctx = ScimContext::resolve(&token, org_id)?;

    schema_definitions(&ctx)
        .into_iter()
        .find(|s| s["id"].as_str() == Some(schema_id))
        .map(single_resource)
        .ok_or_else(|| ScimError::not_found(format!("Schema '{schema_id}' is not supported.")))
}

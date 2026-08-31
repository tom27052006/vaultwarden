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

/// A `reference` attribute, which RFC 7643 section 7 requires to declare what it may point at.
fn reference(name: &str, reference_types: &[&str], required: bool, mutability: &str) -> Value {
    json!({
        "name": name,
        "type": "reference",
        "referenceTypes": reference_types,
        "multiValued": false,
        "required": required,
        "caseExact": true,
        "mutability": mutability,
        "returned": "default",
        "uniqueness": "none",
    })
}

/// A read-only boolean, the shape every `supported` flag in `ServiceProviderConfig` has.
fn read_only_bool(name: &str, required: bool) -> Value {
    json!({
        "name": name,
        "type": "boolean",
        "multiValued": false,
        "required": required,
        "mutability": "readOnly",
        "returned": "default",
    })
}

/// A read-only integer.
fn read_only_int(name: &str) -> Value {
    attribute(name, "integer", false, true, "readOnly", "none", false)
}

/// A read-only complex attribute with the given sub-attributes.
fn complex(name: &str, multi_valued: bool, required: bool, mutability: &str, sub: Vec<Value>) -> Value {
    json!({
        "name": name,
        "type": "complex",
        "multiValued": multi_valued,
        "required": required,
        "mutability": mutability,
        "returned": "default",
        "subAttributes": Value::Array(sub),
    })
}

/// Wrap a set of attributes as a `Schema` resource.
fn schema_resource(ctx: &ScimContext, id: &str, name: &str, description: &str, attributes: Vec<Value>) -> Value {
    json!({
        "schemas": [SCHEMA_SCHEMA],
        "id": id,
        "name": name,
        "description": description,
        "attributes": Value::Array(attributes),
        "meta": {
            "resourceType": "Schema",
            "location": format!("{}/Schemas/{id}", ctx.base_url()),
        },
    })
}

// ---------------------------------------------------------------------------------------------
// Schemas
// ---------------------------------------------------------------------------------------------
//
// RFC 7643 section 7: "For every schema URI used in a resource object, there is a corresponding
// 'Schema' resource." Every URI this server puts in the `schemas` array of a *resource* is
// published here, which is why the three discovery schemas appear alongside `User` and `Group`: a
// `ServiceProviderConfig`, a `ResourceType` and a `Schema` are resources and each announces its
// own URN. RFC 7643 section 8.7.2 gives their definitions, so nothing here is invented.
//
// The `urn:ietf:params:scim:api:messages:2.0:*` URNs -- `ListResponse`, `Error`, `PatchOp` -- are
// deliberately absent. Those are protocol *messages* defined by RFC 7644, not resources, and
// RFC 7643 publishes no schema for any of them. Making some up would be exactly the sort of
// proprietary invention this endpoint must not contain.
//
// Every definition below describes what this server actually emits or accepts. Where that differs
// from the stock RFC text the difference is deliberate and commented.

/// The `User` resource schema.
fn user_schema(ctx: &ScimContext) -> Value {
    // The mutability values here are what the implementation actually enforces, not what a stock
    // Core User schema would say. Three deliberate deviations, all documented in
    // docs/scim/design.md:
    //
    // * `userName` is `immutable` rather than `readWrite`. It maps to the account's global email
    //   address -- the login identity every other organization resolves through -- so SCIM sets it
    //   at creation and refuses any later change.
    // * `displayName` is `immutable` rather than `readWrite`. It names a brand-new account this
    //   request creates; an existing account keeps its own name, because that name is visible in
    //   every organization it belongs to. Re-sending the stored value is a no-op; sending a
    //   different one is refused with `scimType: mutability`.
    // * `emails` is `immutable` rather than `readOnly`, because `POST /Users` genuinely accepts
    //   `emails[].value` as the identity when `userName` is absent. Advertising it `readOnly`
    //   while letting it decide creation state would be describing a different server.
    //   `emails.value` is the same global account email as `userName` and follows exactly the same
    //   rule; `type` and `primary` really are server-derived, so those two stay `readOnly` rather
    //   than being levelled up to match their parent -- and a PATCH that tries to write either is
    //   refused with `scimType: mutability` instead of being read as an address change.
    //
    // `name` is **not** listed, and that absence is the whole statement of this server's policy on
    // it: `POST` accepts `name.formatted` / `givenName` / `familyName` as a fallback when naming an
    // account it is creating -- an input compatibility for identity providers that map only `name`
    // -- but the attribute is not part of this resource. It is never read back, never written to
    // an account that already exists, and never reinterpreted as `displayName` on `PUT` or
    // `PATCH`. See docs/scim/design.md section 7.
    let attributes = vec![
        attribute("userName", "string", false, true, "immutable", "server", false),
        attribute("externalId", "string", false, false, "readWrite", "none", true),
        attribute("displayName", "string", false, false, "immutable", "none", false),
        attribute("active", "boolean", false, false, "readWrite", "none", false),
        complex(
            "emails",
            true,
            false,
            "immutable",
            vec![
                attribute("value", "string", false, false, "immutable", "server", false),
                attribute("type", "string", false, false, "readOnly", "none", false),
                attribute("primary", "boolean", false, false, "readOnly", "none", false),
            ],
        ),
    ];

    schema_resource(ctx, USER_SCHEMA, "User", "Organization member", attributes)
}

/// The `Group` resource schema.
fn group_schema(ctx: &ScimContext) -> Value {
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
    //
    // The `$ref` sub-attribute declares `referenceTypes: ["User"]` rather than the RFC's
    // `["User", "Group"]`. Nested groups are not implemented: a `Group` id sent as a member is
    // refused as a member that is not in the organization. Advertising `Group` would invite
    // exactly the request this server rejects, so the canonical values of `type` are narrowed the
    // same way.
    let attributes = vec![
        attribute("displayName", "string", false, true, "readWrite", "none", false),
        attribute("externalId", "string", false, false, "readWrite", "none", true),
        complex(
            "members",
            true,
            false,
            "readWrite",
            vec![
                attribute("value", "string", false, false, "immutable", "none", true),
                reference("$ref", &["User"], false, "immutable"),
                json!({
                    "name": "type",
                    "type": "string",
                    "multiValued": false,
                    "required": false,
                    "caseExact": false,
                    "canonicalValues": ["User"],
                    "mutability": "immutable",
                    "returned": "default",
                    "uniqueness": "none",
                }),
            ],
        ),
    ];

    schema_resource(ctx, GROUP_SCHEMA, "Group", "Organization group", attributes)
}

/// The `ServiceProviderConfig` resource schema (RFC 7643 section 8.7.2).
fn service_provider_config_schema(ctx: &ScimContext) -> Value {
    let supported_only = |name: &str| complex(name, false, true, "readOnly", vec![read_only_bool("supported", true)]);

    // `etag` is defined in RFC 7643 section 5 but is missing from the section 8.7.2 listing. This
    // server emits it, so it is described here: publishing a resource attribute with no schema
    // entry would be the same omission in the other direction.
    let attributes = vec![
        reference("documentationUri", &["external"], false, "readOnly"),
        supported_only("patch"),
        complex(
            "bulk",
            false,
            true,
            "readOnly",
            vec![read_only_bool("supported", true), read_only_int("maxOperations"), read_only_int("maxPayloadSize")],
        ),
        complex(
            "filter",
            false,
            true,
            "readOnly",
            vec![read_only_bool("supported", true), read_only_int("maxResults")],
        ),
        supported_only("changePassword"),
        supported_only("sort"),
        supported_only("etag"),
        complex(
            "authenticationSchemes",
            true,
            true,
            "readOnly",
            vec![
                attribute("type", "string", false, false, "readOnly", "none", false),
                attribute("name", "string", false, true, "readOnly", "none", false),
                attribute("description", "string", false, true, "readOnly", "none", false),
                reference("specUri", &["external"], false, "readOnly"),
                read_only_bool("primary", false),
            ],
        ),
    ];

    schema_resource(
        ctx,
        SERVICE_PROVIDER_CONFIG_SCHEMA,
        "Service Provider Configuration",
        "Schema for representing the service provider's configuration",
        attributes,
    )
}

/// The `ResourceType` resource schema (RFC 7643 section 8.7.2).
fn resource_type_schema(ctx: &ScimContext) -> Value {
    let attributes = vec![
        attribute("id", "string", false, false, "readOnly", "none", false),
        attribute("name", "string", false, true, "readOnly", "none", false),
        attribute("description", "string", false, false, "readOnly", "none", false),
        reference("endpoint", &["uri"], true, "readOnly"),
        reference("schema", &["uri"], true, "readOnly"),
        // `multiValued: true`, where RFC 7643 section 8.7.2's printed definition says `false`.
        // That is a known slip in the RFC text -- its own ResourceType examples in section 8.6
        // show `schemaExtensions` as an array, and so does every entry this server emits. The
        // schema has to describe the document beside it, not the typo.
        complex(
            "schemaExtensions",
            true,
            true,
            "readOnly",
            vec![reference("schema", &["uri"], true, "readOnly"), read_only_bool("required", true)],
        ),
    ];

    schema_resource(
        ctx,
        RESOURCE_TYPE_SCHEMA,
        "ResourceType",
        "Specifies the schema that describes a SCIM resource type",
        attributes,
    )
}

/// The `Schema` resource schema (RFC 7643 section 8.7.2) -- the schema of the documents this
/// endpoint itself returns.
fn schema_schema(ctx: &ScimContext) -> Value {
    // RFC 7643 section 2.3.8 allows a complex attribute exactly one level of sub-attributes, and
    // the RFC's own definition nests this block once to describe that level. It does the same
    // here, and stops there for the same reason.
    let attribute_definition = |name: &str, nested: Vec<Value>| {
        let mut fields = vec![
            attribute("name", "string", false, true, "readOnly", "none", true),
            attribute("type", "string", false, true, "readOnly", "none", false),
            read_only_bool("multiValued", true),
            attribute("description", "string", false, false, "readOnly", "none", true),
            read_only_bool("required", false),
            attribute("canonicalValues", "string", true, false, "readOnly", "none", true),
            read_only_bool("caseExact", false),
            attribute("mutability", "string", false, false, "readOnly", "none", true),
            attribute("returned", "string", false, false, "readOnly", "none", true),
            attribute("uniqueness", "string", false, false, "readOnly", "none", true),
            attribute("referenceTypes", "string", true, false, "readOnly", "none", true),
        ];
        fields.extend(nested);
        complex(name, true, true, "readOnly", fields)
    };

    let attributes = vec![
        attribute("id", "string", false, true, "readOnly", "none", false),
        attribute("name", "string", false, true, "readOnly", "none", false),
        attribute("description", "string", false, false, "readOnly", "none", false),
        attribute_definition("attributes", vec![attribute_definition("subAttributes", Vec::new())]),
    ];

    schema_resource(ctx, SCHEMA_SCHEMA, "Schema", "Specifies the schema that describes a SCIM schema", attributes)
}

/// Every schema this service provider publishes.
///
/// `Group` disappears with `ORG_GROUPS_ENABLED`, exactly as its resource type does: a schema for an
/// endpoint that answers `501` would be an advertisement for something that does not work.
fn schema_definitions(ctx: &ScimContext) -> Vec<Value> {
    let mut schemas = vec![user_schema(ctx)];
    if super::settings::groups_enabled() {
        schemas.push(group_schema(ctx));
    }
    schemas.push(service_provider_config_schema(ctx));
    schemas.push(resource_type_schema(ctx));
    schemas.push(schema_schema(ctx));
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

    // URN comparison is case-insensitive, and so is the `ResourceTypes` lookup next to this one.
    // A direct lookup has to resolve whatever the listing published, however the client spelled it.
    schema_definitions(&ctx)
        .into_iter()
        .find(|s| s["id"].as_str().is_some_and(|id| id.eq_ignore_ascii_case(schema_id)))
        .map(single_resource)
        .ok_or_else(|| ScimError::not_found(format!("Schema '{schema_id}' is not supported.")))
}

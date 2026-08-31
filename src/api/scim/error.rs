//! SCIM error responses, per RFC 7644 section 3.12.
//!
//! Vaultwarden's normal [`crate::error::Error`] responder emits the Bitwarden error envelope with
//! `Content-Type: application/json`, which SCIM clients cannot parse. Every failure path inside
//! the SCIM module therefore produces a [`ScimError`] instead, which serialises to the
//! `urn:ietf:params:scim:api:messages:2.0:Error` schema with the SCIM media type.
//!
//! Internal detail never reaches the client: helpers such as [`ScimError::internal`] log the
//! underlying cause and return a generic message.

use std::{fmt, io::Cursor};

use rocket::{
    Request,
    http::{Header, Status},
    response::{self, Responder, Response},
};
use serde_json::Value;

use super::SCIM_CONTENT_TYPE;

pub const ERROR_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:Error";

/// The challenge every SCIM `401` carries, identical whatever the cause.
pub const WWW_AUTHENTICATE: &str = "Bearer";

/// The `scimType` values defined by RFC 7644 section 3.12.
///
/// Only the ones this implementation can actually produce are listed; adding a variant that is
/// never returned would be another way of lying about what the server does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScimType {
    InvalidFilter,
    TooMany,
    Uniqueness,
    Mutability,
    InvalidSyntax,
    InvalidPath,
    NoTarget,
    InvalidValue,
}

impl ScimType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidFilter => "invalidFilter",
            Self::TooMany => "tooMany",
            Self::Uniqueness => "uniqueness",
            Self::Mutability => "mutability",
            Self::InvalidSyntax => "invalidSyntax",
            Self::InvalidPath => "invalidPath",
            Self::NoTarget => "noTarget",
            Self::InvalidValue => "invalidValue",
        }
    }
}

impl fmt::Display for ScimType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug)]
pub struct ScimError {
    pub status: Status,
    pub scim_type: Option<ScimType>,
    pub detail: String,
}

pub type ScimResult<T> = Result<T, ScimError>;

impl ScimError {
    pub fn new(status: Status, scim_type: Option<ScimType>, detail: impl Into<String>) -> Self {
        Self {
            status,
            scim_type,
            detail: detail.into(),
        }
    }

    /// 400 with a `scimType`.
    pub fn bad_request(scim_type: ScimType, detail: impl Into<String>) -> Self {
        Self::new(Status::BadRequest, Some(scim_type), detail)
    }

    pub fn invalid_syntax(detail: impl Into<String>) -> Self {
        Self::bad_request(ScimType::InvalidSyntax, detail)
    }

    pub fn invalid_filter(detail: impl Into<String>) -> Self {
        Self::bad_request(ScimType::InvalidFilter, detail)
    }

    pub fn invalid_path(detail: impl Into<String>) -> Self {
        Self::bad_request(ScimType::InvalidPath, detail)
    }

    pub fn invalid_value(detail: impl Into<String>) -> Self {
        Self::bad_request(ScimType::InvalidValue, detail)
    }

    pub fn no_target(detail: impl Into<String>) -> Self {
        Self::bad_request(ScimType::NoTarget, detail)
    }

    /// An attempt to write an attribute this server treats as read-only.
    pub fn immutable(detail: impl Into<String>) -> Self {
        Self::bad_request(ScimType::Mutability, detail)
    }

    /// The single, uniform authentication failure. Callers must never add detail that would let a
    /// client tell "no such organization" apart from "no such key" apart from "wrong secret".
    ///
    /// The response carries [`WWW_AUTHENTICATE`], added by the responder for every `401` this
    /// module produces.
    pub fn unauthorized() -> Self {
        Self::new(Status::Unauthorized, None, "Authorization failed.")
    }

    /// A plain authorization refusal: the request was understood, and the server will not do it.
    ///
    /// Deliberately carries **no** `scimType`. RFC 7644 section 3.12 defines `scimType` values for
    /// specific protocol faults, and none of them describes "an operator switched this off", "an
    /// organization policy says no", or "this server's provisioning policy does not hand that
    /// resource to SCIM at all". Labelling those `mutability` would tell a client the request was
    /// structurally wrong when it was perfectly well formed, and would conflate a policy decision
    /// about a *resource* with a schema statement about one *attribute*.
    ///
    /// The attribute-level counterpart is [`Self::immutable`], which is a genuine `mutability`
    /// fault and is a `400`.
    pub fn forbidden(detail: impl Into<String>) -> Self {
        Self::new(Status::Forbidden, None, detail)
    }

    pub fn not_found(detail: impl Into<String>) -> Self {
        Self::new(Status::NotFound, None, detail)
    }

    pub fn conflict(detail: impl Into<String>) -> Self {
        Self::new(Status::Conflict, Some(ScimType::Uniqueness), detail)
    }

    pub fn payload_too_large(detail: impl Into<String>) -> Self {
        Self::new(Status::PayloadTooLarge, None, detail)
    }

    pub fn too_many_requests() -> Self {
        Self::new(Status::TooManyRequests, None, "Too many requests, try again later.")
    }

    pub fn not_implemented(detail: impl Into<String>) -> Self {
        Self::new(Status::NotImplemented, None, detail)
    }

    /// Turn an internal failure into a generic 500.
    ///
    /// The cause is written to the server log; the client is told nothing beyond "it failed", so
    /// database and configuration details cannot leak through the SCIM surface.
    pub fn internal(context: &str, cause: &impl fmt::Debug) -> Self {
        error!(target: "scim", "{context}: {cause:?}");
        Self::new(Status::InternalServerError, None, "The request could not be completed.")
    }

    pub fn to_json(&self) -> Value {
        let mut body = serde_json::Map::new();
        body.insert("schemas".into(), json!([ERROR_SCHEMA]));
        if let Some(scim_type) = self.scim_type {
            body.insert("scimType".into(), json!(scim_type.as_str()));
        }
        body.insert("detail".into(), json!(self.detail));
        // RFC 7644 defines `status` as a string, not a number.
        body.insert("status".into(), json!(self.status.code.to_string()));
        Value::Object(body)
    }
}

impl fmt::Display for ScimError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.scim_type {
            Some(t) => write!(f, "{} {t}: {}", self.status.code, self.detail),
            None => write!(f, "{} {}", self.status.code, self.detail),
        }
    }
}

impl Responder<'_, 'static> for ScimError {
    fn respond_to(self, _: &Request<'_>) -> response::Result<'static> {
        let body = self.to_json().to_string();
        let mut builder = Response::build();
        builder.status(self.status).header(SCIM_CONTENT_TYPE.clone());

        // RFC 7235 section 3.1 requires a `WWW-Authenticate` challenge on a 401, and
        // `/ServiceProviderConfig` already advertises `oauthbearertoken` pointing at RFC 6750.
        // The challenge is a bare `Bearer`: no `realm`, no `error`, no `error_description`. Each
        // of those would vary with the reason a request failed, and that is precisely what the
        // uniform 401 exists to prevent -- a `realm` naming the organization would turn the header
        // into the tenant-existence oracle the body carefully is not.
        if self.status == Status::Unauthorized {
            builder.header(Header::new("WWW-Authenticate", WWW_AUTHENTICATE));
        }

        builder.sized_body(body.len(), Cursor::new(body)).ok()
    }
}

/// Convenience for turning a Vaultwarden [`crate::error::Error`] into a generic SCIM 500.
impl From<crate::error::Error> for ScimError {
    fn from(e: crate::error::Error) -> Self {
        Self::internal("Internal error while handling a SCIM request", &e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_body_matches_the_rfc_shape() {
        let body = ScimError::not_found("User not found").to_json();

        assert_eq!(body["schemas"], json!([ERROR_SCHEMA]));
        assert_eq!(body["detail"], json!("User not found"));
        assert_eq!(body["status"], json!("404"), "status must be a string, not a number");
        assert!(body.get("scimType").is_none(), "scimType must be omitted when there is none");
    }

    #[test]
    fn scim_type_is_rendered_when_present() {
        let body = ScimError::conflict("Already exists").to_json();

        assert_eq!(body["status"], json!("409"));
        assert_eq!(body["scimType"], json!("uniqueness"));
    }

    #[test]
    fn every_scim_type_uses_the_rfc_spelling() {
        // These strings are wire format; a typo here silently breaks client error handling.
        assert_eq!(ScimType::InvalidFilter.as_str(), "invalidFilter");
        assert_eq!(ScimType::TooMany.as_str(), "tooMany");
        assert_eq!(ScimType::Uniqueness.as_str(), "uniqueness");
        assert_eq!(ScimType::Mutability.as_str(), "mutability");
        assert_eq!(ScimType::InvalidSyntax.as_str(), "invalidSyntax");
        assert_eq!(ScimType::InvalidPath.as_str(), "invalidPath");
        assert_eq!(ScimType::NoTarget.as_str(), "noTarget");
        assert_eq!(ScimType::InvalidValue.as_str(), "invalidValue");
    }

    #[test]
    fn authentication_failures_are_indistinguishable() {
        // Every auth failure must produce a byte-identical body, so a client cannot learn whether
        // the organization, the key id or the secret was the part that was wrong.
        let a = ScimError::unauthorized().to_json().to_string();
        let b = ScimError::unauthorized().to_json().to_string();

        assert_eq!(a, b);
        assert!(!a.contains("organization"), "the 401 body must not hint at what was wrong: {a}");
    }

    #[test]
    fn an_authorization_refusal_carries_no_scim_type() {
        // RFC 7644 section 3.12's `scimType` values describe protocol faults. "An operator turned
        // this off" and "an organization policy says no" are neither, and labelling them
        // `mutability` would tell a client its perfectly well-formed request was malformed.
        let body = ScimError::forbidden("Invitations are disabled on this server.").to_json();

        assert_eq!(body["status"], json!("403"));
        assert!(body.get("scimType").is_none(), "a plain refusal must not be labelled: {body}");
    }

    #[test]
    fn refusing_a_resource_is_not_an_attribute_mutability_fault() {
        // A membership this server's provisioning policy does not hand to SCIM at all is refused
        // as a resource, not as one attribute that violates its schema. `mutability` would tell a
        // client the fix is to send a different attribute value; there is no value that works.
        let body = ScimError::forbidden("That member is managed outside SCIM.").to_json();

        assert_eq!(body["status"], json!("403"));
        assert!(body.get("scimType").is_none(), "a resource-level refusal must not be labelled: {body}");
    }

    #[test]
    fn writing_an_immutable_attribute_is_a_client_error() {
        // RFC 7644 pairs `mutability` with 400 for an attempt to change an immutable attribute.
        let body = ScimError::immutable("'userName' cannot be changed.").to_json();

        assert_eq!(body["status"], json!("400"));
        assert_eq!(body["scimType"], json!("mutability"));
    }

    #[test]
    fn internal_errors_do_not_leak_detail() {
        let cause = "connection refused to 10.1.2.3:5432";
        let err = ScimError::internal("loading members", &cause);

        assert_eq!(err.status, Status::InternalServerError);
        assert!(!err.detail.contains("10.1.2.3"));
        assert!(!err.detail.contains("connection refused"));
    }
}

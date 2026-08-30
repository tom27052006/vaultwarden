//! Request and response bodies for the SCIM endpoints.
//!
//! SCIM uses the `application/scim+json` media type. Vaultwarden's normal `Json<T>` guard and
//! `Error` responder always speak `application/json` and the Bitwarden error envelope, so SCIM
//! brings its own pair:
//!
//! * [`ScimBody`] reads the request body under a SCIM-specific size cap and yields a
//!   [`ScimError`] rather than a Rocket catcher page when the body is unusable.
//! * [`ScimResponse`] writes success bodies with the SCIM media type and, for `201 Created`, the
//!   `Location` header RFC 7644 section 3.3 requires.

use std::io::Cursor;

use rocket::{
    Data, Request,
    data::{FromData, Outcome, ToByteUnit},
    http::{ContentType, Header, Status},
    response::{self, Responder, Response},
};
use serde::de::DeserializeOwned;
use serde_json::Value;

use super::{SCIM_CONTENT_TYPE, error::ScimError};

/// Maximum size of a SCIM request body.
///
/// Deliberately much smaller than Rocket's global 20 MB JSON limit: no legitimate SCIM document
/// comes close, and the endpoints are reachable by anyone who can guess an organization id.
pub const SCIM_MAX_BODY_BYTES: usize = 1024 * 1024;

/// A parsed SCIM request body, or the error that should be returned instead.
///
/// The `FromData` implementation always succeeds so that failures are rendered by this module's
/// own error type instead of a Rocket catcher; handlers unwrap it with `?` as their first step.
pub struct ScimBody<T>(Result<T, ScimError>);

impl<T> ScimBody<T> {
    pub fn into_inner(self) -> Result<T, ScimError> {
        self.0
    }
}

/// Is this a media type we are willing to parse as SCIM?
///
/// `application/scim+json` is the correct one. `application/json` is accepted because several
/// identity providers send it, and no content type at all is accepted because some send none.
/// Parameters such as `;charset=utf-8` are ignored.
fn acceptable_content_type(content_type: Option<&ContentType>) -> bool {
    match content_type {
        None => true,
        Some(ct) => ct.top() == "application" && (ct.sub() == "scim+json" || ct.sub() == "json"),
    }
}

#[rocket::async_trait]
impl<'r, T: DeserializeOwned> FromData<'r> for ScimBody<T> {
    type Error = std::convert::Infallible;

    async fn from_data(req: &'r Request<'_>, data: Data<'r>) -> Outcome<'r, Self, Self::Error> {
        if !acceptable_content_type(req.content_type()) {
            return Outcome::Success(Self(Err(ScimError::new(
                Status::UnsupportedMediaType,
                None,
                "Expected application/scim+json or application/json.",
            ))));
        }

        // Read one byte past the limit so an over-sized body is detected rather than truncated.
        let capped = match data.open(SCIM_MAX_BODY_BYTES.bytes()).into_bytes().await {
            Ok(bytes) => bytes,
            Err(e) => {
                return Outcome::Success(Self(Err(ScimError::internal("Reading the SCIM request body", &e))));
            }
        };

        if !capped.is_complete() {
            return Outcome::Success(Self(Err(ScimError::payload_too_large(format!(
                "Request body exceeds the {SCIM_MAX_BODY_BYTES} byte limit."
            )))));
        }

        let parsed = serde_json::from_slice::<T>(&capped.value).map_err(|e| {
            // The parse error mentions only the client's own document, so it is safe to return
            // and genuinely useful when debugging an identity provider.
            ScimError::invalid_syntax(format!("Request body is not a valid SCIM document: {e}"))
        });

        Outcome::Success(Self(parsed))
    }
}

/// A SCIM success response.
pub struct ScimResponse {
    status: Status,
    body: Value,
    location: Option<String>,
}

impl ScimResponse {
    pub fn ok(body: Value) -> Self {
        Self {
            status: Status::Ok,
            body,
            location: None,
        }
    }

    /// `201 Created` with the `Location` header RFC 7644 section 3.3 requires.
    pub fn created(body: Value, location: impl Into<String>) -> Self {
        Self {
            status: Status::Created,
            body,
            location: Some(location.into()),
        }
    }

    /// `204 No Content`, used for `DELETE`.
    pub fn no_content() -> Self {
        Self {
            status: Status::NoContent,
            body: Value::Null,
            location: None,
        }
    }
}

impl Responder<'_, 'static> for ScimResponse {
    fn respond_to(self, _: &Request<'_>) -> response::Result<'static> {
        let mut builder = Response::build();
        builder.status(self.status);

        if let Some(location) = self.location {
            builder.header(Header::new("Location", location));
        }

        if self.status == Status::NoContent {
            return builder.ok();
        }

        let body = self.body.to_string();
        builder.header(SCIM_CONTENT_TYPE.clone()).sized_body(body.len(), Cursor::new(body)).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn accepted(header: &str) -> bool {
        let ct = ContentType::parse_flexible(header).expect("parsable media type");
        acceptable_content_type(Some(&ct))
    }

    #[test]
    fn accepts_the_scim_media_type() {
        assert!(accepted("application/scim+json"));
    }

    #[test]
    fn accepts_plain_json_for_interoperability() {
        assert!(accepted("application/json"));
    }

    #[test]
    fn accepts_a_missing_content_type() {
        assert!(acceptable_content_type(None));
    }

    #[test]
    fn accepts_media_type_parameters() {
        assert!(accepted("application/scim+json; charset=utf-8"));
        assert!(accepted("application/json;charset=UTF-8"));
    }

    #[test]
    fn rejects_unrelated_media_types() {
        assert!(!accepted("text/plain"));
        assert!(!accepted("application/xml"));
        assert!(!accepted("application/x-www-form-urlencoded"));
    }

    #[test]
    fn no_content_response_has_no_body() {
        let response = ScimResponse::no_content();
        assert_eq!(response.status, Status::NoContent);
        assert_eq!(response.body, Value::Null);
    }

    #[test]
    fn created_response_carries_a_location() {
        let response = ScimResponse::created(json!({"id": "x"}), "https://example.test/scim/v2/org/Users/x");
        assert_eq!(response.status, Status::Created);
        assert_eq!(response.location.as_deref(), Some("https://example.test/scim/v2/org/Users/x"));
    }
}

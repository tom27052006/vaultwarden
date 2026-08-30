//! Bearer authentication for the SCIM endpoints.
//!
//! A SCIM token looks like `scim_v1.<key-uuid>.<secret>`:
//!
//! * `scim_v1` is a version tag, so the format can change later without ambiguity;
//! * `<key-uuid>` is a **non-secret** lookup handle, which turns verification into one indexed
//!   row fetch instead of a scan over every organization's key;
//! * `<secret>` is 256 bits of CSPRNG output, stored only as a SHA-256 hash.
//!
//! Security does not depend on any property of the untrusted parts. Authorization comes from the
//! constant-time secret comparison plus the fact that the candidate row is fetched with the
//! organization from the URL already bound into the query.
//!
//! Every failure produces the *same* `401`, with no detail that would let a client distinguish
//! "no such organization" from "no such key" from "wrong secret".

use std::{net::IpAddr, sync::LazyLock};

use chrono::{TimeDelta, Utc};
use rocket::{
    Request,
    http::Status,
    request::{FromRequest, Outcome},
};

use crate::{
    auth::ClientIp,
    crypto,
    db::{
        DbConn,
        models::{OrganizationId, OrganizationScimKey, SCIM_TOKEN_PREFIX, ScimKeyId},
    },
};

/// A SHA-256 hash to compare against when no key row was found.
///
/// Doing the hash and the constant-time comparison even on a miss keeps the cost of the
/// secret-checking path the same whether or not the key id resolved.
static DUMMY_HASH: LazyLock<String> = LazyLock::new(|| crypto::sha256_hex(b"vaultwarden-scim-absent-key"));

/// How stale `last_used_at` may get before it is refreshed.
///
/// A write on every request would be pure overhead during a full directory sync; the admin panel
/// only needs "roughly when did this key last work".
const LAST_USED_REFRESH: TimeDelta = TimeDelta::minutes(5);

/// A SCIM request that carries a valid token for `org_id`.
pub struct ScimToken {
    pub org_id: OrganizationId,
    pub ip: IpAddr,
}

/// The three parts of a well-formed token.
struct ParsedToken {
    key_id: ScimKeyId,
    secret: String,
}

/// Split a bearer token into its parts.
///
/// Returns `None` for anything that is not exactly `scim_v1.<key-id>.<secret>` with both parts
/// non-empty. Callers must map `None` to the same generic 401 as a wrong secret.
fn parse_token(raw: &str) -> Option<ParsedToken> {
    let mut parts = raw.split('.');
    let prefix = parts.next()?;
    let key_id = parts.next()?;
    let secret = parts.next()?;

    // Exactly three parts: neither the key id (a UUID) nor the secret (base64url) contains a dot.
    if parts.next().is_some() {
        return None;
    }
    if prefix != SCIM_TOKEN_PREFIX || key_id.is_empty() || secret.is_empty() {
        return None;
    }

    Some(ParsedToken {
        key_id: ScimKeyId::from(key_id.to_owned()),
        secret: secret.to_owned(),
    })
}

/// Pull the bearer credential out of an `Authorization` header.
fn bearer_credential(header: &str) -> Option<&str> {
    // The scheme is case-insensitive per RFC 7235.
    let (scheme, credential) = header.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let credential = credential.trim();
    if credential.is_empty() {
        None
    } else {
        Some(credential)
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for ScimToken {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let Outcome::Success(client_ip) = ClientIp::from_request(request).await else {
            return Outcome::Error((Status::Unauthorized, ()));
        };
        let ip = client_ip.ip;

        // Rate limit first, before any parsing or database work, so this covers authentication
        // attempts, expensive list requests and writes alike.
        if super::settings::check_rate_limit(&ip).is_err() {
            return Outcome::Error((Status::TooManyRequests, ()));
        }

        // When SCIM is switched off the endpoints must not operate at all. 404 rather than 401:
        // the resource genuinely does not exist on this server.
        if !super::settings::scim_enabled() {
            return Outcome::Error((Status::NotFound, ()));
        }

        // Every SCIM route has the organization id as its first dynamic segment.
        let Some(Ok(path_org_id)) = request.param::<&str>(0) else {
            return Outcome::Error((Status::Unauthorized, ()));
        };

        let Some(credential) = request.headers().get_one("Authorization").and_then(bearer_credential) else {
            return Outcome::Error((Status::Unauthorized, ()));
        };

        let Outcome::Success(conn) = DbConn::from_request(request).await else {
            error!(target: "scim", "Could not get a database connection while authenticating a SCIM request");
            return Outcome::Error((Status::InternalServerError, ()));
        };

        let org_id: OrganizationId = path_org_id.to_owned().into();

        // A malformed token still goes through a hash and a constant-time comparison so that it
        // is not measurably cheaper to reject than a well-formed one with a wrong secret.
        let (key, secret) = match parse_token(credential) {
            Some(parsed) => {
                let key = OrganizationScimKey::find_by_uuid_and_org(&parsed.key_id, &org_id, &conn).await;
                (key, parsed.secret)
            }
            None => (None, credential.to_owned()),
        };

        let authenticated = if let Some(key) = &key {
            key.matches_secret(&secret)
        } else {
            // Not a real check: the hash and the constant-time comparison run against a fixed
            // dummy value so that rejecting an unknown key id costs the same as rejecting a wrong
            // secret. `black_box` keeps the optimiser from removing work whose result is unused.
            std::hint::black_box(crypto::ct_eq(&*DUMMY_HASH, crypto::sha256_hex(secret.as_bytes())));
            false
        };

        if !authenticated {
            // Deliberately vague, and identical for every cause.
            warn!(target: "scim", "Rejected SCIM request from {ip}");
            return Outcome::Error((Status::Unauthorized, ()));
        }

        let key = key.expect("authenticated implies a key was found");
        if key.last_used_at.is_none_or(|last| Utc::now().naive_utc() - last > LAST_USED_REFRESH) {
            key.touch_last_used(&conn).await;
        }

        Outcome::Success(ScimToken {
            org_id: key.org_uuid,
            ip,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_ID: &str = "6f0f9d1a-2b3c-4d5e-8f90-1a2b3c4d5e6f";
    const SECRET: &str = "wG7pQ2xR9tLmN4vK8sYbA1cZ3eH5jU0dF6iO2nP4qS8";

    fn token() -> String {
        format!("{SCIM_TOKEN_PREFIX}.{KEY_ID}.{SECRET}")
    }

    // -- bearer header parsing -----------------------------------------------------------------

    #[test]
    fn extracts_a_bearer_credential() {
        assert_eq!(bearer_credential("Bearer abc123"), Some("abc123"));
    }

    #[test]
    fn bearer_scheme_is_case_insensitive() {
        assert_eq!(bearer_credential("bearer abc123"), Some("abc123"));
        assert_eq!(bearer_credential("BEARER abc123"), Some("abc123"));
    }

    #[test]
    fn rejects_other_authorization_schemes() {
        assert_eq!(bearer_credential("Basic dXNlcjpwYXNz"), None);
        assert_eq!(bearer_credential("Token abc123"), None);
    }

    #[test]
    fn rejects_empty_or_malformed_authorization_headers() {
        assert_eq!(bearer_credential(""), None);
        assert_eq!(bearer_credential("Bearer"), None);
        assert_eq!(bearer_credential("Bearer "), None);
        assert_eq!(bearer_credential("Bearer    "), None);
        assert_eq!(bearer_credential("abc123"), None);
    }

    // -- token parsing -------------------------------------------------------------------------

    #[test]
    fn parses_a_well_formed_token() {
        let parsed = parse_token(&token()).expect("should parse");
        assert_eq!(*parsed.key_id, KEY_ID);
        assert_eq!(parsed.secret, SECRET);
    }

    #[test]
    fn rejects_a_wrong_or_missing_version_prefix() {
        assert!(parse_token(&format!("scim_v2.{KEY_ID}.{SECRET}")).is_none());
        assert!(parse_token(&format!("{KEY_ID}.{SECRET}")).is_none());
        assert!(parse_token(&format!("SCIM_V1.{KEY_ID}.{SECRET}")).is_none(), "prefix is case-sensitive");
    }

    #[test]
    fn rejects_the_wrong_number_of_parts() {
        assert!(parse_token(SCIM_TOKEN_PREFIX).is_none());
        assert!(parse_token(&format!("{SCIM_TOKEN_PREFIX}.{KEY_ID}")).is_none());
        assert!(parse_token(&format!("{SCIM_TOKEN_PREFIX}.{KEY_ID}.{SECRET}.extra")).is_none());
    }

    #[test]
    fn rejects_empty_components() {
        assert!(parse_token(&format!("{SCIM_TOKEN_PREFIX}..{SECRET}")).is_none());
        assert!(parse_token(&format!("{SCIM_TOKEN_PREFIX}.{KEY_ID}.")).is_none());
    }

    #[test]
    fn rejects_garbage_without_panicking() {
        for garbage in ["", ".", "..", "...", "  ", "\u{0}", "scim_v1", "\u{1F600}.\u{1F600}.\u{1F600}"] {
            // The only requirement is that it does not match and does not panic.
            let parsed = parse_token(garbage);
            assert!(parsed.is_none() || garbage.starts_with(SCIM_TOKEN_PREFIX), "unexpectedly parsed {garbage:?}");
        }
    }

    #[test]
    fn a_parsed_key_id_is_only_a_lookup_handle() {
        // The key id is attacker-controlled: parsing it must not imply anything is authorized.
        // This test documents the invariant that authorization happens later, against the hash.
        let parsed = parse_token(&format!("{SCIM_TOKEN_PREFIX}.not-a-uuid.{SECRET}")).expect("parses");
        assert_eq!(*parsed.key_id, "not-a-uuid");
    }

    // -- hashing -------------------------------------------------------------------------------

    #[test]
    fn dummy_hash_is_the_same_shape_as_a_real_one() {
        // The miss path must do the same amount of work as the hit path.
        assert_eq!(DUMMY_HASH.len(), crypto::sha256_hex(SECRET.as_bytes()).len());
        assert_ne!(*DUMMY_HASH, crypto::sha256_hex(SECRET.as_bytes()));
    }
}

//! End-to-end tests for the SCIM endpoints.
//!
//! These drive the **real request path** -- routing, the bearer-token request guard, the body
//! guard, the handlers and the SCIM catchers -- through a Rocket local client backed by a
//! throwaway SQLite database. Nothing here touches the developer's configured database: the pool
//! is built from an explicit URL under `target/`.
//!
//! Settings the SCIM module reads go through `super::settings`, whose test implementation is
//! driven by [`TestServer`]. Tests that change a setting take an exclusive lock so they cannot
//! disturb tests running in parallel.

use std::{collections::HashSet, sync::atomic::Ordering};

use rocket::{
    http::{ContentType, Header, Status},
    local::asynchronous::{Client, LocalResponse},
};
use serde_json::Value;
use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

use crate::{
    api::WS_USERS,
    db::{
        DbConn, DbPool,
        models::{
            Group, GroupId, Invitation, Membership, MembershipId, MembershipStatus, MembershipType, OrgPolicy,
            OrgPolicyType, Organization, OrganizationId, OrganizationScimKey, User,
        },
    },
};

use super::settings::test_overrides::{
    GROUPS_ENABLED, RATE_LIMIT_EXHAUSTED, SCIM_ENABLED, UNAUTH_RATE_LIMIT_EXHAUSTED,
};

/// Serialises the tests that change server settings against the ones that assume the defaults.
static SETTINGS_LOCK: RwLock<()> = RwLock::const_new(());

#[cfg_attr(test, expect(dead_code, reason = "the guards are held for their lifetime, never read"))]
enum SettingsGuard {
    Shared(RwLockReadGuard<'static, ()>),
    Exclusive(RwLockWriteGuard<'static, ()>),
}

// ---------------------------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------------------------

struct TestServer {
    client: Client,
    pool: DbPool,
    db_path: String,
    guard: SettingsGuard,
}

impl TestServer {
    /// A server with the default settings: SCIM on, groups on, rate limiter not exhausted.
    async fn new() -> Self {
        Self::build(SettingsGuard::Shared(SETTINGS_LOCK.read().await)).await
    }

    /// A server whose settings this test is free to change; other tests are locked out meanwhile.
    async fn with_exclusive_settings() -> Self {
        Self::build(SettingsGuard::Exclusive(SETTINGS_LOCK.write().await)).await
    }

    async fn build(guard: SettingsGuard) -> Self {
        std::fs::create_dir_all("target/scim-tests").expect("test database directory");
        let db_path = format!("target/scim-tests/{}.sqlite3", crate::util::get_uuid());
        let pool = DbPool::from_url_for_tests(&format!("sqlite://{db_path}")).expect("test database");

        let rocket = rocket::build()
            .mount("/scim/v2", super::routes())
            .register("/scim/v2", super::catchers())
            .manage(pool.clone())
            .manage(std::sync::Arc::clone(&WS_USERS));

        let client = Client::untracked(rocket).await.expect("test client");

        Self {
            client,
            pool,
            db_path,
            guard,
        }
    }

    async fn conn(&self) -> DbConn {
        self.pool.get().await.expect("database connection")
    }

    fn set_scim_enabled(&self, enabled: bool) {
        assert!(matches!(self.guard, SettingsGuard::Exclusive(_)), "changing settings needs the exclusive lock");
        SCIM_ENABLED.store(enabled, Ordering::Relaxed);
    }

    fn set_groups_enabled(&self, enabled: bool) {
        assert!(matches!(self.guard, SettingsGuard::Exclusive(_)), "changing settings needs the exclusive lock");
        GROUPS_ENABLED.store(enabled, Ordering::Relaxed);
    }

    fn set_rate_limit_exhausted(&self, exhausted: bool) {
        assert!(matches!(self.guard, SettingsGuard::Exclusive(_)), "changing settings needs the exclusive lock");
        RATE_LIMIT_EXHAUSTED.store(exhausted, Ordering::Relaxed);
    }

    fn set_unauthenticated_rate_limit_exhausted(&self, exhausted: bool) {
        assert!(matches!(self.guard, SettingsGuard::Exclusive(_)), "changing settings needs the exclusive lock");
        UNAUTH_RATE_LIMIT_EXHAUSTED.store(exhausted, Ordering::Relaxed);
    }

    // -- fixtures ------------------------------------------------------------------------------

    /// An organization with a SCIM token, returned as `(organization, plaintext token)`.
    async fn org(&self, name: &str) -> (Organization, String) {
        let conn = self.conn().await;
        let org = Organization::new(name.to_owned(), &format!("{name}@example.test"), None, None);
        org.save(&conn).await.expect("save organization");

        let token = OrganizationScimKey::rotate_for_org(&org.uuid, &conn).await.expect("scim token");
        (org, token)
    }

    /// An account plus a membership of `org`.
    ///
    /// `registered` controls whether the account has a password, which is what decides whether a
    /// new membership starts out `Invited` or `Accepted`.
    async fn member(
        &self,
        org: &Organization,
        email: &str,
        atype: MembershipType,
        registered: bool,
    ) -> (User, Membership) {
        let conn = self.conn().await;

        let mut user = User::new(email, None);
        if registered {
            user.password_hash = vec![1, 2, 3, 4];
        }
        user.save(&conn).await.expect("save user");

        let mut membership = Membership::new(user.uuid.clone(), org.uuid.clone(), None);
        membership.atype = atype as i32;
        membership.status = MembershipStatus::Confirmed as i32;
        membership.save(&conn).await.expect("save membership");

        (user, membership)
    }

    async fn group(&self, org: &Organization, name: &str, external_id: Option<&str>) -> Group {
        let conn = self.conn().await;
        let mut group = Group::new(org.uuid.clone(), name.to_owned(), false, external_id.map(str::to_owned));
        group.save(&conn).await.expect("save group");
        group
    }

    async fn reload_membership(&self, id: &MembershipId, org: &OrganizationId) -> Option<Membership> {
        Membership::find_by_uuid_and_org(id, org, &self.conn().await).await
    }

    // -- requests ------------------------------------------------------------------------------

    fn auth(token: &str) -> Header<'static> {
        Header::new("Authorization", format!("Bearer {token}"))
    }

    async fn get(&self, path: &str, token: &str) -> ScimReply {
        ScimReply::of(self.client.get(path.to_owned()).header(Self::auth(token)).dispatch().await).await
    }

    async fn get_unauthenticated(&self, path: &str) -> ScimReply {
        ScimReply::of(self.client.get(path.to_owned()).dispatch().await).await
    }

    async fn post(&self, path: &str, token: &str, body: Value) -> ScimReply {
        ScimReply::of(
            self.client
                .post(path.to_owned())
                .header(Self::auth(token))
                .header(scim_json())
                .body(body.to_string())
                .dispatch()
                .await,
        )
        .await
    }

    async fn post_raw(&self, path: &str, token: &str, content_type: ContentType, body: String) -> ScimReply {
        ScimReply::of(
            self.client
                .post(path.to_owned())
                .header(Self::auth(token))
                .header(content_type)
                .body(body)
                .dispatch()
                .await,
        )
        .await
    }

    async fn put(&self, path: &str, token: &str, body: Value) -> ScimReply {
        ScimReply::of(
            self.client
                .put(path.to_owned())
                .header(Self::auth(token))
                .header(scim_json())
                .body(body.to_string())
                .dispatch()
                .await,
        )
        .await
    }

    async fn patch(&self, path: &str, token: &str, body: Value) -> ScimReply {
        ScimReply::of(
            self.client
                .patch(path.to_owned())
                .header(Self::auth(token))
                .header(scim_json())
                .body(body.to_string())
                .dispatch()
                .await,
        )
        .await
    }

    async fn delete(&self, path: &str, token: &str) -> ScimReply {
        ScimReply::of(self.client.delete(path.to_owned()).header(Self::auth(token)).dispatch().await).await
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        // Always put the shared settings back, so an exclusive test cannot leak state.
        if matches!(self.guard, SettingsGuard::Exclusive(_)) {
            SCIM_ENABLED.store(true, Ordering::Relaxed);
            GROUPS_ENABLED.store(true, Ordering::Relaxed);
            RATE_LIMIT_EXHAUSTED.store(false, Ordering::Relaxed);
            UNAUTH_RATE_LIMIT_EXHAUSTED.store(false, Ordering::Relaxed);
        }

        // Best effort: on Windows the pool may still hold the file open.
        drop(std::fs::remove_file(&self.db_path));
        drop(std::fs::remove_file(format!("{}-wal", self.db_path)));
        drop(std::fs::remove_file(format!("{}-shm", self.db_path)));
    }
}

fn scim_json() -> ContentType {
    ContentType::new("application", "scim+json")
}

/// A response, already read into memory so assertions can look at both status and body.
struct ScimReply {
    status: Status,
    content_type: Option<ContentType>,
    location: Option<String>,
    content_location: Option<String>,
    body: String,
}

impl ScimReply {
    async fn of(response: LocalResponse<'_>) -> Self {
        let status = response.status();
        let content_type = response.content_type();
        let location = response.headers().get_one("Location").map(str::to_owned);
        let content_location = response.headers().get_one("Content-Location").map(str::to_owned);
        let body = response.into_string().await.unwrap_or_default();

        Self {
            status,
            content_type,
            location,
            content_location,
            body,
        }
    }

    /// A single-resource response identifies the resource it carries, and says the same thing in
    /// the header as in the body.
    fn assert_content_location_matches_meta(&self) {
        let body = self.json();
        let meta_location =
            body["meta"]["location"].as_str().unwrap_or_else(|| panic!("no meta.location in {}", self.body));

        assert_eq!(self.content_location.as_deref(), Some(meta_location), "Content-Location must match meta.location");
    }

    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or_else(|e| panic!("body is not JSON ({e}): {}", self.body))
    }

    /// Assert the status and that the body is a well-formed SCIM error for it.
    fn assert_error(&self, status: Status, scim_type: Option<&str>) {
        assert_eq!(self.status, status, "unexpected status; body was {}", self.body);

        let body = self.json();
        assert_eq!(
            body["schemas"],
            json!(["urn:ietf:params:scim:api:messages:2.0:Error"]),
            "error body must use the SCIM error schema: {}",
            self.body
        );
        assert_eq!(body["status"], json!(status.code.to_string()), "status is a string in SCIM errors");

        match scim_type {
            Some(expected) => assert_eq!(body["scimType"], json!(expected), "body was {}", self.body),
            None => assert!(body.get("scimType").is_none(), "unexpected scimType in {}", self.body),
        }
    }

    fn assert_scim_content_type(&self) {
        assert_eq!(
            self.content_type,
            Some(ContentType::new("application", "scim+json")),
            "SCIM responses must use application/scim+json"
        );
    }
}

fn users_url(org: &Organization) -> String {
    format!("/scim/v2/{}/Users", org.uuid)
}

fn groups_url(org: &Organization) -> String {
    format!("/scim/v2/{}/Groups", org.uuid)
}

// =============================================================================================
// Authentication
// =============================================================================================

#[rocket::async_test]
async fn valid_token_is_accepted() {
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;

    let reply = server.get(&users_url(&org), &token).await;

    assert_eq!(reply.status, Status::Ok, "{}", reply.body);
    reply.assert_scim_content_type();
}

#[rocket::async_test]
async fn a_missing_authorization_header_is_rejected() {
    let server = TestServer::new().await;
    let (org, _) = server.org("acme").await;

    server.get_unauthenticated(&users_url(&org)).await.assert_error(Status::Unauthorized, None);
}

#[rocket::async_test]
async fn malformed_tokens_are_rejected() {
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let secret = token.rsplit('.').next().unwrap();
    let key_id = token.split('.').nth(1).unwrap();

    for bad in [
        String::new(),
        "not-a-token".to_owned(),
        "scim_v2.a.b".to_owned(),
        format!("scim_v1.{key_id}"),
        format!("scim_v1.{key_id}.{secret}.extra"),
        format!("scim_v1..{secret}"),
        format!("scim_v1.{key_id}."),
        format!("{key_id}.{secret}"),
    ] {
        server.get(&users_url(&org), &bad).await.assert_error(Status::Unauthorized, None);
    }
}

#[rocket::async_test]
async fn a_wrong_secret_is_rejected() {
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;

    let key_id = token.split('.').nth(1).unwrap();
    let forged = format!("scim_v1.{key_id}.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

    server.get(&users_url(&org), &forged).await.assert_error(Status::Unauthorized, None);
}

#[rocket::async_test]
async fn a_token_for_another_organization_is_rejected() {
    let server = TestServer::new().await;
    let (org_a, _token_a) = server.org("acme").await;
    let (_org_b, token_b) = server.org("globex").await;

    // Organization B's token must not work against organization A's endpoint.
    server.get(&users_url(&org_a), &token_b).await.assert_error(Status::Unauthorized, None);
}

#[rocket::async_test]
async fn a_revoked_token_stops_working_immediately() {
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;

    assert_eq!(server.get(&users_url(&org), &token).await.status, Status::Ok);

    OrganizationScimKey::delete_all_by_organization(&org.uuid, &server.conn().await).await.expect("revoke");

    server.get(&users_url(&org), &token).await.assert_error(Status::Unauthorized, None);
}

#[rocket::async_test]
async fn rotating_invalidates_the_previous_token_immediately() {
    let server = TestServer::new().await;
    let (org, old_token) = server.org("acme").await;

    let new_token = OrganizationScimKey::rotate_for_org(&org.uuid, &server.conn().await).await.expect("rotate");

    assert_ne!(old_token, new_token);
    server.get(&users_url(&org), &old_token).await.assert_error(Status::Unauthorized, None);
    assert_eq!(server.get(&users_url(&org), &new_token).await.status, Status::Ok);
}

#[rocket::async_test]
async fn every_authentication_failure_looks_identical() {
    // A client must not be able to tell "no such organization" from "no such key" from
    // "wrong secret" -- that is what stops SCIM being an organization-existence oracle.
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let key_id = token.split('.').nth(1).unwrap();
    let unknown_org = crate::util::get_uuid();

    let replies = vec![
        // Wrong secret, real key, real organization.
        server.get(&users_url(&org), &format!("scim_v1.{key_id}.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")).await,
        // Unknown key id, real organization.
        server.get(&users_url(&org), &format!("scim_v1.{}.whatever", crate::util::get_uuid())).await,
        // A real token, but an organization that does not exist.
        server.get(&format!("/scim/v2/{unknown_org}/Users"), &token).await,
        // Garbage.
        server.get(&users_url(&org), "nonsense").await,
    ];

    for reply in &replies {
        reply.assert_error(Status::Unauthorized, None);
    }

    let first = &replies[0].body;
    for reply in &replies[1..] {
        assert_eq!(&reply.body, first, "authentication failures must be byte-identical");
    }
}

#[rocket::async_test]
async fn scim_endpoints_do_not_exist_while_scim_is_disabled() {
    let server = TestServer::with_exclusive_settings().await;
    let (org, token) = server.org("acme").await;

    assert_eq!(server.get(&users_url(&org), &token).await.status, Status::Ok);

    server.set_scim_enabled(false);

    // 404, not 401: with SCIM off the endpoint genuinely is not there.
    server.get(&users_url(&org), &token).await.assert_error(Status::NotFound, None);
    server.get(&groups_url(&org), &token).await.assert_error(Status::NotFound, None);
    server
        .get(&format!("/scim/v2/{}/ServiceProviderConfig", org.uuid), &token)
        .await
        .assert_error(Status::NotFound, None);
}

#[rocket::async_test]
async fn rate_limited_requests_get_a_scim_429() {
    let server = TestServer::with_exclusive_settings().await;
    let (org, token) = server.org("acme").await;

    server.set_rate_limit_exhausted(true);

    server.get(&users_url(&org), &token).await.assert_error(Status::TooManyRequests, None);
}

// =============================================================================================
// Users: read
// =============================================================================================

#[rocket::async_test]
async fn listing_returns_only_this_organizations_members() {
    let server = TestServer::new().await;
    let (org_a, token_a) = server.org("acme").await;
    let (org_b, _) = server.org("globex").await;

    server.member(&org_a, "a1@example.test", MembershipType::User, true).await;
    server.member(&org_a, "a2@example.test", MembershipType::User, true).await;
    server.member(&org_b, "b1@example.test", MembershipType::User, true).await;

    let reply = server.get(&users_url(&org_a), &token_a).await;
    let body = reply.json();

    assert_eq!(body["schemas"], json!(["urn:ietf:params:scim:api:messages:2.0:ListResponse"]));
    assert_eq!(body["totalResults"], json!(2));
    assert_eq!(body["startIndex"], json!(1));
    assert_eq!(body["itemsPerPage"], json!(2));

    let names: Vec<String> =
        body["Resources"].as_array().unwrap().iter().map(|r| r["userName"].as_str().unwrap().to_owned()).collect();
    assert!(names.contains(&"a1@example.test".to_owned()));
    assert!(!names.iter().any(|n| n.starts_with("b1")), "another organization's member leaked: {names:?}");
}

#[rocket::async_test]
async fn getting_one_user_returns_the_core_schema() {
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let (_, membership) = server.member(&org, "alice@example.test", MembershipType::User, true).await;

    let reply = server.get(&format!("{}/{}", users_url(&org), membership.uuid), &token).await;
    reply.assert_scim_content_type();

    let body = reply.json();
    assert_eq!(body["schemas"], json!(["urn:ietf:params:scim:schemas:core:2.0:User"]));
    assert_eq!(body["id"], json!(membership.uuid.to_string()));
    assert_eq!(body["userName"], json!("alice@example.test"));
    assert_eq!(body["active"], json!(true));
    assert_eq!(body["meta"]["resourceType"], json!("User"));
    // The membership role is an internal authorization attribute and is never published.
    assert!(body.get("type").is_none());
}

#[rocket::async_test]
async fn filtering_by_user_name_is_case_insensitive() {
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    server.member(&org, "alice@example.test", MembershipType::User, true).await;
    server.member(&org, "bob@example.test", MembershipType::User, true).await;

    // This is exactly the request Entra ID makes before deciding whether to create a user.
    let reply =
        server.get(&format!("{}?filter=userName%20eq%20%22ALICE@example.test%22", users_url(&org)), &token).await;

    let body = reply.json();
    assert_eq!(body["totalResults"], json!(1), "{}", reply.body);
    assert_eq!(body["Resources"][0]["userName"], json!("alice@example.test"));
}

#[rocket::async_test]
async fn filtering_by_external_id_and_id_works() {
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let (_, mut membership) = server.member(&org, "alice@example.test", MembershipType::User, true).await;

    membership.set_external_id(Some("ext-42".to_owned()));
    membership.save(&server.conn().await).await.expect("set external id");

    let by_external = server.get(&format!("{}?filter=externalId%20eq%20%22ext-42%22", users_url(&org)), &token).await;
    assert_eq!(by_external.json()["totalResults"], json!(1), "{}", by_external.body);

    let by_id = server.get(&format!("{}?filter=id%20eq%20%22{}%22", users_url(&org), membership.uuid), &token).await;
    assert_eq!(by_id.json()["totalResults"], json!(1), "{}", by_id.body);
}

#[rocket::async_test]
async fn the_filter_shapes_microsoft_documents_all_work() {
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let (_, mut membership) = server.member(&org, "alice@example.test", MembershipType::User, true).await;

    membership.set_external_id(Some("jyoung".to_owned()));
    membership.save(&server.conn().await).await.expect("set external id");

    // Microsoft's documentation shows an unquoted filter value...
    let unquoted = server.get(&format!("{}?filter=externalId%20eq%20jyoung", users_url(&org)), &token).await;
    assert_eq!(unquoted.json()["totalResults"], json!(1), "{}", unquoted.body);

    // ...and requires this form for any attribute used to match users.
    let value_path = server
        .get(
            &format!(
                "{}?filter=emails%5Btype%20eq%20%22work%22%5D.value%20eq%20%22alice@example.test%22",
                users_url(&org)
            ),
            &token,
        )
        .await;
    assert_eq!(value_path.json()["totalResults"], json!(1), "{}", value_path.body);

    // Narrowing must not change the answer: a non-matching sub-filter still excludes the user.
    let wrong_type = server
        .get(
            &format!(
                "{}?filter=emails%5Btype%20eq%20%22home%22%5D.value%20eq%20%22alice@example.test%22",
                users_url(&org)
            ),
            &token,
        )
        .await;
    assert_eq!(wrong_type.json()["totalResults"], json!(0), "{}", wrong_type.body);
}

#[rocket::async_test]
async fn narrowing_does_not_change_which_resources_match() {
    // The listing narrows by an indexed equality and then re-applies the whole filter. A
    // conjunction whose other half fails must still return nothing.
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let (_, mut revoked) = server.member(&org, "alice@example.test", MembershipType::User, true).await;

    revoked.revoke();
    revoked.save(&server.conn().await).await.expect("revoke");

    let matching =
        server.get(&format!("{}?filter=userName%20eq%20%22alice@example.test%22", users_url(&org)), &token).await;
    assert_eq!(matching.json()["totalResults"], json!(1), "the user is returned whether active or not");

    let narrowed = server
        .get(
            &format!("{}?filter=userName%20eq%20%22alice@example.test%22%20and%20active%20eq%20true", users_url(&org)),
            &token,
        )
        .await;
    assert_eq!(narrowed.json()["totalResults"], json!(0), "{}", narrowed.body);
}

#[rocket::async_test]
async fn a_filter_that_matches_nothing_returns_an_empty_list() {
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    server.member(&org, "alice@example.test", MembershipType::User, true).await;

    let reply =
        server.get(&format!("{}?filter=userName%20eq%20%22nobody@example.test%22", users_url(&org)), &token).await;

    let body = reply.json();
    assert_eq!(body["totalResults"], json!(0));
    assert_eq!(body["Resources"], json!([]));
}

#[rocket::async_test]
async fn compound_filters_are_evaluated() {
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let (_, mut revoked) = server.member(&org, "revoked@example.test", MembershipType::User, true).await;
    server.member(&org, "active@example.test", MembershipType::User, true).await;

    revoked.revoke();
    revoked.save(&server.conn().await).await.expect("revoke");

    let reply = server.get(&format!("{}?filter=active%20eq%20true", users_url(&org)), &token).await;
    let body = reply.json();

    assert_eq!(body["totalResults"], json!(1), "{}", reply.body);
    assert_eq!(body["Resources"][0]["userName"], json!("active@example.test"));
}

#[rocket::async_test]
async fn an_invalid_filter_is_a_scim_error() {
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;

    server
        .get(&format!("{}?filter=userName%20eq", users_url(&org)), &token)
        .await
        .assert_error(Status::BadRequest, Some("invalidFilter"));

    // An unknown attribute is refused rather than silently matching nothing.
    server
        .get(&format!("{}?filter=nickName%20eq%20%22x%22", users_url(&org)), &token)
        .await
        .assert_error(Status::BadRequest, Some("invalidFilter"));
}

#[rocket::async_test]
async fn pagination_walks_the_collection() {
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    for i in 0..5 {
        server.member(&org, &format!("user{i}@example.test"), MembershipType::User, true).await;
    }

    let first = server.get(&format!("{}?startIndex=1&count=2", users_url(&org)), &token).await.json();
    assert_eq!(first["totalResults"], json!(5));
    assert_eq!(first["startIndex"], json!(1));
    assert_eq!(first["itemsPerPage"], json!(2));

    let last = server.get(&format!("{}?startIndex=5&count=2", users_url(&org)), &token).await.json();
    assert_eq!(last["itemsPerPage"], json!(1), "the final page is short, not an error");

    let past_end = server.get(&format!("{}?startIndex=99&count=2", users_url(&org)), &token).await.json();
    assert_eq!(past_end["itemsPerPage"], json!(0));
    assert_eq!(past_end["totalResults"], json!(5), "totalResults is still the real total");
}

#[rocket::async_test]
async fn count_zero_returns_a_total_without_resources() {
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    server.member(&org, "alice@example.test", MembershipType::User, true).await;

    let body = server.get(&format!("{}?count=0", users_url(&org)), &token).await.json();

    assert_eq!(body["totalResults"], json!(1));
    assert_eq!(body["Resources"], json!([]));
}

#[rocket::async_test]
async fn page_size_is_capped() {
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    server.member(&org, "alice@example.test", MembershipType::User, true).await;

    // A client cannot ask for an unbounded response.
    let body = server.get(&format!("{}?count=100000", users_url(&org)), &token).await.json();
    assert_eq!(body["totalResults"], json!(1));

    server
        .get(&format!("{}?count=abc", users_url(&org)), &token)
        .await
        .assert_error(Status::BadRequest, Some("invalidValue"));
}

#[rocket::async_test]
async fn requested_attributes_are_honoured() {
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    server.member(&org, "alice@example.test", MembershipType::User, true).await;

    let body = server.get(&format!("{}?attributes=userName", users_url(&org)), &token).await.json();
    let resource = &body["Resources"][0];

    assert_eq!(resource["userName"], json!("alice@example.test"));
    assert!(resource.get("emails").is_none());
    assert!(resource.get("id").is_some(), "id is never excluded");
}

// =============================================================================================
// Users: create
// =============================================================================================

#[rocket::async_test]
async fn creating_a_user_provisions_an_invited_unprivileged_member() {
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;

    let reply = server
        .post(
            &users_url(&org),
            &token,
            json!({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "userName": "new@example.test",
                "externalId": "ext-1",
                "displayName": "New Person",
                "emails": [{"value": "new@example.test", "primary": true, "type": "work"}],
                "active": true,
            }),
        )
        .await;

    assert_eq!(reply.status, Status::Created, "{}", reply.body);
    reply.assert_scim_content_type();

    let body = reply.json();
    assert_eq!(body["userName"], json!("new@example.test"));
    assert_eq!(body["externalId"], json!("ext-1"));
    assert_eq!(body["active"], json!(true));

    let member_id = MembershipId::from(body["id"].as_str().unwrap().to_owned());
    let membership = server.reload_membership(&member_id, &org.uuid).await.expect("membership exists");

    assert_eq!(membership.atype, MembershipType::User as i32, "provisioned members are never privileged");
    assert!(!membership.access_all, "provisioned members never get access to every collection");
    assert_eq!(
        membership.status,
        MembershipStatus::Invited as i32,
        "SCIM invites; it never confirms a membership on its own"
    );
    assert_eq!(membership.external_id.as_deref(), Some("ext-1"));

    // A brand-new account may take the supplied display name, since nobody else has a claim on it.
    let user = User::find_by_uuid(&membership.user_uuid, &server.conn().await).await.expect("account");
    assert_eq!(user.name, "New Person");
}

#[rocket::async_test]
async fn creating_a_user_reuses_an_existing_account() {
    let server = TestServer::new().await;
    let (org_a, _) = server.org("acme").await;
    let (org_b, token_b) = server.org("globex").await;

    // The person already has an account, through a different organization.
    let (existing_user, _) = server.member(&org_a, "shared@example.test", MembershipType::User, true).await;

    let reply = server
        .post(&users_url(&org_b), &token_b, json!({"userName": "SHARED@example.test", "displayName": "Renamed"}))
        .await;
    assert_eq!(reply.status, Status::Created, "{}", reply.body);

    let member_id = MembershipId::from(reply.json()["id"].as_str().unwrap().to_owned());
    let membership = server.reload_membership(&member_id, &org_b.uuid).await.expect("membership");

    assert_eq!(membership.user_uuid, existing_user.uuid, "the existing account is reused, not duplicated");
    assert_eq!(
        membership.status,
        MembershipStatus::Accepted as i32,
        "a registered account is auto-accepted when mail is disabled"
    );

    // The account keeps its own name: one organization's directory does not rename a person
    // everywhere else.
    let user = User::find_by_uuid(&existing_user.uuid, &server.conn().await).await.expect("account");
    assert_eq!(user.name, "shared@example.test");
}

#[rocket::async_test]
async fn creating_a_duplicate_user_conflicts() {
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    server.member(&org, "alice@example.test", MembershipType::User, true).await;

    server
        .post(&users_url(&org), &token, json!({"userName": "alice@example.test"}))
        .await
        .assert_error(Status::Conflict, Some("uniqueness"));

    // ...including when only the capitalisation differs.
    server
        .post(&users_url(&org), &token, json!({"userName": "Alice@Example.TEST"}))
        .await
        .assert_error(Status::Conflict, Some("uniqueness"));
}

#[rocket::async_test]
async fn a_duplicate_external_id_conflicts() {
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;

    let first = server.post(&users_url(&org), &token, json!({"userName": "a@example.test", "externalId": "dup"})).await;
    assert_eq!(first.status, Status::Created, "{}", first.body);

    server
        .post(&users_url(&org), &token, json!({"userName": "b@example.test", "externalId": "dup"}))
        .await
        .assert_error(Status::Conflict, Some("uniqueness"));

    // The failed request must not have created anything.
    let listed = server.get(&users_url(&org), &token).await.json();
    assert_eq!(listed["totalResults"], json!(1));
}

#[rocket::async_test]
async fn creating_a_user_without_an_identifier_is_rejected() {
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;

    server.post(&users_url(&org), &token, json!({})).await.assert_error(Status::BadRequest, Some("invalidValue"));

    server
        .post(&users_url(&org), &token, json!({"userName": "not-an-email"}))
        .await
        .assert_error(Status::BadRequest, Some("invalidValue"));
}

#[rocket::async_test]
async fn creating_a_user_inactive_provisions_then_revokes() {
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;

    let reply = server.post(&users_url(&org), &token, json!({"userName": "out@example.test", "active": false})).await;
    assert_eq!(reply.status, Status::Created, "{}", reply.body);

    let body = reply.json();
    assert_eq!(body["active"], json!(false));

    let member_id = MembershipId::from(body["id"].as_str().unwrap().to_owned());
    let membership = server.reload_membership(&member_id, &org.uuid).await.expect("membership");
    assert!(membership.status < MembershipStatus::Invited as i32, "the membership is revoked");
}

// =============================================================================================
// Users: update and deprovision
// =============================================================================================

#[rocket::async_test]
async fn patching_active_false_revokes_without_losing_anything() {
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let (user, membership) = server.member(&org, "alice@example.test", MembershipType::User, true).await;

    let reply = server
        .patch(
            &format!("{}/{}", users_url(&org), membership.uuid),
            &token,
            json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations": [{"op": "Replace", "path": "active", "value": false}],
            }),
        )
        .await;

    assert_eq!(reply.status, Status::Ok, "{}", reply.body);
    assert_eq!(reply.json()["active"], json!(false));

    let stored = server.reload_membership(&membership.uuid, &org.uuid).await.expect("membership preserved");
    assert!(stored.status < MembershipStatus::Invited as i32, "access is removed");
    assert_eq!(
        stored.get_unrevoked_status(),
        MembershipStatus::Confirmed as i32,
        "the pre-revocation status is preserved so a restore is exact"
    );
    assert!(User::find_by_uuid(&user.uuid, &server.conn().await).await.is_some(), "the account is untouched");
}

#[rocket::async_test]
async fn patching_active_true_restores_the_previous_status() {
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let (_, mut membership) = server.member(&org, "alice@example.test", MembershipType::User, true).await;

    membership.revoke();
    membership.save(&server.conn().await).await.expect("revoke");

    let reply = server
        .patch(
            &format!("{}/{}", users_url(&org), membership.uuid),
            &token,
            json!({"Operations": [{"op": "Replace", "path": "active", "value": true}]}),
        )
        .await;

    assert_eq!(reply.status, Status::Ok, "{}", reply.body);
    assert_eq!(reply.json()["active"], json!(true));

    let stored = server.reload_membership(&membership.uuid, &org.uuid).await.expect("membership");
    assert_eq!(stored.status, MembershipStatus::Confirmed as i32, "restored to exactly what it was");
}

#[rocket::async_test]
async fn a_reactivation_an_org_policy_refuses_is_reported_as_a_refusal() {
    // The organization enforces two-step login; the member has no second factor, so restoring
    // them is refused. The identity provider must get an actionable 403, not an opaque 500, and
    // the membership must stay exactly as it was.
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let (_, mut membership) = server.member(&org, "alice@example.test", MembershipType::User, true).await;

    let conn = server.conn().await;
    OrgPolicy::new(org.uuid.clone(), OrgPolicyType::TwoFactorAuthentication, true, "null".to_owned())
        .save(&conn)
        .await
        .expect("save policy");
    drop(conn);

    membership.revoke();
    membership.save(&server.conn().await).await.expect("revoke");

    let reply = server
        .patch(
            &format!("{}/{}", users_url(&org), membership.uuid),
            &token,
            json!({"Operations": [{"op": "Replace", "path": "active", "value": true}]}),
        )
        .await;

    // A policy refusal is a plain 403: the request was well formed and the server declined it.
    // Labelling it `mutability` would tell the client its document was structurally wrong.
    reply.assert_error(Status::Forbidden, None);
    assert!(reply.json()["detail"].as_str().unwrap().contains("2FA"), "the policy reason should reach the client");

    let stored = server.reload_membership(&membership.uuid, &org.uuid).await.expect("membership");
    assert!(stored.status < MembershipStatus::Invited as i32, "a refused restore leaves the member revoked");
}

#[rocket::async_test]
async fn entra_string_booleans_are_accepted_over_the_wire() {
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let (_, membership) = server.member(&org, "alice@example.test", MembershipType::User, true).await;

    let reply = server
        .patch(
            &format!("{}/{}", users_url(&org), membership.uuid),
            &token,
            json!({"Operations": [{"op": "Replace", "path": "active", "value": "False"}]}),
        )
        .await;

    assert_eq!(reply.status, Status::Ok, "{}", reply.body);
    assert_eq!(reply.json()["active"], json!(false));
}

#[rocket::async_test]
async fn patching_external_id_updates_it() {
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let (_, membership) = server.member(&org, "alice@example.test", MembershipType::User, true).await;

    let reply = server
        .patch(
            &format!("{}/{}", users_url(&org), membership.uuid),
            &token,
            json!({"Operations": [{"op": "Add", "path": "externalId", "value": "ext-9"}]}),
        )
        .await;

    assert_eq!(reply.status, Status::Ok, "{}", reply.body);
    assert_eq!(reply.json()["externalId"], json!("ext-9"));

    let stored = server.reload_membership(&membership.uuid, &org.uuid).await.expect("membership");
    assert_eq!(stored.external_id.as_deref(), Some("ext-9"));
}

#[rocket::async_test]
async fn renaming_a_user_is_refused() {
    // Changing the account email would be an account-takeover primitive and a cross-tenant
    // mutation, so SCIM refuses it outright.
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let (user, membership) = server.member(&org, "alice@example.test", MembershipType::User, true).await;

    server
        .patch(
            &format!("{}/{}", users_url(&org), membership.uuid),
            &token,
            json!({"Operations": [{"op": "Replace", "path": "userName", "value": "attacker@evil.test"}]}),
        )
        .await
        .assert_error(Status::BadRequest, Some("mutability"));

    server
        .put(&format!("{}/{}", users_url(&org), membership.uuid), &token, json!({"userName": "attacker@evil.test"}))
        .await
        .assert_error(Status::BadRequest, Some("mutability"));

    let stored = User::find_by_uuid(&user.uuid, &server.conn().await).await.expect("account");
    assert_eq!(stored.email, "alice@example.test", "the account email is unchanged");
}

#[rocket::async_test]
async fn resending_the_same_user_name_is_a_no_op() {
    // Identity providers send the full resource on every update; a matching userName must not
    // fail the request.
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let (_, membership) = server.member(&org, "alice@example.test", MembershipType::User, true).await;

    let reply = server
        .put(
            &format!("{}/{}", users_url(&org), membership.uuid),
            &token,
            json!({"userName": "ALICE@example.test", "active": true, "displayName": "Whatever"}),
        )
        .await;

    assert_eq!(reply.status, Status::Ok, "{}", reply.body);
}

#[rocket::async_test]
async fn put_leaves_omitted_attributes_alone() {
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let (_, mut membership) = server.member(&org, "alice@example.test", MembershipType::User, true).await;

    membership.set_external_id(Some("keep-me".to_owned()));
    membership.save(&server.conn().await).await.expect("set external id");

    // A sparse payload must not clear attributes it does not mention.
    let reply =
        server.put(&format!("{}/{}", users_url(&org), membership.uuid), &token, json!({"displayName": "X"})).await;
    assert_eq!(reply.status, Status::Ok, "{}", reply.body);

    let stored = server.reload_membership(&membership.uuid, &org.uuid).await.expect("membership");
    assert_eq!(stored.external_id.as_deref(), Some("keep-me"));
    assert_eq!(stored.status, MembershipStatus::Confirmed as i32, "active was not sent, so it did not change");
}

#[rocket::async_test]
async fn an_unsupported_patch_path_is_refused() {
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let (_, membership) = server.member(&org, "alice@example.test", MembershipType::User, true).await;

    server
        .patch(
            &format!("{}/{}", users_url(&org), membership.uuid),
            &token,
            json!({"Operations": [{"op": "Replace", "path": "somethingMadeUp", "value": "x"}]}),
        )
        .await
        .assert_error(Status::BadRequest, Some("invalidPath"));
}

#[rocket::async_test]
async fn a_patch_with_one_bad_operation_changes_nothing() {
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let (_, membership) = server.member(&org, "alice@example.test", MembershipType::User, true).await;

    // The first operation on its own would succeed; the second is invalid, so neither applies.
    server
        .patch(
            &format!("{}/{}", users_url(&org), membership.uuid),
            &token,
            json!({
                "Operations": [
                    {"op": "Replace", "path": "active", "value": false},
                    {"op": "Replace", "path": "nonsense", "value": "x"},
                ],
            }),
        )
        .await
        .assert_error(Status::BadRequest, Some("invalidPath"));

    let stored = server.reload_membership(&membership.uuid, &org.uuid).await.expect("membership");
    assert_eq!(stored.status, MembershipStatus::Confirmed as i32, "the valid operation must not have been applied");
}

#[rocket::async_test]
async fn deleting_a_user_removes_the_membership_but_keeps_the_account() {
    let server = TestServer::new().await;
    let (org_a, token_a) = server.org("acme").await;
    let (org_b, _) = server.org("globex").await;

    let (user, membership_a) = server.member(&org_a, "alice@example.test", MembershipType::User, true).await;

    let conn = server.conn().await;
    let mut membership_b = Membership::new(user.uuid.clone(), org_b.uuid.clone(), None);
    membership_b.status = MembershipStatus::Confirmed as i32;
    membership_b.save(&conn).await.expect("second membership");
    drop(conn);

    let reply = server.delete(&format!("{}/{}", users_url(&org_a), membership_a.uuid), &token_a).await;
    assert_eq!(reply.status, Status::NoContent, "{}", reply.body);

    assert!(server.reload_membership(&membership_a.uuid, &org_a.uuid).await.is_none(), "membership removed");
    assert!(User::find_by_uuid(&user.uuid, &server.conn().await).await.is_some(), "account preserved");
    assert!(
        server.reload_membership(&membership_b.uuid, &org_b.uuid).await.is_some(),
        "the other organization's membership is untouched"
    );

    // RFC 7644 section 3.6: a deleted resource must be gone.
    server
        .get(&format!("{}/{}", users_url(&org_a), membership_a.uuid), &token_a)
        .await
        .assert_error(Status::NotFound, None);
}

// =============================================================================================
// Privileged memberships
// =============================================================================================

#[rocket::async_test]
async fn privileged_memberships_are_visible_but_read_only() {
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let (_, owner) = server.member(&org, "owner@example.test", MembershipType::Owner, true).await;

    // Visible: otherwise the identity provider would try to create a duplicate.
    let listed = server.get(&users_url(&org), &token).await.json();
    assert_eq!(listed["totalResults"], json!(1));
    assert_eq!(server.get(&format!("{}/{}", users_url(&org), owner.uuid), &token).await.status, Status::Ok);

    // ...but every mutation is refused.
    let path = format!("{}/{}", users_url(&org), owner.uuid);
    server
        .patch(&path, &token, json!({"Operations": [{"op": "Replace", "path": "active", "value": false}]}))
        .await
        .assert_error(Status::Forbidden, Some("mutability"));
    server.put(&path, &token, json!({"active": false})).await.assert_error(Status::Forbidden, Some("mutability"));
    server.delete(&path, &token).await.assert_error(Status::Forbidden, Some("mutability"));

    let stored = server.reload_membership(&owner.uuid, &org.uuid).await.expect("owner still there");
    assert_eq!(stored.atype, MembershipType::Owner as i32);
    assert_eq!(stored.status, MembershipStatus::Confirmed as i32);
}

#[rocket::async_test]
async fn admins_and_managers_are_equally_read_only() {
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;

    for (email, role) in
        [("admin@example.test", MembershipType::Admin), ("manager@example.test", MembershipType::Manager)]
    {
        let (_, membership) = server.member(&org, email, role, true).await;
        server
            .delete(&format!("{}/{}", users_url(&org), membership.uuid), &token)
            .await
            .assert_error(Status::Forbidden, Some("mutability"));
    }
}

#[rocket::async_test]
async fn the_last_owner_cannot_be_removed_or_disabled_through_scim() {
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let (_, owner) = server.member(&org, "owner@example.test", MembershipType::Owner, true).await;

    let path = format!("{}/{}", users_url(&org), owner.uuid);
    server.delete(&path, &token).await.assert_error(Status::Forbidden, Some("mutability"));
    server
        .patch(&path, &token, json!({"Operations": [{"op": "Replace", "path": "active", "value": false}]}))
        .await
        .assert_error(Status::Forbidden, Some("mutability"));

    assert_eq!(
        Membership::count_confirmed_by_org_and_type(&org.uuid, MembershipType::Owner, &server.conn().await).await,
        1
    );
}

#[rocket::async_test]
async fn a_revoked_owner_cannot_be_reactivated_through_scim() {
    // Otherwise a stale or compromised token could restore privileged access an administrator
    // had deliberately taken away.
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let (_, mut owner) = server.member(&org, "owner@example.test", MembershipType::Owner, true).await;

    owner.revoke();
    owner.save(&server.conn().await).await.expect("revoke");

    server
        .patch(
            &format!("{}/{}", users_url(&org), owner.uuid),
            &token,
            json!({"Operations": [{"op": "Replace", "path": "active", "value": true}]}),
        )
        .await
        .assert_error(Status::Forbidden, Some("mutability"));

    let stored = server.reload_membership(&owner.uuid, &org.uuid).await.expect("membership");
    assert!(stored.status < MembershipStatus::Invited as i32, "still revoked");
}

#[rocket::async_test]
async fn a_request_body_cannot_ask_for_a_privileged_role() {
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;

    let reply = server
        .post(
            &users_url(&org),
            &token,
            json!({
                "userName": "escalate@example.test",
                "type": 0,
                "atype": 0,
                "role": "Owner",
                "accessAll": true,
                "permissions": {"manageUsers": true, "manageScim": true},
                "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {"department": "Owner"},
            }),
        )
        .await;

    assert_eq!(reply.status, Status::Created, "{}", reply.body);

    let member_id = MembershipId::from(reply.json()["id"].as_str().unwrap().to_owned());
    let membership = server.reload_membership(&member_id, &org.uuid).await.expect("membership");

    assert_eq!(membership.atype, MembershipType::User as i32, "role fields in the body are not honoured");
    assert!(!membership.access_all);
}

// =============================================================================================
// Cross-tenant isolation
// =============================================================================================

#[rocket::async_test]
async fn a_member_of_another_organization_is_not_found() {
    let server = TestServer::new().await;
    let (org_a, token_a) = server.org("acme").await;
    let (org_b, _) = server.org("globex").await;
    let (_, victim) = server.member(&org_b, "victim@example.test", MembershipType::User, true).await;

    // Reading it, updating it and deleting it all look exactly like "no such resource".
    let path = format!("{}/{}", users_url(&org_a), victim.uuid);
    server.get(&path, &token_a).await.assert_error(Status::NotFound, None);
    server.put(&path, &token_a, json!({"active": false})).await.assert_error(Status::NotFound, None);
    server
        .patch(&path, &token_a, json!({"Operations": [{"op": "Replace", "path": "active", "value": false}]}))
        .await
        .assert_error(Status::NotFound, None);
    server.delete(&path, &token_a).await.assert_error(Status::NotFound, None);

    let stored = server.reload_membership(&victim.uuid, &org_b.uuid).await.expect("untouched");
    assert_eq!(stored.status, MembershipStatus::Confirmed as i32);
}

#[rocket::async_test]
async fn a_group_of_another_organization_is_not_found() {
    let server = TestServer::new().await;
    let (org_a, token_a) = server.org("acme").await;
    let (org_b, _) = server.org("globex").await;
    let victim = server.group(&org_b, "Secret Group", Some("g-secret")).await;

    let path = format!("{}/{}", groups_url(&org_a), victim.uuid);
    server.get(&path, &token_a).await.assert_error(Status::NotFound, None);
    server.put(&path, &token_a, json!({"displayName": "Hijacked"})).await.assert_error(Status::NotFound, None);
    server.delete(&path, &token_a).await.assert_error(Status::NotFound, None);

    let stored = Group::find_by_uuid_and_org(&victim.uuid, &org_b.uuid, &server.conn().await).await.expect("group");
    assert_eq!(stored.name, "Secret Group");
}

#[rocket::async_test]
async fn a_foreign_membership_cannot_be_injected_into_a_group() {
    let server = TestServer::new().await;
    let (org_a, token_a) = server.org("acme").await;
    let (org_b, _) = server.org("globex").await;

    let (_, foreign) = server.member(&org_b, "foreign@example.test", MembershipType::User, true).await;
    let group = server.group(&org_a, "Engineering", None).await;

    // On create...
    server
        .post(&groups_url(&org_a), &token_a, json!({"displayName": "New", "members": [{"value": foreign.uuid}]}))
        .await
        .assert_error(Status::BadRequest, Some("invalidValue"));

    // ...on PUT...
    server
        .put(
            &format!("{}/{}", groups_url(&org_a), group.uuid),
            &token_a,
            json!({"displayName": "Engineering", "members": [{"value": foreign.uuid}]}),
        )
        .await
        .assert_error(Status::BadRequest, Some("invalidValue"));

    // ...and on PATCH.
    server
        .patch(
            &format!("{}/{}", groups_url(&org_a), group.uuid),
            &token_a,
            json!({"Operations": [{"op": "Add", "path": "members", "value": [{"value": foreign.uuid}]}]}),
        )
        .await
        .assert_error(Status::BadRequest, Some("invalidValue"));

    let body = server.get(&format!("{}/{}", groups_url(&org_a), group.uuid), &token_a).await.json();
    assert_eq!(body["members"], json!([]), "no foreign member was written");
}

#[rocket::async_test]
async fn a_partly_foreign_member_list_writes_nothing_at_all() {
    let server = TestServer::new().await;
    let (org_a, token_a) = server.org("acme").await;
    let (org_b, _) = server.org("globex").await;

    let (_, local) = server.member(&org_a, "local@example.test", MembershipType::User, true).await;
    let (_, foreign) = server.member(&org_b, "foreign@example.test", MembershipType::User, true).await;

    server
        .post(
            &groups_url(&org_a),
            &token_a,
            json!({"displayName": "Mixed", "members": [{"value": local.uuid}, {"value": foreign.uuid}]}),
        )
        .await
        .assert_error(Status::BadRequest, Some("invalidValue"));

    // The valid half must not have been created either: validation happens before any write.
    let listed = server.get(&groups_url(&org_a), &token_a).await.json();
    assert_eq!(listed["totalResults"], json!(0), "no group was created");
}

#[rocket::async_test]
async fn external_ids_do_not_resolve_across_organizations() {
    let server = TestServer::new().await;
    let (org_a, token_a) = server.org("acme").await;
    let (org_b, _) = server.org("globex").await;

    let (_, mut theirs) = server.member(&org_b, "theirs@example.test", MembershipType::User, true).await;
    theirs.set_external_id(Some("shared-ext".to_owned()));
    theirs.save(&server.conn().await).await.expect("set external id");

    let body =
        server.get(&format!("{}?filter=externalId%20eq%20%22shared-ext%22", users_url(&org_a)), &token_a).await.json();
    assert_eq!(body["totalResults"], json!(0), "another organization's externalId must not resolve");

    // And the same externalId is free to use in this organization.
    let reply = server
        .post(&users_url(&org_a), &token_a, json!({"userName": "mine@example.test", "externalId": "shared-ext"}))
        .await;
    assert_eq!(reply.status, Status::Created, "{}", reply.body);
}

// =============================================================================================
// Groups
// =============================================================================================

#[rocket::async_test]
async fn creating_a_group_with_members() {
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let (_, member) = server.member(&org, "alice@example.test", MembershipType::User, true).await;

    let reply = server
        .post(
            &groups_url(&org),
            &token,
            json!({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
                "displayName": "Engineering",
                "externalId": "g-eng",
                "members": [{"value": member.uuid}],
            }),
        )
        .await;

    assert_eq!(reply.status, Status::Created, "{}", reply.body);
    reply.assert_scim_content_type();

    let body = reply.json();
    assert_eq!(body["displayName"], json!("Engineering"));
    assert_eq!(body["externalId"], json!("g-eng"));
    assert_eq!(body["members"][0]["value"], json!(member.uuid.to_string()));
    assert_eq!(body["meta"]["resourceType"], json!("Group"));
    assert!(body["meta"]["created"].is_string());

    let group_id = GroupId::from(body["id"].as_str().unwrap().to_owned());
    let stored = Group::find_by_uuid_and_org(&group_id, &org.uuid, &server.conn().await).await.expect("group");
    assert!(!stored.access_all, "SCIM never grants a group access to every collection");
}

#[rocket::async_test]
async fn groups_can_be_listed_filtered_and_fetched() {
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    server.group(&org, "Engineering", Some("g-eng")).await;
    let sales = server.group(&org, "Sales", Some("g-sales")).await;

    let listed = server.get(&groups_url(&org), &token).await.json();
    assert_eq!(listed["totalResults"], json!(2));

    // This is the lookup Entra ID performs before creating a group.
    let filtered =
        server.get(&format!("{}?filter=displayName%20eq%20%22Sales%22", groups_url(&org)), &token).await.json();
    assert_eq!(filtered["totalResults"], json!(1));
    assert_eq!(filtered["Resources"][0]["id"], json!(sales.uuid.to_string()));

    let by_external =
        server.get(&format!("{}?filter=externalId%20eq%20%22g-eng%22", groups_url(&org)), &token).await.json();
    assert_eq!(by_external["totalResults"], json!(1));

    let fetched = server.get(&format!("{}/{}", groups_url(&org), sales.uuid), &token).await;
    assert_eq!(fetched.status, Status::Ok);
    assert_eq!(fetched.json()["displayName"], json!("Sales"));
}

#[rocket::async_test]
async fn excluding_members_skips_them() {
    // Entra ID asks for groups this way, so the server can skip loading the membership entirely.
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let (_, member) = server.member(&org, "alice@example.test", MembershipType::User, true).await;
    let group = server.group(&org, "Engineering", None).await;

    server
        .patch(
            &format!("{}/{}", groups_url(&org), group.uuid),
            &token,
            json!({"Operations": [{"op": "Add", "path": "members", "value": [{"value": member.uuid}]}]}),
        )
        .await;

    let body = server
        .get(
            &format!("{}?filter=displayName%20eq%20%22Engineering%22&excludedAttributes=members", groups_url(&org)),
            &token,
        )
        .await
        .json();

    assert_eq!(body["totalResults"], json!(1));
    assert!(body["Resources"][0].get("members").is_none(), "members must be absent, not empty");
}

#[rocket::async_test]
async fn renaming_a_group_and_updating_its_external_id() {
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let group = server.group(&org, "Engineering", Some("g-eng")).await;

    let reply = server
        .patch(
            &format!("{}/{}", groups_url(&org), group.uuid),
            &token,
            json!({
                "Operations": [
                    {"op": "Replace", "path": "displayName", "value": "Platform"},
                    {"op": "Replace", "path": "externalId", "value": "g-platform"},
                ],
            }),
        )
        .await;

    assert_eq!(reply.status, Status::Ok, "{}", reply.body);

    let body = reply.json();
    assert_eq!(body["displayName"], json!("Platform"));
    assert_eq!(body["externalId"], json!("g-platform"));
}

#[rocket::async_test]
async fn group_membership_can_be_added_removed_and_replaced() {
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let (_, a) = server.member(&org, "a@example.test", MembershipType::User, true).await;
    let (_, b) = server.member(&org, "b@example.test", MembershipType::User, true).await;
    let (_, c) = server.member(&org, "c@example.test", MembershipType::User, true).await;

    let group = server.group(&org, "Engineering", None).await;
    let path = format!("{}/{}", groups_url(&org), group.uuid);

    let member_ids = |body: &Value| -> Vec<String> {
        body["members"].as_array().unwrap().iter().map(|m| m["value"].as_str().unwrap().to_owned()).collect()
    };

    // Add, the way Entra ID sends it.
    let added = server
        .patch(
            &path,
            &token,
            json!({"Operations": [{"op": "Add", "path": "members", "value": [{"value": a.uuid}, {"value": b.uuid}]}]}),
        )
        .await;
    assert_eq!(added.status, Status::Ok, "{}", added.body);
    let ids = member_ids(&added.json());
    assert_eq!(ids.len(), 2);
    assert!(ids.contains(&a.uuid.to_string()) && ids.contains(&b.uuid.to_string()));

    // Remove by body value.
    let removed = server
        .patch(
            &path,
            &token,
            json!({"Operations": [{"op": "Remove", "path": "members", "value": [{"value": a.uuid}]}]}),
        )
        .await;
    assert_eq!(member_ids(&removed.json()), vec![b.uuid.to_string()]);

    // Remove by value filter, the way older Azure AD connectors send it.
    let removed_by_filter = server
        .patch(
            &path,
            &token,
            json!({"Operations": [{"op": "Remove", "path": format!("members[value eq \"{}\"]", b.uuid)}]}),
        )
        .await;
    assert_eq!(removed_by_filter.status, Status::Ok, "{}", removed_by_filter.body);
    assert!(member_ids(&removed_by_filter.json()).is_empty());

    // Replace sets the membership exactly.
    let replaced = server
        .patch(
            &path,
            &token,
            json!({"Operations": [{"op": "Replace", "path": "members", "value": [{"value": c.uuid}]}]}),
        )
        .await;
    assert_eq!(member_ids(&replaced.json()), vec![c.uuid.to_string()]);
}

#[rocket::async_test]
async fn put_without_members_leaves_the_membership_alone() {
    // A strict reading of RFC 7644 would empty the group here. Vaultwarden treats an omitted
    // multi-valued attribute as "unchanged" so a sparse client payload cannot mass-deprovision.
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let (_, member) = server.member(&org, "alice@example.test", MembershipType::User, true).await;
    let group = server.group(&org, "Engineering", None).await;
    let path = format!("{}/{}", groups_url(&org), group.uuid);

    server
        .patch(
            &path,
            &token,
            json!({"Operations": [{"op": "Add", "path": "members", "value": [{"value": member.uuid}]}]}),
        )
        .await;

    let reply = server.put(&path, &token, json!({"displayName": "Engineering"})).await;
    assert_eq!(reply.status, Status::Ok, "{}", reply.body);
    assert_eq!(reply.json()["members"].as_array().unwrap().len(), 1, "membership survived a sparse PUT");

    // ...whereas an explicit empty array does clear it.
    let cleared = server.put(&path, &token, json!({"displayName": "Engineering", "members": []})).await;
    assert_eq!(cleared.json()["members"], json!([]));
}

#[rocket::async_test]
async fn deleting_a_group_keeps_its_members_in_the_organization() {
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let (_, member) = server.member(&org, "alice@example.test", MembershipType::User, true).await;
    let group = server.group(&org, "Engineering", None).await;
    let path = format!("{}/{}", groups_url(&org), group.uuid);

    server
        .patch(
            &path,
            &token,
            json!({"Operations": [{"op": "Add", "path": "members", "value": [{"value": member.uuid}]}]}),
        )
        .await;

    assert_eq!(server.delete(&path, &token).await.status, Status::NoContent);

    server.get(&path, &token).await.assert_error(Status::NotFound, None);
    assert!(
        server.reload_membership(&member.uuid, &org.uuid).await.is_some(),
        "deleting a group must not deprovision its members"
    );
}

#[rocket::async_test]
async fn duplicate_group_names_and_external_ids_conflict() {
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    server.group(&org, "Engineering", Some("g-eng")).await;

    server
        .post(&groups_url(&org), &token, json!({"displayName": "Engineering"}))
        .await
        .assert_error(Status::Conflict, Some("uniqueness"));

    server
        .post(&groups_url(&org), &token, json!({"displayName": "Other", "externalId": "g-eng"}))
        .await
        .assert_error(Status::Conflict, Some("uniqueness"));
}

#[rocket::async_test]
async fn a_group_needs_a_display_name() {
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;

    server
        .post(&groups_url(&org), &token, json!({"externalId": "g-1"}))
        .await
        .assert_error(Status::BadRequest, Some("invalidValue"));
}

#[rocket::async_test]
async fn group_endpoints_report_not_implemented_when_groups_are_disabled() {
    let server = TestServer::with_exclusive_settings().await;
    let (org, token) = server.org("acme").await;

    server.set_groups_enabled(false);

    server.get(&groups_url(&org), &token).await.assert_error(Status::NotImplemented, None);
    server
        .post(&groups_url(&org), &token, json!({"displayName": "Engineering"}))
        .await
        .assert_error(Status::NotImplemented, None);

    // ...and discovery stops advertising the resource type at all.
    let types = server.get(&format!("/scim/v2/{}/ResourceTypes", org.uuid), &token).await.json();
    let ids: Vec<String> =
        types["Resources"].as_array().unwrap().iter().map(|t| t["id"].as_str().unwrap().to_owned()).collect();
    assert_eq!(ids, vec!["User".to_owned()], "an unusable resource type must not be advertised");

    // Users keep working.
    assert_eq!(server.get(&users_url(&org), &token).await.status, Status::Ok);
}

// =============================================================================================
// Protocol
// =============================================================================================

#[rocket::async_test]
async fn discovery_reports_only_what_is_supported() {
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;

    let config = server.get(&format!("/scim/v2/{}/ServiceProviderConfig", org.uuid), &token).await;
    config.assert_scim_content_type();

    let body = config.json();
    assert_eq!(body["schemas"], json!(["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"]));
    assert_eq!(body["patch"]["supported"], json!(true));
    assert_eq!(body["filter"]["supported"], json!(true));
    assert_eq!(body["bulk"]["supported"], json!(false));
    assert_eq!(body["sort"]["supported"], json!(false));
    assert_eq!(body["etag"]["supported"], json!(false));
    assert_eq!(body["changePassword"]["supported"], json!(false));
    assert_eq!(body["authenticationSchemes"][0]["type"], json!("oauthbearertoken"));

    let schemas = server.get(&format!("/scim/v2/{}/Schemas", org.uuid), &token).await.json();
    assert_eq!(schemas["totalResults"], json!(2));

    let user_schema =
        server.get(&format!("/scim/v2/{}/Schemas/urn:ietf:params:scim:schemas:core:2.0:User", org.uuid), &token).await;
    assert_eq!(user_schema.status, Status::Ok, "{}", user_schema.body);
    assert_eq!(user_schema.json()["name"], json!("User"));

    server
        .get(&format!("/scim/v2/{}/Schemas/urn:made:up", org.uuid), &token)
        .await
        .assert_error(Status::NotFound, None);
}

#[rocket::async_test]
async fn discovery_requires_a_token() {
    let server = TestServer::new().await;
    let (org, _) = server.org("acme").await;

    server
        .get_unauthenticated(&format!("/scim/v2/{}/ServiceProviderConfig", org.uuid))
        .await
        .assert_error(Status::Unauthorized, None);
}

#[rocket::async_test]
async fn invalid_json_is_a_scim_syntax_error() {
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;

    server
        .post_raw(&users_url(&org), &token, scim_json(), "{not json".to_owned())
        .await
        .assert_error(Status::BadRequest, Some("invalidSyntax"));
}

#[rocket::async_test]
async fn plain_json_is_accepted_but_other_media_types_are_not() {
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;

    // Several identity providers send application/json rather than application/scim+json.
    let accepted = server
        .post_raw(&users_url(&org), &token, ContentType::JSON, json!({"userName": "json@example.test"}).to_string())
        .await;
    assert_eq!(accepted.status, Status::Created, "{}", accepted.body);

    let refused = server.post_raw(&users_url(&org), &token, ContentType::XML, "<user/>".to_owned()).await;
    refused.assert_error(Status::UnsupportedMediaType, None);
}

#[rocket::async_test]
async fn an_oversized_body_is_rejected() {
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;

    let padding = "x".repeat(super::json::SCIM_MAX_BODY_BYTES + 1024);
    let body = json!({"userName": "big@example.test", "displayName": padding}).to_string();

    server.post_raw(&users_url(&org), &token, scim_json(), body).await.assert_error(Status::PayloadTooLarge, None);
}

#[rocket::async_test]
async fn an_unknown_path_under_the_scim_mount_returns_a_scim_404() {
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;

    // Even a route that does not exist has to answer in a shape the client can parse.
    server.get(&format!("/scim/v2/{}/Nonsense", org.uuid), &token).await.assert_error(Status::NotFound, None);
}

#[rocket::async_test]
async fn a_patch_document_with_no_operations_is_rejected() {
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let (_, membership) = server.member(&org, "alice@example.test", MembershipType::User, true).await;

    server
        .patch(&format!("{}/{}", users_url(&org), membership.uuid), &token, json!({"Operations": []}))
        .await
        .assert_error(Status::BadRequest, Some("invalidValue"));

    server
        .patch(
            &format!("{}/{}", users_url(&org), membership.uuid),
            &token,
            json!({"Operations": [{"op": "upsert", "path": "active", "value": true}]}),
        )
        .await
        .assert_error(Status::BadRequest, Some("invalidSyntax"));
}

#[rocket::async_test]
async fn resource_ids_do_not_reveal_other_tenants() {
    // Probing an id that exists in another organization must be indistinguishable from probing
    // one that exists nowhere.
    let server = TestServer::new().await;
    let (org_a, token_a) = server.org("acme").await;
    let (org_b, _) = server.org("globex").await;
    let (_, elsewhere) = server.member(&org_b, "elsewhere@example.test", MembershipType::User, true).await;

    let real_elsewhere = server.get(&format!("{}/{}", users_url(&org_a), elsewhere.uuid), &token_a).await;
    let pure_fiction = server.get(&format!("{}/{}", users_url(&org_a), crate::util::get_uuid()), &token_a).await;

    assert_eq!(real_elsewhere.status, Status::NotFound);
    assert_eq!(pure_fiction.status, Status::NotFound);
    assert_eq!(
        real_elsewhere.json()["status"],
        pure_fiction.json()["status"],
        "the two 404s must be indistinguishable"
    );
}

// =============================================================================================
// Hardening regressions
//
// Each block below pins down a specific defect found in review, grouped by the behaviour it
// protects rather than by endpoint, because several of them span both resource types.
// =============================================================================================

// -- duplicate member ids ----------------------------------------------------------------------

#[rocket::async_test]
async fn duplicate_member_ids_are_collapsed_everywhere() {
    // A client repeating an id is harmless input. Left alone it would reach the database as the
    // same `(group, member)` primary key twice and fail an otherwise reasonable request.
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let (_, a) = server.member(&org, "a@example.test", MembershipType::User, true).await;
    let (_, b) = server.member(&org, "b@example.test", MembershipType::User, true).await;

    let member_count = |body: &Value| body["members"].as_array().unwrap().len();

    // POST with the same member listed three times.
    let created = server
        .post(
            &groups_url(&org),
            &token,
            json!({
                "displayName": "Dupes",
                "members": [{"value": a.uuid}, {"value": a.uuid}, {"value": a.uuid}],
            }),
        )
        .await;
    assert_eq!(created.status, Status::Created, "{}", created.body);
    assert_eq!(member_count(&created.json()), 1, "duplicates collapse to one member");

    let group_id = created.json()["id"].as_str().unwrap().to_owned();
    let path = format!("{}/{}", groups_url(&org), group_id);

    // PUT with duplicates.
    let put = server
        .put(&path, &token, json!({"displayName": "Dupes", "members": [{"value": b.uuid}, {"value": b.uuid}]}))
        .await;
    assert_eq!(put.status, Status::Ok, "{}", put.body);
    assert_eq!(member_count(&put.json()), 1);

    // PATCH add with duplicates.
    let added = server
        .patch(
            &path,
            &token,
            json!({"Operations": [{"op": "Add", "path": "members", "value": [{"value": a.uuid}, {"value": a.uuid}]}]}),
        )
        .await;
    assert_eq!(added.status, Status::Ok, "{}", added.body);
    assert_eq!(member_count(&added.json()), 2);

    // PATCH replace with duplicates.
    let replaced = server
        .patch(
            &path,
            &token,
            json!({
                "Operations": [
                    {"op": "Replace", "path": "members", "value": [{"value": a.uuid}, {"value": a.uuid}]},
                ],
            }),
        )
        .await;
    assert_eq!(replaced.status, Status::Ok, "{}", replaced.body);
    assert_eq!(member_count(&replaced.json()), 1);

    // The same id repeated across several operations in one document.
    let across_ops = server
        .patch(
            &path,
            &token,
            json!({
                "Operations": [
                    {"op": "Add", "path": "members", "value": [{"value": b.uuid}]},
                    {"op": "Add", "path": "members", "value": [{"value": b.uuid}]},
                    {"op": "Add", "path": "members", "value": [{"value": b.uuid}]},
                ],
            }),
        )
        .await;
    assert_eq!(across_ops.status, Status::Ok, "{}", across_ops.body);
    assert_eq!(member_count(&across_ops.json()), 2);
}

// -- atomicity ---------------------------------------------------------------------------------

#[rocket::async_test]
async fn a_failed_member_write_rolls_the_new_group_back() {
    // Driven at the model layer, because the endpoint validates member ids before writing and so
    // cannot reach this state. The point is that the transaction is what protects the invariant,
    // not just the validation in front of it.
    let server = TestServer::new().await;
    let (org, _) = server.org("acme").await;
    let conn = server.conn().await;

    let mut group = Group::new(org.uuid.clone(), "Doomed".to_owned(), false, None);
    let group_id = group.uuid.clone();

    // A membership id that does not exist violates the foreign key on `groups_users`.
    let bogus = MembershipId::from(crate::util::get_uuid());
    let result = group.save_with_members(true, true, Some(vec![bogus]), &conn).await;

    assert!(result.is_err(), "the member insert must fail");
    assert!(
        Group::find_by_uuid_and_org(&group_id, &org.uuid, &conn).await.is_none(),
        "a create that could not persist its members must not leave an empty group behind"
    );
}

#[rocket::async_test]
async fn a_failed_member_write_leaves_group_metadata_untouched() {
    let server = TestServer::new().await;
    let (org, _) = server.org("acme").await;
    let conn = server.conn().await;

    let mut group = Group::new(org.uuid.clone(), "Original".to_owned(), false, Some("ext-1".to_owned()));
    group.save_with_members(true, true, Some(Vec::new()), &conn).await.expect("create");
    let group_id = group.uuid.clone();
    let before = Group::find_by_uuid_and_org(&group_id, &org.uuid, &conn).await.expect("stored");

    // Rename and swap the membership in one call, with a member that cannot be written.
    group.name = "Renamed".to_owned();
    let bogus = MembershipId::from(crate::util::get_uuid());
    let result = group.save_with_members(false, true, Some(vec![bogus]), &conn).await;

    assert!(result.is_err());
    let after = Group::find_by_uuid_and_org(&group_id, &org.uuid, &conn).await.expect("still there");
    assert_eq!(after.name, before.name, "the rename must have rolled back with the member write");
    assert_eq!(after.revision_date, before.revision_date, "and so must the revision timestamp");
}

// -- membership deltas and lastModified ---------------------------------------------------------

#[rocket::async_test]
async fn membership_changes_report_only_what_moved() {
    // Updating {A, B} to {A, C} must report C joining and B leaving, and say nothing about A.
    // Exactly those members get an `OrganizationUserUpdatedGroups` event.
    let server = TestServer::new().await;
    let (org, _) = server.org("acme").await;
    let (_, a) = server.member(&org, "a@example.test", MembershipType::User, true).await;
    let (_, b) = server.member(&org, "b@example.test", MembershipType::User, true).await;
    let (_, c) = server.member(&org, "c@example.test", MembershipType::User, true).await;
    let conn = server.conn().await;

    let mut group = Group::new(org.uuid.clone(), "Eng".to_owned(), false, None);
    let created =
        group.save_with_members(true, true, Some(vec![a.uuid.clone(), b.uuid.clone()]), &conn).await.expect("create");
    assert_eq!(created.added.len(), 2);
    assert!(created.removed.is_empty());

    let swapped =
        group.save_with_members(false, false, Some(vec![a.uuid.clone(), c.uuid.clone()]), &conn).await.expect("swap");
    assert_eq!(swapped.added, vec![c.uuid.clone()], "only the joiner");
    assert_eq!(swapped.removed, vec![b.uuid.clone()], "only the leaver");
    assert!(swapped.changed);

    // Sending the same membership again changes nothing at all.
    let repeat =
        group.save_with_members(false, false, Some(vec![a.uuid.clone(), c.uuid.clone()]), &conn).await.expect("repeat");
    assert!(repeat.added.is_empty() && repeat.removed.is_empty(), "a no-op reports no movement");
    assert!(!repeat.changed, "and writes nothing");

    // Clearing reports everyone leaving.
    let cleared = group.save_with_members(false, false, Some(Vec::new()), &conn).await.expect("clear");
    assert_eq!(cleared.removed.len(), 2);
    assert!(cleared.added.is_empty());
}

#[rocket::async_test]
async fn last_modified_tracks_every_change_to_the_scim_resource() {
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let (_, member) = server.member(&org, "a@example.test", MembershipType::User, true).await;
    let group = server.group(&org, "Eng", None).await;
    let path = format!("{}/{}", groups_url(&org), group.uuid);

    let last_modified = |body: &Value| body["meta"]["lastModified"].as_str().unwrap().to_owned();

    let initial = last_modified(&server.get(&path, &token).await.json());

    // A membership-only change still changes the resource, so the timestamp has to move.
    let after_members = server
        .patch(
            &path,
            &token,
            json!({"Operations": [{"op": "Add", "path": "members", "value": [{"value": member.uuid}]}]}),
        )
        .await;
    let after_members = last_modified(&after_members.json());
    assert_ne!(after_members, initial, "adding a member changes the resource");

    // A metadata-only change moves it too.
    let after_rename = server
        .patch(&path, &token, json!({"Operations": [{"op": "Replace", "path": "displayName", "value": "Platform"}]}))
        .await;
    let after_rename = last_modified(&after_rename.json());
    assert_ne!(after_rename, after_members);

    // A request that changes nothing must not.
    let noop = server
        .patch(&path, &token, json!({"Operations": [{"op": "Replace", "path": "displayName", "value": "Platform"}]}))
        .await;
    assert_eq!(last_modified(&noop.json()), after_rename, "a no-op must not touch lastModified");
}

#[rocket::async_test]
async fn removing_a_member_updates_every_group_they_were_in() {
    // Indirect membership removal: `DELETE /Users/<id>` changes the `members` of each group the
    // person belonged to, so each of those SCIM resources has changed.
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let (_, member) = server.member(&org, "a@example.test", MembershipType::User, true).await;
    let group = server.group(&org, "Eng", None).await;
    let group_path = format!("{}/{}", groups_url(&org), group.uuid);

    server
        .patch(
            &group_path,
            &token,
            json!({"Operations": [{"op": "Add", "path": "members", "value": [{"value": member.uuid}]}]}),
        )
        .await;

    let before = server.get(&group_path, &token).await.json()["meta"]["lastModified"].as_str().unwrap().to_owned();

    let deleted = server.delete(&format!("{}/{}", users_url(&org), member.uuid), &token).await;
    assert_eq!(deleted.status, Status::NoContent, "{}", deleted.body);

    let after = server.get(&group_path, &token).await.json();
    assert_eq!(after["members"], json!([]), "the member is gone from the group");
    assert_ne!(
        after["meta"]["lastModified"].as_str().unwrap(),
        before,
        "the group's representation changed, so lastModified must have moved"
    );
}

// -- idempotent remove --------------------------------------------------------------------------

#[rocket::async_test]
async fn removing_a_member_who_is_not_in_the_group_succeeds() {
    // RFC 7644 section 3.5.2.2: `remove` targeting somebody who is not a member succeeds without
    // changing anything. It is deliberately *not* a `noTarget` error.
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let (_, outsider) = server.member(&org, "outsider@example.test", MembershipType::User, true).await;
    let (_, insider) = server.member(&org, "insider@example.test", MembershipType::User, true).await;
    let group = server.group(&org, "Eng", None).await;
    let path = format!("{}/{}", groups_url(&org), group.uuid);

    server
        .patch(
            &path,
            &token,
            json!({"Operations": [{"op": "Add", "path": "members", "value": [{"value": insider.uuid}]}]}),
        )
        .await;

    // Both spellings of remove, for somebody who is not a member.
    let by_filter = server
        .patch(
            &path,
            &token,
            json!({"Operations": [{"op": "Remove", "path": format!("members[value eq \"{}\"]", outsider.uuid)}]}),
        )
        .await;
    assert_eq!(by_filter.status, Status::Ok, "removing a non-member must succeed: {}", by_filter.body);

    let by_value = server
        .patch(
            &path,
            &token,
            json!({"Operations": [{"op": "Remove", "path": "members", "value": [{"value": outsider.uuid}]}]}),
        )
        .await;
    assert_eq!(by_value.status, Status::Ok, "{}", by_value.body);

    // ...and the group is untouched.
    let body = by_value.json();
    let ids: Vec<&str> = body["members"].as_array().unwrap().iter().map(|m| m["value"].as_str().unwrap()).collect();
    assert_eq!(ids, vec![insider.uuid.to_string()], "the existing member is still there");
}

// -- Entra extension attributes ------------------------------------------------------------------

#[rocket::async_test]
async fn entra_enterprise_extension_attributes_do_not_break_patch() {
    // Entra ID maps the EnterpriseUser extension by default. Vaultwarden stores none of it, so
    // these have to be ignored rather than rejected, or user provisioning fails outright.
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let (_, membership) = server.member(&org, "alice@example.test", MembershipType::User, true).await;
    let path = format!("{}/{}", users_url(&org), membership.uuid);

    // Fully qualified extension paths, alongside an operation that is supported.
    let qualified = server
        .patch(
            &path,
            &token,
            json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations": [
                    {
                        "op": "Replace",
                        "path": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department",
                        "value": "R&D",
                    },
                    {
                        "op": "Replace",
                        "path": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber",
                        "value": "12345",
                    },
                    {"op": "Replace", "path": "active", "value": false},
                ],
            }),
        )
        .await;
    assert_eq!(qualified.status, Status::Ok, "{}", qualified.body);
    assert_eq!(qualified.json()["active"], json!(false), "the supported operation still applied");

    // A pathless replace carrying the whole extension object, which Entra also sends.
    let pathless = server
        .patch(
            &path,
            &token,
            json!({
                "Operations": [{
                    "op": "Replace",
                    "value": {
                        "active": true,
                        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
                            "department": "R&D",
                            "costCenter": "CC-1",
                            "manager": {"value": "someone-else"},
                        },
                    },
                }],
            }),
        )
        .await;
    assert_eq!(pathless.status, Status::Ok, "{}", pathless.body);
    assert_eq!(pathless.json()["active"], json!(true));

    // ...and the unqualified spellings, in case a provider sends them bare.
    let unqualified = server
        .patch(
            &path,
            &token,
            json!({"Operations": [{"op": "Replace", "value": {"department": "R&D", "division": "Eng"}}]}),
        )
        .await;
    assert_eq!(unqualified.status, Status::Ok, "{}", unqualified.body);
}

#[rocket::async_test]
async fn an_extension_attribute_cannot_impersonate_a_core_one() {
    // The final segment of these paths is a core attribute name, but the namespace is not the core
    // schema. Aliasing them would let any extension toggle `active` or rewrite `members`.
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let (_, membership) = server.member(&org, "alice@example.test", MembershipType::User, true).await;
    let user_path = format!("{}/{}", users_url(&org), membership.uuid);

    let reply = server
        .patch(
            &user_path,
            &token,
            json!({
                "Operations": [
                    {"op": "Replace", "path": "urn:example:Custom:active", "value": false},
                    {"op": "Replace", "path": "urn:example:Custom:externalId", "value": "hijacked"},
                    {"op": "Replace", "path": "urn:example:Custom:userName", "value": "attacker@evil.test"},
                ],
            }),
        )
        .await;
    assert_eq!(reply.status, Status::Ok, "extension attributes are ignored, not errors: {}", reply.body);

    let stored = server.get(&user_path, &token).await.json();
    assert_eq!(stored["active"], json!(true), "an extension `active` must not deactivate the member");
    assert!(stored["externalId"].is_null(), "an extension `externalId` must not be stored");
    assert_eq!(stored["userName"], json!("alice@example.test"), "and it certainly must not rename the account");

    // The same for groups: an extension `members` must not rewrite the membership.
    let (_, member) = server.member(&org, "b@example.test", MembershipType::User, true).await;
    let group = server.group(&org, "Eng", None).await;
    let group_path = format!("{}/{}", groups_url(&org), group.uuid);

    let group_reply = server
        .patch(
            &group_path,
            &token,
            json!({
                "Operations": [{
                    "op": "Add",
                    "path": "urn:example:Custom:members",
                    "value": [{"value": member.uuid}],
                }],
            }),
        )
        .await;
    assert_eq!(group_reply.status, Status::Ok, "{}", group_reply.body);
    assert_eq!(group_reply.json()["members"], json!([]), "an extension `members` must not add anyone");
}

#[rocket::async_test]
async fn an_extension_attribute_is_not_a_filterable_core_attribute() {
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    server.member(&org, "alice@example.test", MembershipType::User, true).await;

    // `urn:example:Custom:userName` ends in `userName` but is not the core attribute, so it is not
    // filterable rather than silently matching on the core one.
    server
        .get(&format!("{}?filter=urn:example:Custom:userName%20eq%20%22alice@example.test%22", users_url(&org)), &token)
        .await
        .assert_error(Status::BadRequest, Some("invalidFilter"));

    // The properly qualified core attribute still works.
    let ok = server
        .get(
            &format!(
                "{}?filter=urn:ietf:params:scim:schemas:core:2.0:User:userName%20eq%20%22alice@example.test%22",
                users_url(&org)
            ),
            &token,
        )
        .await;
    assert_eq!(ok.json()["totalResults"], json!(1), "{}", ok.body);
}

// -- inactive provisioning -----------------------------------------------------------------------

#[rocket::async_test]
async fn provisioning_inactive_creates_no_invitation() {
    // Mail is disabled in tests, so the observable side effect is the `Invitation` row: the
    // credential that lets an unregistered account complete registration. Creating one for
    // somebody the identity provider marked inactive would hand out a way in that the inactive
    // state is meant to deny.
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;

    let reply =
        server.post(&users_url(&org), &token, json!({"userName": "inactive@example.test", "active": false})).await;
    assert_eq!(reply.status, Status::Created, "{}", reply.body);
    assert_eq!(reply.json()["active"], json!(false));

    let conn = server.conn().await;
    assert!(
        Invitation::find_by_mail("inactive@example.test", &conn).await.is_none(),
        "an inactive member must not be given a usable invitation"
    );
    drop(conn);

    let member_id = MembershipId::from(reply.json()["id"].as_str().unwrap().to_owned());
    let membership = server.reload_membership(&member_id, &org.uuid).await.expect("membership");
    assert!(membership.status < MembershipStatus::Invited as i32, "and the membership starts revoked");
}

#[rocket::async_test]
async fn reactivating_an_unregistered_member_creates_the_invitation_then() {
    // The invitation is withheld while inactive, so reactivation is the point at which it becomes
    // wanted -- otherwise the account could never complete registration.
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;

    let created =
        server.post(&users_url(&org), &token, json!({"userName": "later@example.test", "active": false})).await;
    let member_id = created.json()["id"].as_str().unwrap().to_owned();

    let reactivated = server
        .patch(
            &format!("{}/{}", users_url(&org), member_id),
            &token,
            json!({"Operations": [{"op": "Replace", "path": "active", "value": true}]}),
        )
        .await;
    assert_eq!(reactivated.status, Status::Ok, "{}", reactivated.body);
    assert_eq!(reactivated.json()["active"], json!(true));

    let conn = server.conn().await;
    assert!(
        Invitation::find_by_mail("later@example.test", &conn).await.is_some(),
        "reactivation must leave the account able to register"
    );
}

#[rocket::async_test]
async fn provisioning_active_still_creates_an_invitation() {
    // The ordinary path is unchanged, which is also what the Directory Connector relies on.
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;

    let reply = server.post(&users_url(&org), &token, json!({"userName": "active@example.test"})).await;
    assert_eq!(reply.status, Status::Created, "{}", reply.body);

    let conn = server.conn().await;
    assert!(Invitation::find_by_mail("active@example.test", &conn).await.is_some());
}

// -- projection, Content-Location, pagination ------------------------------------------------------

#[rocket::async_test]
async fn single_resource_responses_carry_a_matching_content_location() {
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let (_, membership) = server.member(&org, "alice@example.test", MembershipType::User, true).await;
    let user_path = format!("{}/{}", users_url(&org), membership.uuid);

    server.get(&user_path, &token).await.assert_content_location_matches_meta();
    server.put(&user_path, &token, json!({"active": true})).await.assert_content_location_matches_meta();
    server
        .patch(&user_path, &token, json!({"Operations": [{"op": "Replace", "path": "active", "value": true}]}))
        .await
        .assert_content_location_matches_meta();

    // POST carries both Location and Content-Location, and they agree.
    let created = server.post(&users_url(&org), &token, json!({"userName": "new@example.test"})).await;
    assert_eq!(created.status, Status::Created, "{}", created.body);
    created.assert_content_location_matches_meta();
    assert_eq!(created.location.as_deref(), created.content_location.as_deref());

    // Groups likewise.
    let group = server.post(&groups_url(&org), &token, json!({"displayName": "Eng"})).await;
    assert_eq!(group.status, Status::Created, "{}", group.body);
    group.assert_content_location_matches_meta();

    let group_path = format!("{}/{}", groups_url(&org), group.json()["id"].as_str().unwrap());
    server.get(&group_path, &token).await.assert_content_location_matches_meta();
    server.put(&group_path, &token, json!({"displayName": "Eng"})).await.assert_content_location_matches_meta();
    server
        .patch(&group_path, &token, json!({"Operations": [{"op": "Replace", "path": "displayName", "value": "Eng"}]}))
        .await
        .assert_content_location_matches_meta();

    // A ListResponse describes many resources, so it gets no Content-Location.
    let listed = server.get(&users_url(&org), &token).await;
    assert!(listed.content_location.is_none(), "a list response must not claim one resource's location");
}

#[rocket::async_test]
async fn projection_applies_to_every_representation() {
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let (_, membership) = server.member(&org, "alice@example.test", MembershipType::User, true).await;

    // A single-resource GET honours `attributes`, and `meta` is not forced in.
    let projected =
        server.get(&format!("{}/{}?attributes=userName", users_url(&org), membership.uuid), &token).await.json();
    assert_eq!(projected["userName"], json!("alice@example.test"));
    assert!(projected.get("id").is_some(), "id is in the minimum response set");
    assert!(projected.get("meta").is_none(), "meta is `returned: default`, not `always`");
    assert!(projected.get("emails").is_none());

    // Sub-attribute selection.
    let sub =
        server.get(&format!("{}/{}?attributes=emails.value", users_url(&org), membership.uuid), &token).await.json();
    assert_eq!(sub["emails"][0]["value"], json!("alice@example.test"));
    assert!(sub["emails"][0].get("type").is_none(), "only the named sub-attribute survives");

    // Sub-attribute exclusion keeps the parent.
    let excluded = server
        .get(&format!("{}/{}?excludedAttributes=emails.type", users_url(&org), membership.uuid), &token)
        .await
        .json();
    assert!(excluded["emails"][0].get("type").is_none());
    assert_eq!(excluded["emails"][0]["value"], json!("alice@example.test"), "the parent is not dropped wholesale");

    // Both at once is a client error rather than something to reconcile silently.
    server
        .get(&format!("{}?attributes=userName&excludedAttributes=emails", users_url(&org)), &token)
        .await
        .assert_error(Status::BadRequest, Some("invalidValue"));
}

#[rocket::async_test]
async fn pagination_walks_a_stable_sequence() {
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    for i in 0..6 {
        server.member(&org, &format!("user{i}@example.test"), MembershipType::User, true).await;
    }

    let ids_of = |body: &Value| -> Vec<String> {
        body["Resources"].as_array().unwrap().iter().map(|r| r["id"].as_str().unwrap().to_owned()).collect()
    };

    let first = ids_of(&server.get(&format!("{}?startIndex=1&count=2", users_url(&org)), &token).await.json());
    let second = ids_of(&server.get(&format!("{}?startIndex=3&count=2", users_url(&org)), &token).await.json());
    let third = ids_of(&server.get(&format!("{}?startIndex=5&count=2", users_url(&org)), &token).await.json());

    let mut walked = Vec::new();
    walked.extend(first.clone());
    walked.extend(second.clone());
    walked.extend(third);

    assert_eq!(walked.len(), 6, "paging must visit every resource");
    let unique: HashSet<&String> = walked.iter().collect();
    assert_eq!(unique.len(), 6, "no resource may appear on two pages: {walked:?}");

    // The same page twice returns the same thing.
    let first_again = ids_of(&server.get(&format!("{}?startIndex=1&count=2", users_url(&org)), &token).await.json());
    assert_eq!(first_again, first, "paging must be repeatable");

    // ...and the whole listing is in the order the pages walked.
    let all = ids_of(&server.get(&format!("{}?count=100", users_url(&org)), &token).await.json());
    assert_eq!(all, walked, "pages must follow the collection's own order");
}

// -- legacy duplicate externalIds ------------------------------------------------------------------

#[rocket::async_test]
async fn a_filter_returns_every_row_sharing_an_external_id() {
    // `external_id` has no unique constraint and Directory Connector data may already contain
    // duplicates. A filter optimisation must not quietly drop the extra rows.
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let (_, mut first) = server.member(&org, "one@example.test", MembershipType::User, true).await;
    let (_, mut second) = server.member(&org, "two@example.test", MembershipType::User, true).await;

    let conn = server.conn().await;
    first.set_external_id(Some("legacy-dup".to_owned()));
    first.save(&conn).await.expect("first");
    second.set_external_id(Some("legacy-dup".to_owned()));
    second.save(&conn).await.expect("second");

    for name in ["G1", "G2"] {
        let mut group = Group::new(org.uuid.clone(), name.to_owned(), false, Some("g-dup".to_owned()));
        group.save(&conn).await.expect("group");
    }
    drop(conn);

    let listed =
        server.get(&format!("{}?filter=externalId%20eq%20%22legacy-dup%22", users_url(&org)), &token).await.json();
    assert_eq!(listed["totalResults"], json!(2), "both legacy user rows must be returned");

    let groups = server.get(&format!("{}?filter=externalId%20eq%20%22g-dup%22", groups_url(&org)), &token).await.json();
    assert_eq!(groups["totalResults"], json!(2), "both legacy group rows must be returned");
}

// -- group displayName uniqueness --------------------------------------------------------------------

#[rocket::async_test]
async fn group_display_name_uniqueness_holds_on_rename_too() {
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    server.group(&org, "Engineering", None).await;
    let other = server.group(&org, "Sales", None).await;
    let path = format!("{}/{}", groups_url(&org), other.uuid);

    // An invariant only checked on create is one a rename walks straight through.
    server
        .put(&path, &token, json!({"displayName": "Engineering"}))
        .await
        .assert_error(Status::Conflict, Some("uniqueness"));

    server
        .patch(&path, &token, json!({"Operations": [{"op": "Replace", "path": "displayName", "value": "Engineering"}]}))
        .await
        .assert_error(Status::Conflict, Some("uniqueness"));

    // Case-insensitively, the same way creation compares.
    server
        .patch(&path, &token, json!({"Operations": [{"op": "Replace", "path": "displayName", "value": "ENGINEERING"}]}))
        .await
        .assert_error(Status::Conflict, Some("uniqueness"));

    // Renaming a group to the name it already has is not a collision with itself.
    let self_rename = server.put(&path, &token, json!({"displayName": "Sales"})).await;
    assert_eq!(self_rename.status, Status::Ok, "{}", self_rename.body);
}

// -- privileged membership policy ---------------------------------------------------------------------

#[rocket::async_test]
async fn privileged_members_may_be_managed_in_groups() {
    // Chosen policy: privileged memberships are read-only as *User* resources -- SCIM cannot
    // change their role, revoke them or delete them -- but their group association is ordinary
    // directory data an identity provider is expected to manage. Blocking it would fail an entire
    // group sync because one member happens to be an Owner.
    //
    // This is a real access decision, not a formality: adding anyone to a group that already has
    // collection assignments grants them that access. Documented in docs/scim/README.md.
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let (_, owner) = server.member(&org, "owner@example.test", MembershipType::Owner, true).await;
    let group = server.group(&org, "Eng", None).await;
    let path = format!("{}/{}", groups_url(&org), group.uuid);

    let added = server
        .patch(
            &path,
            &token,
            json!({"Operations": [{"op": "Add", "path": "members", "value": [{"value": owner.uuid}]}]}),
        )
        .await;
    assert_eq!(added.status, Status::Ok, "group membership is manageable for privileged members: {}", added.body);
    assert_eq!(added.json()["members"][0]["value"], json!(owner.uuid.to_string()));

    // The User resource itself remains untouchable.
    server
        .patch(
            &format!("{}/{}", users_url(&org), owner.uuid),
            &token,
            json!({"Operations": [{"op": "Replace", "path": "active", "value": false}]}),
        )
        .await
        .assert_error(Status::Forbidden, Some("mutability"));
}

// -- forbidden vs mutability ----------------------------------------------------------------------------

#[rocket::async_test]
async fn a_read_only_resource_is_a_mutability_fault_and_a_policy_refusal_is_not() {
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let (_, owner) = server.member(&org, "owner@example.test", MembershipType::Owner, true).await;

    // Writing a resource this server treats as read-only is a genuine `mutability` fault.
    server
        .delete(&format!("{}/{}", users_url(&org), owner.uuid), &token)
        .await
        .assert_error(Status::Forbidden, Some("mutability"));

    // Renaming an account is refused as immutable, with the RFC's 400 rather than a 403.
    let (_, member) = server.member(&org, "alice@example.test", MembershipType::User, true).await;
    server
        .put(&format!("{}/{}", users_url(&org), member.uuid), &token, json!({"userName": "other@example.test"}))
        .await
        .assert_error(Status::BadRequest, Some("mutability"));
}

// -- request-wide member limits ---------------------------------------------------------------------------

#[rocket::async_test]
async fn the_member_limit_covers_the_whole_patch_document() {
    // The per-array cap only bounds one operation; spreading ids across operations must not get
    // past it.
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let group = server.group(&org, "Eng", None).await;

    let ops: Vec<Value> = (0..10)
        .map(|op| {
            let values: Vec<Value> = (0..600).map(|i| json!({"value": format!("m-{op}-{i}")})).collect();
            json!({"op": "Add", "path": "members", "value": values})
        })
        .collect();

    server
        .patch(&format!("{}/{}", groups_url(&org), group.uuid), &token, json!({"Operations": ops}))
        .await
        .assert_error(Status::BadRequest, Some("tooMany"));
}

// -- token rotation ---------------------------------------------------------------------------------------

#[rocket::async_test]
async fn rotation_replaces_the_token_atomically() {
    let server = TestServer::new().await;
    let (org, first) = server.org("acme").await;
    let conn = server.conn().await;

    let second = OrganizationScimKey::rotate_for_org(&org.uuid, &conn).await.expect("rotate");
    drop(conn);

    assert_ne!(first, second);
    server.get(&users_url(&org), &first).await.assert_error(Status::Unauthorized, None);
    assert_eq!(server.get(&users_url(&org), &second).await.status, Status::Ok);

    // One key per organization survives rotation.
    let conn = server.conn().await;
    assert!(OrganizationScimKey::find_by_org(&org.uuid, &conn).await.is_some());
}

// -- unauthenticated traffic is charged separately ------------------------------------------------------------

#[rocket::async_test]
async fn junk_requests_do_not_consume_the_provisioning_budget() {
    // A request with no bearer token, or one that is not even the right shape, is never something
    // an identity provider sends. Those are charged to the strict unauthenticated limiter so a
    // flood of them cannot eat the allowance a real sync needs.
    let server = TestServer::with_exclusive_settings().await;
    let (org, token) = server.org("acme").await;

    server.set_unauthenticated_rate_limit_exhausted(true);

    // Junk is rejected by the strict budget...
    server.get_unauthenticated(&users_url(&org)).await.assert_error(Status::TooManyRequests, None);
    server.get(&users_url(&org), "not-a-token").await.assert_error(Status::TooManyRequests, None);

    // ...while real provisioning traffic is unaffected.
    assert_eq!(server.get(&users_url(&org), &token).await.status, Status::Ok);
}

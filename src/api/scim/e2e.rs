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

use super::resource::MAX_ACCOUNT_NAME_LEN;
use super::settings::test_overrides::{
    GROUPS_ENABLED, INVITATION_FAILS, KEY_LOOKUPS, PRE_AUTH_RATE_LIMIT_CHECKS, PRE_AUTH_RATE_LIMIT_EXHAUSTED,
    RATE_LIMIT_CHECKS, RATE_LIMIT_KEYS, RATE_LIMITED_ORG, SCIM_ENABLED, UNAUTH_RATE_LIMIT_CHECKS,
    UNAUTH_RATE_LIMIT_EXHAUSTED, reset as reset_settings,
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
    ///
    /// Only these tests may read the limiter counters, because only they hold the lock that keeps
    /// another test's requests from incrementing them.
    async fn with_exclusive_settings() -> Self {
        let guard = SettingsGuard::Exclusive(SETTINGS_LOCK.write().await);
        reset_settings();
        Self::build(guard).await
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

    /// Exhaust the provisioning budget for one organization.
    ///
    /// Per organization rather than globally, because the budget is keyed by
    /// `(organization, address)`: a test that could only exhaust "everything" could not show that
    /// two organizations on one address have separate allowances.
    fn set_rate_limited_org(&self, org: Option<&OrganizationId>) {
        assert!(matches!(self.guard, SettingsGuard::Exclusive(_)), "changing settings needs the exclusive lock");
        *RATE_LIMITED_ORG.lock().expect("rate-limited organization") = org.cloned();
    }

    fn set_unauthenticated_rate_limit_exhausted(&self, exhausted: bool) {
        assert!(matches!(self.guard, SettingsGuard::Exclusive(_)), "changing settings needs the exclusive lock");
        UNAUTH_RATE_LIMIT_EXHAUSTED.store(exhausted, Ordering::Relaxed);
    }

    fn set_pre_auth_rate_limit_exhausted(&self, exhausted: bool) {
        assert!(matches!(self.guard, SettingsGuard::Exclusive(_)), "changing settings needs the exclusive lock");
        PRE_AUTH_RATE_LIMIT_EXHAUSTED.store(exhausted, Ordering::Relaxed);
    }

    /// Make the invitation side effect of a reactivation fail.
    ///
    /// The only way to reach the rollback in `apply_user_changes` from a test: every real cause of
    /// failure is a database state the foreign keys will not let a test construct.
    fn set_invitation_fails(&self, fails: bool) {
        assert!(matches!(self.guard, SettingsGuard::Exclusive(_)), "changing settings needs the exclusive lock");
        INVITATION_FAILS.store(fails, Ordering::Relaxed);
    }

    /// The counters and the recorded limiter keys are process-wide, so reading them is only
    /// meaningful while no other test can be making requests.
    fn assert_counters_are_readable(&self) {
        assert!(matches!(self.guard, SettingsGuard::Exclusive(_)), "reading counters needs the exclusive lock");
    }

    fn reset_counters(&self) {
        self.assert_counters_are_readable();
        RATE_LIMIT_CHECKS.store(0, Ordering::Relaxed);
        UNAUTH_RATE_LIMIT_CHECKS.store(0, Ordering::Relaxed);
        PRE_AUTH_RATE_LIMIT_CHECKS.store(0, Ordering::Relaxed);
        KEY_LOOKUPS.store(0, Ordering::Relaxed);
        RATE_LIMIT_KEYS.lock().expect("rate-limit keys").clear();
    }

    fn provisioning_checks(&self) -> usize {
        self.assert_counters_are_readable();
        RATE_LIMIT_CHECKS.load(Ordering::Relaxed)
    }

    fn unauthenticated_checks(&self) -> usize {
        self.assert_counters_are_readable();
        UNAUTH_RATE_LIMIT_CHECKS.load(Ordering::Relaxed)
    }

    fn pre_auth_checks(&self) -> usize {
        self.assert_counters_are_readable();
        PRE_AUTH_RATE_LIMIT_CHECKS.load(Ordering::Relaxed)
    }

    fn key_lookups(&self) -> usize {
        self.assert_counters_are_readable();
        KEY_LOOKUPS.load(Ordering::Relaxed)
    }

    fn provisioning_keys(&self) -> Vec<(OrganizationId, std::net::IpAddr)> {
        self.assert_counters_are_readable();
        RATE_LIMIT_KEYS.lock().expect("rate-limit keys").clone()
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
            reset_settings();
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
    www_authenticate: Option<String>,
    body: String,
}

impl ScimReply {
    async fn of(response: LocalResponse<'_>) -> Self {
        let status = response.status();
        let content_type = response.content_type();
        let location = response.headers().get_one("Location").map(str::to_owned);
        let content_location = response.headers().get_one("Content-Location").map(str::to_owned);
        let www_authenticate = response.headers().get_one("WWW-Authenticate").map(str::to_owned);
        let body = response.into_string().await.unwrap_or_default();

        Self {
            status,
            content_type,
            location,
            content_location,
            www_authenticate,
            body,
        }
    }

    /// A `401` carries the generic bearer challenge and nothing that varies with the cause.
    fn assert_generic_bearer_challenge(&self) {
        assert_eq!(self.status, Status::Unauthorized, "body was {}", self.body);
        assert_eq!(
            self.www_authenticate.as_deref(),
            Some("Bearer"),
            "every SCIM 401 carries the same bare Bearer challenge"
        );
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
        // Unknown key id, real organization. Structurally valid, so it costs a database lookup
        // that misses -- the path the dummy-hash comparison exists to keep indistinguishable.
        server
            .get(
                &users_url(&org),
                &format!("scim_v1.{}.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", crate::util::get_uuid()),
            )
            .await,
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

    server.set_rate_limited_org(Some(&org.uuid));

    server.get(&users_url(&org), &token).await.assert_error(Status::TooManyRequests, None);
}

#[rocket::async_test]
async fn authenticated_traffic_consumes_the_provisioning_budget() {
    // Every verb, not just GET: the guard runs before any handler, so exhausting the provisioning
    // budget has to stop writes as well as reads.
    let server = TestServer::with_exclusive_settings().await;
    let (org, token) = server.org("acme").await;
    let (_, membership) = server.member(&org, "alice@example.test", MembershipType::User, true).await;
    let user_path = format!("{}/{}", users_url(&org), membership.uuid);

    server.set_rate_limited_org(Some(&org.uuid));

    server.get(&users_url(&org), &token).await.assert_error(Status::TooManyRequests, None);
    server.get(&user_path, &token).await.assert_error(Status::TooManyRequests, None);
    server
        .post(&users_url(&org), &token, json!({"userName": "new@example.test"}))
        .await
        .assert_error(Status::TooManyRequests, None);
    server.put(&user_path, &token, json!({"active": true})).await.assert_error(Status::TooManyRequests, None);
    server
        .patch(&user_path, &token, json!({"Operations": [{"op": "replace", "path": "active", "value": true}]}))
        .await
        .assert_error(Status::TooManyRequests, None);
    server.delete(&user_path, &token).await.assert_error(Status::TooManyRequests, None);
    server.get(&groups_url(&org), &token).await.assert_error(Status::TooManyRequests, None);

    // Nothing was written: the guard refused before any handler ran.
    assert!(server.reload_membership(&membership.uuid, &org.uuid).await.is_some(), "DELETE must not have run");
    assert!(
        Membership::find_by_email_and_org("new@example.test", &org.uuid, &server.conn().await).await.is_none(),
        "POST must not have run"
    );
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

    // The account was created without a name, so Vaultwarden stores the address as the name and
    // that is what `displayName` reads back as. Echoing it is a no-op, as is echoing the address.
    let reply = server
        .put(
            &format!("{}/{}", users_url(&org), membership.uuid),
            &token,
            json!({"userName": "ALICE@example.test", "active": true, "displayName": "alice@example.test"}),
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
    let reply = server.put(&format!("{}/{}", users_url(&org), membership.uuid), &token, json!({"active": true})).await;
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
async fn privileged_memberships_are_visible_but_not_writable() {
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
        .assert_error(Status::Forbidden, None);
    server.put(&path, &token, json!({"active": false})).await.assert_error(Status::Forbidden, None);
    server.delete(&path, &token).await.assert_error(Status::Forbidden, None);

    let stored = server.reload_membership(&owner.uuid, &org.uuid).await.expect("owner still there");
    assert_eq!(stored.atype, MembershipType::Owner as i32);
    assert_eq!(stored.status, MembershipStatus::Confirmed as i32);
}

#[rocket::async_test]
async fn admins_and_managers_are_equally_off_limits() {
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;

    for (email, role) in
        [("admin@example.test", MembershipType::Admin), ("manager@example.test", MembershipType::Manager)]
    {
        let (_, membership) = server.member(&org, email, role, true).await;
        server
            .delete(&format!("{}/{}", users_url(&org), membership.uuid), &token)
            .await
            .assert_error(Status::Forbidden, None);
    }
}

#[rocket::async_test]
async fn the_last_owner_cannot_be_removed_or_disabled_through_scim() {
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let (_, owner) = server.member(&org, "owner@example.test", MembershipType::Owner, true).await;

    let path = format!("{}/{}", users_url(&org), owner.uuid);
    server.delete(&path, &token).await.assert_error(Status::Forbidden, None);
    server
        .patch(&path, &token, json!({"Operations": [{"op": "Replace", "path": "active", "value": false}]}))
        .await
        .assert_error(Status::Forbidden, None);

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
        .assert_error(Status::Forbidden, None);

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

    // The full listing is checked by `schemas_publishes_every_schema_the_server_uses`; this only
    // pins that the endpoint answers and carries the resource type's own schema.
    let schemas = server.get(&format!("/scim/v2/{}/Schemas", org.uuid), &token).await.json();
    assert!(
        schemas["Resources"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["id"] == json!("urn:ietf:params:scim:schemas:core:2.0:User")),
        "{schemas}"
    );

    let user_schema =
        server.get(&format!("/scim/v2/{}/Schemas/urn:ietf:params:scim:schemas:core:2.0:User", org.uuid), &token).await;
    assert_eq!(user_schema.status, Status::Ok, "{}", user_schema.body);
    assert_eq!(user_schema.json()["name"], json!("User"));

    server
        .get(&format!("/scim/v2/{}/Schemas/urn:made:up", org.uuid), &token)
        .await
        .assert_error(Status::NotFound, None);
}

/// Pull one attribute definition out of a published schema document.
fn schema_attribute<'a>(schema: &'a Value, name: &str) -> &'a Value {
    schema["attributes"]
        .as_array()
        .unwrap_or_else(|| panic!("no attributes in {schema}"))
        .iter()
        .find(|a| a["name"] == json!(name))
        .unwrap_or_else(|| panic!("no '{name}' attribute in {schema}"))
}

fn sub_attribute<'a>(attribute: &'a Value, name: &str) -> &'a Value {
    attribute["subAttributes"]
        .as_array()
        .unwrap_or_else(|| panic!("no subAttributes in {attribute}"))
        .iter()
        .find(|a| a["name"] == json!(name))
        .unwrap_or_else(|| panic!("no '{name}' sub-attribute in {attribute}"))
}

#[rocket::async_test]
async fn the_published_user_schema_matches_what_the_server_enforces() {
    // Discovery is a promise. Every mutability value here is checked against the behaviour it
    // claims by the tests further down this file; this one just pins the advertisement.
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;

    let schema =
        server.get(&format!("/scim/v2/{}/Schemas/urn:ietf:params:scim:schemas:core:2.0:User", org.uuid), &token).await;
    let schema = schema.json();

    // The account's global identity: settable at creation, never changed afterwards.
    assert_eq!(schema_attribute(&schema, "userName")["mutability"], json!("immutable"));
    // The account's global name: same rule.
    assert_eq!(schema_attribute(&schema, "displayName")["mutability"], json!("immutable"));
    // Ordinary directory data.
    assert_eq!(schema_attribute(&schema, "externalId")["mutability"], json!("readWrite"));
    assert_eq!(schema_attribute(&schema, "active")["mutability"], json!("readWrite"));

    // `emails` is `immutable`, not `readOnly`: POST accepts `emails[].value` as the identity when
    // `userName` is absent, so calling it read-only would describe a different server.
    let emails = schema_attribute(&schema, "emails");
    assert_eq!(emails["mutability"], json!("immutable"));
    assert_eq!(sub_attribute(emails, "value")["mutability"], json!("immutable"), "the same address as userName");
    // ...but the parts the server derives really are read-only.
    assert_eq!(sub_attribute(emails, "type")["mutability"], json!("readOnly"));
    assert_eq!(sub_attribute(emails, "primary")["mutability"], json!("readOnly"));
}

#[rocket::async_test]
async fn group_display_name_uniqueness_is_not_over_advertised() {
    // SCIM refuses to introduce a duplicate `displayName`, but `groups.name` carries no unique
    // constraint and an installation may already hold duplicates from a legacy or manual path.
    // `uniqueness: "server"` would claim an invariant the storage does not hold.
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;

    let schema = server
        .get(&format!("/scim/v2/{}/Schemas/urn:ietf:params:scim:schemas:core:2.0:Group", org.uuid), &token)
        .await
        .json();

    assert_eq!(schema_attribute(&schema, "displayName")["uniqueness"], json!("none"));
    assert_eq!(schema_attribute(&schema, "displayName")["required"], json!(true));

    // The SCIM-layer collision check is unaffected: it is an interoperability rule, not a
    // storage guarantee, and it still refuses a new duplicate.
    assert_eq!(server.post(&groups_url(&org), &token, json!({"displayName": "Eng"})).await.status, Status::Created);
    server
        .post(&groups_url(&org), &token, json!({"displayName": "eng"}))
        .await
        .assert_error(Status::Conflict, Some("uniqueness"));

    // ...and a duplicate that already exists keeps working, which is exactly why the schema
    // cannot promise uniqueness.
    server.group(&org, "Eng", None).await;
    let listed = server.get(&format!("{}?filter=displayName%20eq%20%22Eng%22", groups_url(&org)), &token).await.json();
    assert_eq!(listed["totalResults"], json!(2), "pre-existing duplicates are still returned");
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

#[rocket::async_test]
async fn reactivation_is_idempotent_and_does_not_reissue_an_invitation() {
    // A retry of a reactivation that already succeeded must not repeat the invitation side
    // effect. With mail enabled that would be a second email; with mail disabled it would be a
    // second `Invitation` row for the same address.
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;

    let created =
        server.post(&users_url(&org), &token, json!({"userName": "again@example.test", "active": false})).await;
    let member_id = created.json()["id"].as_str().unwrap().to_owned();
    let path = format!("{}/{}", users_url(&org), member_id);
    let activate = json!({"Operations": [{"op": "Replace", "path": "active", "value": true}]});

    assert_eq!(server.patch(&path, &token, activate.clone()).await.status, Status::Ok);
    let after_first = Invitation::find_by_mail("again@example.test", &server.conn().await).await;
    assert!(after_first.is_some(), "the first reactivation issues the invitation");

    // The second one changes nothing: the membership is already active, so the reactivation
    // branch -- and with it the invitation -- is never entered again.
    let second = server.patch(&path, &token, activate).await;
    assert_eq!(second.status, Status::Ok, "{}", second.body);
    assert_eq!(second.json()["active"], json!(true));
    assert!(Invitation::find_by_mail("again@example.test", &server.conn().await).await.is_some());
}

#[rocket::async_test]
async fn reactivating_a_registered_member_needs_no_invitation() {
    // An account that can already sign in needs nothing issued, so there is no side effect that
    // could fail and nothing for the reactivation to depend on.
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let (user, mut membership) = server.member(&org, "registered@example.test", MembershipType::User, true).await;

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

    assert!(
        Invitation::find_by_mail(&user.email, &server.conn().await).await.is_none(),
        "a registered account is not invited again"
    );
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
        .assert_error(Status::Forbidden, None);
}

// -- resource refusals vs attribute mutability -------------------------------------------------------

#[rocket::async_test]
async fn a_refused_resource_is_not_an_attribute_mutability_fault() {
    // Two different faults that an earlier revision spelled the same way.
    //
    // A privileged membership is a *resource* this server's provisioning policy does not hand to
    // SCIM: no attribute value makes the request work, so `scimType: mutability` -- which tells a
    // client one attribute violated its declared changeability -- names the wrong problem and
    // points at a fix that does not exist. It is a plain 403.
    //
    // An attempt to change `userName` really is an attribute mutability fault, and keeps the pair
    // RFC 7644 section 3.12 gives it: 400 with `scimType: mutability`.
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let (_, owner) = server.member(&org, "owner@example.test", MembershipType::Owner, true).await;

    let refused = server.delete(&format!("{}/{}", users_url(&org), owner.uuid), &token).await;
    refused.assert_error(Status::Forbidden, None);
    assert!(
        refused.json()["detail"].as_str().unwrap_or_default().contains("privileged"),
        "the refusal still says why: {}",
        refused.body
    );

    let (_, member) = server.member(&org, "alice@example.test", MembershipType::User, true).await;
    server
        .put(&format!("{}/{}", users_url(&org), member.uuid), &token, json!({"userName": "other@example.test"}))
        .await
        .assert_error(Status::BadRequest, Some("mutability"));

    // ...and so does an attempt to change the other two immutable account attributes.
    server
        .put(&format!("{}/{}", users_url(&org), member.uuid), &token, json!({"displayName": "Someone Else"}))
        .await
        .assert_error(Status::BadRequest, Some("mutability"));
    server
        .put(
            &format!("{}/{}", users_url(&org), member.uuid),
            &token,
            json!({"emails": [{"value": "other@example.test", "primary": true}]}),
        )
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

#[rocket::async_test]
async fn unauthenticated_requests_never_reach_the_provisioning_limiter() {
    // The inverse of the test above, and the one that actually proves the ordering: with the
    // provisioning budget exhausted and the strict budget intact, junk still gets the plain 401
    // it deserves. If the provisioning limiter still ran first these would all be 429, which is
    // exactly the leak that let junk traffic eat a real sync's allowance.
    let server = TestServer::with_exclusive_settings().await;
    let (org, token) = server.org("acme").await;
    let key_id = token.split('.').nth(1).unwrap();
    let secret = token.rsplit('.').next().unwrap();

    server.set_rate_limited_org(Some(&org.uuid));

    // No Authorization header at all.
    server.get_unauthenticated(&users_url(&org)).await.assert_error(Status::Unauthorized, None);

    for junk in [
        // Not a bearer credential.
        String::new(),
        "not-a-token".to_owned(),
        // Bearer, but not this server's token format.
        format!("scim_v2.{key_id}.{secret}"),
        format!("scim_v1.{key_id}"),
        format!("scim_v1.{key_id}.{secret}.extra"),
        format!("scim_v1..{secret}"),
        format!("scim_v1.{key_id}."),
        // Right prefix, wrong key-id shape.
        format!("scim_v1.not-a-uuid.{secret}"),
        // Right prefix and key id, wrong secret shape.
        format!("scim_v1.{key_id}.short"),
        format!("scim_v1.{key_id}.{secret}+"),
    ] {
        server.get(&users_url(&org), &junk).await.assert_error(Status::Unauthorized, None);
    }

    // A structurally valid credential with the wrong secret is an authentication failure too, so
    // it is charged to the strict budget rather than the exhausted provisioning one.
    server
        .get(&users_url(&org), &format!("scim_v1.{key_id}.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
        .await
        .assert_error(Status::Unauthorized, None);

    // ...and the valid token is the only thing the exhausted provisioning budget stops.
    server.get(&users_url(&org), &token).await.assert_error(Status::TooManyRequests, None);
}

#[rocket::async_test]
async fn a_wrong_but_well_formed_credential_is_charged_to_the_strict_budget() {
    // Brute force does not get the generous provisioning allowance: an attempt that looks right
    // and fails is throttled by the same strict budget as obvious junk.
    let server = TestServer::with_exclusive_settings().await;
    let (org, token) = server.org("acme").await;
    let key_id = token.split('.').nth(1).unwrap();

    server.set_unauthenticated_rate_limit_exhausted(true);

    // Real key id, wrong secret.
    server
        .get(&users_url(&org), &format!("scim_v1.{key_id}.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
        .await
        .assert_error(Status::TooManyRequests, None);

    // Unknown key id, well-formed secret.
    server
        .get(
            &users_url(&org),
            &format!("scim_v1.{}.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", crate::util::get_uuid()),
        )
        .await
        .assert_error(Status::TooManyRequests, None);

    // A valid token for another organization is an authentication failure here as well.
    let (_org_b, token_b) = server.org("globex").await;
    server.get(&users_url(&org), &token_b).await.assert_error(Status::TooManyRequests, None);

    // The organization's own token still works: the two budgets are independent.
    assert_eq!(server.get(&users_url(&org), &token).await.status, Status::Ok);
}

#[rocket::async_test]
async fn a_disabled_server_is_not_an_authentication_failure() {
    // With SCIM off the endpoints do not exist, whatever the credential. That answer must not
    // depend on either budget, and must not consume either.
    let server = TestServer::with_exclusive_settings().await;
    let (org, token) = server.org("acme").await;

    server.set_scim_enabled(false);
    server.set_rate_limited_org(Some(&org.uuid));
    server.set_unauthenticated_rate_limit_exhausted(true);
    server.set_pre_auth_rate_limit_exhausted(true);
    server.reset_counters();

    server.get(&users_url(&org), &token).await.assert_error(Status::NotFound, None);
    server.get_unauthenticated(&users_url(&org)).await.assert_error(Status::NotFound, None);
    server.get(&users_url(&org), "not-a-token").await.assert_error(Status::NotFound, None);

    // Not one budget was consulted, and the database was never asked for a key: a switched-off
    // endpoint is answered from configuration alone.
    assert_eq!(server.provisioning_checks(), 0);
    assert_eq!(server.unauthenticated_checks(), 0);
    assert_eq!(server.pre_auth_checks(), 0);
    assert_eq!(server.key_lookups(), 0);
}

// -- immutable account attributes ------------------------------------------------------------------
//
// `userName` and `displayName` both map to *global* account state that is visible in every
// organization the account belongs to. Discovery advertises both as `immutable`, and these tests
// are what make that advertisement true rather than aspirational: re-sending the stored value is
// the no-op an identity provider performs on every sync, and a genuine change is refused instead
// of being silently dropped.

/// The display name a fresh shell account gets. `User::new` stores the address as the name when
/// no name was supplied, so that is what `displayName` reads back as.
const SHELL_NAME: &str = "alice@example.test";

#[rocket::async_test]
async fn re_asserting_the_stored_display_name_is_a_no_op() {
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let (user, membership) = server.member(&org, SHELL_NAME, MembershipType::User, true).await;
    let path = format!("{}/{}", users_url(&org), membership.uuid);

    // PUT with the value the server would return.
    let put = server.put(&path, &token, json!({"displayName": SHELL_NAME, "active": true})).await;
    assert_eq!(put.status, Status::Ok, "{}", put.body);
    assert_eq!(put.json()["displayName"], json!(SHELL_NAME));

    // PATCH with a path...
    let patched = server
        .patch(&path, &token, json!({"Operations": [{"op": "Replace", "path": "displayName", "value": SHELL_NAME}]}))
        .await;
    assert_eq!(patched.status, Status::Ok, "{}", patched.body);

    // ...and pathless, which is the shape Entra ID sends.
    let pathless = server
        .patch(&path, &token, json!({"Operations": [{"op": "Replace", "value": {"displayName": SHELL_NAME}}]}))
        .await;
    assert_eq!(pathless.status, Status::Ok, "{}", pathless.body);

    let stored = User::find_by_uuid(&user.uuid, &server.conn().await).await.expect("account");
    assert_eq!(stored.name, SHELL_NAME, "the account name is untouched either way");
}

#[rocket::async_test]
async fn changing_the_display_name_is_refused_as_immutable() {
    // Silently ignoring the change -- what this used to do -- contradicts the `immutable` the
    // schema advertises and leaves the identity provider believing a rename took effect.
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let (user, membership) = server.member(&org, SHELL_NAME, MembershipType::User, true).await;
    let path = format!("{}/{}", users_url(&org), membership.uuid);

    // PUT.
    server
        .put(&path, &token, json!({"displayName": "Someone Else"}))
        .await
        .assert_error(Status::BadRequest, Some("mutability"));

    // PATCH with a path.
    server
        .patch(
            &path,
            &token,
            json!({"Operations": [{"op": "Replace", "path": "displayName", "value": "Someone Else"}]}),
        )
        .await
        .assert_error(Status::BadRequest, Some("mutability"));

    // Pathless PATCH.
    server
        .patch(&path, &token, json!({"Operations": [{"op": "Replace", "value": {"displayName": "Someone Else"}}]}))
        .await
        .assert_error(Status::BadRequest, Some("mutability"));

    // `add` is a write too.
    server
        .patch(&path, &token, json!({"Operations": [{"op": "Add", "path": "displayName", "value": "Someone Else"}]}))
        .await
        .assert_error(Status::BadRequest, Some("mutability"));

    // A qualified path is the same attribute.
    server
        .patch(
            &path,
            &token,
            json!({"Operations": [{
                "op": "Replace",
                "path": "urn:ietf:params:scim:schemas:core:2.0:User:displayName",
                "value": "Someone Else",
            }]}),
        )
        .await
        .assert_error(Status::BadRequest, Some("mutability"));

    let stored = User::find_by_uuid(&user.uuid, &server.conn().await).await.expect("account");
    assert_eq!(stored.name, SHELL_NAME, "nothing was renamed");
}

#[rocket::async_test]
async fn removing_the_display_name_is_refused_as_immutable() {
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let (user, membership) = server.member(&org, SHELL_NAME, MembershipType::User, true).await;

    server
        .patch(
            &format!("{}/{}", users_url(&org), membership.uuid),
            &token,
            json!({"Operations": [{"op": "Remove", "path": "displayName"}]}),
        )
        .await
        .assert_error(Status::BadRequest, Some("mutability"));

    let stored = User::find_by_uuid(&user.uuid, &server.conn().await).await.expect("account");
    assert_eq!(stored.name, SHELL_NAME);
}

#[rocket::async_test]
async fn an_extension_display_name_does_not_trip_the_immutability_check() {
    // The namespace rule and the mutability rule have to compose: an extension attribute whose
    // last segment is `displayName` is not this server's `displayName`, so it is ignored rather
    // than refused. Rejecting it would fail provisioning over an attribute that is none of this
    // server's business.
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let (user, membership) = server.member(&org, SHELL_NAME, MembershipType::User, true).await;

    let reply = server
        .patch(
            &format!("{}/{}", users_url(&org), membership.uuid),
            &token,
            json!({"Operations": [{"op": "Replace", "path": "urn:example:Custom:displayName", "value": "Ignored"}]}),
        )
        .await;
    assert_eq!(reply.status, Status::Ok, "{}", reply.body);

    let stored = User::find_by_uuid(&user.uuid, &server.conn().await).await.expect("account");
    assert_eq!(stored.name, SHELL_NAME);
}

#[rocket::async_test]
async fn display_name_names_a_new_account_and_is_bounded() {
    // The one place SCIM writes a name: an account that did not exist a moment ago. Bounded by
    // the same 50-character limit registration and the profile endpoint enforce, so SCIM cannot
    // write a name the account's own owner would not be allowed to keep.
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;

    let created = server
        .post(&users_url(&org), &token, json!({"userName": "new@example.test", "displayName": "Alice Example"}))
        .await;
    assert_eq!(created.status, Status::Created, "{}", created.body);
    assert_eq!(created.json()["displayName"], json!("Alice Example"));

    let account = User::find_by_mail("new@example.test", &server.conn().await).await.expect("account");
    assert_eq!(account.name, "Alice Example");

    // Exactly at the limit is accepted...
    let at_limit = "a".repeat(MAX_ACCOUNT_NAME_LEN);
    let ok =
        server.post(&users_url(&org), &token, json!({"userName": "edge@example.test", "displayName": at_limit})).await;
    assert_eq!(ok.status, Status::Created, "{}", ok.body);
    assert_eq!(ok.json()["displayName"], json!(at_limit));

    // ...one character past it is not.
    server
        .post(
            &users_url(&org),
            &token,
            json!({"userName": "toolong@example.test", "displayName": "a".repeat(MAX_ACCOUNT_NAME_LEN + 1)}),
        )
        .await
        .assert_error(Status::BadRequest, Some("invalidValue"));
    assert!(
        User::find_by_mail("toolong@example.test", &server.conn().await).await.is_none(),
        "a rejected name must not have created an account"
    );
}

#[rocket::async_test]
async fn the_display_name_limit_counts_characters_not_bytes() {
    // 50 is a character limit. Counting UTF-8 bytes would refuse a 50-character name of non-Latin
    // text while accepting a 50-character ASCII one, which is a different rule than the one the
    // rest of Vaultwarden documents.
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;

    // At the limit in characters, comfortably over it in bytes.
    let wide: String = "\u{4e2d}".repeat(MAX_ACCOUNT_NAME_LEN);
    assert_eq!(wide.chars().count(), MAX_ACCOUNT_NAME_LEN);
    assert!(wide.len() > MAX_ACCOUNT_NAME_LEN, "and over the limit if it were counted in bytes");

    let created =
        server.post(&users_url(&org), &token, json!({"userName": "wide@example.test", "displayName": wide})).await;
    assert_eq!(created.status, Status::Created, "{}", created.body);
    assert_eq!(created.json()["displayName"], json!(wide));

    server
        .post(
            &users_url(&org),
            &token,
            json!({
                "userName": "wider@example.test",
                "displayName": "\u{4e2d}".repeat(MAX_ACCOUNT_NAME_LEN + 1),
            }),
        )
        .await
        .assert_error(Status::BadRequest, Some("invalidValue"));
}

#[rocket::async_test]
async fn an_existing_account_keeps_its_own_name_when_a_membership_is_added() {
    // `POST /Users` creates a *membership*. An account that already exists keeps the name it
    // chose, because that name is global; the response tells the identity provider what the
    // server actually holds rather than echoing what it asked for.
    let server = TestServer::new().await;
    let (org_a, _) = server.org("acme").await;
    let (org_b, token_b) = server.org("globex").await;

    let (user, _) = server.member(&org_a, "shared@example.test", MembershipType::User, true).await;
    let mut account = User::find_by_uuid(&user.uuid, &server.conn().await).await.expect("account");
    account.name = "Chosen Name".to_owned();
    account.save(&server.conn().await).await.expect("rename");

    let created = server
        .post(&users_url(&org_b), &token_b, json!({"userName": "shared@example.test", "displayName": "Directory Name"}))
        .await;
    assert_eq!(created.status, Status::Created, "{}", created.body);
    assert_eq!(
        created.json()["displayName"],
        json!("Chosen Name"),
        "the stored name is returned, not the asserted one"
    );

    let reloaded = User::find_by_uuid(&user.uuid, &server.conn().await).await.expect("account");
    assert_eq!(reloaded.name, "Chosen Name", "another organization's identity provider cannot rename an account");
}

#[rocket::async_test]
async fn emails_may_create_but_never_rename() {
    // `emails[].value` is the same global account email as `userName`, which is why the schema
    // now advertises it `immutable` rather than `readOnly`: it genuinely decides creation state.
    // Everything after creation follows the `userName` rule exactly.
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;

    // POST with no `userName` at all: identity comes from the primary email.
    let created = server
        .post(
            &users_url(&org),
            &token,
            json!({"emails": [
                {"value": "secondary@example.test", "type": "home", "primary": false},
                {"value": "Primary@Example.test", "type": "work", "primary": true},
            ]}),
        )
        .await;
    assert_eq!(created.status, Status::Created, "{}", created.body);
    assert_eq!(created.json()["userName"], json!("primary@example.test"), "normalised like any account email");
    assert_eq!(created.json()["emails"][0]["value"], json!("primary@example.test"));

    let member_id = created.json()["id"].as_str().unwrap().to_owned();
    let path = format!("{}/{}", users_url(&org), member_id);

    // The identical address is the no-op an identity provider sends on every update.
    let echo = server
        .put(&path, &token, json!({"emails": [{"value": "PRIMARY@example.test", "primary": true}], "active": true}))
        .await;
    assert_eq!(echo.status, Status::Ok, "{}", echo.body);

    // A different address is a rename of the global account, and is refused.
    server
        .put(&path, &token, json!({"emails": [{"value": "attacker@evil.test", "primary": true}]}))
        .await
        .assert_error(Status::BadRequest, Some("mutability"));

    server
        .patch(
            &path,
            &token,
            json!({"Operations": [{"op": "Replace", "path": "emails", "value": [{"value": "attacker@evil.test"}]}]}),
        )
        .await
        .assert_error(Status::BadRequest, Some("mutability"));

    // Removing it is refused for the same reason.
    server
        .patch(&path, &token, json!({"Operations": [{"op": "Remove", "path": "emails"}]}))
        .await
        .assert_error(Status::BadRequest, Some("mutability"));

    let account = User::find_by_mail("primary@example.test", &server.conn().await).await.expect("account");
    assert_eq!(account.email, "primary@example.test", "the account email is untouched");
    assert!(User::find_by_mail("attacker@evil.test", &server.conn().await).await.is_none());
}

#[rocket::async_test]
async fn a_mapped_user_principal_name_and_mail_do_not_fight() {
    // Entra ID maps `userName` from `userPrincipalName` and `emails` from `mail`, and in real
    // tenants those differ for plenty of people. The account was provisioned from the UPN, so a
    // document carrying both has to resolve to the UPN -- whichever order the operations arrive
    // in, and on PUT as well as PATCH.
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;

    let created = server.post(&users_url(&org), &token, json!({"userName": "upn@example.test"})).await;
    assert_eq!(created.status, Status::Created, "{}", created.body);
    let path = format!("{}/{}", users_url(&org), created.json()["id"].as_str().unwrap());

    let put = server
        .put(
            &path,
            &token,
            json!({
                "userName": "upn@example.test",
                "emails": [{"value": "mail@example.test", "type": "work", "primary": true}],
                "active": true,
            }),
        )
        .await;
    assert_eq!(put.status, Status::Ok, "{}", put.body);

    for operations in [
        json!([
            {"op": "Replace", "path": "userName", "value": "upn@example.test"},
            {"op": "Replace", "path": "emails", "value": [{"value": "mail@example.test"}]},
        ]),
        json!([
            {"op": "Replace", "path": "emails", "value": [{"value": "mail@example.test"}]},
            {"op": "Replace", "path": "userName", "value": "upn@example.test"},
        ]),
    ] {
        let reply = server.patch(&path, &token, json!({"Operations": operations})).await;
        assert_eq!(reply.status, Status::Ok, "operation order must not decide the outcome: {}", reply.body);
    }

    // ...and `emails` on its own, with no `userName` to defer to, still asserts the identity.
    server
        .patch(
            &path,
            &token,
            json!({"Operations": [{"op": "Replace", "path": "emails", "value": [{"value": "mail@example.test"}]}]}),
        )
        .await
        .assert_error(Status::BadRequest, Some("mutability"));
}

#[rocket::async_test]
async fn a_user_name_and_a_matching_email_agree() {
    // Both spellings of the same identity in one document must not fight each other.
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let (_, membership) = server.member(&org, "alice@example.test", MembershipType::User, true).await;

    let reply = server
        .put(
            &format!("{}/{}", users_url(&org), membership.uuid),
            &token,
            json!({
                "userName": "alice@example.test",
                "emails": [{"value": "alice@example.test", "primary": true}],
                "active": true,
            }),
        )
        .await;
    assert_eq!(reply.status, Status::Ok, "{}", reply.body);
}

// -- projection on every representation ---------------------------------------------------------
//
// RFC 7644 section 3.9 allows `attributes` and `excludedAttributes` on any operation that returns
// a resource representation, not just on reads.

#[rocket::async_test]
async fn projection_applies_to_user_writes() {
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;

    let created = server
        .post(&format!("{}?attributes=userName", users_url(&org)), &token, json!({"userName": "new@example.test"}))
        .await;
    assert_eq!(created.status, Status::Created, "{}", created.body);
    let body = created.json();
    assert_eq!(body["userName"], json!("new@example.test"));
    assert!(body.get("id").is_some(), "the minimum response set survives");
    assert!(body.get("active").is_none(), "an unrequested attribute is not returned");
    assert!(body.get("emails").is_none());
    // Projection changes the representation, never the headers that identify the resource.
    assert!(created.location.is_some(), "201 still carries Location");
    assert_eq!(created.location.as_deref(), created.content_location.as_deref());

    let path = format!("{}/{}", users_url(&org), body["id"].as_str().unwrap());

    let put = server.put(&format!("{path}?excludedAttributes=emails"), &token, json!({"active": true})).await;
    assert_eq!(put.status, Status::Ok, "{}", put.body);
    assert!(put.json().get("emails").is_none());
    assert_eq!(put.json()["userName"], json!("new@example.test"), "the rest of the resource is still there");
    put.assert_content_location_matches_meta();

    let patched = server
        .patch(
            &format!("{path}?attributes=active"),
            &token,
            json!({"Operations": [{"op": "Replace", "path": "active", "value": false}]}),
        )
        .await;
    assert_eq!(patched.status, Status::Ok, "{}", patched.body);
    assert_eq!(patched.json()["active"], json!(false), "projection does not change what the write did");
    assert!(patched.json().get("userName").is_none());

    // The mutation really happened, projected response or not.
    let member_id = MembershipId::from(body["id"].as_str().unwrap().to_owned());
    let stored = server.reload_membership(&member_id, &org.uuid).await.expect("membership");
    assert!(stored.status < MembershipStatus::Invited as i32, "the member was revoked");
}

#[rocket::async_test]
async fn projection_applies_to_group_writes() {
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let (_, member) = server.member(&org, "alice@example.test", MembershipType::User, true).await;

    let created = server
        .post(
            &format!("{}?excludedAttributes=members", groups_url(&org)),
            &token,
            json!({"displayName": "Engineering", "members": [{"value": member.uuid}]}),
        )
        .await;
    assert_eq!(created.status, Status::Created, "{}", created.body);
    assert!(created.json().get("members").is_none(), "excluded from the representation");
    assert_eq!(created.json()["displayName"], json!("Engineering"));
    created.assert_content_location_matches_meta();

    let group_id = created.json()["id"].as_str().unwrap().to_owned();
    let path = format!("{}/{}", groups_url(&org), group_id);

    // ...but the member was still written: projection is about the response, not the write.
    let full = server.get(&path, &token).await.json();
    assert_eq!(full["members"][0]["value"], json!(member.uuid.to_string()));

    let put =
        server.put(&format!("{path}?attributes=displayName"), &token, json!({"displayName": "Engineering"})).await;
    assert_eq!(put.status, Status::Ok, "{}", put.body);
    assert_eq!(put.json()["displayName"], json!("Engineering"));
    assert!(put.json().get("members").is_none());
    assert!(put.json().get("externalId").is_none());

    let patched = server
        .patch(
            &format!("{path}?excludedAttributes=members"),
            &token,
            json!({"Operations": [{"op": "Remove", "path": "members", "value": [{"value": member.uuid}]}]}),
        )
        .await;
    assert_eq!(patched.status, Status::Ok, "{}", patched.body);
    assert!(patched.json().get("members").is_none());

    // And the removal happened.
    let after = server.get(&path, &token).await.json();
    assert_eq!(after["members"], json!([]));
}

#[rocket::async_test]
async fn projection_is_validated_before_a_write_happens() {
    // `attributes` and `excludedAttributes` stay mutually exclusive on every verb, and the
    // request fails before it provisions anybody.
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;

    server
        .post(
            &format!("{}?attributes=userName&excludedAttributes=emails", users_url(&org)),
            &token,
            json!({"userName": "never@example.test"}),
        )
        .await
        .assert_error(Status::BadRequest, Some("invalidValue"));

    assert!(
        Membership::find_by_email_and_org("never@example.test", &org.uuid, &server.conn().await).await.is_none(),
        "a rejected projection must not have created a membership"
    );

    server
        .post(
            &format!("{}?attributes=displayName&excludedAttributes=members", groups_url(&org)),
            &token,
            json!({"displayName": "Never"}),
        )
        .await
        .assert_error(Status::BadRequest, Some("invalidValue"));

    assert!(
        Group::find_by_organization(&org.uuid, &server.conn().await).await.is_empty(),
        "a rejected projection must not have created a group"
    );
}

// -- projection namespace isolation over the wire -----------------------------------------------

#[rocket::async_test]
async fn a_group_qualified_attribute_does_not_project_a_user() {
    // The bug this guards: parsing the projection against both core schemas at once let a
    // Group-qualified name select the User attribute that shares its last segment.
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let (_, mut membership) = server.member(&org, "alice@example.test", MembershipType::User, true).await;

    membership.set_external_id(Some("ext-1".to_owned()));
    membership.save(&server.conn().await).await.expect("set external id");
    let path = format!("{}/{}", users_url(&org), membership.uuid);

    // Selecting a Group attribute on /Users selects nothing of the User.
    let selected = server
        .get(&format!("{path}?attributes=urn:ietf:params:scim:schemas:core:2.0:Group:externalId"), &token)
        .await
        .json();
    assert!(selected.get("externalId").is_none(), "a Group-qualified name must not select the User's externalId");
    assert!(selected.get("userName").is_none());
    assert_eq!(selected["id"], json!(membership.uuid.to_string()), "the minimum response set survives");

    // Excluding one excludes nothing of the User.
    let excluded = server
        .get(&format!("{path}?excludedAttributes=urn:ietf:params:scim:schemas:core:2.0:Group:externalId"), &token)
        .await
        .json();
    assert_eq!(excluded["externalId"], json!("ext-1"), "a Group-qualified name must not exclude the User's");

    // And the User's own qualified name still works, so this is isolation rather than blanket
    // rejection.
    let own = server
        .get(&format!("{path}?attributes=urn:ietf:params:scim:schemas:core:2.0:User:externalId"), &token)
        .await
        .json();
    assert_eq!(own["externalId"], json!("ext-1"));
}

#[rocket::async_test]
async fn a_user_qualified_attribute_does_not_project_a_group() {
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let (_, member) = server.member(&org, "alice@example.test", MembershipType::User, true).await;

    let created = server
        .post(&groups_url(&org), &token, json!({"displayName": "Engineering", "members": [{"value": member.uuid}]}))
        .await;
    let path = format!("{}/{}", groups_url(&org), created.json()["id"].as_str().unwrap());

    let selected = server
        .get(&format!("{path}?attributes=urn:ietf:params:scim:schemas:core:2.0:User:displayName"), &token)
        .await
        .json();
    assert!(selected.get("displayName").is_none(), "a User-qualified name must not select the Group's displayName");

    let excluded = server
        .get(&format!("{path}?excludedAttributes=urn:ietf:params:scim:schemas:core:2.0:User:displayName"), &token)
        .await
        .json();
    assert_eq!(excluded["displayName"], json!("Engineering"));

    // A User-qualified `members` must not trigger the Group-specific membership optimisation.
    let members_kept = server
        .get(&format!("{path}?excludedAttributes=urn:ietf:params:scim:schemas:core:2.0:User:members"), &token)
        .await
        .json();
    assert_eq!(members_kept["members"][0]["value"], json!(member.uuid.to_string()), "membership must still be loaded");
}

#[rocket::async_test]
async fn an_arbitrary_extension_attribute_cannot_project_a_core_one() {
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let (_, membership) = server.member(&org, "alice@example.test", MembershipType::User, true).await;
    let path = format!("{}/{}", users_url(&org), membership.uuid);

    // An extension attribute called `active` is not the core `active`.
    let excluded = server.get(&format!("{path}?excludedAttributes=urn:example:Custom:active"), &token).await.json();
    assert_eq!(excluded["active"], json!(true), "an extension attribute must not hide a core one");

    let selected = server.get(&format!("{path}?attributes=urn:example:Custom:active"), &token).await.json();
    assert!(selected.get("active").is_none(), "an extension attribute must not select a core one");
    assert!(selected.get("userName").is_none(), "the list named nothing this server renders");
    assert_eq!(selected["id"], json!(membership.uuid.to_string()));
}

// -- the membership-loading optimisation ---------------------------------------------------------

#[rocket::async_test]
async fn membership_is_loaded_only_when_the_projection_asks_for_it() {
    // `excludedAttributes=members` is what Entra ID sends when it resolves a group by name, and
    // honouring it saves one query per group. Making projection schema-aware must not have broken
    // it -- nor started skipping the load for a projection that does need it.
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let (_, member) = server.member(&org, "alice@example.test", MembershipType::User, true).await;

    let created = server
        .post(&groups_url(&org), &token, json!({"displayName": "Engineering", "members": [{"value": member.uuid}]}))
        .await;
    let path = format!("{}/{}", groups_url(&org), created.json()["id"].as_str().unwrap());

    // Excluded outright: not loaded, so the key is absent rather than an empty array. An empty
    // array would be a lie -- the group does have a member.
    let skipped = server.get(&format!("{path}?excludedAttributes=members"), &token).await.json();
    assert!(skipped.get("members").is_none());

    // A projection that does not name `members` at all: also not loaded.
    let narrowed = server.get(&format!("{path}?attributes=displayName"), &token).await.json();
    assert!(narrowed.get("members").is_none());
    assert_eq!(narrowed["displayName"], json!("Engineering"));

    // A sub-attribute selection needs the data, so it is loaded.
    let sub = server.get(&format!("{path}?attributes=members.value"), &token).await.json();
    assert_eq!(sub["members"][0]["value"], json!(member.uuid.to_string()));
    assert!(sub["members"][0].get("$ref").is_none(), "only the named sub-attribute survives");

    // Excluding a *sub*-attribute must not skip the load either: the rest of the parent is wanted.
    let sub_excluded = server.get(&format!("{path}?excludedAttributes=members.type"), &token).await.json();
    assert_eq!(sub_excluded["members"][0]["value"], json!(member.uuid.to_string()));
    assert!(sub_excluded["members"][0].get("type").is_none());

    // The same rules on the list endpoint, which is where the per-group cost actually adds up.
    let listed = server.get(&format!("{}?excludedAttributes=members", groups_url(&org)), &token).await.json();
    assert!(listed["Resources"][0].get("members").is_none());
}

#[rocket::async_test]
async fn a_group_qualified_attribute_on_users_does_no_group_work() {
    // `/Users` has no membership to load and no group to resolve; a Group-qualified projection
    // must not change that, it must simply select nothing.
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    server.member(&org, "alice@example.test", MembershipType::User, true).await;

    let listed = server
        .get(&format!("{}?attributes=urn:ietf:params:scim:schemas:core:2.0:Group:members", users_url(&org)), &token)
        .await;
    assert_eq!(listed.status, Status::Ok, "{}", listed.body);

    let resource = &listed.json()["Resources"][0];
    assert!(resource.get("members").is_none(), "a User has no members, projected or otherwise");
    assert!(resource.get("userName").is_none(), "the list named nothing this server renders on a User");
    assert!(resource.get("id").is_some());
}

// -- filter operator/type validation over the wire ------------------------------------------------
//
// A filter whose operator cannot apply to the attribute's type used to evaluate to "no match",
// which a client cannot tell apart from a correct filter over an empty directory. It is a
// `400`/`invalidFilter` now, with a detail that says what is wrong.

#[rocket::async_test]
async fn a_semantically_invalid_filter_is_a_400_not_an_empty_list() {
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    server.member(&org, "alice@example.test", MembershipType::User, true).await;

    for filter in [
        // Substring and ordering operators on a boolean.
        "active%20co%20true",
        "active%20gt%20true",
        "active%20sw%20false",
        "active%20ew%20true",
        "active%20ge%20false",
        "active%20lt%20true",
        "active%20le%20true",
        // A literal that is not a boolean at all.
        "active%20eq%20%22yes%22",
        "active%20eq%201",
        // A complex attribute compared directly.
        "emails%20eq%20%22alice@example.test%22",
        // `null` with an operator that cannot use it.
        "externalId%20co%20null",
    ] {
        let reply = server.get(&format!("{}?filter={filter}", users_url(&org)), &token).await;
        reply.assert_error(Status::BadRequest, Some("invalidFilter"));
        assert!(!reply.body.is_empty(), "the error should say what is wrong: {filter}");
    }

    // Groups too.
    server
        .get(&format!("{}?filter=members%20eq%20%22m1%22", groups_url(&org)), &token)
        .await
        .assert_error(Status::BadRequest, Some("invalidFilter"));
}

#[rocket::async_test]
async fn valid_boolean_filters_still_work() {
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    server.member(&org, "active@example.test", MembershipType::User, true).await;
    let (_, mut revoked) = server.member(&org, "revoked@example.test", MembershipType::User, true).await;
    revoked.revoke();
    revoked.save(&server.conn().await).await.expect("revoke");

    let active = server.get(&format!("{}?filter=active%20eq%20true", users_url(&org)), &token).await;
    assert_eq!(active.json()["totalResults"], json!(1), "{}", active.body);
    assert_eq!(active.json()["Resources"][0]["userName"], json!("active@example.test"));

    let inactive = server.get(&format!("{}?filter=active%20eq%20false", users_url(&org)), &token).await;
    assert_eq!(inactive.json()["totalResults"], json!(1), "{}", inactive.body);
    assert_eq!(inactive.json()["Resources"][0]["userName"], json!("revoked@example.test"));

    let ne = server.get(&format!("{}?filter=active%20ne%20true", users_url(&org)), &token).await;
    assert_eq!(ne.json()["totalResults"], json!(1), "{}", ne.body);

    let present = server.get(&format!("{}?filter=active%20pr", users_url(&org)), &token).await;
    assert_eq!(present.json()["totalResults"], json!(2), "{}", present.body);

    // A quoted boolean is still a boolean: Entra ID sends them that way in some flows.
    let quoted = server.get(&format!("{}?filter=active%20eq%20%22true%22", users_url(&org)), &token).await;
    assert_eq!(quoted.json()["totalResults"], json!(1), "{}", quoted.body);
}

#[rocket::async_test]
async fn an_unquoted_value_on_a_string_attribute_is_still_text() {
    // The tokenizer types a literal by shape. Against a string attribute the literal text is what
    // the client meant, so a numeric-looking externalId must not become a type mismatch that
    // matches nothing.
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let (_, mut membership) = server.member(&org, "alice@example.test", MembershipType::User, true).await;

    membership.set_external_id(Some("12345".to_owned()));
    membership.save(&server.conn().await).await.expect("set external id");

    let unquoted = server.get(&format!("{}?filter=externalId%20eq%2012345", users_url(&org)), &token).await;
    assert_eq!(unquoted.json()["totalResults"], json!(1), "{}", unquoted.body);

    let quoted = server.get(&format!("{}?filter=externalId%20eq%20%2212345%22", users_url(&org)), &token).await;
    assert_eq!(quoted.json()["totalResults"], json!(1), "{}", quoted.body);
}

#[rocket::async_test]
async fn a_null_comparison_tests_for_absence() {
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let (_, mut with) = server.member(&org, "with@example.test", MembershipType::User, true).await;
    server.member(&org, "without@example.test", MembershipType::User, true).await;

    with.set_external_id(Some("ext-1".to_owned()));
    with.save(&server.conn().await).await.expect("set external id");

    let absent = server.get(&format!("{}?filter=externalId%20eq%20null", users_url(&org)), &token).await;
    assert_eq!(absent.json()["totalResults"], json!(1), "{}", absent.body);
    assert_eq!(absent.json()["Resources"][0]["userName"], json!("without@example.test"));

    let present = server.get(&format!("{}?filter=externalId%20ne%20null", users_url(&org)), &token).await;
    assert_eq!(present.json()["totalResults"], json!(1), "{}", present.body);
    assert_eq!(present.json()["Resources"][0]["userName"], json!("with@example.test"));
}

// =============================================================================================
// PATCH atomicity (RFC 7644 section 3.5.2)
// =============================================================================================
//
// "If any operation fails, the service provider SHALL return the resource to its original state."
// The only side effect in the User write path that can fail *after* the row has been saved is the
// invitation a reactivation issues, so that is the failure these tests force. Every SCIM-visible
// field the request touched has to come back, not just the one the side effect belonged to.
//
// No event assertions here: `log_event` is a no-op unless `ORG_EVENTS_ENABLED` is set, and that is
// read from the process environment, which a test cannot change in a crate that forbids `unsafe`.
// The property is structural instead -- the rollback returns before any `log_event` call -- and is
// noted in docs/scim/design.md section 7.

/// Provision an inactive member carrying `externalId`, and return its SCIM id.
async fn inactive_member_with_external_id(server: &TestServer, org: &Organization, token: &str, email: &str) -> String {
    let created =
        server.post(&users_url(org), token, json!({"userName": email, "externalId": "old", "active": false})).await;
    assert_eq!(created.status, Status::Created, "{}", created.body);
    created.json()["id"].as_str().unwrap().to_owned()
}

#[rocket::async_test]
async fn a_failed_reactivation_rolls_back_every_field_the_patch_changed() {
    // The motivating case. Before: `active = false`, `externalId = "old"`. The PATCH asks for both
    // `externalId = "new"` and `active = true`; the invitation the reactivation needs then fails.
    //
    // An earlier revision re-revoked the membership but deliberately kept `externalId = "new"`, on
    // the grounds that directory metadata is "correct anyway". That left the resource in a state
    // the client never asked for -- half of a document it was told had failed -- and no response
    // said so.
    let server = TestServer::with_exclusive_settings().await;
    let (org, token) = server.org("acme").await;
    let member_id = inactive_member_with_external_id(&server, &org, &token, "rollback@example.test").await;
    let path = format!("{}/{}", users_url(&org), member_id);

    let combined = json!({"Operations": [
        {"op": "Replace", "path": "externalId", "value": "new"},
        {"op": "Replace", "path": "active", "value": true},
    ]});

    server.set_invitation_fails(true);
    let failed = server.patch(&path, &token, combined.clone()).await;
    assert_eq!(failed.status, Status::InternalServerError, "{}", failed.body);

    let id = MembershipId::from(member_id.clone());
    let stored = server.reload_membership(&id, &org.uuid).await.expect("membership");
    assert!(stored.status < MembershipStatus::Invited as i32, "the membership must be revoked again");
    assert_eq!(stored.external_id.as_deref(), Some("old"), "and the externalId the same PATCH set must be back");

    // The representation a client reads back agrees with the row.
    let after = server.get(&path, &token).await;
    assert_eq!(after.json()["active"], json!(false));
    assert_eq!(after.json()["externalId"], json!("old"));

    // The retry the identity provider makes next succeeds, and applies the whole document.
    server.set_invitation_fails(false);
    let retried = server.patch(&path, &token, combined).await;
    assert_eq!(retried.status, Status::Ok, "{}", retried.body);
    assert_eq!(retried.json()["active"], json!(true));
    assert_eq!(retried.json()["externalId"], json!("new"));

    let stored = server.reload_membership(&id, &org.uuid).await.expect("membership");
    assert!(stored.status > MembershipStatus::Revoked as i32);
    assert_eq!(stored.external_id.as_deref(), Some("new"));
    assert!(
        Invitation::find_by_mail("rollback@example.test", &server.conn().await).await.is_some(),
        "the retry issued the invitation the first attempt could not"
    );
}

#[rocket::async_test]
async fn a_failed_reactivation_through_put_rolls_back_too() {
    // `PUT` has no explicit atomicity requirement in RFC 7644, but it runs the same write path and
    // can leave the same half-applied state, so it gets the same rollback.
    let server = TestServer::with_exclusive_settings().await;
    let (org, token) = server.org("acme").await;
    let member_id = inactive_member_with_external_id(&server, &org, &token, "putback@example.test").await;
    let path = format!("{}/{}", users_url(&org), member_id);

    server.set_invitation_fails(true);
    let failed = server
        .put(&path, &token, json!({"userName": "putback@example.test", "externalId": "new", "active": true}))
        .await;
    assert_eq!(failed.status, Status::InternalServerError, "{}", failed.body);

    let stored = server.reload_membership(&MembershipId::from(member_id), &org.uuid).await.expect("membership");
    assert!(stored.status < MembershipStatus::Invited as i32);
    assert_eq!(stored.external_id.as_deref(), Some("old"));
}

#[rocket::async_test]
async fn a_failed_reactivation_rolls_back_a_cleared_external_id() {
    // `remove` is a change too: a document that clears `externalId` and reactivates has to put the
    // old value back, not leave the attribute unset.
    let server = TestServer::with_exclusive_settings().await;
    let (org, token) = server.org("acme").await;
    let member_id = inactive_member_with_external_id(&server, &org, &token, "cleared@example.test").await;
    let path = format!("{}/{}", users_url(&org), member_id);

    server.set_invitation_fails(true);
    server
        .patch(
            &path,
            &token,
            json!({"Operations": [
                {"op": "Remove", "path": "externalId"},
                {"op": "Replace", "path": "active", "value": true},
            ]}),
        )
        .await
        .assert_error(Status::InternalServerError, None);

    let stored = server.reload_membership(&MembershipId::from(member_id), &org.uuid).await.expect("membership");
    assert_eq!(stored.external_id.as_deref(), Some("old"), "a cleared externalId comes back too");
    assert!(stored.status < MembershipStatus::Invited as i32);
}

#[rocket::async_test]
async fn a_reactivation_restores_the_exact_previous_status_on_rollback() {
    // `restore()` returns a membership to whatever it was before -- Invited, Accepted or Confirmed
    // -- so a rollback that only knew "it was inactive" could put a Confirmed member back as
    // Invited and silently deprovision their access.
    let server = TestServer::with_exclusive_settings().await;
    let (org, token) = server.org("acme").await;
    let (_, mut membership) = server.member(&org, "confirmed@example.test", MembershipType::User, false).await;

    // Confirmed, then revoked: the stored status encodes "was Confirmed".
    membership.revoke();
    membership.save(&server.conn().await).await.expect("revoke");
    let revoked_status = server.reload_membership(&membership.uuid, &org.uuid).await.expect("membership").status;

    server.set_invitation_fails(true);
    server
        .patch(
            &format!("{}/{}", users_url(&org), membership.uuid),
            &token,
            json!({"Operations": [{"op": "Replace", "path": "active", "value": true}]}),
        )
        .await
        .assert_error(Status::InternalServerError, None);

    let stored = server.reload_membership(&membership.uuid, &org.uuid).await.expect("membership");
    assert_eq!(stored.status, revoked_status, "the exact status is restored, not merely 'revoked'");
}

#[rocket::async_test]
async fn a_successful_patch_is_unaffected_by_the_rollback_path() {
    // The ordinary case still writes both fields and issues the invitation exactly once.
    let server = TestServer::with_exclusive_settings().await;
    let (org, token) = server.org("acme").await;
    let member_id = inactive_member_with_external_id(&server, &org, &token, "happy@example.test").await;
    let path = format!("{}/{}", users_url(&org), member_id);

    let reply = server
        .patch(
            &path,
            &token,
            json!({"Operations": [
                {"op": "Replace", "path": "externalId", "value": "new"},
                {"op": "Replace", "path": "active", "value": true},
            ]}),
        )
        .await;
    assert_eq!(reply.status, Status::Ok, "{}", reply.body);
    assert_eq!(reply.json()["externalId"], json!("new"));
    assert_eq!(reply.json()["active"], json!(true));
    assert!(Invitation::find_by_mail("happy@example.test", &server.conn().await).await.is_some());
}

#[rocket::async_test]
async fn a_combined_patch_that_fails_validation_writes_nothing_at_all() {
    // The other half of atomicity, and the cheaper one: a document whose *planning* fails never
    // reaches the database, so there is nothing to roll back. Combined documents, not just
    // single-operation ones -- the operation that fails is deliberately not the first.
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let (_, membership) = server.member(&org, "alice@example.test", MembershipType::User, true).await;
    let path = format!("{}/{}", users_url(&org), membership.uuid);

    for (operations, status, scim_type) in [
        // A valid change followed by an immutable assertion.
        (
            json!([
                {"op": "Replace", "path": "externalId", "value": "should-not-stick"},
                {"op": "Replace", "path": "active", "value": false},
                {"op": "Replace", "path": "userName", "value": "attacker@evil.test"},
            ]),
            Status::BadRequest,
            Some("mutability"),
        ),
        // A valid change followed by an unsupported path.
        (
            json!([
                {"op": "Replace", "path": "externalId", "value": "should-not-stick"},
                {"op": "Replace", "path": "nonsense", "value": "x"},
            ]),
            Status::BadRequest,
            Some("invalidPath"),
        ),
        // A valid change followed by a value the schema cannot accept.
        (
            json!([
                {"op": "Replace", "path": "externalId", "value": "should-not-stick"},
                {"op": "Replace", "path": "active", "value": "maybe"},
            ]),
            Status::BadRequest,
            Some("invalidValue"),
        ),
    ] {
        server.patch(&path, &token, json!({"Operations": operations})).await.assert_error(status, scim_type);

        let stored = server.reload_membership(&membership.uuid, &org.uuid).await.expect("membership");
        assert_eq!(stored.external_id, None, "the earlier operation in the same document must not have been applied");
        assert!(stored.status > MembershipStatus::Revoked as i32, "and neither must the deactivation");
    }
}

#[rocket::async_test]
async fn repeated_operations_on_one_attribute_resolve_to_the_last() {
    // A document may touch the same attribute more than once. The change set is a plan, so the
    // last operation wins and exactly one write happens -- rather than two writes, or a rollback
    // that only knows about one of them.
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let (_, membership) = server.member(&org, "alice@example.test", MembershipType::User, true).await;
    let path = format!("{}/{}", users_url(&org), membership.uuid);

    let reply = server
        .patch(
            &path,
            &token,
            json!({"Operations": [
                {"op": "Replace", "path": "externalId", "value": "first"},
                {"op": "Replace", "path": "externalId", "value": "second"},
                {"op": "Replace", "path": "active", "value": false},
                {"op": "Replace", "path": "active", "value": true},
            ]}),
        )
        .await;
    assert_eq!(reply.status, Status::Ok, "{}", reply.body);
    assert_eq!(reply.json()["externalId"], json!("second"));
    assert_eq!(reply.json()["active"], json!(true), "the membership was never revoked on the way through");

    let stored = server.reload_membership(&membership.uuid, &org.uuid).await.expect("membership");
    assert_eq!(stored.external_id.as_deref(), Some("second"));
    assert!(stored.status > MembershipStatus::Revoked as i32);
}

// =============================================================================================
// Rate-limit budgets
// =============================================================================================
//
// Three budgets, and these tests are about which one a given request draws on. The counters come
// from `settings::test_overrides` and are only readable under the exclusive settings lock, so no
// other test can be incrementing them at the same time.

#[rocket::async_test]
async fn malformed_credentials_never_reach_the_provisioning_limiter_or_the_database() {
    // Junk is settled from the request headers alone: the strict budget, and nothing else. Neither
    // the provisioning budget nor the pre-verification budget is even consulted, and no key row is
    // ever fetched.
    let server = TestServer::with_exclusive_settings().await;
    let (org, token) = server.org("acme").await;
    let key_id = token.split('.').nth(1).unwrap().to_owned();
    let secret = token.rsplit('.').next().unwrap().to_owned();

    server.reset_counters();

    let junk = [
        String::new(),
        "not-a-token".to_owned(),
        format!("scim_v2.{key_id}.{secret}"),
        format!("scim_v1.{key_id}"),
        format!("scim_v1.{key_id}.{secret}.extra"),
        format!("scim_v1..{secret}"),
        format!("scim_v1.{key_id}."),
        format!("scim_v1.not-a-uuid.{secret}"),
        format!("scim_v1.{key_id}.short"),
        format!("scim_v1.{key_id}.{secret}+"),
    ];
    for bad in &junk {
        server.get(&users_url(&org), bad).await.assert_generic_bearer_challenge();
    }
    server.get_unauthenticated(&users_url(&org)).await.assert_generic_bearer_challenge();

    assert_eq!(server.unauthenticated_checks(), junk.len() + 1, "every one is charged to the strict budget");
    assert_eq!(server.provisioning_checks(), 0, "and none of them to the provisioning budget");
    assert_eq!(server.pre_auth_checks(), 0, "nor to the pre-verification budget");
    assert_eq!(server.key_lookups(), 0, "and none of them cost a database lookup");
}

#[rocket::async_test]
async fn structurally_valid_junk_is_bounded_before_the_database_is_asked() {
    // The gap this budget closes. A credential of the right shape cannot be told apart from a real
    // one without an indexed lookup and a hash comparison, so before this the strict budget could
    // only throttle the *next* attempt: every request of a spray still bought a database round trip
    // on its way to a 429.
    //
    // With the pre-verification budget exhausted, the same requests cost nothing at all.
    let server = TestServer::with_exclusive_settings().await;
    let (org, token) = server.org("acme").await;
    let key_id = token.split('.').nth(1).unwrap().to_owned();

    // First, with budget: a valid-looking credential does reach the database and is rejected.
    server.reset_counters();
    let spray: Vec<String> = (0..5)
        .map(|_| format!("scim_v1.{}.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", crate::util::get_uuid()))
        .collect();
    for credential in &spray {
        server.get(&users_url(&org), credential).await.assert_generic_bearer_challenge();
    }
    assert_eq!(server.pre_auth_checks(), spray.len(), "each one is charged before the lookup");
    assert_eq!(server.key_lookups(), spray.len(), "and each one costs exactly one lookup");
    assert_eq!(server.unauthenticated_checks(), spray.len(), "the failures are still charged to the strict budget");

    // Now exhaust it. The same requests -- and a real key id with a wrong secret, and even the
    // organization's own valid token -- are refused without the database being asked at all.
    server.set_pre_auth_rate_limit_exhausted(true);
    server.reset_counters();

    for credential in &spray {
        server.get(&users_url(&org), credential).await.assert_error(Status::TooManyRequests, None);
    }
    server
        .get(&users_url(&org), &format!("scim_v1.{key_id}.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
        .await
        .assert_error(Status::TooManyRequests, None);
    server.get(&users_url(&org), &token).await.assert_error(Status::TooManyRequests, None);

    assert_eq!(server.key_lookups(), 0, "nothing reached the database");
    assert_eq!(server.provisioning_checks(), 0, "and a throttled request draws on no other budget");
    assert_eq!(server.unauthenticated_checks(), 0, "including the strict one: a 429 is not an auth failure");
}

#[rocket::async_test]
async fn a_malformed_credential_is_still_rejected_when_only_the_pre_verification_budget_is_gone() {
    // The budgets stay separate in this direction too: exhausting the one that gates the database
    // must not change how junk that never gets that far is answered.
    let server = TestServer::with_exclusive_settings().await;
    let (org, _token) = server.org("acme").await;

    server.set_pre_auth_rate_limit_exhausted(true);
    server.reset_counters();

    server.get(&users_url(&org), "not-a-token").await.assert_generic_bearer_challenge();
    assert_eq!(server.pre_auth_checks(), 0, "a malformed credential never reaches that budget");
    assert_eq!(server.unauthenticated_checks(), 1);
}

#[rocket::async_test]
async fn authenticated_traffic_is_charged_to_the_provisioning_budget_alone() {
    let server = TestServer::with_exclusive_settings().await;
    let (org, token) = server.org("acme").await;

    server.reset_counters();
    assert_eq!(server.get(&users_url(&org), &token).await.status, Status::Ok);

    assert_eq!(server.provisioning_checks(), 1);
    assert_eq!(server.unauthenticated_checks(), 0, "a request that authenticated is not an authentication failure");
    assert_eq!(server.pre_auth_checks(), 1, "it is charged for the lookup it caused, like any other well-formed token");
    assert_eq!(server.key_lookups(), 1);
}

#[rocket::async_test]
async fn two_organizations_on_one_address_have_independent_provisioning_budgets() {
    // Two tenants syncing through one NAT, proxy or Microsoft egress address is a normal
    // deployment. Keyed by address alone -- what an earlier revision did -- organization A's burst
    // would throttle organization B, and B's operator would have no way to see why.
    let server = TestServer::with_exclusive_settings().await;
    let (org_a, token_a) = server.org("acme").await;
    let (org_b, token_b) = server.org("globex").await;

    server.reset_counters();
    assert_eq!(server.get(&users_url(&org_a), &token_a).await.status, Status::Ok);
    assert_eq!(server.get(&users_url(&org_b), &token_b).await.status, Status::Ok);

    // Both requests came from the same client address, and produced two different keys.
    let keys = server.provisioning_keys();
    assert_eq!(keys.len(), 2);
    assert_eq!(keys[0].1, keys[1].1, "the local client is one address");
    assert_eq!(keys[0].0, org_a.uuid);
    assert_eq!(keys[1].0, org_b.uuid);

    // Exhausting one organization's budget leaves the other's untouched.
    server.set_rate_limited_org(Some(&org_a.uuid));
    server.get(&users_url(&org_a), &token_a).await.assert_error(Status::TooManyRequests, None);
    assert_eq!(
        server.get(&users_url(&org_b), &token_b).await.status,
        Status::Ok,
        "one tenant's burst must not throttle another on the same address"
    );

    // ...and the throttled organization is genuinely throttled, not merely slowed.
    server.get(&users_url(&org_a), &token_a).await.assert_error(Status::TooManyRequests, None);
}

#[rocket::async_test]
async fn the_provisioning_budget_is_keyed_by_the_authenticated_organization_not_the_url() {
    // The organization in the URL is attacker-controlled until the token has proved it. Keying by
    // it would let anyone mint limiter entries for organizations that do not exist, and would put a
    // forged request in a real tenant's bucket.
    let server = TestServer::with_exclusive_settings().await;
    let (org, token) = server.org("acme").await;
    let unknown = crate::util::get_uuid();

    server.reset_counters();

    // A valid token against somebody else's path is an authentication failure: it never reaches
    // the provisioning budget, so no key is created for the path organization.
    server.get(&format!("/scim/v2/{unknown}/Users"), &token).await.assert_generic_bearer_challenge();
    assert!(server.provisioning_keys().is_empty(), "a failed request creates no provisioning key");

    // The one key that does get created names the organization on the key row, paired with the
    // address the request came from.
    assert_eq!(server.get(&users_url(&org), &token).await.status, Status::Ok);
    let keys = server.provisioning_keys();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].0, org.uuid, "the key names the organization the token authenticated, not the URL");
}

// =============================================================================================
// WWW-Authenticate (RFC 6750 / RFC 7235)
// =============================================================================================

#[rocket::async_test]
async fn every_401_carries_the_same_generic_bearer_challenge() {
    // `/ServiceProviderConfig` advertises `oauthbearertoken` and points at RFC 6750, so a 401 owes
    // the client a challenge. It must be the *same* challenge every time: a `realm` naming the
    // organization, or an `error_description` naming the cause, would turn the header into the
    // tenant-existence oracle the response body carefully is not.
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let (org_b, token_b) = server.org("globex").await;
    let key_id = token.split('.').nth(1).unwrap();
    let secret = token.rsplit('.').next().unwrap();
    let unknown_org = crate::util::get_uuid();

    let replies = vec![
        // Missing Authorization.
        server.get_unauthenticated(&users_url(&org)).await,
        // Malformed token.
        server.get(&users_url(&org), "not-a-token").await,
        server.get(&users_url(&org), &format!("scim_v1.{key_id}")).await,
        // Unknown key id, well-formed secret.
        server.get(&users_url(&org), &format!("scim_v1.{}.{secret}", crate::util::get_uuid())).await,
        // Real key, wrong secret.
        server.get(&users_url(&org), &format!("scim_v1.{key_id}.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")).await,
        // A valid token for the wrong organization.
        server.get(&users_url(&org), &token_b).await,
        // ...and the same token against an organization that does not exist at all.
        server.get(&format!("/scim/v2/{unknown_org}/Users"), &token_b).await,
        // Discovery is no different.
        server.get_unauthenticated(&format!("/scim/v2/{}/ServiceProviderConfig", org_b.uuid)).await,
    ];

    for reply in &replies {
        reply.assert_generic_bearer_challenge();
        reply.assert_scim_content_type();
        assert_eq!(reply.body, replies[0].body, "the bodies stay byte-identical too");
        assert_eq!(
            reply.www_authenticate.as_deref(),
            Some("Bearer"),
            "no realm, no error, no error_description: {:?}",
            reply.www_authenticate
        );
    }
}

#[rocket::async_test]
async fn responses_that_are_not_401_carry_no_challenge() {
    // The header belongs to an authentication failure and nothing else. On a 403 or a 404 it would
    // invite a client to retry with different credentials, which is not the problem.
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let (_, owner) = server.member(&org, "owner@example.test", MembershipType::Owner, true).await;

    let ok = server.get(&users_url(&org), &token).await;
    assert_eq!(ok.status, Status::Ok);
    assert!(ok.www_authenticate.is_none());

    let forbidden = server.delete(&format!("{}/{}", users_url(&org), owner.uuid), &token).await;
    forbidden.assert_error(Status::Forbidden, None);
    assert!(forbidden.www_authenticate.is_none());

    let missing = server.get(&format!("{}/nope", users_url(&org)), &token).await;
    missing.assert_error(Status::NotFound, None);
    assert!(missing.www_authenticate.is_none());
}

// =============================================================================================
// emails value paths (RFC 7644 section 3.5.2, Microsoft Entra ID)
// =============================================================================================
//
// Entra documents `emails[type eq "work" and primary eq true].value`. This server renders exactly
// one virtual element -- `{"value": <account email>, "type": "work", "primary": true}` -- so the
// selector has a definite answer, and the sub-attribute decides what the operation means.

#[rocket::async_test]
async fn the_entra_email_value_path_asserts_the_account_address() {
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let (_, membership) = server.member(&org, "alice@example.test", MembershipType::User, true).await;
    let path = format!("{}/{}", users_url(&org), membership.uuid);

    // The address that is already there: the no-op an identity provider sends on every sync.
    for selector in [
        r#"emails[type eq "work" and primary eq true].value"#,
        r#"emails[type eq "work"].value"#,
        "emails[primary eq true].value",
        r#"emails[value eq "alice@example.test"].value"#,
    ] {
        let reply = server
            .patch(
                &path,
                &token,
                json!({"Operations": [{"op": "Replace", "path": selector, "value": "alice@example.test"}]}),
            )
            .await;
        assert_eq!(reply.status, Status::Ok, "{selector} should be a no-op: {}", reply.body);
    }

    // A different address through the same path is still an account rename, and still refused.
    server
        .patch(
            &path,
            &token,
            json!({"Operations": [{
                "op": "Replace",
                "path": r#"emails[type eq "work" and primary eq true].value"#,
                "value": "attacker@evil.test",
            }]}),
        )
        .await
        .assert_error(Status::BadRequest, Some("mutability"));

    assert!(User::find_by_mail("attacker@evil.test", &server.conn().await).await.is_none());
}

#[rocket::async_test]
async fn an_email_selector_that_matches_nothing_is_a_no_target() {
    // RFC 7644 sections 3.5.2.2 and 3.5.2.3. An earlier revision treated every path whose base was
    // `emails` as the same assertion, so `emails[type eq "home"].value` quietly became a write to
    // the work address -- the selector was parsed and then ignored.
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let (_, membership) = server.member(&org, "alice@example.test", MembershipType::User, true).await;
    let path = format!("{}/{}", users_url(&org), membership.uuid);

    for selector in [
        // Wrong type.
        r#"emails[type eq "home"].value"#,
        r#"emails[type eq "other"].value"#,
        // Not the primary element.
        "emails[primary eq false].value",
        r#"emails[type eq "work" and primary eq false].value"#,
        // A value that is not this account's address.
        r#"emails[value eq "someone@else.test"].value"#,
        // A conjunction where only one half matches.
        r#"emails[type eq "home" and primary eq true].value"#,
    ] {
        for op in ["Replace", "Add", "Remove"] {
            server
                .patch(
                    &path,
                    &token,
                    json!({"Operations": [{"op": op, "path": selector, "value": "alice@example.test"}]}),
                )
                .await
                .assert_error(Status::BadRequest, Some("noTarget"));
        }
    }
}

#[rocket::async_test]
async fn the_derived_parts_of_an_email_cannot_be_changed() {
    // `type` and `primary` are published `readOnly` -- this server derives both as `"work"` and
    // `true`. They follow the same three-outcome rule as the other unwritable attributes here:
    // re-asserting the derived value is the no-op a client sending the whole element performs, and
    // anything else is a `mutability` fault.
    //
    // Accepting a write to either as if it were `.value`, which is what ignoring the sub-attribute
    // amounted to, turned `emails[...].type = "someone@else"` into an account rename attempt.
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let (user, membership) = server.member(&org, "alice@example.test", MembershipType::User, true).await;
    let path = format!("{}/{}", users_url(&org), membership.uuid);

    for (selector, value) in [
        (r#"emails[type eq "work" and primary eq true].type"#, json!("home")),
        (r#"emails[type eq "work"].primary"#, json!(false)),
        // ...including an address smuggled in through the read-only sub-attribute.
        (r#"emails[type eq "work"].type"#, json!("attacker@evil.test")),
        // ...and without a selector at all.
        ("emails.type", json!("home")),
        ("emails.primary", json!(false)),
    ] {
        server
            .patch(&path, &token, json!({"Operations": [{"op": "Replace", "path": selector, "value": value}]}))
            .await
            .assert_error(Status::BadRequest, Some("mutability"));
    }

    // Re-asserting what the server already renders is accepted, so a client echoing the element
    // back does not fail over an attribute it could not have sent differently.
    for (selector, value) in [
        (r#"emails[type eq "work" and primary eq true].type"#, json!("work")),
        (r#"emails[type eq "work"].primary"#, json!(true)),
        ("emails.type", json!("work")),
    ] {
        let reply = server
            .patch(&path, &token, json!({"Operations": [{"op": "Replace", "path": selector, "value": value}]}))
            .await;
        assert_eq!(reply.status, Status::Ok, "{selector} should be a no-op: {}", reply.body);
    }

    let stored = User::find_by_uuid(&user.uuid, &server.conn().await).await.expect("account");
    assert_eq!(stored.email, "alice@example.test", "nothing was renamed");
    assert!(User::find_by_mail("attacker@evil.test", &server.conn().await).await.is_none());
}

#[rocket::async_test]
async fn an_email_value_selection_must_be_a_single_value_path() {
    // A PATCH path is split on the first `[` and the last `]`, so the selector text can carry
    // brackets of its own. `emails[type eq "home"] or emails[type eq "work"].value` would otherwise
    // parse into a disjunction and select the element through a clause the client never targeted.
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let (_, membership) = server.member(&org, "alice@example.test", MembershipType::User, true).await;
    let path = format!("{}/{}", users_url(&org), membership.uuid);

    for selector in [
        r#"emails[type eq "home"] or emails[type eq "work"].value"#,
        r#"emails[type eq "home"] or userName eq "alice@example.test"].value"#,
    ] {
        server
            .patch(
                &path,
                &token,
                json!({"Operations": [{"op": "Replace", "path": selector, "value": "alice@example.test"}]}),
            )
            .await
            .assert_error(Status::BadRequest, Some("invalidPath"));
    }
}

#[rocket::async_test]
async fn an_explicit_email_value_path_needs_an_address() {
    // Skipping a `.value` write whose value carries no address would report success for a write
    // that did nothing, which is how a broken attribute mapping goes unnoticed.
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let (_, membership) = server.member(&org, "alice@example.test", MembershipType::User, true).await;
    let path = format!("{}/{}", users_url(&org), membership.uuid);

    for value in [json!(123), json!(true), Value::Null, json!({"type": "work"})] {
        server
            .patch(
                &path,
                &token,
                json!({"Operations": [{
                    "op": "Replace",
                    "path": r#"emails[type eq "work"].value"#,
                    "value": value,
                }]}),
            )
            .await
            .assert_error(Status::BadRequest, Some("invalidValue"));
    }

    // A bare `emails` path stays lenient: an element without a `value` asserts no identity at all.
    let lenient = server
        .patch(&path, &token, json!({"Operations": [{"op": "Replace", "path": "emails", "value": [{"type": "work"}]}]}))
        .await;
    assert_eq!(lenient.status, Status::Ok, "{}", lenient.body);
}

#[rocket::async_test]
async fn an_unknown_email_sub_attribute_is_an_invalid_path() {
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let (_, membership) = server.member(&org, "alice@example.test", MembershipType::User, true).await;
    let path = format!("{}/{}", users_url(&org), membership.uuid);

    for selector in [r#"emails[type eq "work"].nonsense"#, "emails.nonsense", r#"emails[type eq "work"].value.extra"#] {
        server
            .patch(&path, &token, json!({"Operations": [{"op": "Replace", "path": selector, "value": "x"}]}))
            .await
            .assert_error(Status::BadRequest, Some("invalidPath"));
    }
}

#[rocket::async_test]
async fn a_malformed_or_arbitrary_email_selector_is_an_invalid_path() {
    // `emails[whatever eq "x"]` must not be quietly treated as the real element. The selector goes
    // through the validated filter parser, which knows this resource type's attributes, so an
    // attribute that is not one of them is a client error rather than a silent match.
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let (_, membership) = server.member(&org, "alice@example.test", MembershipType::User, true).await;
    let path = format!("{}/{}", users_url(&org), membership.uuid);

    for selector in [
        r#"emails[whatever eq "x"].value"#,
        r#"emails[userName eq "alice@example.test"].value"#,
        "emails[type eq].value",
        r#"emails[type "work"].value"#,
        "emails[].value",
        r#"emails[primary co "true"].value"#,
    ] {
        let reply = server
            .patch(
                &path,
                &token,
                json!({"Operations": [{"op": "Replace", "path": selector, "value": "alice@example.test"}]}),
            )
            .await;
        assert_eq!(reply.status, Status::BadRequest, "{selector} should be refused: {}", reply.body);
        assert_eq!(
            reply.json()["scimType"],
            json!("invalidPath"),
            "{selector} must not be read as the real email element: {}",
            reply.body
        );
    }
}

#[rocket::async_test]
async fn an_extension_namespaced_email_path_is_ignored_not_applied() {
    // The namespace rule and the value-path rule have to compose. An extension attribute whose last
    // segment is `emails` is not this server's `emails`, brackets or no brackets, so it is ignored
    // rather than evaluated -- and certainly not treated as an assertion about the account email.
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let (user, membership) = server.member(&org, "alice@example.test", MembershipType::User, true).await;
    let path = format!("{}/{}", users_url(&org), membership.uuid);

    for selector in [
        r#"urn:example:Custom:emails[type eq "work"].value"#,
        "urn:example:Custom:emails.value",
        r#"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:emails[type eq "home"].value"#,
    ] {
        let reply = server
            .patch(
                &path,
                &token,
                json!({"Operations": [{"op": "Replace", "path": selector, "value": "attacker@evil.test"}]}),
            )
            .await;
        assert_eq!(reply.status, Status::Ok, "{selector} should be ignored: {}", reply.body);
    }

    // The core-qualified spelling, by contrast, *is* the real attribute and follows the real rules.
    server
        .patch(
            &path,
            &token,
            json!({"Operations": [{
                "op": "Replace",
                "path": r#"urn:ietf:params:scim:schemas:core:2.0:User:emails[type eq "work"].value"#,
                "value": "attacker@evil.test",
            }]}),
        )
        .await
        .assert_error(Status::BadRequest, Some("mutability"));

    let stored = User::find_by_uuid(&user.uuid, &server.conn().await).await.expect("account");
    assert_eq!(stored.email, "alice@example.test");
    assert!(User::find_by_mail("attacker@evil.test", &server.conn().await).await.is_none());
}

#[rocket::async_test]
async fn a_simple_attribute_has_no_sub_attribute() {
    // `active` is a boolean, not a complex attribute. Ignoring the sub-attribute and writing the
    // parent would let `active.whatever` deprovision somebody through a path this schema does not
    // define.
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let (_, membership) = server.member(&org, "alice@example.test", MembershipType::User, true).await;
    let path = format!("{}/{}", users_url(&org), membership.uuid);

    for selector in ["active.whatever", "externalId.value", "userName.value", "displayName.formatted"] {
        server
            .patch(&path, &token, json!({"Operations": [{"op": "Replace", "path": selector, "value": false}]}))
            .await
            .assert_error(Status::BadRequest, Some("invalidPath"));
    }

    let stored = server.reload_membership(&membership.uuid, &org.uuid).await.expect("membership");
    assert!(stored.status > MembershipStatus::Revoked as i32, "nothing was deprovisioned");
}

// =============================================================================================
// name.* is input compatibility, not schema support
// =============================================================================================

#[rocket::async_test]
async fn name_parts_name_a_new_account_and_nothing_else() {
    // The deliberate policy: `POST` accepts `name.*` as a fallback so an identity provider that
    // maps only `name` still creates a usefully named account, and no other operation looks at it.
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;

    let created = server
        .post(
            &users_url(&org),
            &token,
            json!({"userName": "formatted@example.test", "name": {"formatted": "Alice Example"}}),
        )
        .await;
    assert_eq!(created.status, Status::Created, "{}", created.body);
    assert_eq!(created.json()["displayName"], json!("Alice Example"));
    assert_eq!(
        User::find_by_mail("formatted@example.test", &server.conn().await).await.expect("account").name,
        "Alice Example"
    );

    // givenName/familyName are joined when there is no `formatted`.
    let joined = server
        .post(
            &users_url(&org),
            &token,
            json!({"userName": "joined@example.test", "name": {"givenName": "Bob", "familyName": "Builder"}}),
        )
        .await;
    assert_eq!(joined.status, Status::Created, "{}", joined.body);
    assert_eq!(joined.json()["displayName"], json!("Bob Builder"));

    // `displayName` still wins over `name` when both are sent.
    let both = server
        .post(
            &users_url(&org),
            &token,
            json!({
                "userName": "both@example.test",
                "displayName": "From displayName",
                "name": {"formatted": "From name"},
            }),
        )
        .await;
    assert_eq!(both.status, Status::Created, "{}", both.body);
    assert_eq!(both.json()["displayName"], json!("From displayName"));

    // ...and `name` is never echoed back: it is not an attribute of this resource.
    assert!(created.json().get("name").is_none(), "an unsupported attribute must not appear in the representation");
}

#[rocket::async_test]
async fn name_parts_are_ignored_on_an_account_that_already_exists() {
    // The inconsistency this fixes. `PUT` used to fall back from `displayName` to `name.formatted`
    // and then assert the result against the stored account name, so an identity provider that
    // mapped `name` -- and whose `name` differed from the account's -- got a `mutability` fault
    // about `displayName`, an attribute it had never sent. `PATCH` had always ignored `name`. Now
    // both ignore it.
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let (user, membership) = server.member(&org, "alice@example.test", MembershipType::User, true).await;
    let path = format!("{}/{}", users_url(&org), membership.uuid);

    let put = server
        .put(
            &path,
            &token,
            json!({
                "userName": "alice@example.test",
                "name": {"formatted": "Someone Else", "givenName": "Someone", "familyName": "Else"},
                "active": true,
            }),
        )
        .await;
    assert_eq!(put.status, Status::Ok, "an unsupported attribute must not fail the request: {}", put.body);

    let patched = server
        .patch(
            &path,
            &token,
            json!({"Operations": [
                {"op": "Replace", "path": "name.formatted", "value": "Someone Else"},
                {"op": "Replace", "value": {"name": {"givenName": "Someone"}}},
            ]}),
        )
        .await;
    assert_eq!(patched.status, Status::Ok, "{}", patched.body);

    let stored = User::find_by_uuid(&user.uuid, &server.conn().await).await.expect("account");
    assert_eq!(stored.name, "alice@example.test", "the account name is untouched by either verb");

    // `displayName` itself is still asserted, so the immutability rule has not been weakened.
    server
        .put(&path, &token, json!({"userName": "alice@example.test", "displayName": "Someone Else"}))
        .await
        .assert_error(Status::BadRequest, Some("mutability"));
}

#[rocket::async_test]
async fn name_is_not_advertised_as_a_supported_attribute() {
    // Discovery is the statement of the policy: `name` is not part of this resource, which is why
    // no operation on an existing account reinterprets it.
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;

    let schema =
        server.get(&format!("/scim/v2/{}/Schemas/urn:ietf:params:scim:schemas:core:2.0:User", org.uuid), &token).await;
    let names: Vec<String> = schema.json()["attributes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["name"].as_str().unwrap().to_owned())
        .collect();

    assert!(!names.iter().any(|n| n == "name"), "published attributes were {names:?}");
    assert!(names.iter().any(|n| n == "displayName"), "but displayName is published: {names:?}");
}

// =============================================================================================
// Discovery: /Schemas completeness
// =============================================================================================

#[rocket::async_test]
async fn schemas_publishes_every_schema_the_server_uses() {
    // RFC 7643 section 7: "For every schema URI used in a resource object, there is a corresponding
    // 'Schema' resource." The three discovery resources announce their own URNs, so they need their
    // own definitions -- which RFC 7643 section 8.7.2 provides.
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;

    let listed = server.get(&format!("/scim/v2/{}/Schemas", org.uuid), &token).await;
    listed.assert_scim_content_type();
    let body = listed.json();

    let ids: HashSet<String> =
        body["Resources"].as_array().unwrap().iter().map(|s| s["id"].as_str().unwrap().to_owned()).collect();

    let expected: HashSet<String> = [
        "urn:ietf:params:scim:schemas:core:2.0:User",
        "urn:ietf:params:scim:schemas:core:2.0:Group",
        "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig",
        "urn:ietf:params:scim:schemas:core:2.0:ResourceType",
        "urn:ietf:params:scim:schemas:core:2.0:Schema",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();

    assert_eq!(ids, expected);
    assert_eq!(body["totalResults"], json!(5));
    assert_eq!(body["itemsPerPage"], json!(5));

    // Every one of them announces itself as a Schema resource and is fetchable at its own location.
    for schema in body["Resources"].as_array().unwrap() {
        assert_eq!(schema["schemas"], json!(["urn:ietf:params:scim:schemas:core:2.0:Schema"]), "{schema}");
        assert_eq!(schema["meta"]["resourceType"], json!("Schema"), "{schema}");
        assert!(schema["attributes"].as_array().is_some_and(|a| !a.is_empty()), "{schema}");
    }
}

#[rocket::async_test]
async fn every_published_schema_resolves_by_direct_lookup() {
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let base = format!("/scim/v2/{}", org.uuid);

    let listed = server.get(&format!("{base}/Schemas"), &token).await.json();
    for schema in listed["Resources"].as_array().unwrap() {
        let id = schema["id"].as_str().unwrap();
        let direct = server.get(&format!("{base}/Schemas/{id}"), &token).await;

        assert_eq!(direct.status, Status::Ok, "{id}: {}", direct.body);
        assert_eq!(direct.json(), *schema, "the listing and the direct lookup must agree for {id}");
        direct.assert_content_location_matches_meta();

        // URNs are case-insensitive, and the ResourceTypes lookup beside this one already is.
        let upper = server.get(&format!("{base}/Schemas/{}", id.to_uppercase()), &token).await;
        assert_eq!(upper.status, Status::Ok, "{id} should resolve however it is spelled: {}", upper.body);
    }
}

#[rocket::async_test]
async fn an_unknown_schema_is_a_404() {
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let base = format!("/scim/v2/{}", org.uuid);

    for unknown in [
        "urn:made:up",
        // Real SCIM URNs this server does not publish, because they are protocol messages rather
        // than resources.
        "urn:ietf:params:scim:api:messages:2.0:ListResponse",
        "urn:ietf:params:scim:api:messages:2.0:PatchOp",
        "urn:ietf:params:scim:api:messages:2.0:Error",
        // An extension this server does not implement.
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
    ] {
        server.get(&format!("{base}/Schemas/{unknown}"), &token).await.assert_error(Status::NotFound, None);
    }
}

#[rocket::async_test]
async fn the_group_schema_disappears_with_groups() {
    // A schema for an endpoint that answers 501 is an advertisement for something that does not
    // work, exactly as the resource type would be.
    let server = TestServer::with_exclusive_settings().await;
    let (org, token) = server.org("acme").await;
    let base = format!("/scim/v2/{}", org.uuid);

    server.set_groups_enabled(false);

    let listed = server.get(&format!("{base}/Schemas"), &token).await.json();
    let ids: Vec<String> =
        listed["Resources"].as_array().unwrap().iter().map(|s| s["id"].as_str().unwrap().to_owned()).collect();

    assert!(!ids.iter().any(|id| id == "urn:ietf:params:scim:schemas:core:2.0:Group"), "{ids:?}");
    assert!(ids.iter().any(|id| id == "urn:ietf:params:scim:schemas:core:2.0:User"), "{ids:?}");
    assert_eq!(listed["totalResults"], json!(4));

    server
        .get(&format!("{base}/Schemas/urn:ietf:params:scim:schemas:core:2.0:Group"), &token)
        .await
        .assert_error(Status::NotFound, None);

    // The other four are unaffected.
    for id in &ids {
        assert_eq!(server.get(&format!("{base}/Schemas/{id}"), &token).await.status, Status::Ok, "{id}");
    }
}

#[rocket::async_test]
async fn the_group_member_reference_advertises_only_what_it_accepts() {
    // Nested groups are not implemented: a Group id sent as a member is refused as a member that is
    // not in the organization. `referenceTypes: ["User", "Group"]` -- the stock RFC value -- would
    // invite exactly the request this server rejects.
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;

    let schema = server
        .get(&format!("/scim/v2/{}/Schemas/urn:ietf:params:scim:schemas:core:2.0:Group", org.uuid), &token)
        .await
        .json();
    let members = schema_attribute(&schema, "members");

    let reference = sub_attribute(members, "$ref");
    assert_eq!(reference["type"], json!("reference"));
    assert_eq!(reference["referenceTypes"], json!(["User"]), "no nested groups: {reference}");
    assert_eq!(sub_attribute(members, "type")["canonicalValues"], json!(["User"]));

    // And the behaviour the advertisement describes: a group id is not a member.
    let group = server.group(&org, "Eng", None).await;
    let other = server.group(&org, "Other", None).await;
    server
        .patch(
            &format!("{}/{}", groups_url(&org), group.uuid),
            &token,
            json!({"Operations": [{"op": "Add", "path": "members", "value": [{"value": other.uuid}]}]}),
        )
        .await
        .assert_error(Status::BadRequest, Some("invalidValue"));
}

#[rocket::async_test]
async fn the_discovery_schemas_describe_what_discovery_actually_emits() {
    // A schema that does not match its own resource is worse than no schema: it tells a client to
    // expect fields that are not there. These check the three definitions against the documents the
    // very same server returns.
    /// Every top-level attribute name a schema publishes.
    fn published(schema: &Value) -> HashSet<String> {
        schema["attributes"].as_array().unwrap().iter().map(|a| a["name"].as_str().unwrap().to_owned()).collect()
    }

    /// Every key a resource emits, minus the ones every resource has.
    fn emitted(resource: &Value) -> HashSet<String> {
        resource
            .as_object()
            .unwrap()
            .keys()
            .filter(|k| !matches!(k.as_str(), "schemas" | "id" | "meta"))
            .cloned()
            .collect()
    }

    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;
    let base = format!("/scim/v2/{}", org.uuid);

    let config_schema = server
        .get(&format!("{base}/Schemas/urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"), &token)
        .await
        .json();
    let config = server.get(&format!("{base}/ServiceProviderConfig"), &token).await.json();
    assert!(
        emitted(&config).is_subset(&published(&config_schema)),
        "emitted {:?} vs published {:?}",
        emitted(&config),
        published(&config_schema)
    );
    assert!(published(&config_schema).contains("etag"), "the server emits `etag`, so the schema has to describe it");

    let type_schema =
        server.get(&format!("{base}/Schemas/urn:ietf:params:scim:schemas:core:2.0:ResourceType"), &token).await.json();
    let types = server.get(&format!("{base}/ResourceTypes"), &token).await.json();
    for resource_type in types["Resources"].as_array().unwrap() {
        assert!(
            emitted(resource_type).is_subset(&published(&type_schema)),
            "emitted {:?} vs published {:?}",
            emitted(resource_type),
            published(&type_schema)
        );
    }

    let schema_schema =
        server.get(&format!("{base}/Schemas/urn:ietf:params:scim:schemas:core:2.0:Schema"), &token).await.json();
    let published_here = published(&schema_schema);
    for schema in server.get(&format!("{base}/Schemas"), &token).await.json()["Resources"].as_array().unwrap() {
        assert!(
            emitted(schema).is_subset(&published_here),
            "emitted {:?} vs published {published_here:?}",
            emitted(schema)
        );
    }
}

// =============================================================================================
// Query parameters on writes
// =============================================================================================

#[rocket::async_test]
async fn unknown_query_parameters_on_a_write_are_ignored_not_rejected() {
    // Documenting Rocket 0.5's actual behaviour rather than an assumption about it. Query parsing
    // is lenient: a field the handler's query type does not declare is skipped. RFC 7644 defines
    // no error for an unrecognised query parameter either, and identity providers do append their
    // own, so nothing here tries to be stricter -- but the comment next to `ProjectionQuery` used
    // to claim these were rejected, which they never were.
    let server = TestServer::new().await;
    let (org, token) = server.org("acme").await;

    let created = server
        .post(
            &format!("{}?filter=userName%20eq%20%22x%22&startIndex=5&count=99&unknown=1", users_url(&org)),
            &token,
            json!({"userName": "querystring@example.test"}),
        )
        .await;
    assert_eq!(created.status, Status::Created, "unknown query parameters must not fail a write: {}", created.body);
    assert_eq!(created.json()["userName"], json!("querystring@example.test"));

    let path = format!("{}/{}", users_url(&org), created.json()["id"].as_str().unwrap());

    // ...and the projection parameters that *are* declared still work alongside them.
    let projected = server
        .patch(
            &format!("{path}?attributes=userName&filter=nonsense&count=abc"),
            &token,
            json!({"Operations": [{"op": "Replace", "path": "externalId", "value": "ext-1"}]}),
        )
        .await;
    assert_eq!(projected.status, Status::Ok, "{}", projected.body);
    assert_eq!(projected.json()["userName"], json!("querystring@example.test"));
    assert!(projected.json().get("externalId").is_none(), "the declared projection was applied: {}", projected.body);

    // On a *list* endpoint the same names are real parameters, and are still validated.
    server
        .get(&format!("{}?count=abc", users_url(&org)), &token)
        .await
        .assert_error(Status::BadRequest, Some("invalidValue"));
}

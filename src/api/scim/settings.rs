//! Server settings and fallible side effects the SCIM module reaches through, behind a thin
//! indirection.
//!
//! In a running server these are plain reads of [`crate::CONFIG`], calls into the shared rate
//! limiter, and a direct call to the shared provisioning helper. The indirection exists so the
//! test suite can drive the real request path -- guard, routing, catchers and all -- with specific
//! settings, which it otherwise could not do: `std::env::set_var` is `unsafe` and this crate
//! forbids unsafe code, and `Config::update_config` persists a `config.json` into the operator's
//! data folder. It is also the only way to exercise the rollback that runs when a side effect
//! fails after a write has been persisted.
//!
//! The non-test implementations below are the whole production behaviour; nothing test-specific
//! is compiled into a release build.

#[cfg(not(test))]
use std::net::IpAddr;

#[cfg(not(test))]
use crate::{
    api::EmptyResult,
    db::{DbConn, models::Membership},
};

#[cfg(not(test))]
pub fn scim_enabled() -> bool {
    crate::CONFIG.scim_enabled()
}

#[cfg(not(test))]
pub fn groups_enabled() -> bool {
    crate::CONFIG.org_groups_enabled()
}

/// The high-volume provisioning budget, charged **only to requests that authenticated**, and keyed
/// by the authenticated organization as well as the client address.
///
/// A directory sync is inherently high-volume, so this budget is generous. That is exactly why
/// nothing unauthenticated may draw on it: see [`check_auth_rate_limit`].
#[cfg(not(test))]
pub fn check_rate_limit(org_id: &crate::db::models::OrganizationId, ip: &IpAddr) -> Result<(), ()> {
    crate::ratelimit::check_limit_scim(org_id, ip)
}

/// Budget for authentication *attempts* that did not succeed.
///
/// A request with no bearer credential, one whose token is not even the right shape, and one whose
/// secret is simply wrong are all charged here -- to Vaultwarden's existing strict unauthenticated
/// limiter -- and never to the provisioning budget. A flood of junk therefore cannot consume the
/// allowance a real sync needs, and conversely a saturated provisioning budget cannot stop the
/// server from rejecting junk.
#[cfg(not(test))]
pub fn check_auth_rate_limit(ip: &IpAddr) -> Result<(), ()> {
    crate::ratelimit::check_limit_unauthenticated(ip).map_err(|_| ())
}

/// Budget for authentication attempts this server is willing to *verify*, charged before the key
/// lookup runs.
///
/// A token of the right shape cannot be told apart from a real one without a database round trip,
/// so this is what bounds the database work a credential spray can cause. See
/// `docs/scim/design.md` section 5.
#[cfg(not(test))]
pub fn check_pre_auth_rate_limit(ip: &IpAddr) -> Result<(), ()> {
    crate::ratelimit::check_limit_scim_auth(ip)
}

/// Marks the point at which a request costs a database lookup for its key.
///
/// A no-op in a real server. The test suite counts these to prove that a request rejected by the
/// pre-verification budget never reached the database at all.
#[cfg(not(test))]
#[inline]
pub fn note_key_lookup() {}

/// Issue the invitation a reactivated membership needs.
///
/// A straight call to the shared provisioning helper. It is routed through here so the test suite
/// can make it fail on demand and exercise the rollback in `apply_user_changes`, which is
/// otherwise unreachable: every real cause of failure is a database state SQLite's foreign keys
/// will not let a test construct.
#[cfg(not(test))]
pub async fn ensure_invitation(member: &Membership, conn: &DbConn) -> EmptyResult {
    crate::api::core::organizations::ensure_invitation_for(member, conn).await
}

#[cfg(test)]
pub use test_overrides::{
    check_auth_rate_limit, check_pre_auth_rate_limit, check_rate_limit, ensure_invitation, groups_enabled,
    note_key_lookup, scim_enabled,
};

#[cfg(test)]
pub(in crate::api::scim) mod test_overrides {
    use std::{
        net::IpAddr,
        sync::{
            Mutex,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
    };

    use crate::{
        api::EmptyResult,
        db::{
            DbConn,
            models::{Membership, OrganizationId},
        },
    };

    /// Defaults match a server with SCIM and groups switched on, which is what most tests want.
    /// Tests that need a different value hold the settings write lock in `e2e.rs` while they
    /// change it, so they cannot disturb tests running in parallel.
    pub(in crate::api::scim) static SCIM_ENABLED: AtomicBool = AtomicBool::new(true);
    pub(in crate::api::scim) static GROUPS_ENABLED: AtomicBool = AtomicBool::new(true);
    pub(in crate::api::scim) static UNAUTH_RATE_LIMIT_EXHAUSTED: AtomicBool = AtomicBool::new(false);
    pub(in crate::api::scim) static PRE_AUTH_RATE_LIMIT_EXHAUSTED: AtomicBool = AtomicBool::new(false);
    pub(in crate::api::scim) static INVITATION_FAILS: AtomicBool = AtomicBool::new(false);

    /// How many times each limiter was consulted, so a test can assert which budget a request was
    /// charged to rather than inferring it from a status code alone.
    pub(in crate::api::scim) static RATE_LIMIT_CHECKS: AtomicUsize = AtomicUsize::new(0);
    pub(in crate::api::scim) static UNAUTH_RATE_LIMIT_CHECKS: AtomicUsize = AtomicUsize::new(0);
    pub(in crate::api::scim) static PRE_AUTH_RATE_LIMIT_CHECKS: AtomicUsize = AtomicUsize::new(0);
    /// How many times a request got as far as fetching a key row from the database.
    pub(in crate::api::scim) static KEY_LOOKUPS: AtomicUsize = AtomicUsize::new(0);

    /// When set, only this organization's provisioning budget is exhausted. That is what lets a
    /// test show two organizations on one address have independent allowances: a limiter keyed by
    /// address alone could not tell them apart.
    pub(in crate::api::scim) static RATE_LIMITED_ORG: Mutex<Option<OrganizationId>> = Mutex::new(None);
    /// Every `(organization, address)` pair the provisioning limiter was charged against.
    pub(in crate::api::scim) static RATE_LIMIT_KEYS: Mutex<Vec<(OrganizationId, IpAddr)>> = Mutex::new(Vec::new());

    /// Put every override back to its default. Called by the harness for tests that hold the
    /// exclusive settings lock, so one cannot leak state into the next.
    pub(in crate::api::scim) fn reset() {
        SCIM_ENABLED.store(true, Ordering::Relaxed);
        GROUPS_ENABLED.store(true, Ordering::Relaxed);
        UNAUTH_RATE_LIMIT_EXHAUSTED.store(false, Ordering::Relaxed);
        PRE_AUTH_RATE_LIMIT_EXHAUSTED.store(false, Ordering::Relaxed);
        INVITATION_FAILS.store(false, Ordering::Relaxed);

        RATE_LIMIT_CHECKS.store(0, Ordering::Relaxed);
        UNAUTH_RATE_LIMIT_CHECKS.store(0, Ordering::Relaxed);
        PRE_AUTH_RATE_LIMIT_CHECKS.store(0, Ordering::Relaxed);
        KEY_LOOKUPS.store(0, Ordering::Relaxed);

        *RATE_LIMITED_ORG.lock().expect("rate-limited organization") = None;
        RATE_LIMIT_KEYS.lock().expect("rate-limit keys").clear();
    }

    pub fn scim_enabled() -> bool {
        SCIM_ENABLED.load(Ordering::Relaxed)
    }

    pub fn groups_enabled() -> bool {
        GROUPS_ENABLED.load(Ordering::Relaxed)
    }

    pub fn check_rate_limit(org_id: &OrganizationId, ip: &IpAddr) -> Result<(), ()> {
        RATE_LIMIT_CHECKS.fetch_add(1, Ordering::Relaxed);
        RATE_LIMIT_KEYS.lock().expect("rate-limit keys").push((org_id.clone(), *ip));

        let limited = RATE_LIMITED_ORG.lock().expect("rate-limited organization");
        if limited.as_ref().is_some_and(|limited| limited == org_id) {
            Err(())
        } else {
            Ok(())
        }
    }

    pub fn check_auth_rate_limit(_ip: &IpAddr) -> Result<(), ()> {
        UNAUTH_RATE_LIMIT_CHECKS.fetch_add(1, Ordering::Relaxed);
        if UNAUTH_RATE_LIMIT_EXHAUSTED.load(Ordering::Relaxed) {
            Err(())
        } else {
            Ok(())
        }
    }

    pub fn check_pre_auth_rate_limit(_ip: &IpAddr) -> Result<(), ()> {
        PRE_AUTH_RATE_LIMIT_CHECKS.fetch_add(1, Ordering::Relaxed);
        if PRE_AUTH_RATE_LIMIT_EXHAUSTED.load(Ordering::Relaxed) {
            Err(())
        } else {
            Ok(())
        }
    }

    pub fn note_key_lookup() {
        KEY_LOOKUPS.fetch_add(1, Ordering::Relaxed);
    }

    /// The real helper unless a test has asked for it to fail, so every invitation test still
    /// exercises the production behaviour.
    pub async fn ensure_invitation(member: &Membership, conn: &DbConn) -> EmptyResult {
        if INVITATION_FAILS.load(Ordering::Relaxed) {
            err!("Forced invitation failure")
        }
        crate::api::core::organizations::ensure_invitation_for(member, conn).await
    }
}

//! Server settings the SCIM module reads, behind a thin indirection.
//!
//! In a running server these are plain reads of [`crate::CONFIG`] and the shared rate limiter.
//! The indirection exists so the test suite can drive the real request path -- guard, routing,
//! catchers and all -- with specific settings, which it otherwise could not do: `std::env::set_var`
//! is `unsafe` and this crate forbids unsafe code, and `Config::update_config` persists a
//! `config.json` into the operator's data folder.
//!
//! The non-test implementations below are the whole production behaviour; nothing test-specific
//! is compiled into a release build.

#[cfg(not(test))]
use std::net::IpAddr;

#[cfg(not(test))]
pub fn scim_enabled() -> bool {
    crate::CONFIG.scim_enabled()
}

#[cfg(not(test))]
pub fn groups_enabled() -> bool {
    crate::CONFIG.org_groups_enabled()
}

/// The high-volume provisioning budget, charged **only to requests that authenticated**.
///
/// A directory sync is inherently high-volume, so this budget is generous. That is exactly why
/// nothing unauthenticated may draw on it: see [`check_auth_rate_limit`].
#[cfg(not(test))]
pub fn check_rate_limit(ip: &IpAddr) -> Result<(), ()> {
    crate::ratelimit::check_limit_scim(ip)
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

#[cfg(test)]
pub use test_overrides::{check_auth_rate_limit, check_rate_limit, groups_enabled, scim_enabled};

#[cfg(test)]
pub(in crate::api::scim) mod test_overrides {
    use std::{
        net::IpAddr,
        sync::atomic::{AtomicBool, Ordering},
    };

    /// Defaults match a server with SCIM and groups switched on, which is what most tests want.
    /// Tests that need a different value hold the settings write lock in `tests.rs` while they
    /// change it, so they cannot disturb tests running in parallel.
    pub(in crate::api::scim) static SCIM_ENABLED: AtomicBool = AtomicBool::new(true);
    pub(in crate::api::scim) static GROUPS_ENABLED: AtomicBool = AtomicBool::new(true);
    pub(in crate::api::scim) static RATE_LIMIT_EXHAUSTED: AtomicBool = AtomicBool::new(false);
    pub(in crate::api::scim) static UNAUTH_RATE_LIMIT_EXHAUSTED: AtomicBool = AtomicBool::new(false);

    pub fn scim_enabled() -> bool {
        SCIM_ENABLED.load(Ordering::Relaxed)
    }

    pub fn groups_enabled() -> bool {
        GROUPS_ENABLED.load(Ordering::Relaxed)
    }

    pub fn check_rate_limit(_ip: &IpAddr) -> Result<(), ()> {
        if RATE_LIMIT_EXHAUSTED.load(Ordering::Relaxed) {
            Err(())
        } else {
            Ok(())
        }
    }

    pub fn check_auth_rate_limit(_ip: &IpAddr) -> Result<(), ()> {
        if UNAUTH_RATE_LIMIT_EXHAUSTED.load(Ordering::Relaxed) {
            Err(())
        } else {
            Ok(())
        }
    }
}

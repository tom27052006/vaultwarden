use std::{
    net::IpAddr,
    num::NonZeroU32,
    sync::{
        LazyLock,
        atomic::{AtomicI64, Ordering},
    },
    time::Duration,
};

use governor::{
    Quota, RateLimiter,
    clock::DefaultClock,
    state::keyed::{DashMapStateStore, ShrinkableKeyedStateStore},
};

use crate::{CONFIG, Error, db::models::OrganizationId};

type Limiter<T = IpAddr> = RateLimiter<T, DashMapStateStore<T>, DefaultClock>;

/// The key the authenticated SCIM provisioning limiter is charged against.
///
/// Keyed by tenant *and* source address, not by address alone. Two organizations syncing through
/// the same NAT, proxy or Microsoft egress address are a normal deployment, and one of them
/// exhausting its burst must not throttle the other. Both halves are bounded: the organization id
/// comes from the key row that was just authenticated -- never from the URL -- so no key can exist
/// for an organization that does not, and an attacker cannot mint entries without a valid token.
pub type ScimTenantKey = (OrganizationId, IpAddr);

static LIMITER_LOGIN: LazyLock<Limiter> = LazyLock::new(|| {
    let seconds = Duration::from_secs(CONFIG.login_ratelimit_seconds());
    let burst = NonZeroU32::new(CONFIG.login_ratelimit_max_burst()).expect("Non-zero login ratelimit burst");
    RateLimiter::keyed(Quota::with_period(seconds).expect("Non-zero login ratelimit seconds").allow_burst(burst))
});

static LIMITER_ADMIN: LazyLock<Limiter> = LazyLock::new(|| {
    let seconds = Duration::from_secs(CONFIG.admin_ratelimit_seconds());
    let burst = NonZeroU32::new(CONFIG.admin_ratelimit_max_burst()).expect("Non-zero admin ratelimit burst");
    RateLimiter::keyed(Quota::with_period(seconds).expect("Non-zero admin ratelimit seconds").allow_burst(burst))
});

/// Provisioning traffic from an identity provider, charged only once a request has authenticated.
///
/// Expressed as a sustained rate rather than "one request per N seconds", because a directory
/// sync is inherently high-volume: a first full sync of a few thousand members is several
/// thousand requests, and a limiter that replenishes once a minute would stretch that over days.
#[cfg_attr(
    test,
    expect(dead_code, reason = "the SCIM test suite substitutes a limiter it can drive deterministically")
)]
static LIMITER_SCIM: LazyLock<Limiter<ScimTenantKey>> = LazyLock::new(|| {
    let per_second = NonZeroU32::new(CONFIG.scim_ratelimit_per_second()).expect("Non-zero SCIM ratelimit rate");
    let burst = NonZeroU32::new(CONFIG.scim_ratelimit_max_burst()).expect("Non-zero SCIM ratelimit burst");
    RateLimiter::keyed(Quota::per_second(per_second).allow_burst(burst))
});

/// Budget for SCIM *authentication attempts* that are worth verifying, charged before any
/// database work happens.
///
/// A credential of the right shape cannot be recognised as wrong without one indexed row fetch
/// and a hash comparison, so without this an attacker who has already exhausted the strict
/// unauthenticated budget can keep paying for that lookup on every request: the 429 would be
/// decided only after the database had already been asked. This budget is consulted *first*, so
/// a spray is bounded before it costs anything.
///
/// Sized well above the provisioning budget on purpose: every request with a well-formed token
/// is charged here, including the ones that go on to authenticate, so it must never be the
/// constraint a legitimate sync hits first -- including several tenants syncing through one
/// address.
#[cfg_attr(
    test,
    expect(dead_code, reason = "the SCIM test suite substitutes a limiter it can drive deterministically")
)]
static LIMITER_SCIM_AUTH: LazyLock<Limiter> = LazyLock::new(|| {
    let per_second =
        NonZeroU32::new(CONFIG.scim_auth_ratelimit_per_second()).expect("Non-zero SCIM auth ratelimit rate");
    let burst = NonZeroU32::new(CONFIG.scim_auth_ratelimit_max_burst()).expect("Non-zero SCIM auth ratelimit burst");
    RateLimiter::keyed(Quota::per_second(per_second).allow_burst(burst))
});

static LIMITER_UNAUTHENTICATED: LazyLock<Limiter> = LazyLock::new(|| {
    let seconds = Duration::from_secs(CONFIG.unauthenticated_ratelimit_seconds());
    let burst = NonZeroU32::new(CONFIG.unauthenticated_ratelimit_max_burst())
        .expect("Non-zero unauthenticated ratelimit burst");
    RateLimiter::keyed(
        Quota::with_period(seconds).expect("Non-zero unauthenticated ratelimit seconds").allow_burst(burst),
    )
});

// ---------------------------------------------------------------------------------------------
// Keyed state housekeeping
// ---------------------------------------------------------------------------------------------

/// Live keys a SCIM limiter may hold before a prune is considered worthwhile.
const SCIM_PRUNE_THRESHOLD: usize = 10_000;
/// Shortest interval between two prunes of the same limiter, in seconds.
///
/// `retain_recent` walks the whole state store, so it must not be able to run per request. With
/// this floor the housekeeping cost is bounded no matter how many distinct keys arrive.
const SCIM_PRUNE_INTERVAL_SECS: i64 = 60;

/// Drop rate-limit state that is indistinguishable from "never seen".
///
/// `governor`'s DashMap state store keeps an entry per key until it is asked to let go, so a
/// limiter keyed by source address accumulates one small entry per address that ever reached it.
/// Vaultwarden's other limiters have always behaved this way; the SCIM ones prune themselves so
/// the new keys this module introduces cannot become a growth vector of their own.
///
/// Deliberately opportunistic: nothing is walked while the store is small, and never more often
/// than [`SCIM_PRUNE_INTERVAL_SECS`].
fn prune_if_stale<K>(limiter: &Limiter<K>, last_pruned: &AtomicI64)
where
    K: std::hash::Hash + Eq + Clone,
    DashMapStateStore<K>: ShrinkableKeyedStateStore<K>,
{
    if limiter.len() <= SCIM_PRUNE_THRESHOLD {
        return;
    }

    let now = chrono::Utc::now().timestamp();
    let previous = last_pruned.load(Ordering::Relaxed);
    if now - previous < SCIM_PRUNE_INTERVAL_SECS {
        return;
    }
    // Only the thread that wins the swap does the walk; the others carry on unthrottled.
    if last_pruned.compare_exchange(previous, now, Ordering::Relaxed, Ordering::Relaxed).is_err() {
        return;
    }

    limiter.retain_recent();
}

static SCIM_PRUNED_AT: AtomicI64 = AtomicI64::new(0);
static SCIM_AUTH_PRUNED_AT: AtomicI64 = AtomicI64::new(0);

pub fn check_limit_unauthenticated(ip: &IpAddr) -> Result<(), Error> {
    match LIMITER_UNAUTHENTICATED.check_key(ip) {
        Ok(()) => Ok(()),
        Err(_e) => {
            err_code!("Too many requests", 429);
        }
    }
}

pub fn check_limit_login(ip: &IpAddr) -> Result<(), Error> {
    match LIMITER_LOGIN.check_key(ip) {
        Ok(()) => Ok(()),
        Err(_e) => {
            err_code!("Too many login requests", 429);
        }
    }
}

/// Rate limit for SCIM provisioning traffic, applied **after** a request has authenticated.
///
/// Keyed by `(organization, ip)`: it covers expensive listing/filter requests and writes, and is
/// deliberately more lenient than the login limiter because identity providers sync in bursts.
/// One organization's burst cannot eat another's allowance merely because both sync from the same
/// address.
///
/// Authentication *attempts* are not charged here: a request that fails to authenticate -- no
/// token, a malformed one, or a wrong one -- goes to [`check_limit_unauthenticated`] instead, and
/// one that is merely well-formed is bounded by [`check_limit_scim_auth`] before it costs a
/// database lookup. See `docs/scim/design.md` section 5.
#[cfg_attr(
    test,
    expect(dead_code, reason = "the SCIM test suite substitutes a limiter it can drive deterministically")
)]
pub fn check_limit_scim(org_id: &OrganizationId, ip: &IpAddr) -> Result<(), ()> {
    prune_if_stale(&LIMITER_SCIM, &SCIM_PRUNED_AT);
    LIMITER_SCIM.check_key(&(org_id.clone(), *ip)).map_err(|_| ())
}

/// Rate limit for SCIM authentication attempts that are worth a database lookup, applied
/// **before** the key row is fetched.
///
/// Keyed by source address only: the organization a request claims comes from the URL and is
/// entirely attacker-controlled at this point, so keying by it would let anyone mint unbounded
/// limiter entries. See `docs/scim/design.md` section 5.
#[cfg_attr(
    test,
    expect(dead_code, reason = "the SCIM test suite substitutes a limiter it can drive deterministically")
)]
pub fn check_limit_scim_auth(ip: &IpAddr) -> Result<(), ()> {
    prune_if_stale(&LIMITER_SCIM_AUTH, &SCIM_AUTH_PRUNED_AT);
    LIMITER_SCIM_AUTH.check_key(ip).map_err(|_| ())
}

pub fn check_limit_admin(ip: &IpAddr) -> Result<(), Error> {
    match LIMITER_ADMIN.check_key(ip) {
        Ok(()) => Ok(()),
        Err(_e) => {
            err_code!("Too many admin requests", 429);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn tenant_limiter(burst: u32) -> Limiter<ScimTenantKey> {
        RateLimiter::keyed(Quota::per_second(NonZeroU32::new(1).unwrap()).allow_burst(NonZeroU32::new(burst).unwrap()))
    }

    fn org(name: &str) -> OrganizationId {
        OrganizationId::from(name.to_owned())
    }

    #[test]
    fn one_tenants_burst_does_not_throttle_another_on_the_same_address() {
        // The whole point of keying the provisioning budget by `(organization, ip)`: two
        // organizations behind one NAT or one Microsoft egress address must not share an
        // allowance. Keyed by address alone, the second organization would be refused here.
        let limiter = tenant_limiter(2);
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);

        assert!(limiter.check_key(&(org("a"), ip)).is_ok());
        assert!(limiter.check_key(&(org("a"), ip)).is_ok());
        assert!(limiter.check_key(&(org("a"), ip)).is_err(), "organization A has spent its burst");

        assert!(limiter.check_key(&(org("b"), ip)).is_ok(), "organization B has its own budget");
        assert!(limiter.check_key(&(org("b"), ip)).is_ok());
    }

    #[test]
    fn one_tenant_is_still_bounded() {
        // Independence must not become "unbounded": a single organization still runs out.
        let limiter = tenant_limiter(2);
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);

        assert!(limiter.check_key(&(org("a"), ip)).is_ok());
        assert!(limiter.check_key(&(org("a"), ip)).is_ok());
        for _ in 0..10 {
            assert!(limiter.check_key(&(org("a"), ip)).is_err());
        }
    }

    #[test]
    fn one_tenant_is_bounded_per_address() {
        // The address is part of the key too, so a single organization does not get one global
        // allowance shared by every client that holds its token.
        let limiter = tenant_limiter(1);
        let a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let b = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));

        assert!(limiter.check_key(&(org("a"), a)).is_ok());
        assert!(limiter.check_key(&(org("a"), a)).is_err());
        assert!(limiter.check_key(&(org("a"), b)).is_ok());
    }

    #[test]
    fn pruning_drops_state_that_is_indistinguishable_from_unseen() {
        // The bound on key growth. `retain_recent` keeps only keys whose bucket is still drawn
        // down; a key that has fully replenished is the same as one that was never seen.
        let limiter: Limiter<ScimTenantKey> = tenant_limiter(1);
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);

        for i in 0..50 {
            drop(limiter.check_key(&(org(&format!("org-{i}")), ip)));
        }
        assert_eq!(limiter.len(), 50);

        // Nothing has replenished yet, so a prune keeps every key rather than resetting budgets.
        limiter.retain_recent();
        assert_eq!(limiter.len(), 50, "pruning must not hand out fresh budgets");
    }

    #[test]
    fn pruning_is_skipped_while_the_store_is_small() {
        // The opportunistic guard: no walk at all below the threshold, whatever the clock says.
        let limiter: Limiter<ScimTenantKey> = tenant_limiter(1);
        let last = AtomicI64::new(0);

        prune_if_stale(&limiter, &last);
        assert_eq!(last.load(Ordering::Relaxed), 0, "a small store is not walked, and the clock is not touched");
    }
}

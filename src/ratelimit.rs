use std::{net::IpAddr, num::NonZeroU32, sync::LazyLock, time::Duration};

use governor::{Quota, RateLimiter, clock::DefaultClock, state::keyed::DashMapStateStore};

use crate::{CONFIG, Error};

type Limiter<T = IpAddr> = RateLimiter<T, DashMapStateStore<T>, DefaultClock>;

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

/// Provisioning traffic from an identity provider.
///
/// Expressed as a sustained rate rather than "one request per N seconds", because a directory
/// sync is inherently high-volume: a first full sync of a few thousand members is several
/// thousand requests, and a limiter that replenishes once a minute would stretch that over days.
#[cfg_attr(
    test,
    expect(dead_code, reason = "the SCIM test suite substitutes a limiter it can drive deterministically")
)]
static LIMITER_SCIM: LazyLock<Limiter> = LazyLock::new(|| {
    let per_second = NonZeroU32::new(CONFIG.scim_ratelimit_per_second()).expect("Non-zero SCIM ratelimit rate");
    let burst = NonZeroU32::new(CONFIG.scim_ratelimit_max_burst()).expect("Non-zero SCIM ratelimit burst");
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

/// Rate limit for the SCIM endpoints, applied to every request before the bearer token is even
/// parsed. This covers authentication attempts, expensive listing/filter requests and writes with
/// a single limiter, and is deliberately more lenient than the login limiter because identity
/// providers sync in bursts.
#[cfg_attr(
    test,
    expect(dead_code, reason = "the SCIM test suite substitutes a limiter it can drive deterministically")
)]
pub fn check_limit_scim(ip: &IpAddr) -> Result<(), ()> {
    LIMITER_SCIM.check_key(ip).map_err(|_| ())
}

pub fn check_limit_admin(ip: &IpAddr) -> Result<(), Error> {
    match LIMITER_ADMIN.check_key(ip) {
        Ok(()) => Ok(()),
        Err(_e) => {
            err_code!("Too many admin requests", 429);
        }
    }
}

//! HTTP response cache policy for OpenID Provider metadata.

use std::time::{Duration, SystemTime};

const MAX_DELTA_SECONDS: u64 = 2_147_483_648;

/// Freshness and revalidation requirements derived from response headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CachePolicy {
    CacheFor {
        lifetime: Duration,
        must_revalidate: bool,
    },
    Revalidate,
    DoNotStore,
}

/// Applies a caller-selected floor to response freshness.
pub(crate) fn apply_minimum_cache_duration(
    policy: CachePolicy,
    minimum_cache_duration: Duration,
) -> CachePolicy {
    if minimum_cache_duration.is_zero() {
        return policy;
    }

    match policy {
        CachePolicy::CacheFor {
            lifetime,
            must_revalidate,
        } => CachePolicy::CacheFor {
            lifetime: lifetime.max(minimum_cache_duration),
            must_revalidate,
        },
        CachePolicy::Revalidate | CachePolicy::DoNotStore => CachePolicy::CacheFor {
            lifetime: minimum_cache_duration,
            must_revalidate: true,
        },
    }
}

/// Parsed directives that affect a private HTTP cache.
#[derive(Default)]
struct CacheDirectives {
    max_age: Option<Duration>,
    no_cache: bool,
    no_store: bool,
    must_revalidate: bool,
}

/// Computes response cache policy from case-insensitive HTTP headers.
pub(crate) fn policy_from_headers(
    headers: &[(String, String)],
    default_lifetime: Duration,
) -> CachePolicy {
    let mut directives = CacheDirectives::default();
    for (_, value) in headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("cache-control"))
    {
        parse_cache_control(value, &mut directives);
    }
    let expires = header(headers, "expires");
    let date = header(headers, "date").and_then(|value| httpdate::parse_http_date(value).ok());
    let stated_age = header(headers, "age")
        .and_then(|value| value.parse().ok())
        .map(Duration::from_secs);
    let apparent_age = date.and_then(|date| SystemTime::now().duration_since(date).ok());
    let age = stated_age.max(apparent_age);
    compute_policy_from_directives(&directives, expires, date, age, default_lifetime)
}

/// Applies RFC 9111 freshness precedence for a private cache.
#[cfg(test)]
fn compute_policy(
    cache_control: Option<&str>,
    expires: Option<&str>,
    age: Option<Duration>,
    default_lifetime: Duration,
) -> CachePolicy {
    let mut directives = CacheDirectives::default();
    if let Some(cache_control) = cache_control {
        parse_cache_control(cache_control, &mut directives);
    }
    compute_policy_from_directives(&directives, expires, None, age, default_lifetime)
}

/// Resolves parsed directives against expiration and fallback freshness.
fn compute_policy_from_directives(
    directives: &CacheDirectives,
    expires: Option<&str>,
    date: Option<SystemTime>,
    age: Option<Duration>,
    default_lifetime: Duration,
) -> CachePolicy {
    if directives.no_store {
        return CachePolicy::DoNotStore;
    }
    if directives.no_cache {
        return CachePolicy::Revalidate;
    }

    if let Some(lifetime) = directives.max_age {
        return CachePolicy::CacheFor {
            lifetime: lifetime.saturating_sub(age.unwrap_or_default()),
            must_revalidate: directives.must_revalidate,
        };
    }

    if let Some(expires) = expires {
        return CachePolicy::CacheFor {
            lifetime: expires_lifetime(expires, date, age),
            must_revalidate: directives.must_revalidate,
        };
    }

    CachePolicy::CacheFor {
        lifetime: default_lifetime.saturating_sub(age.unwrap_or_default()),
        must_revalidate: directives.must_revalidate,
    }
}

/// Finds the first response header with the requested case-insensitive name.
fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

/// Adds cache directives that affect a private metadata cache.
fn parse_cache_control(value: &str, directives: &mut CacheDirectives) {
    for raw in value.split(',') {
        let part = raw.trim_ascii();
        if part.is_empty() {
            continue;
        }
        let (name, argument) = match part.split_once('=') {
            Some((name, argument)) => (name.trim_ascii(), Some(argument.trim_ascii())),
            None => (part, None),
        };

        if name.eq_ignore_ascii_case("max-age") {
            if let Some(argument) = argument {
                let lifetime = parse_delta_seconds(argument);
                directives.max_age = Some(
                    directives
                        .max_age
                        .map_or(lifetime, |current| current.min(lifetime)),
                );
            }
        } else if name.eq_ignore_ascii_case("no-cache") {
            directives.no_cache = true;
        } else if name.eq_ignore_ascii_case("no-store") {
            directives.no_store = true;
        } else if name.eq_ignore_ascii_case("must-revalidate") {
            directives.must_revalidate = true;
        }
    }
}

/// Parses and bounds delta-seconds; malformed values expire immediately.
fn parse_delta_seconds(value: &str) -> Duration {
    let seconds = value.trim_matches('"').parse::<u128>().unwrap_or_default();
    let capped = seconds.min(u128::from(MAX_DELTA_SECONDS));
    Duration::from_secs(u64::try_from(capped).unwrap_or(MAX_DELTA_SECONDS))
}

/// Returns the remaining lifetime of an absolute HTTP expiration date.
fn expires_lifetime(
    value: &str,
    response_date: Option<SystemTime>,
    age: Option<Duration>,
) -> Duration {
    let Ok(expires) = httpdate::parse_http_date(value) else {
        return Duration::ZERO;
    };
    expires
        .duration_since(response_date.unwrap_or_else(SystemTime::now))
        .unwrap_or_default()
        .saturating_sub(age.unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_control_precedes_expires_and_default() {
        assert_eq!(
            compute_policy(
                Some("public, max-age=120"),
                Some("Sun, 06 Nov 1994 08:49:37 GMT"),
                Some(Duration::from_secs(20)),
                Duration::from_secs(30),
            ),
            CachePolicy::CacheFor {
                lifetime: Duration::from_secs(100),
                must_revalidate: false,
            }
        );
    }

    #[test]
    fn strict_directives_require_revalidation() {
        assert_eq!(
            compute_policy(
                Some("no-cache, max-age=300"),
                None,
                None,
                Duration::from_secs(60),
            ),
            CachePolicy::Revalidate
        );
        assert_eq!(
            compute_policy(
                Some("no-store, max-age=300"),
                None,
                None,
                Duration::from_secs(60),
            ),
            CachePolicy::DoNotStore
        );
        assert_eq!(
            compute_policy(
                Some("max-age=300, must-revalidate"),
                None,
                None,
                Duration::from_secs(60),
            ),
            CachePolicy::CacheFor {
                lifetime: Duration::from_secs(300),
                must_revalidate: true,
            }
        );
    }

    #[test]
    fn restrictive_max_age_and_invalid_values_become_stale() {
        assert_eq!(
            compute_policy(
                Some("max-age=120, MAX-AGE=60"),
                None,
                None,
                Duration::from_secs(30),
            ),
            CachePolicy::CacheFor {
                lifetime: Duration::from_secs(60),
                must_revalidate: false,
            }
        );
        assert_eq!(
            compute_policy(Some("max-age=invalid"), None, None, Duration::from_secs(30),),
            CachePolicy::CacheFor {
                lifetime: Duration::ZERO,
                must_revalidate: false,
            }
        );
    }

    #[test]
    fn expires_and_default_supply_fallback_lifetimes() {
        let expires = httpdate::fmt_http_date(SystemTime::now() + Duration::from_secs(3600));
        let CachePolicy::CacheFor { lifetime, .. } =
            compute_policy(None, Some(&expires), None, Duration::from_secs(30))
        else {
            panic!("Expires should produce a cache lifetime");
        };
        assert!(lifetime > Duration::from_secs(3500));

        assert_eq!(
            compute_policy(
                None,
                None,
                Some(Duration::from_secs(10)),
                Duration::from_secs(30),
            ),
            CachePolicy::CacheFor {
                lifetime: Duration::from_secs(20),
                must_revalidate: false,
            }
        );
    }

    #[test]
    fn response_header_names_are_case_insensitive() {
        let headers = vec![
            ("CACHE-CONTROL".into(), "max-age=60".into()),
            ("Age".into(), "15".into()),
        ];
        assert_eq!(
            policy_from_headers(&headers, Duration::from_secs(30)),
            CachePolicy::CacheFor {
                lifetime: Duration::from_secs(45),
                must_revalidate: false,
            }
        );
    }

    #[test]
    fn repeated_cache_control_fields_are_combined() {
        let headers = vec![
            ("cache-control".into(), "max-age=60".into()),
            ("Cache-Control".into(), "no-store".into()),
        ];
        assert_eq!(
            policy_from_headers(&headers, Duration::from_secs(30)),
            CachePolicy::DoNotStore
        );
    }

    #[test]
    fn observed_public_idp_freshness_shapes_use_private_cache_rules() {
        let default_lifetime = Duration::from_secs(3600);

        let google = vec![
            ("cache-control".into(), "public, max-age=3600".into()),
            ("age".into(), "3183".into()),
        ];
        assert_eq!(
            policy_from_headers(&google, default_lifetime),
            CachePolicy::CacheFor {
                lifetime: Duration::from_secs(417),
                must_revalidate: false,
            }
        );

        let microsoft = vec![("cache-control".into(), "max-age=86400, private".into())];
        assert_eq!(
            policy_from_headers(&microsoft, default_lifetime),
            CachePolicy::CacheFor {
                lifetime: Duration::from_secs(86400),
                must_revalidate: false,
            }
        );

        let paypal = vec![
            (
                "cache-control".into(),
                "s-maxage=31536000, public,max-age=3600".into(),
            ),
            ("age".into(), "46185".into()),
        ];
        assert_eq!(
            policy_from_headers(&paypal, default_lifetime),
            CachePolicy::CacheFor {
                lifetime: Duration::ZERO,
                must_revalidate: false,
            }
        );

        assert_eq!(
            policy_from_headers(&[], default_lifetime),
            CachePolicy::CacheFor {
                lifetime: default_lifetime,
                must_revalidate: false,
            }
        );
    }

    #[test]
    fn observed_public_idp_strict_directives_are_not_reused() {
        let default_lifetime = Duration::from_secs(3600);
        let gitlab = vec![(
            "cache-control".into(),
            "max-age=0, private, must-revalidate".into(),
        )];
        assert_eq!(
            policy_from_headers(&gitlab, default_lifetime),
            CachePolicy::CacheFor {
                lifetime: Duration::ZERO,
                must_revalidate: true,
            }
        );

        let salesforce = vec![(
            "cache-control".into(),
            "no-cache,must-revalidate,max-age=0,no-store,private".into(),
        )];
        assert_eq!(
            policy_from_headers(&salesforce, default_lifetime),
            CachePolicy::DoNotStore
        );

        let atlassian = vec![("cache-control".into(), "no-cache".into())];
        assert_eq!(
            policy_from_headers(&atlassian, default_lifetime),
            CachePolicy::Revalidate
        );
    }

    #[test]
    fn minimum_cache_duration_floors_response_freshness() {
        let minimum = Duration::from_secs(60);

        assert_eq!(
            apply_minimum_cache_duration(
                CachePolicy::CacheFor {
                    lifetime: Duration::ZERO,
                    must_revalidate: false,
                },
                minimum,
            ),
            CachePolicy::CacheFor {
                lifetime: minimum,
                must_revalidate: false,
            }
        );
    }

    #[test]
    fn minimum_cache_duration_throttles_strict_directives() {
        let minimum = Duration::from_secs(60);
        for policy in [CachePolicy::Revalidate, CachePolicy::DoNotStore] {
            assert_eq!(
                apply_minimum_cache_duration(policy, minimum),
                CachePolicy::CacheFor {
                    lifetime: minimum,
                    must_revalidate: true,
                }
            );
        }
    }

    #[test]
    fn response_date_contributes_to_current_age() {
        let headers = vec![
            ("cache-control".into(), "max-age=3600".into()),
            (
                "date".into(),
                httpdate::fmt_http_date(SystemTime::now() - Duration::from_secs(3000)),
            ),
            ("age".into(), "120".into()),
        ];
        let CachePolicy::CacheFor { lifetime, .. } =
            policy_from_headers(&headers, Duration::from_secs(30))
        else {
            panic!("max-age should produce a cache lifetime");
        };
        assert!(lifetime <= Duration::from_secs(600));
        assert!(lifetime > Duration::from_secs(590));
    }

    #[test]
    fn stated_age_reduces_expires_freshness() {
        let now = SystemTime::now();
        let headers = vec![
            ("date".into(), httpdate::fmt_http_date(now)),
            (
                "expires".into(),
                httpdate::fmt_http_date(now + Duration::from_secs(3600)),
            ),
            ("age".into(), "3000".into()),
        ];
        let CachePolicy::CacheFor { lifetime, .. } =
            policy_from_headers(&headers, Duration::from_secs(30))
        else {
            panic!("Expires should produce a cache lifetime");
        };
        assert!(lifetime <= Duration::from_secs(600));
        assert!(lifetime > Duration::from_secs(590));
    }

    #[test]
    fn zero_minimum_cache_duration_preserves_response_policy() {
        for policy in [
            CachePolicy::CacheFor {
                lifetime: Duration::from_secs(30),
                must_revalidate: false,
            },
            CachePolicy::Revalidate,
            CachePolicy::DoNotStore,
        ] {
            assert_eq!(apply_minimum_cache_duration(policy, Duration::ZERO), policy);
        }
    }
}

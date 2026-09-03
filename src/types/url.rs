//! Newtype URLs with `FromStr` validation.
//!
//! Each newtype enforces that the input parses as a URL. By default the
//! scheme must be `https`. `RedirectUrl` is the one exception -- native
//! apps may use custom-scheme redirects (e.g. `com.example.app:/oauth`).

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use url::Url;

use crate::error::OidcError;

macro_rules! https_url_newtype {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub struct $name(Url);

        impl $name {
            pub fn as_url(&self) -> &Url {
                &self.0
            }

            pub fn as_str(&self) -> &str {
                self.0.as_str()
            }

            pub fn into_inner(self) -> Url {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }

        impl FromStr for $name {
            type Err = OidcError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let url = Url::parse(s)
                    .map_err(|e| OidcError::InvalidUrl(e.to_string()))?;
                if url.scheme() != "https" {
                    return Err(OidcError::InvalidUrl(format!(
                        "{} requires https, got {}",
                        stringify!($name),
                        url.scheme()
                    )));
                }
                Ok(Self(url))
            }
        }

        impl Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(self.0.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let s = String::deserialize(d)?;
                s.parse().map_err(serde::de::Error::custom)
            }
        }

        impl AsRef<Url> for $name {
            fn as_ref(&self) -> &Url {
                &self.0
            }
        }
    };
}

/// Issuer identifier used for discovery and exact claim comparison.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IssuerUrl {
    url: Url,
    serialized: String,
}

impl IssuerUrl {
    pub fn as_url(&self) -> &Url {
        &self.url
    }

    pub fn as_str(&self) -> &str {
        &self.serialized
    }

    pub fn into_inner(self) -> Url {
        self.url
    }
}

impl fmt::Display for IssuerUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.serialized)
    }
}

impl FromStr for IssuerUrl {
    type Err = OidcError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let url = Url::parse(s).map_err(|e| OidcError::InvalidUrl(e.to_string()))?;
        if url.scheme() != "https" {
            return Err(OidcError::InvalidUrl(format!(
                "IssuerUrl requires https, got {}",
                url.scheme()
            )));
        }
        if url.query().is_some() || url.fragment().is_some() {
            return Err(OidcError::InvalidUrl(
                "IssuerUrl must not contain a query or fragment".into(),
            ));
        }
        Ok(Self {
            url,
            serialized: s.to_owned(),
        })
    }
}

impl Serialize for IssuerUrl {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.serialized)
    }
}

impl<'de> Deserialize<'de> for IssuerUrl {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let serialized = String::deserialize(deserializer)?;
        serialized.parse().map_err(serde::de::Error::custom)
    }
}

impl AsRef<Url> for IssuerUrl {
    fn as_ref(&self) -> &Url {
        &self.url
    }
}

https_url_newtype!(
    /// Authorization endpoint URL.
    AuthUrl
);
https_url_newtype!(
    /// Token endpoint URL.
    TokenUrl
);
https_url_newtype!(
    /// UserInfo endpoint URL.
    UserInfoUrl
);
https_url_newtype!(
    /// RP-initiated logout endpoint URL.
    EndSessionUrl
);
https_url_newtype!(
    /// JWKS endpoint URL.
    JwksUrl
);

/// Redirect URI registered with the OP. Custom schemes are permitted for
/// native apps, so we do not enforce `https` here.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RedirectUrl(Url);

impl RedirectUrl {
    pub fn as_url(&self) -> &Url {
        &self.0
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub fn into_inner(self) -> Url {
        self.0
    }
}

impl fmt::Display for RedirectUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl FromStr for RedirectUrl {
    type Err = OidcError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let url = Url::parse(s).map_err(|e| OidcError::InvalidUrl(e.to_string()))?;
        Ok(Self(url))
    }
}

impl Serialize for RedirectUrl {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.0.as_str())
    }
}

impl<'de> Deserialize<'de> for RedirectUrl {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl AsRef<Url> for RedirectUrl {
    fn as_ref(&self) -> &Url {
        &self.0
    }
}

/// Redirect URI used after RP-initiated logout (OIDC RP-Initiated
/// Logout 1.0 section 2.1). The `post_logout_redirect_uri` parameter
/// on the end-session request must be one of the URIs the RP
/// pre-registered with the OP.
///
/// Custom schemes are permitted for native apps, so we do not
/// enforce `https` here.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PostLogoutRedirectUrl(Url);

impl PostLogoutRedirectUrl {
    pub fn as_url(&self) -> &Url {
        &self.0
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Display for PostLogoutRedirectUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl FromStr for PostLogoutRedirectUrl {
    type Err = OidcError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let url = Url::parse(s).map_err(|e| OidcError::InvalidUrl(e.to_string()))?;
        Ok(Self(url))
    }
}

impl Serialize for PostLogoutRedirectUrl {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.0.as_str())
    }
}

impl<'de> Deserialize<'de> for PostLogoutRedirectUrl {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl AsRef<Url> for PostLogoutRedirectUrl {
    fn as_ref(&self) -> &Url {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issuer_preserves_exact_serialized_value() {
        let without_slash = IssuerUrl::from_str("https://idp.example.com").unwrap();
        let with_slash = IssuerUrl::from_str("https://idp.example.com/").unwrap();

        assert_eq!(without_slash.as_url(), with_slash.as_url());
        assert_ne!(without_slash, with_slash);
        assert_eq!(without_slash.as_str(), "https://idp.example.com");
        assert_eq!(with_slash.as_str(), "https://idp.example.com/");
        assert_eq!(
            serde_json::to_string(&without_slash).unwrap(),
            r#""https://idp.example.com""#
        );
    }

    #[test]
    fn issuer_rejects_query_and_fragment() {
        assert!(IssuerUrl::from_str("https://idp.example.com?tenant=a").is_err());
        assert!(IssuerUrl::from_str("https://idp.example.com#issuer").is_err());
    }
}

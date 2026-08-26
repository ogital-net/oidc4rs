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

https_url_newtype!(
    /// Issuer URL. Used as the basis for discovery via
    /// `/.well-known/openid-configuration`.
    IssuerUrl
);
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

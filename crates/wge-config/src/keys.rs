use std::{fmt, str::FromStr};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{ConfigError, ErrorKind};

#[derive(Clone, Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey([u8; 32]);

impl SecretKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, ConfigError> {
        let key = Self(bytes);
        if key.0 == [0; 32] {
            return Err(ConfigError::new(ErrorKind::InvalidKey, "Key"));
        }
        Ok(key)
    }

    /// Only the daemon should access secret bytes, except for an explicit reveal.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn expose_base64(&self) -> Zeroizing<String> {
        Zeroizing::new(STANDARD.encode(self.0.as_slice()))
    }

    pub fn public_key(&self) -> PublicKey {
        let secret = x25519_dalek::StaticSecret::from(self.0);
        PublicKey(x25519_dalek::PublicKey::from(&secret).to_bytes())
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey([REDACTED])")
    }
}

impl FromStr for SecretKey {
    type Err = ConfigError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::from_bytes(*decode(value)?)
    }
}

#[derive(Clone, Copy, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, ConfigError> {
        if bytes == [0; 32] {
            return Err(ConfigError::new(ErrorKind::InvalidKey, "PublicKey"));
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&STANDARD.encode(self.0))
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl FromStr for PublicKey {
    type Err = ConfigError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::from_bytes(*decode(value)?)
    }
}

impl TryFrom<String> for PublicKey {
    type Error = ConfigError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl From<PublicKey> for String {
    fn from(value: PublicKey) -> Self {
        value.to_string()
    }
}

fn decode(value: &str) -> Result<Zeroizing<[u8; 32]>, ConfigError> {
    let invalid = || ConfigError::new(ErrorKind::InvalidKey, "Key");
    if value.len() != 44 {
        return Err(invalid());
    }
    let mut decoded = Zeroizing::new([0_u8; 33]);
    let len = STANDARD
        .decode_slice(value, decoded.as_mut())
        .map_err(|_| invalid())?;
    if len != 32 {
        return Err(invalid());
    }
    let mut bytes = Zeroizing::new([0; 32]);
    bytes.copy_from_slice(&decoded[..32]);
    Ok(bytes)
}

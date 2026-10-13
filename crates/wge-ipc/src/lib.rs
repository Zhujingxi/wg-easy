//! Bounded, versioned local protocol. Ordinary responses contain public data only.
#![forbid(unsafe_code)]

mod transport;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::fmt;
pub use transport::*;
use wge_config::{IpNetwork, PublicConfig, PublicKey};
use zeroize::Zeroizing;

pub const PROTOCOL_VERSION: u32 = 2;
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;
#[cfg(target_os = "linux")]
pub const DEFAULT_ENDPOINT: &str = "/run/wireguardeasy/control.sock";
#[cfg(target_os = "macos")]
pub const DEFAULT_ENDPOINT: &str = "/var/run/wireguardeasy/control.sock";
#[cfg(windows)]
pub const DEFAULT_ENDPOINT: &str = r"\\.\pipe\wireguardeasy";

/// An explicit secret transfer. Both Debug output and dropped storage are safe.
#[derive(Clone, Default)]
pub struct SensitiveText(Zeroizing<String>);
impl SensitiveText {
    pub fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }
    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn from_zeroizing(value: Zeroizing<String>) -> Self {
        Self(value)
    }
}
impl fmt::Debug for SensitiveText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SensitiveText([REDACTED])")
    }
}
impl Serialize for SensitiveText {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if self.expose().len() > MAX_FRAME_BYTES {
            return Err(serde::ser::Error::custom(
                "Secret transfer exceeds the size limit",
            ));
        }
        // Escape-free JSON avoids serde's temporary unzeroized string scratch buffer.
        let encoded = Zeroizing::new(STANDARD.encode(self.expose()));
        serializer.serialize_str(&encoded)
    }
}
impl<'de> Deserialize<'de> for SensitiveText {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SecretVisitor;
        impl<'de> serde::de::Visitor<'de> for SecretVisitor {
            type Value = SensitiveText;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a Base64 encoded secret transfer")
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                if value.len() > MAX_FRAME_BYTES {
                    return Err(E::custom("Secret transfer exceeds the size limit"));
                }
                let mut decoded =
                    Zeroizing::new(vec![0; base64::decoded_len_estimate(value.len())]);
                let length = STANDARD
                    .decode_slice(value, &mut decoded)
                    .map_err(|_| E::custom("Invalid secret transfer"))?;
                let value = std::str::from_utf8(&decoded[..length])
                    .map_err(|_| E::custom("Invalid secret transfer"))?;
                Ok(SensitiveText::new(value.to_owned()))
            }

            fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Self::Value, E> {
                self.visit_str(&Zeroizing::new(value))
            }
        }
        deserializer.deserialize_str(SecretVisitor)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TunnelId(pub String);
impl TunnelId {
    pub fn is_valid(&self) -> bool {
        self.0.len() == 32
            && self
                .0
                .bytes()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tunnel {
    pub id: TunnelId,
    pub name: String,
    pub config: PublicConfig,
    pub status: TunnelStatus,
    pub saved: bool,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub tunnels: Vec<Tunnel>,
    pub local_networks: Vec<IpNetwork>,
    #[serde(default)]
    pub next_page: Option<TunnelId>,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunnelStatus {
    pub state: ConnectionState,
    pub peers: Vec<PeerStatus>,
    pub error: Option<ApiError>,
}
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionState {
    #[default]
    Off,
    Connecting,
    Connected,
    NoHandshake,
    Error,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerStatus {
    pub public_key: PublicKey,
    pub last_handshake_unix: Option<u64>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub endpoint: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerSecretUpdate {
    pub public_key: PublicKey,
    pub value: Option<SensitiveText>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    List,
    ListAfter {
        after: TunnelId,
    },
    BeginDraft,
    Get {
        id: TunnelId,
    },
    Save {
        id: TunnelId,
        name: String,
        config: PublicConfig,
        preshared_keys: Vec<PeerSecretUpdate>,
    },
    Import {
        name: String,
        config: SensitiveText,
    },
    Delete {
        id: TunnelId,
    },
    Connect {
        id: TunnelId,
    },
    Disconnect {
        id: TunnelId,
    },
    RevealPrivateKey {
        id: TunnelId,
    },
    Export {
        id: TunnelId,
        confirmed: bool,
    },
    DiscardDraft {
        id: TunnelId,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    tag = "result",
    content = "data",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[allow(clippy::large_enum_variant)] // Only one response is retained per connection.
pub enum Response {
    Snapshot(Snapshot),
    Tunnel(Tunnel),
    Secret(SensitiveText),
    Ok,
    Error(ApiError),
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiError {
    pub code: ErrorCode,
    pub message: String,
    pub conflict: Option<RouteConflict>,
}
impl ApiError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            conflict: None,
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    Validation,
    ScriptHook,
    UnsupportedConfig,
    NotFound,
    Conflict,
    Unauthorized,
    Busy,
    Network,
    Endpoint,
    Dns,
    Permission,
    Driver,
    Recovery,
    Protocol,
    Internal,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteConflict {
    pub tunnel_name: String,
    pub requested_range: String,
    pub active_range: String,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope<T> {
    pub version: u32,
    pub body: T,
}
impl<T> Envelope<T> {
    pub fn new(body: T) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            body,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn explicit_secrets_are_redacted() {
        let request = Request::Import {
            name: "home".into(),
            config: SensitiveText::new("PRIVATE MATERIAL".into()),
        };
        assert!(!format!("{request:?}").contains("PRIVATE MATERIAL"));
        let encoded = serde_json::to_string(&request).unwrap();
        let decoded: Request = serde_json::from_str(&encoded).unwrap();
        assert!(
            matches!(decoded, Request::Import { config, .. } if config.expose() == "PRIVATE MATERIAL")
        );
        let response = Response::Secret(SensitiveText::new("PRIVATE MATERIAL".into()));
        assert!(!format!("{response:?}").contains("PRIVATE MATERIAL"));
    }
    #[test]
    fn ids_cannot_escape_storage() {
        for invalid in [
            "../secret",
            "/tmp/example",
            "",
            "0123456789ABCDEF0123456789ABCDEF",
        ] {
            assert!(!TunnelId(invalid.into()).is_valid());
        }
        assert!(TunnelId("0123456789abcdef0123456789abcdef".into()).is_valid());
    }
    #[test]
    fn unknown_commands_and_fields_are_rejected() {
        assert!(serde_json::from_str::<Request>(r#"{"command":"run","script":"bad"}"#).is_err());
        assert!(
            serde_json::from_str::<Request>(
                r#"{"command":"export","id":"a","confirmed":true,"script":"bad"}"#
            )
            .is_err()
        );
    }
}

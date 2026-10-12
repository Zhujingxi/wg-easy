use crate::service::Network;
use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
use wge_config::TunnelConfig;
use wge_ipc::{ApiError, ConnectionState, ErrorCode, PeerStatus, TunnelStatus};

pub struct NativeNetwork {
    pub recovery: PathBuf,
}
impl Network for NativeNetwork {
    type Handle = wge_engine::RunningTunnel;
    async fn start(&mut self, config: &TunnelConfig, name: &str) -> Result<Self::Handle, ApiError> {
        wge_engine::RunningTunnel::start(config, name, &self.recovery)
            .await
            .map_err(|error| {
                let mut error = api_error(error);
                if self.recovery.join(format!("{name}.json")).exists() {
                    error.code = ErrorCode::Recovery;
                }
                error
            })
    }
    async fn status(handle: &Self::Handle) -> TunnelStatus {
        let status = handle.status().await;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let state = match status.state {
            wge_engine::ConnectionState::Connecting => ConnectionState::Connecting,
            wge_engine::ConnectionState::Connected => ConnectionState::Connected,
            wge_engine::ConnectionState::NoHandshake => ConnectionState::NoHandshake,
            wge_engine::ConnectionState::Failed => ConnectionState::Error,
        };
        let peers = status
            .peers
            .into_iter()
            .filter_map(|peer| {
                Some(PeerStatus {
                    public_key: wge_config::PublicKey::from_bytes(peer.public_key).ok()?,
                    last_handshake_unix: peer
                        .last_handshake
                        .map(|age| now.saturating_sub(age.as_secs())),
                    rx_bytes: peer.rx_bytes,
                    tx_bytes: peer.tx_bytes,
                    endpoint: peer.endpoint.map(|endpoint| endpoint.to_string()),
                })
            })
            .collect();
        TunnelStatus {
            state,
            peers,
            error: (state == ConnectionState::Error).then(|| {
                ApiError::new(
                    ErrorCode::Network,
                    "The tunnel stopped unexpectedly. Disconnect and reconnect it.",
                )
            }),
        }
    }
    async fn stop(handle: Self::Handle) -> Result<(), ApiError> {
        handle.stop().await.map_err(api_error)
    }
    async fn local_networks(&self) -> Vec<wge_config::IpNetwork> {
        wge_platform::local_networks().await.unwrap_or_default()
    }
}

fn api_error(error: wge_engine::Error) -> ApiError {
    use wge_engine::Error;
    let code = match &error {
        Error::Resolve(_) => ErrorCode::Endpoint,
        Error::Invalid(_) => ErrorCode::Validation,
        Error::Tun(_) => ErrorCode::Driver,
        Error::Platform(error) => match error {
            wge_platform::Error::Dns(_) => ErrorCode::Dns,
            wge_platform::Error::Journal(_) => ErrorCode::Recovery,
            wge_platform::Error::Invalid(_) => ErrorCode::Validation,
            wge_platform::Error::Tun(_) => ErrorCode::Driver,
            wge_platform::Error::Io(error)
                if error.kind() == std::io::ErrorKind::PermissionDenied =>
            {
                ErrorCode::Permission
            }
            _ => ErrorCode::Network,
        },
        _ => ErrorCode::Network,
    };
    ApiError::new(code, error.to_string())
}

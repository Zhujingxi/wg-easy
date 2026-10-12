//! Built-in userspace WireGuard with native network ownership.

#![forbid(unsafe_code)]

use gotatun::device::{DefaultDeviceTransports, Device, DeviceBuilder, Peer};
use gotatun::tun::tun_async_device::TunDevice;
use std::{
    future::{Future, poll_fn},
    net::SocketAddr,
    path::Path,
    sync::Arc,
    task::Poll,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;
use wge_config::TunnelConfig;
use zeroize::Zeroize;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Platform(#[from] wge_platform::Error),
    #[error("Could not start WireGuard: {0}")]
    Engine(#[from] gotatun::device::Error),
    #[error("Could not open the tunnel: {0}")]
    Tun(#[from] gotatun::tun::tun_async_device::Error),
    #[error("Could not resolve server {0}. Check its address and this computer's connection.")]
    Resolve(String),
    #[error("Invalid tunnel configuration: {0}")]
    Invalid(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionState {
    Connecting,
    Connected,
    NoHandshake,
    Failed,
}

#[derive(Clone, Debug)]
pub struct PeerStatus {
    pub public_key: [u8; 32],
    pub endpoint: Option<SocketAddr>,
    pub last_handshake: Option<Duration>,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
}

#[derive(Clone, Debug)]
pub struct TunnelStatus {
    pub state: ConnectionState,
    pub peers: Vec<PeerStatus>,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
}

pub struct RunningTunnel {
    device: Arc<Mutex<Device<DefaultDeviceTransports>>>,
    network: wge_platform::Network,
    started: Instant,
    bootstrap: tokio::task::JoinHandle<()>,
}

impl RunningTunnel {
    pub async fn start(
        config: &TunnelConfig,
        interface_name: &str,
        recovery_directory: &Path,
    ) -> Result<Self, Error> {
        config
            .validate()
            .map_err(|e| Error::Invalid(e.to_string()))?;
        let mut peers = Vec::with_capacity(config.peers.len());
        let mut endpoints = Vec::new();
        let mut initial_keepalives = Vec::new();
        let resolve_deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        for config in &config.peers {
            let mut peer = Peer::new(x25519_dalek::PublicKey::from(*config.public_key.as_bytes()));
            peer.allowed_ips = config.allowed_ips.clone();
            peer.preshared_key = config.preshared_key.as_ref().map(|key| *key.as_bytes());
            peer.keepalive = config.persistent_keepalive.filter(|n| *n > 0);
            if let Some(endpoint) = &config.endpoint {
                let address = tokio::time::timeout_at(
                    resolve_deadline,
                    tokio::net::lookup_host((endpoint.host.as_str(), endpoint.port)),
                )
                .await
                .ok()
                .and_then(Result::ok)
                .and_then(|mut addresses| addresses.next())
                .ok_or_else(|| Error::Resolve(endpoint.to_string()))?;
                endpoints.push(address);
                peer.endpoint = Some(address);
                // A first WireGuard keepalive initiates a handshake without an external probe.
                initial_keepalives.push((peer.public_key, peer.keepalive));
                peer.keepalive = Some(1);
            }
            peers.push(peer);
        }
        let listen_port = config.interface.listen_port.unwrap_or(0);
        #[cfg(target_os = "macos")]
        let listen_port = if listen_port == 0 {
            std::net::UdpSocket::bind("0.0.0.0:0")
                .and_then(|socket| socket.local_addr())
                .map_err(wge_platform::Error::from)?
                .port()
        } else {
            listen_port
        };
        let (network, tun) = wge_platform::Network::create(
            config,
            interface_name,
            &endpoints,
            recovery_directory,
            listen_port,
        )
        .await?;
        let ip = match TunDevice::from_tun_device(tun) {
            Ok(ip) => ip,
            Err(error) => {
                network.stop().await?;
                return Err(error.into());
            }
        };
        let builder = DeviceBuilder::new()
            .with_default_udp()
            .with_ip(ip)
            .with_private_key(x25519_dalek::StaticSecret::from(
                *config.interface.private_key.as_bytes(),
            ))
            .with_listen_port(listen_port)
            .with_peers(peers);
        #[cfg(target_os = "linux")]
        let builder = builder.with_fwmark(wge_platform::SOCKET_MARK);
        let device = builder.build().await;
        let device = match device {
            Ok(device) => device,
            Err(error) => {
                network.stop().await?;
                return Err(error.into());
            }
        };
        let device = Arc::new(Mutex::new(device));
        let bootstrap_device = Arc::downgrade(&device);
        let bootstrap = tokio::spawn(async move {
            let deadline = Instant::now() + Duration::from_secs(30);
            while !initial_keepalives.is_empty() {
                tokio::time::sleep(Duration::from_millis(250)).await;
                let Some(device) = bootstrap_device.upgrade() else {
                    break;
                };
                let mut device = device.lock().await;
                for mut peer in device.peers().await {
                    let restore = peer.stats.last_handshake.is_some() || Instant::now() >= deadline;
                    if restore
                        && let Some(position) = initial_keepalives
                            .iter()
                            .position(|(key, _)| *key == peer.peer.public_key)
                    {
                        let (key, interval) = initial_keepalives[position];
                        if device
                            .modify_peer(&key, |p| p.set_keepalive(interval))
                            .await
                            .is_ok()
                        {
                            initial_keepalives.remove(position);
                        }
                    }
                    peer.peer.preshared_key.zeroize();
                }
                if Instant::now() >= deadline {
                    break;
                }
            }
        });
        Ok(Self {
            device,
            network,
            started: Instant::now(),
            bootstrap,
        })
    }

    pub async fn status(&self) -> TunnelStatus {
        let mut device = self.device.lock().await;
        let failed = {
            let mut failure = std::pin::pin!(device.wait());
            poll_fn(|cx| Poll::Ready(failure.as_mut().poll(cx).is_ready())).await
        };
        let mut peers = Vec::new();
        for mut peer in device.peers().await {
            peers.push(PeerStatus {
                public_key: *peer.peer.public_key.as_bytes(),
                endpoint: peer.peer.endpoint,
                last_handshake: peer.stats.last_handshake,
                tx_bytes: peer.stats.tx_bytes as u64,
                rx_bytes: peer.stats.rx_bytes as u64,
            });
            // gotatun's inspection API includes a PSK copy; never retain or format it.
            peer.peer.preshared_key.zeroize();
        }
        let state = classify(&peers, self.started.elapsed(), failed);
        TunnelStatus {
            state,
            tx_bytes: peers.iter().map(|p| p.tx_bytes).sum(),
            rx_bytes: peers.iter().map(|p| p.rx_bytes).sum(),
            peers,
        }
    }

    pub async fn stop(self) -> Result<(), Error> {
        self.bootstrap.abort();
        let _ = self.bootstrap.await;
        // Restore DNS and routes before dropping the interface that carried them.
        let result = self.network.stop().await;
        if let Ok(device) = Arc::try_unwrap(self.device) {
            device.into_inner().stop().await;
        }
        result.map_err(Into::into)
    }
}

fn classify(peers: &[PeerStatus], elapsed: Duration, failed: bool) -> ConnectionState {
    if failed {
        return ConnectionState::Failed;
    }
    if !peers.is_empty()
        && peers.iter().all(|p| {
            p.last_handshake
                .is_some_and(|age| age <= Duration::from_secs(180))
        })
    {
        return ConnectionState::Connected;
    }
    if elapsed < Duration::from_secs(20) {
        ConnectionState::Connecting
    } else {
        ConnectionState::NoHandshake
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn running_tunnels_and_errors_can_cross_async_tasks() {
        fn send_sync<T: Send + Sync>() {}
        send_sync::<RunningTunnel>();
        send_sync::<Error>();
    }

    fn peer(age: Option<u64>) -> PeerStatus {
        PeerStatus {
            public_key: [1; 32],
            endpoint: None,
            last_handshake: age.map(Duration::from_secs),
            tx_bytes: 0,
            rx_bytes: 0,
        }
    }

    #[test]
    fn connected_requires_recent_handshakes_for_all_peers() {
        assert_eq!(
            classify(&[peer(None)], Duration::ZERO, false),
            ConnectionState::Connecting
        );
        assert_eq!(
            classify(&[peer(None)], Duration::from_secs(20), false),
            ConnectionState::NoHandshake
        );
        assert_eq!(
            classify(&[peer(Some(10))], Duration::from_secs(50), false),
            ConnectionState::Connected
        );
        assert_eq!(
            classify(&[peer(Some(181))], Duration::from_secs(200), false),
            ConnectionState::NoHandshake
        );
        assert_eq!(
            classify(
                &[peer(Some(10)), peer(None)],
                Duration::from_secs(50),
                false
            ),
            ConnectionState::NoHandshake
        );
        assert_eq!(
            classify(&[peer(Some(1))], Duration::from_secs(50), true),
            ConnectionState::Failed
        );
    }
}

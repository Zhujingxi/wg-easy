//! Built-in userspace WireGuard with native network ownership.

#![forbid(unsafe_code)]

mod endpoint;
mod recovery;
pub use endpoint::export;

use gotatun::device::{DefaultDeviceTransports, Device, DeviceBuilder, Peer};
use gotatun::tun::tun_async_device::TunDevice;
use std::{
    future::{Future, poll_fn},
    net::SocketAddr,
    path::{Path, PathBuf},
    task::Poll,
    time::{Duration, Instant},
};
use tokio::sync::{oneshot, watch};
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
    #[error(
        "Could not resolve server {0}. Check its address, SRV records and this computer's connection."
    )]
    Resolve(String),
    #[error("Invalid tunnel configuration: {0}")]
    Invalid(String),
    #[error("The tunnel worker stopped unexpectedly.")]
    Worker,
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
    pub error: Option<String>,
}

pub struct RunningTunnel {
    status: watch::Receiver<TunnelStatus>,
    stop: oneshot::Sender<()>,
    worker: tokio::task::JoinHandle<Result<(), Error>>,
}

struct Session {
    device: Device<DefaultDeviceTransports>,
    network: wge_platform::Network,
    started: Instant,
    endpoints: Vec<recovery::PeerEndpoint>,
}

impl RunningTunnel {
    pub async fn start(
        config: &TunnelConfig,
        interface_name: &str,
        recovery_directory: &Path,
    ) -> Result<Self, Error> {
        config
            .validate()
            .map_err(|error| Error::Invalid(error.to_string()))?;
        let mut session = Session::start(config, interface_name, recovery_directory).await?;
        let (sender, status) = watch::channel(session.status().await);
        let (stop, stopped) = oneshot::channel();
        let worker = tokio::spawn(run(
            session,
            config.clone(),
            interface_name.to_owned(),
            recovery_directory.to_owned(),
            sender,
            stopped,
        ));
        Ok(Self {
            status,
            stop,
            worker,
        })
    }

    pub async fn status(&self) -> TunnelStatus {
        let mut status = self.status.borrow().clone();
        if self.worker.is_finished() && status.state != ConnectionState::Failed {
            status.state = ConnectionState::Failed;
        }
        status
    }

    pub async fn stop(self) -> Result<(), Error> {
        let _ = self.stop.send(());
        // Join instead of aborting: native network mutations must finish or roll back.
        self.worker.await.map_err(|_| Error::Worker)?
    }
}

impl Session {
    async fn start(
        config: &TunnelConfig,
        interface_name: &str,
        recovery_directory: &Path,
    ) -> Result<Self, Error> {
        let mut addresses = endpoint::resolve(config).await?;
        let routable = wge_platform::routable_endpoints(
            &addresses.iter().flatten().copied().collect::<Vec<_>>(),
        )?;
        for (peer, addresses) in config.peers.iter().zip(&mut addresses) {
            addresses.retain(|address| routable.contains(address));
            if addresses.is_empty()
                && let Some(endpoint) = &peer.endpoint
            {
                return Err(Error::Resolve(format!("{endpoint} (no network route)")));
            }
        }
        Self::start_resolved(config, interface_name, recovery_directory, addresses).await
    }

    async fn start_resolved(
        config: &TunnelConfig,
        interface_name: &str,
        recovery_directory: &Path,
        addresses: Vec<Vec<SocketAddr>>,
    ) -> Result<Self, Error> {
        let mut peers = Vec::with_capacity(config.peers.len());
        let mut endpoints = Vec::new();
        for (config, addresses) in config.peers.iter().zip(&addresses) {
            let mut peer = Peer::new(x25519_dalek::PublicKey::from(*config.public_key.as_bytes()));
            peer.allowed_ips = config.allowed_ips.clone();
            peer.preshared_key = config.preshared_key.as_ref().map(|key| *key.as_bytes());
            peer.keepalive = config.persistent_keepalive.filter(|n| *n > 0);
            if let Some(address) = addresses.first() {
                peer.endpoint = Some(*address);
                endpoints.extend_from_slice(addresses);
                // Initiate a WireGuard handshake without an external connectivity probe.
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
        let device = match builder.build().await {
            Ok(device) => device,
            Err(error) => {
                network.stop().await?;
                return Err(error.into());
            }
        };
        Ok(Self {
            device,
            network,
            started: Instant::now(),
            endpoints: config
                .peers
                .iter()
                .zip(addresses)
                .map(|(peer, addresses)| {
                    recovery::PeerEndpoint::new(peer, addresses, Instant::now())
                })
                .collect(),
        })
    }

    async fn status(&mut self) -> TunnelStatus {
        let failed = {
            let mut failure = std::pin::pin!(self.device.wait());
            poll_fn(|cx| Poll::Ready(failure.as_mut().poll(cx).is_ready())).await
        };
        let mut peers = Vec::new();
        for mut peer in self.device.peers().await {
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
        TunnelStatus {
            state: classify(&peers, self.started.elapsed(), failed),
            tx_bytes: peers.iter().map(|peer| peer.tx_bytes).sum(),
            rx_bytes: peers.iter().map(|peer| peer.rx_bytes).sum(),
            peers,
            error: None,
        }
    }

    async fn maintain(&mut self, status: &TunnelStatus) -> Result<bool, Error> {
        for endpoint in &mut self.endpoints {
            let Some(peer) = status
                .peers
                .iter()
                .find(|peer| peer.public_key == endpoint.key)
            else {
                continue;
            };
            let action = endpoint.advance(peer.last_handshake, Instant::now());
            match action {
                recovery::Action::None => {}
                recovery::Action::Refresh => return Ok(true),
                recovery::Action::Keepalive(interval) => {
                    self.device
                        .modify_peer(&endpoint.key.into(), |peer| peer.set_keepalive(interval))
                        .await?;
                }
                recovery::Action::Switch(address) => {
                    self.device
                        .modify_peer(&endpoint.key.into(), |peer| {
                            peer.set_endpoint(Some(address));
                            peer.set_keepalive(Some(1));
                        })
                        .await?;
                }
            }
        }
        Ok(false)
    }

    async fn stop(self) -> Result<(), Error> {
        // Restore DNS and routes before dropping the interface that carried them.
        let result = self.network.stop().await;
        self.device.stop().await;
        result.map_err(Into::into)
    }
}

async fn run(
    session: Session,
    config: TunnelConfig,
    name: String,
    directory: PathBuf,
    status: watch::Sender<TunnelStatus>,
    mut stopped: oneshot::Receiver<()>,
) -> Result<(), Error> {
    let started = session.started;
    let mut session = Some(session);
    let mut timer = tokio::time::interval(Duration::from_secs(1));
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut retry = Instant::now();
    loop {
        tokio::select! {
            biased;
            _ = &mut stopped => return match session { Some(session) => session.stop().await, None => Ok(()) },
            _ = timer.tick() => {}
        }
        if let Some(active) = &mut session {
            let current = active.status().await;
            let refresh = if current.state == ConnectionState::Failed {
                false
            } else {
                match active.maintain(&current).await {
                    Ok(refresh) => refresh,
                    Err(error) => {
                        if let Err(cleanup) = session.take().unwrap().stop().await {
                            publish_error(&status, &cleanup, ConnectionState::Failed);
                            return Err(cleanup);
                        }
                        publish_error(&status, &error, ConnectionState::Failed);
                        return Err(error);
                    }
                }
            };
            status.send_replace(current);
            if !refresh {
                continue;
            }
            let mut reconnecting = status.borrow().clone();
            reconnecting.state = ConnectionState::Connecting;
            reconnecting.peers.clear();
            status.send_replace(reconnecting);
            let previous = session.take().unwrap();
            let interface_name = previous.network.interface_name().to_owned();
            let cleanup = async {
                previous.stop().await?;
                wge_platform::wait_for_interface_removal(&interface_name).await?;
                Ok::<_, Error>(())
            }
            .await;
            if let Err(error) = cleanup {
                publish_error(&status, &error, ConnectionState::Failed);
                return Err(error);
            }
        }
        if Instant::now() < retry {
            continue;
        }
        match Session::start(&config, &name, &directory).await {
            Ok(mut active) => {
                // Retries must not keep an unreachable server in Connecting forever.
                active.started = started;
                session = Some(active);
            }
            Err(error @ Error::Resolve(_)) => {
                publish_error(&status, &error, ConnectionState::NoHandshake);
                retry = Instant::now() + Duration::from_secs(15);
            }
            Err(error) => {
                publish_error(&status, &error, ConnectionState::Failed);
                return Err(error);
            }
        }
    }
}

fn publish_error(status: &watch::Sender<TunnelStatus>, error: &Error, state: ConnectionState) {
    status.send_replace(TunnelStatus {
        state,
        peers: Vec::new(),
        tx_bytes: 0,
        rx_bytes: 0,
        error: Some(error.to_string()),
    });
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

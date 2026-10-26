#![forbid(unsafe_code)]
#![cfg(target_os = "linux")]

use gotatun::{
    device::{DeviceBuilder, Peer},
    packet::{Ip, Packet, PacketBufPool},
    tun::{IpRecv, IpSend, MtuWatcher},
};
use std::{
    io,
    net::SocketAddr,
    os::unix::fs::PermissionsExt,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    net::UdpSocket,
    sync::{Mutex, mpsc},
};
use wge_config::{Endpoint, InterfaceConfig, PeerConfig, SecretKey, TunnelConfig};
use wge_engine::{ConnectionState, RunningTunnel};

#[path = "support/dns.rs"]
mod dns;

#[derive(Clone)]
struct ServerTun {
    incoming: Arc<Mutex<mpsc::Receiver<Packet<Ip>>>>,
    outgoing: mpsc::Sender<Packet<Ip>>,
}
impl IpSend for ServerTun {
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        self.outgoing.send(packet).await.map_err(io::Error::other)
    }
}
impl IpRecv for ServerTun {
    async fn recv<'a>(
        &'a mut self,
        _: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
        let packet = self
            .incoming
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))?;
        Ok(std::iter::once(packet))
    }
    fn mtu(&self) -> MtuWatcher {
        MtuWatcher::new(1420)
    }
}

fn namespace_only() {
    let host = std::env::var_os("WGE_HOST_NETNS")
        .map(std::path::PathBuf::from)
        .or_else(|| std::fs::read_link("/proc/1/ns/net").ok())
        .expect("Set WGE_HOST_NETNS to the host network namespace before unshare");
    assert_ne!(
        std::fs::read_link("/proc/self/ns/net").unwrap(),
        host,
        "Run inside an isolated network namespace; never on the host network"
    );
    // A new namespace starts with loopback down. RTM_NEWLINK enables it without a subprocess.
    let mut socket = netlink_sys::Socket::new(netlink_sys::protocols::NETLINK_ROUTE).unwrap();
    socket.bind_auto().unwrap();
    socket.connect(&netlink_sys::SocketAddr::new(0, 0)).unwrap();
    let mut request = [0u8; 32];
    request[0..4].copy_from_slice(&32u32.to_ne_bytes());
    request[4..6].copy_from_slice(&16u16.to_ne_bytes());
    request[6..8].copy_from_slice(&5u16.to_ne_bytes());
    request[8..12].copy_from_slice(&1u32.to_ne_bytes());
    request[20..24].copy_from_slice(&1u32.to_ne_bytes());
    request[24..28].copy_from_slice(&1u32.to_ne_bytes());
    request[28..32].copy_from_slice(&1u32.to_ne_bytes());
    socket.send(&request, 0).unwrap();
    let (reply, _) = socket.recv_from_full().unwrap();
    assert_eq!(i32::from_ne_bytes(reply[16..20].try_into().unwrap()), 0);
}

fn cpu_nanoseconds() -> u64 {
    std::fs::read_dir("/proc/self/task")
        .unwrap()
        .filter_map(Result::ok)
        .filter_map(|task| {
            std::fs::read_to_string(task.path().join("schedstat"))
                .ok()?
                .split_whitespace()
                .next()?
                .parse::<u64>()
                .ok()
        })
        .sum()
}
fn resident_bytes() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find(|l| l.starts_with("VmRSS:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .unwrap()
        .parse::<u64>()
        .unwrap()
        * 1024
}

async fn next_packet(receiver: &mut mpsc::Receiver<Packet<Ip>>) -> Packet<Ip> {
    tokio::time::timeout(Duration::from_secs(8), receiver.recv())
        .await
        .expect("WireGuard must deliver the packet")
        .unwrap()
}

async fn interface_removed(name: &str) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while netconfig::Interface::try_from_name(name).is_ok() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("The stopped WireGuard device must release its tun interface");
}

#[tokio::test]
#[ignore = "requires an isolated Linux network namespace and a real tun interface"]
async fn namespace_unreachable_peer_stays_running() {
    namespace_only();
    let directory = tempfile::tempdir().unwrap();
    let config = wge_config::parse(
        "[Interface]\n\
         PrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
         Address = 198.18.254.2/32\n\
         [Peer]\n\
         PublicKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\n\
         Endpoint = 127.0.0.1:51820\n\
         AllowedIPs = 198.18.254.1/32\n\
         PersistentKeepalive = 1\n",
    )
    .unwrap();
    let tunnel = RunningTunnel::start(&config, "wge-unreachable", directory.path())
        .await
        .unwrap();
    for _ in 0..5 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let status = tunnel.status().await;
        assert!(
            matches!(
                status.state,
                ConnectionState::Connecting | ConnectionState::NoHandshake
            ),
            "{status:?}"
        );
    }
    tunnel.stop().await.unwrap();
    interface_removed("wge-unreachable").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires unshare --user --map-root-user --net; creates a real tun interface"]
async fn namespace_handshake_ipv4_ipv6_cleanup_and_metrics() {
    namespace_only();
    let recovery = tempfile::tempdir().unwrap();
    std::fs::set_permissions(recovery.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let client_key = SecretKey::from_bytes([1; 32]).unwrap();
    let server_key = SecretKey::from_bytes([2; 32]).unwrap();
    let psk = [3; 32];
    let (to_server, server_input) = mpsc::channel(128);
    let (server_output, mut received) = mpsc::channel(128);
    let server_tun = ServerTun {
        incoming: Arc::new(Mutex::new(server_input)),
        outgoing: server_output,
    };
    let server_peer = Peer::new(x25519_dalek::PublicKey::from(
        *client_key.public_key().as_bytes(),
    ))
    .with_preshared_key(psk)
    .with_allowed_ips([
        "10.200.1.1/32".parse().unwrap(),
        "fd42:1::1/128".parse().unwrap(),
    ]);
    let server = DeviceBuilder::new()
        .with_default_udp()
        .with_ip(server_tun)
        .with_private_key(x25519_dalek::StaticSecret::from(*server_key.as_bytes()))
        .with_listen_port(51829)
        .with_peer(server_peer)
        .build()
        .await
        .unwrap();
    let config = TunnelConfig {
        interface: InterfaceConfig {
            private_key: client_key,
            addresses: vec![
                "10.200.1.1/24".parse().unwrap(),
                "fd42:1::1/64".parse().unwrap(),
            ],
            dns: vec![],
            search_domains: vec![],
            listen_port: None,
            mtu: Some(1420),
        },
        peers: vec![PeerConfig {
            public_key: server_key.public_key(),
            preshared_key: Some(SecretKey::from_bytes(psk).unwrap()),
            endpoint: Some(Endpoint {
                host: "127.0.0.1".into(),
                port: Some(51829),
            }),
            allowed_ips: vec![
                "10.200.2.0/24".parse().unwrap(),
                "fd42:2::/64".parse().unwrap(),
            ],
            persistent_keepalive: None,
        }],
    };
    let client = RunningTunnel::start(&config, "wge-test", recovery.path())
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(8), async {
        while client.status().await.state != ConnectionState::Connected {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("A keepalive must initiate a handshake without an external probe");

    for (source, destination, version) in [
        ("10.200.1.1:0", "10.200.2.1:9011", 4),
        ("[fd42:1::1]:0", "[fd42:2::1]:9011", 6),
    ] {
        let socket = UdpSocket::bind(source).await.unwrap();
        let destination: SocketAddr = destination.parse().unwrap();
        let payload = b"wg-easy encrypted namespace payload";
        socket.send_to(payload, destination).await.unwrap();
        let packet = next_packet(&mut received).await.into_bytes();
        assert_eq!(packet[0] >> 4, version);
        assert!(packet.ends_with(payload));
        // Swapping equal-length addresses and ports preserves both IP and UDP checksums.
        let mut response = packet.to_vec();
        if version == 4 {
            let (left, right) = response[12..20].split_at_mut(4);
            left.swap_with_slice(right);
            let (left, right) = response[20..24].split_at_mut(2);
            left.swap_with_slice(right);
        } else {
            let (left, right) = response[8..40].split_at_mut(16);
            left.swap_with_slice(right);
            let (left, right) = response[40..44].split_at_mut(2);
            left.swap_with_slice(right);
        }
        to_server
            .send(
                Packet::copy_from(response.as_slice())
                    .try_into_ip()
                    .unwrap(),
            )
            .await
            .unwrap();
        let mut reply = [0; 100];
        let bytes = tokio::time::timeout(Duration::from_secs(5), socket.recv(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&reply[..bytes], payload);
    }

    let idle_cpu = cpu_nanoseconds();
    let idle_start = Instant::now();
    tokio::time::sleep(Duration::from_secs(3)).await;
    let idle_cpu_percent = cpu_nanoseconds().saturating_sub(idle_cpu) as f64
        / idle_start.elapsed().as_nanos() as f64
        * 100.0;
    let socket = UdpSocket::bind("10.200.1.1:0").await.unwrap();
    let payload = [0x5a; 1024];
    let started = Instant::now();
    for _ in 0..128 {
        for _ in 0..32 {
            socket.send_to(&payload, "10.200.2.1:9011").await.unwrap();
        }
        for _ in 0..32 {
            assert!(
                next_packet(&mut received)
                    .await
                    .into_bytes()
                    .ends_with(&payload)
            );
        }
    }
    let throughput_mbps =
        (128 * 32 * 1024 * 8) as f64 / started.elapsed().as_secs_f64() / 1_000_000.0;
    let status = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let status = client.status().await;
            if status.tx_bytes >= 128 * 32 * 1024 {
                break status;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("The supervised statistics snapshot must include the completed transfer");
    assert!(status.tx_bytes >= 128 * 32 * 1024);
    assert!(status.rx_bytes > 0);
    let measurement = serde_json::json!({"scenario":"native-linux-userspace-loopback", "throughput_mbps":throughput_mbps, "idle_cpu_percent":idle_cpu_percent, "resident_bytes":resident_bytes(), "payload_bytes":128*32*1024});
    println!("WGE_METRICS {measurement}");
    if let Some(path) = std::env::var_os("WGE_METRICS_PATH") {
        std::fs::write(path, format!("{measurement}\n")).unwrap();
    }

    client.stop().await.unwrap();
    server.stop().await;
    assert_eq!(std::fs::read_dir(recovery.path()).unwrap().count(), 0);
    interface_removed("wge-test").await;
}

struct BoundUdp(std::net::IpAddr);

impl gotatun::udp::UdpTransportFactory for BoundUdp {
    type Send = gotatun::udp::socket::UdpSocket;
    type Recv = gotatun::udp::socket::UdpSocket;
    async fn bind(
        &mut self,
        params: &gotatun::udp::UdpTransportFactoryParams,
    ) -> io::Result<(Self::Send, Self::Recv)> {
        let mut params = params.clone();
        params.addr = Some(self.0);
        gotatun::udp::socket::UdpSocketFactory::default()
            .bind(&params)
            .await
    }
}

struct ResolverMount(std::path::PathBuf);
impl Drop for ResolverMount {
    fn drop(&mut self) {
        rustix::mount::unmount(&self.0, rustix::mount::UnmountFlags::empty()).unwrap();
    }
}

async fn srv_server(
    client: &SecretKey,
    server: &SecretKey,
    address: &str,
    port: u16,
) -> (
    gotatun::device::Device<(BoundUdp, ServerTun, ServerTun)>,
    mpsc::Sender<Packet<Ip>>,
    mpsc::Receiver<Packet<Ip>>,
) {
    let (input, incoming) = mpsc::channel(128);
    let (outgoing, output) = mpsc::channel(128);
    let device = DeviceBuilder::new()
        .with_udp(BoundUdp(address.parse().unwrap()))
        .with_ip(ServerTun {
            incoming: Arc::new(Mutex::new(incoming)),
            outgoing,
        })
        .with_private_key(x25519_dalek::StaticSecret::from(*server.as_bytes()))
        .with_listen_port(port)
        .with_peer(
            Peer::new((*client.public_key().as_bytes()).into())
                .with_allowed_ips(["10.201.1.1/32".parse().unwrap()]),
        )
        .build()
        .await
        .unwrap();
    (device, input, output)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated user, mount and network namespaces; exercises real DNS and three-minute handshake expiry"]
async fn namespace_srv_family_failover_changed_ipv6_endpoint_and_cleanup() {
    namespace_only();
    let host = std::env::var_os("WGE_HOST_MNTNS")
        .map(std::path::PathBuf::from)
        .or_else(|| std::fs::read_link("/proc/1/ns/mnt").ok())
        .unwrap();
    assert_ne!(
        std::fs::read_link("/proc/self/ns/mnt").unwrap(),
        host,
        "Run in a private mount namespace; never replace the host resolver"
    );
    rustix::mount::mount_change(
        "/",
        rustix::mount::MountPropagationFlags::PRIVATE | rustix::mount::MountPropagationFlags::REC,
    )
    .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let resolver_file = directory.path().join("resolv.conf");
    std::fs::write(
        &resolver_file,
        "nameserver 127.0.0.1\noptions attempts:1 timeout:1\n",
    )
    .unwrap();
    let resolver_path = std::fs::canonicalize("/etc/resolv.conf").unwrap();
    rustix::mount::mount_bind(&resolver_file, &resolver_path).unwrap();
    let _mount = ResolverMount(resolver_path);
    let fixture = dns::DnsFixture::bind("127.0.0.1:53").await;
    {
        let mut zone = fixture.zone.lock().unwrap();
        zone.srv = vec![dns::srv(0, 100, 51830, "server.test.")];
        zone.addresses.insert(
            "server.test.".into(),
            vec!["::1".parse().unwrap(), "127.0.0.1".parse().unwrap()],
        );
    }
    assert!(matches!(
        &fixture.resolver.srv_lookup("_wireguard._udp.vpn.test.").await.unwrap().answers()[0].data,
        hickory_resolver::proto::rr::RData::SRV(record) if record.port == 51830
    ));
    let client_key = SecretKey::from_bytes([4; 32]).unwrap();
    let server_key = SecretKey::from_bytes([5; 32]).unwrap();
    let (first, _first_input, _first_output) =
        srv_server(&client_key, &server_key, "127.0.0.1", 51830).await;
    let config = TunnelConfig {
        interface: InterfaceConfig {
            private_key: client_key.clone(),
            addresses: vec!["10.201.1.1/24".parse().unwrap()],
            dns: vec![],
            search_domains: vec![],
            listen_port: None,
            mtu: None,
        },
        peers: vec![PeerConfig {
            public_key: server_key.public_key(),
            preshared_key: None,
            endpoint: Some("vpn.test".parse().unwrap()),
            allowed_ips: vec!["10.201.2.0/24".parse().unwrap()],
            persistent_keepalive: None,
        }],
    };
    let recovery = directory.path().join("recovery");
    let client = RunningTunnel::start(&config, "wge-srv", &recovery)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let status = client.status().await;
            if status.state == ConnectionState::Connected {
                assert_eq!(
                    status.peers[0].endpoint,
                    Some("127.0.0.1:51830".parse().unwrap())
                );
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("An unreachable IPv6 endpoint must fall back to IPv4");
    let exported = wge_engine::export(&config).await.unwrap();
    assert!(exported.contains("# wg-easy-srv: vpn.test"));
    first.stop().await;
    let (second, _second_input, _second_output) =
        srv_server(&client_key, &server_key, "::1", 51831).await;
    {
        let mut zone = fixture.zone.lock().unwrap();
        zone.srv = vec![dns::srv(0, 100, 51831, "moved.test.")];
        zone.addresses
            .insert("moved.test.".into(), vec!["::1".parse().unwrap()]);
    }
    tokio::time::timeout(Duration::from_secs(220), async {
        loop {
            let status = client.status().await;
            if status.state == ConnectionState::Connected
                && status.peers[0].endpoint == Some("[::1]:51831".parse().unwrap())
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    })
    .await
    .expect("A stale connection must discover the changed IPv6 address and port");
    assert!(fixture.zone.lock().unwrap().srv_queries >= 3);
    client.stop().await.unwrap();
    second.stop().await;
    assert_eq!(std::fs::read_dir(&recovery).unwrap().count(), 0);
    interface_removed("wge-srv").await;
    let unreachable = RunningTunnel::start(&config, "wge-srv", &recovery)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(25), async {
        while unreachable.status().await.state != ConnectionState::NoHandshake {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("Repeated discovery attempts must not report Connecting forever");
    unreachable.stop().await.unwrap();
    interface_removed("wge-srv").await;
    assert_eq!(std::fs::read_dir(&recovery).unwrap().count(), 0);
}

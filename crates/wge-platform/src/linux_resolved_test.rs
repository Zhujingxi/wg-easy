//! Real resolved integration, run only by scripts/test-resolved.sh.

use std::{fs, net::IpAddr, os::unix::fs::PermissionsExt, time::Duration};
use tokio::{net::UdpSocket, task::JoinHandle, time::timeout};
use tun::AbstractDevice;
use zbus::{Connection, Proxy, zvariant::OwnedObjectPath};

use crate::{
    Network,
    linux_policy::namespace_tests::{device, prepare_namespace},
    recover,
    tests::configuration,
};

struct DnsServer(JoinHandle<()>);

impl DnsServer {
    async fn start(address: &str, answer: [u8; 4]) -> Self {
        let socket = timeout(Duration::from_secs(4), async {
            loop {
                match UdpSocket::bind(address).await {
                    Ok(socket) => break socket,
                    Err(error) if error.kind() == std::io::ErrorKind::AddrNotAvailable => {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                    Err(error) => panic!("Cannot bind DNS fixture: {error}"),
                }
            }
        })
        .await
        .unwrap();
        Self(tokio::spawn(async move {
            let mut request = [0; 4096];
            loop {
                let (size, source) = socket.recv_from(&mut request).await.unwrap();
                assert!(size >= 17);
                let mut end = 12;
                while request[end] != 0 {
                    end += request[end] as usize + 1;
                    assert!(end < size);
                }
                end += 5; // root label, type and class
                let mut reply = request[..end].to_vec();
                reply[2..12].copy_from_slice(&[0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
                reply.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4]);
                reply.extend_from_slice(&answer);
                socket.send_to(&reply, source).await.unwrap();
            }
        }))
    }
}

impl Drop for DnsServer {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn query(name: &str, expected: [u8; 4]) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut request = vec![0x77, 0x65, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        request.push(label.len() as u8);
        request.extend_from_slice(label.as_bytes());
    }
    request.extend_from_slice(&[0, 0, 1, 0, 1]);
    socket.send_to(&request, "127.0.0.53:53").await.unwrap();
    let mut response = [0; 4096];
    let size = timeout(Duration::from_secs(5), socket.recv(&mut response))
        .await
        .expect("The real resolver must answer the query")
        .unwrap();
    assert_eq!(&response[..2], &request[..2]);
    assert_eq!(
        response[3] & 15,
        0,
        "DNS failed for {name}: {:?}",
        &response[..size]
    );
    assert_eq!(
        &response[size - 4..size],
        &expected,
        "Wrong upstream for {name}"
    );
}

async fn link<'a>(connection: &'a Connection, index: u32) -> Proxy<'a> {
    let manager = Proxy::new(
        connection,
        "org.freedesktop.resolve1",
        "/org/freedesktop/resolve1",
        "org.freedesktop.resolve1.Manager",
    )
    .await
    .unwrap();
    let path: OwnedObjectPath = manager.call("GetLink", &(index as i32,)).await.unwrap();
    Proxy::new(
        connection,
        "org.freedesktop.resolve1",
        path,
        "org.freedesktop.resolve1.Link",
    )
    .await
    .unwrap()
}

async fn servers(connection: &Connection, index: u32) -> Vec<IpAddr> {
    let values: Vec<(i32, Vec<u8>)> = link(connection, index)
        .await
        .get_property("DNS")
        .await
        .unwrap();
    values
        .into_iter()
        .map(|(family, bytes)| match family {
            libc::AF_INET => std::net::Ipv4Addr::from(<[u8; 4]>::try_from(bytes).unwrap()).into(),
            libc::AF_INET6 => std::net::Ipv6Addr::from(<[u8; 16]>::try_from(bytes).unwrap()).into(),
            _ => panic!("Unexpected DNS address family"),
        })
        .collect()
}

#[tokio::test]
#[ignore = "requires the private real-resolved harness in scripts/test-resolved.sh"]
async fn resolved_service_split_full_and_recovery() {
    assert_eq!(std::env::var("WGE_RESOLVED_TEST").as_deref(), Ok("1"));
    assert_eq!(
        std::env::var("DBUS_SYSTEM_BUS_ADDRESS").as_deref(),
        Ok("unix:path=/run/dbus/system_bus_socket")
    );
    for (kind, variable) in [("mnt", "WGE_HOST_MNTNS"), ("pid", "WGE_HOST_PIDNS")] {
        assert_ne!(
            fs::read_link(format!("/proc/self/ns/{kind}")).unwrap(),
            std::path::PathBuf::from(std::env::var_os(variable).unwrap())
        );
    }
    prepare_namespace();
    let connection = Connection::system().await.unwrap();
    let bus = Proxy::new(
        &connection,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
    )
    .await
    .unwrap();
    timeout(Duration::from_secs(5), async {
        loop {
            let ready: bool = bus
                .call("NameHasOwner", &("org.freedesktop.resolve1",))
                .await
                .unwrap();
            if ready {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("The real resolved service must start");
    let manager = Proxy::new(
        &connection,
        "org.freedesktop.resolve1",
        "/org/freedesktop/resolve1",
        "org.freedesktop.resolve1.Manager",
    )
    .await
    .unwrap();
    let uplink = device(
        "wge-uplink",
        &["192.0.2.1/24", "192.0.2.53/32", "192.0.2.54/32"],
    );
    let uplink_index = uplink.tun_index().unwrap() as u32;
    let _physical_dns = DnsServer::start("192.0.2.53:53", [198, 51, 100, 1]).await;
    let _renewed_dns = DnsServer::start("192.0.2.54:53", [198, 51, 100, 4]).await;
    let physical_servers: Vec<IpAddr> = vec!["192.0.2.53".parse().unwrap()];
    let _: () = manager
        .call(
            "SetLinkDNS",
            &(
                uplink_index as i32,
                vec![(libc::AF_INET, vec![192_u8, 0, 2, 53])],
            ),
        )
        .await
        .unwrap();
    let _: () = manager
        .call(
            "SetLinkDomains",
            &(uplink_index as i32, vec![("lan.example", true)]),
        )
        .await
        .unwrap();
    let _: () = manager
        .call("SetLinkDefaultRoute", &(uplink_index as i32, true))
        .await
        .unwrap();
    query("before.example", [198, 51, 100, 1]).await;

    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let mut config = configuration();
    config.interface.addresses = [
        "10.53.1.1/24",
        "10.53.1.53/32",
        "fd42:53::1/64",
        "fd42:53::53/128",
    ]
    .map(|a| a.parse().unwrap())
    .into();
    config.interface.dns = vec!["10.53.1.53".parse().unwrap()];
    config.interface.search_domains = vec!["corp.example".into()];
    config.peers[0].allowed_ips = ["10.53.1.0/24", "fd42:53::/64"]
        .map(|a| a.parse().unwrap())
        .into();
    let endpoint = "127.0.0.1:51820".parse().unwrap();
    let (network, tunnel) =
        Network::create(&config, "wge-resolved", &[endpoint], directory.path(), 0)
            .await
            .unwrap();
    let tunnel_index = tunnel.tun_index().unwrap() as u32;
    let tunnel_dns = DnsServer::start("10.53.1.53:53", [198, 51, 100, 2]).await;
    assert_eq!(servers(&connection, uplink_index).await, physical_servers);
    assert_eq!(
        servers(&connection, tunnel_index).await,
        config.interface.dns
    );
    let domains: Vec<(String, bool)> = link(&connection, tunnel_index)
        .await
        .get_property("Domains")
        .await
        .unwrap();
    assert_eq!(domains, vec![("corp.example".into(), true)]);
    query("split.corp.example", [198, 51, 100, 2]).await;
    query("outside.example", [198, 51, 100, 1]).await;
    query("split.lan.example", [198, 51, 100, 1]).await;
    network.stop().await.unwrap();
    assert_eq!(servers(&connection, uplink_index).await, physical_servers);
    assert!(servers(&connection, tunnel_index).await.is_empty());
    drop(tunnel_dns);
    drop(tunnel);

    config.interface.dns = vec!["fd42:53::53".parse().unwrap()];
    config.interface.search_domains.clear();
    config.peers[0].allowed_ips = ["0.0.0.0/0", "::/0"].map(|a| a.parse().unwrap()).into();
    for (crash, renewed) in [(false, false), (true, false), (false, true)] {
        let (network, tunnel) =
            Network::create(&config, "wge-resolved", &[endpoint], directory.path(), 0)
                .await
                .unwrap();
        let tunnel_index = tunnel.tun_index().unwrap() as u32;
        let tunnel_dns = DnsServer::start("[fd42:53::53]:53", [198, 51, 100, 3]).await;
        assert!(servers(&connection, uplink_index).await.is_empty());
        assert_eq!(
            servers(&connection, tunnel_index).await,
            config.interface.dns
        );
        let domains: Vec<(String, bool)> = link(&connection, tunnel_index)
            .await
            .get_property("Domains")
            .await
            .unwrap();
        assert_eq!(domains, vec![(".".into(), true)]);
        query("full.example", [198, 51, 100, 3]).await;
        query("full.lan.example", [198, 51, 100, 3]).await;
        if renewed {
            // An external DHCP renewal must survive restoration of our temporary settings.
            let _: () = manager
                .call(
                    "SetLinkDNS",
                    &(
                        uplink_index as i32,
                        vec![(libc::AF_INET, vec![192_u8, 0, 2, 54])],
                    ),
                )
                .await
                .unwrap();
        }
        if crash {
            drop(network);
            drop(tunnel_dns);
            drop(tunnel);
            recover(directory.path()).await.unwrap();
        } else {
            network.stop().await.unwrap();
            assert!(servers(&connection, tunnel_index).await.is_empty());
            drop(tunnel_dns);
            drop(tunnel);
        }
        if renewed {
            assert_eq!(
                servers(&connection, uplink_index).await,
                vec!["192.0.2.54".parse::<IpAddr>().unwrap()]
            );
            query("renewed.example", [198, 51, 100, 4]).await;
        } else {
            assert_eq!(servers(&connection, uplink_index).await, physical_servers);
            query("restored.example", [198, 51, 100, 1]).await;
        }
        assert!(fs::read_dir(directory.path()).unwrap().next().is_none());
    }
}

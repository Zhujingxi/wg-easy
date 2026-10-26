//! A marked WireGuard socket bypasses the dedicated full-tunnel routing table.

use crate::Error;
use netlink_packet_core::{
    NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP, NLM_F_EXCL, NLM_F_REQUEST, NetlinkMessage, NetlinkPayload,
};
use netlink_packet_route::{
    AddressFamily, RouteNetlinkMessage,
    rule::{RuleAction, RuleAttribute, RuleMessage},
};
use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_ROUTE};
use std::io;

pub(crate) const TABLE: u8 = 246;
pub const SOCKET_MARK: u32 = 0x776765;

fn rules(family: AddressFamily) -> [RuleMessage; 3] {
    let mut bypass = RuleMessage::default();
    bypass.header.family = family;
    bypass.header.table = 254;
    bypass.header.action = RuleAction::ToTable;
    bypass.attributes = vec![
        RuleAttribute::Priority(1),
        RuleAttribute::FwMark(SOCKET_MARK),
        RuleAttribute::FwMask(u32::MAX),
        RuleAttribute::Table(254),
    ];
    let mut unreachable = RuleMessage::default();
    unreachable.header.family = family;
    unreachable.header.action = RuleAction::Unreachable;
    unreachable.attributes = vec![
        RuleAttribute::Priority(2),
        RuleAttribute::FwMark(SOCKET_MARK),
        RuleAttribute::FwMask(u32::MAX),
    ];
    let mut tunnel = RuleMessage::default();
    tunnel.header.family = family;
    tunnel.header.table = TABLE;
    tunnel.header.action = RuleAction::ToTable;
    // Match local output only: reverse-path checks on incoming UDP must use the physical route.
    tunnel.attributes = vec![
        RuleAttribute::Priority(3),
        RuleAttribute::Iifname("lo".into()),
        RuleAttribute::Table(TABLE.into()),
    ];
    [bypass, unreachable, tunnel]
}

fn request(message: RouteNetlinkMessage, flags: u16) -> io::Result<Vec<RuleMessage>> {
    let mut socket = Socket::new(NETLINK_ROUTE)?;
    socket.bind_auto()?;
    socket.connect(&SocketAddr::new(0, 0))?;
    let mut packet = NetlinkMessage::from(message);
    packet.header.flags = flags | NLM_F_REQUEST;
    packet.header.sequence_number = 1;
    packet.finalize();
    let mut bytes = vec![0; packet.buffer_len()];
    packet.serialize(&mut bytes);
    socket.send(&bytes, 0)?;
    let mut rules = Vec::new();
    loop {
        let (bytes, sender) = socket.recv_from_full()?;
        if sender.port_number() != 0 {
            continue;
        }
        let mut offset = 0;
        while offset < bytes.len() {
            let message = NetlinkMessage::<RouteNetlinkMessage>::deserialize(&bytes[offset..])
                .map_err(io::Error::other)?;
            if message.header.length < 16 {
                return Err(io::Error::other("Invalid netlink response length"));
            }
            offset += (message.header.length as usize + 3) & !3;
            match message.payload {
                NetlinkPayload::Done(_) => return Ok(rules),
                NetlinkPayload::Error(e) if e.code.is_none() => return Ok(rules),
                NetlinkPayload::Error(e) => return Err(e.to_io()),
                NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewRule(rule)) => {
                    rules.push(rule)
                }
                _ => {}
            }
        }
    }
}

fn list(family: AddressFamily) -> io::Result<Vec<RuleMessage>> {
    let mut query = RuleMessage::default();
    query.header.family = family;
    request(RouteNetlinkMessage::GetRule(query), NLM_F_DUMP)
}

pub(crate) fn check_available() -> Result<(), Error> {
    if route_manager::RouteManager::new()?
        .list()?
        .iter()
        .any(|r| r.table() == TABLE)
    {
        return Err(Error::Invalid(format!(
            "Routing table {TABLE} is already used. Disconnect the other VPN first."
        )));
    }
    for family in [AddressFamily::Inet, AddressFamily::Inet6] {
        for existing in list(family)? {
            let priority = existing
                .attributes
                .iter()
                .find_map(|a| {
                    if let RuleAttribute::Priority(p) = a {
                        Some(*p)
                    } else {
                        None
                    }
                })
                .unwrap_or(0);
            if priority <= 3 && existing.header.table != 255 {
                return Err(Error::Invalid("An existing high-priority routing policy would bypass this tunnel. Disconnect the other VPN first.".into()));
            }
        }
    }
    Ok(())
}

pub(crate) fn install() -> Result<(), Error> {
    for family in [AddressFamily::Inet, AddressFamily::Inet6] {
        for rule in rules(family) {
            request(
                RouteNetlinkMessage::NewRule(rule),
                NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
            )?;
        }
    }
    Ok(())
}

pub(crate) fn remove() -> Result<(), Error> {
    for family in [AddressFamily::Inet, AddressFamily::Inet6] {
        let targets = rules(family);
        for existing in list(family)? {
            if targets.iter().any(|target| {
                existing.header == target.header
                    && target
                        .attributes
                        .iter()
                        .all(|a| existing.attributes.contains(a))
            }) {
                request(RouteNetlinkMessage::DelRule(existing), NLM_F_ACK)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn full_tunnel_policy_bypasses_only_the_wireguard_socket() {
        let [bypass, stop_loop, tunnel] = rules(AddressFamily::Inet6);
        assert_eq!(bypass.header.table, 254);
        assert!(
            bypass
                .attributes
                .contains(&RuleAttribute::FwMark(SOCKET_MARK))
        );
        assert_eq!(stop_loop.header.action, RuleAction::Unreachable);
        assert_eq!(tunnel.header.table, TABLE);
        assert!(
            tunnel
                .attributes
                .contains(&RuleAttribute::Iifname("lo".into()))
        );
    }
}

#[cfg(test)]
pub(crate) mod namespace_tests {
    use super::*;
    use crate::{Journal, Network, dns, plan_routes, tests::configuration};
    use std::{fs, os::unix::fs::PermissionsExt, time::Duration};
    use tun::AbstractDevice;

    pub(crate) fn prepare_namespace() {
        let host = std::env::var_os("WGE_HOST_NETNS")
            .map(std::path::PathBuf::from)
            .or_else(|| fs::read_link("/proc/1/ns/net").ok())
            .expect("Set WGE_HOST_NETNS before unshare");
        assert_ne!(
            fs::read_link("/proc/self/ns/net").unwrap(),
            host,
            "Refusing to change host networking"
        );
        let mut link = netlink_packet_route::link::LinkMessage::default();
        link.header.index = 1;
        link.header.flags = netlink_packet_route::link::LinkFlags::Up;
        link.header.change_mask = netlink_packet_route::link::LinkFlags::Up;
        request(RouteNetlinkMessage::NewLink(link), NLM_F_ACK).unwrap();
    }

    pub(crate) fn device(name: &str, addresses: &[&str]) -> tun::AsyncDevice {
        let mut config = tun::Configuration::default();
        config.tun_name(name).mtu(1420).up();
        let device = tun::create_as_async(&config).unwrap();
        let interface = netconfig::Interface::try_from_name(name).unwrap();
        for address in addresses {
            interface.add_address(address.parse().unwrap()).unwrap();
        }
        device
    }

    async fn read_payload(device: &tun::AsyncDevice, payload: &[u8]) {
        tokio::time::timeout(Duration::from_secs(3), async {
            let mut bytes = vec![0u8; 2048];
            loop {
                let len = device.recv(&mut bytes).await.unwrap();
                if bytes[..len].ends_with(payload) {
                    break;
                }
            }
        })
        .await
        .expect("The kernel must route the payload to the expected interface");
    }

    #[tokio::test]
    #[ignore = "requires an isolated Linux network namespace"]
    async fn namespace_full_routes_capture_lan_dns_bypass_endpoint_and_recover_crash() {
        prepare_namespace();
        let uplink = device("wge-uplink", &["192.0.2.1/24", "fd00:1::1/64"]);
        let tunnel = device("wge-policy", &["10.0.0.1/24", "fd42:1::1/64"]);
        check_available().unwrap();
        let temporary = tempfile::tempdir().unwrap();
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let routes = plan_routes(
            &configuration(),
            &[],
            &["192.0.2.53".parse().unwrap(), "fd00:1::53".parse().unwrap()],
            "wge-policy",
            tunnel.tun_index().unwrap() as u32,
        )
        .unwrap();
        let network = Network {
            path: temporary.path().join("wge-policy.json"),
            journal: Journal {
                version: 1,
                interface_name: "wge-policy".into(),
                routes,
                displaced_routes: vec![],
                dns: dns::State::None,
                full_tunnel_policy: true,
            },
        };
        network.save().unwrap();
        crate::linux_filter::install("wge-policy").unwrap();
        assert!(crate::linux_filter::installed("wge-policy").unwrap());
        let mut manager = route_manager::RouteManager::new().unwrap();
        for route in &network.journal.routes {
            manager.add(&route.native()).unwrap();
        }
        // Route deletion can race with the kernel removing an interface's routes.
        let route = &network.journal.routes[0];
        route.remove(&mut manager).unwrap();
        route.remove(&mut manager).unwrap();
        manager.add(&route.native()).unwrap();
        install().unwrap();
        for (source, destination) in [
            ("192.0.2.1:0", "192.0.2.53:53"),
            ("[fd00:1::1]:0", "[fd00:1::53]:53"),
        ] {
            let socket = tokio::net::UdpSocket::bind(source).await.unwrap();
            socket
                .send_to(b"tunnel-only-dns", destination)
                .await
                .unwrap();
            read_payload(&tunnel, b"tunnel-only-dns").await;
            let bound = tokio::net::UdpSocket::bind(source).await.unwrap();
            socket2::SockRef::from(&bound)
                .bind_device(Some(b"wge-uplink"))
                .unwrap();
            assert!(
                bound
                    .send_to(b"bound-uplink-must-not-leak", destination)
                    .await
                    .is_err(),
                "A physical-interface-bound socket must not fall back to the main table: {source}"
            );
            socket2::SockRef::from(&socket)
                .set_mark(SOCKET_MARK)
                .unwrap();
            socket
                .send_to(b"wireguard-endpoint-bypass", destination)
                .await
                .unwrap();
            read_payload(&uplink, b"wireguard-endpoint-bypass").await;
        }
        assert!(check_available().is_err());
        // A process crash drops in-memory state while the persisted cleanup intent survives.
        drop(network);
        crate::recover(temporary.path()).await.unwrap();
        assert!(!crate::linux_filter::installed("wge-policy").unwrap());
        assert_eq!(fs::read_dir(temporary.path()).unwrap().count(), 0);
        assert!(manager.list().unwrap().iter().all(|r| r.table() != TABLE));
        check_available().unwrap();
        for (source, destination) in [
            ("192.0.2.1:0", "192.0.2.53:53"),
            ("[fd00:1::1]:0", "[fd00:1::53]:53"),
        ] {
            let socket = tokio::net::UdpSocket::bind(source).await.unwrap();
            socket2::SockRef::from(&socket)
                .bind_device(Some(b"wge-uplink"))
                .unwrap();
            socket
                .send_to(b"restored-physical-route", destination)
                .await
                .unwrap();
            read_payload(&uplink, b"restored-physical-route").await;
        }
        crate::linux_filter::assert_ownership_collision();
        let normal = Network {
            path: temporary.path().join("wge-policy.json"),
            journal: Journal {
                version: 1,
                interface_name: "wge-policy".into(),
                routes: vec![],
                displaced_routes: vec![],
                dns: dns::State::None,
                full_tunnel_policy: true,
            },
        };
        normal.save().unwrap();
        crate::linux_filter::install("wge-policy").unwrap();
        normal.stop().await.unwrap();
        assert!(!crate::linux_filter::installed("wge-policy").unwrap());
        drop(tunnel);
        drop(uplink);
    }
}

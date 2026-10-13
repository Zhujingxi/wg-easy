use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use proptest::prelude::*;
use wge_config::{
    Endpoint, ErrorKind, InterfaceConfig, IpNetwork, MAX_CONFIG_BYTES, PeerConfig, PublicConfig,
    PublicKey, SecretKey, TunnelConfig, coverage, overlaps, parse, route_overlaps,
    routes_all_traffic, server_snippet, validate_domain, validate_name, write,
};

fn config() -> TunnelConfig {
    TunnelConfig {
        interface: InterfaceConfig {
            private_key: SecretKey::from_bytes([1; 32]).unwrap(),
            addresses: vec![
                "10.4.0.2/24".parse().unwrap(),
                "fd00::2/64".parse().unwrap(),
            ],
            dns: vec!["10.4.0.1".parse().unwrap(), "fd00::1".parse().unwrap()],
            search_domains: vec!["internal.example".to_owned()],
            listen_port: Some(0),
            mtu: Some(1420),
        },
        peers: vec![PeerConfig {
            public_key: PublicKey::from_bytes([2; 32]).unwrap(),
            preshared_key: Some(SecretKey::from_bytes([3; 32]).unwrap()),
            endpoint: Some("[2001:db8::7]:51820".parse().unwrap()),
            allowed_ips: vec!["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()],
            persistent_keepalive: Some(25),
        }],
    }
}

#[test]
fn standard_dual_stack_round_trip_preserves_host_addresses() {
    let config = config();
    let text = write(&config).unwrap();
    assert!(text.contains("Address = 10.4.0.2/24, fd00::2/64"));
    assert!(text.contains("DNS = 10.4.0.1, fd00::1, internal.example"));
    assert_eq!(parse(&text).unwrap(), config);
}

#[test]
fn comments_crlf_bom_case_and_repeated_lists_work() {
    let text = format!(
        "\u{feff}# imported\r\n[interface]\r\nprivatekey = {} # private\r\nAddress=10.4.0.2/24\r\nAddress=fd00::2/64\r\nDNS=10.4.0.1\r\nDNS=internal.example\r\n[peer]\r\nPublicKey={}\r\nAllowedIPs=10.0.0.0/8\r\nAllowedIPs=fd00::/8\r\n",
        config().interface.private_key.expose_base64().as_str(),
        config().peers[0].public_key
    );
    let config = parse(&text).unwrap();
    assert_eq!(config.interface.addresses.len(), 2);
    assert_eq!(config.peers[0].allowed_ips.len(), 2);
    assert_eq!(config.interface.search_domains, ["internal.example"]);
    assert_eq!(parse(&write(&config).unwrap()).unwrap(), config);
}

#[test]
fn keys_reject_invalid_encoding_length_and_zero() {
    for bad in [
        "",
        "a",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!=",
        "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQF=",
    ] {
        assert!(bad.parse::<SecretKey>().is_err(), "{bad}");
        assert!(bad.parse::<PublicKey>().is_err(), "{bad}");
    }
    assert!(SecretKey::from_bytes([0; 32]).is_err());
    assert!(PublicKey::from_bytes([0; 32]).is_err());
}

#[test]
fn private_key_derivation_matches_rfc7748() {
    let private = [
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66,
        0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9,
        0x2c, 0x2a,
    ];
    let expected = [
        0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7,
        0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b,
        0x4e, 0x6a,
    ];
    assert_eq!(
        SecretKey::from_bytes(private)
            .unwrap()
            .public_key()
            .as_bytes(),
        &expected
    );
}

#[test]
fn debug_and_public_models_do_not_disclose_private_or_preshared_keys() {
    let config = config();
    let debug = format!("{config:?}");
    let serialized = serde_json::to_string(&config.public()).unwrap();
    for secret in [
        &config.interface.private_key,
        config.peers[0].preshared_key.as_ref().unwrap(),
    ] {
        assert!(!debug.contains(secret.expose_base64().as_str()));
        assert!(!serialized.contains(secret.expose_base64().as_str()));
    }
    assert!(debug.contains("[REDACTED]"));
    assert!(config.public().peers[0].has_preshared_key);
    assert_eq!(
        serde_json::from_str::<PublicConfig>(&serialized).unwrap(),
        config.public()
    );
}

#[test]
fn hooks_are_refused_with_the_exact_field_and_line() {
    for hook in ["PreUp", "PostUp", "PreDown", "PostDown"] {
        let text = format!("[Interface]\n{hook} = DO_NOT_RUN_SECRET_COMMAND\n");
        let error = parse(&text).unwrap_err();
        assert_eq!(error.kind, ErrorKind::ScriptHook);
        assert_eq!(error.field, hook);
        assert_eq!(error.line, Some(2));
        assert!(!format!("{error:?} {error}").contains("DO_NOT_RUN_SECRET_COMMAND"));
    }
}

#[test]
fn unknown_and_platform_specific_settings_are_not_silently_lost() {
    for setting in ["Table", "SaveConfig", "FwMark", "MadeUp"] {
        let error = parse(&format!("[Interface]\n{setting} = secret\n")).unwrap_err();
        assert_eq!(error.kind, ErrorKind::UnsupportedField);
        assert_eq!(error.line, Some(2));
    }
}

#[test]
fn singleton_duplicates_and_duplicate_sections_are_rejected() {
    let text = write(&config()).unwrap();
    for duplicate in [
        "Endpoint=server.example:12",
        "PublicKey=AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
        "[Interface]",
    ] {
        let error = parse(&format!("{}{duplicate}\n", text.as_str())).unwrap_err();
        assert_eq!(error.kind, ErrorKind::DuplicateField);
    }
}

#[test]
fn required_settings_and_sections_are_checked() {
    let text = write(&config()).unwrap();
    for (bad, kind) in [
        (String::new(), ErrorKind::MissingField),
        ("[Peer]\n".to_owned(), ErrorKind::MissingField),
        ("[Invalid]\n".to_owned(), ErrorKind::UnsupportedSection),
        (
            text.replace("Address = 10.4.0.2/24, fd00::2/64\n", ""),
            ErrorKind::MissingAddress,
        ),
        (
            text.split("[Peer]").next().unwrap().to_owned(),
            ErrorKind::MissingPeer,
        ),
        (
            text.replace("AllowedIPs = 0.0.0.0/0, ::/0\n", ""),
            ErrorKind::MissingRoutes,
        ),
        (
            text.replace(
                "Address = 10.4.0.2/24, fd00::2/64",
                "Address = 10.4.0.2/24,",
            ),
            ErrorKind::InvalidAddress,
        ),
    ] {
        assert_eq!(parse(&bad).unwrap_err().kind, kind);
    }
    assert_eq!(
        parse(&" ".repeat(MAX_CONFIG_BYTES + 1)).unwrap_err().kind,
        ErrorKind::TooLarge
    );
}

#[test]
fn endpoints_cover_both_families_and_validate_direct_ipc_models() {
    for value in [
        "192.0.2.1:51820",
        "[2001:db8::1]:1",
        "vpn.example:65535",
        "localhost:1234",
        "vpn.example.:51820",
    ] {
        let endpoint: Endpoint = value.parse().unwrap();
        assert_eq!(endpoint.to_string(), value);
    }
    for value in [
        "[::1]",
        "[vpn.example]:42",
        "host:0",
        "host:65536",
        "host:+1",
        "host: 42",
        "0.0.0.0:42",
        "[::]:42",
        "bad host:42",
        "-host:42",
        "host..example:42",
        "1.2.3.999:42",
        "224.0.0.1:42",
        "[fe80::1%eth0]:42",
    ] {
        assert!(value.parse::<Endpoint>().is_err(), "{value}");
    }
    assert!(
        Endpoint {
            host: "host\nPostUp=malicious".to_owned(),
            port: Some(42)
        }
        .validate()
        .is_err()
    );
    assert!(
        Endpoint {
            host: "host".to_owned(),
            port: Some(0)
        }
        .validate()
        .is_err()
    );
}

#[test]
fn discovery_survives_storage_ipc_and_standard_ipv6_export() {
    let mut config = config();
    config.peers[0].endpoint = Some("vpn.example".parse().unwrap());
    let stored = write(&config).unwrap();
    assert!(stored.contains("# wg-easy-srv: vpn.example\nEndpoint = vpn.example:51820"));
    assert_eq!(parse(&stored).unwrap(), config);
    let public = config.public();
    assert_eq!(
        serde_json::from_str::<PublicConfig>(&serde_json::to_string(&public).unwrap()).unwrap(),
        public
    );
    let exported =
        wge_config::write_resolved(&config, &[Some("[2001:db8::5]:443".parse().unwrap())]).unwrap();
    assert!(exported.contains("Endpoint = [2001:db8::5]:443"));
    assert_eq!(parse(&exported).unwrap(), config);
    let standard = exported
        .lines()
        .filter(|line| !line.starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    assert_eq!(
        parse(&standard).unwrap().peers[0].endpoint,
        Some("[2001:db8::5]:443".parse().unwrap())
    );
    assert!(wge_config::write_resolved(&config, &[None]).is_err());
    assert!(wge_config::write_resolved(&config, &[]).is_err());
    assert!(wge_config::write_resolved(&config, &[Some("[::]:443".parse().unwrap())]).is_err());
    assert_eq!(
        serde_json::from_str::<Endpoint>(r#"{"host":"vpn.example","port":42}"#)
            .unwrap()
            .port,
        Some(42)
    );
}

#[test]
fn discovery_metadata_is_validated_and_standard_imports_stay_explicit() {
    let config = config();
    let text = write(&config).unwrap();
    assert!(
        parse(&text).unwrap().peers[0]
            .endpoint
            .as_ref()
            .unwrap()
            .port
            .is_some()
    );
    for host in [
        "",
        "bad host",
        "192.0.2.1",
        "_wireguard._udp.example",
        "host:443",
    ] {
        let invalid = text.replace("Endpoint =", &format!("# wg-easy-srv: {host}\nEndpoint ="));
        assert!(parse(&invalid).is_err(), "{host}");
    }
    let duplicate = text.replace(
        "Endpoint =",
        "# wg-easy-srv: vpn.example\n# wg-easy-srv: vpn.example\nEndpoint =",
    );
    assert!(parse(&duplicate).is_err());
    assert!(parse(&format!("# wg-easy-srv: vpn.example\n{}", text.as_str())).is_err());
    let missing = text.replace(
        "Endpoint = [2001:db8::7]:51820",
        "# wg-easy-srv: vpn.example",
    );
    assert!(parse(&missing).is_err());
    for value in ["vpn.example", "192.0.2.1", "2001:db8::1", "::1:51820"] {
        assert!(parse(&text.replace("[2001:db8::7]:51820", value)).is_err());
    }
}

#[test]
fn mtu_validation_accounts_for_ipv6_routes() {
    let mut config = config();
    config.interface.mtu = Some(1279);
    assert_eq!(config.validate().unwrap_err().kind, ErrorKind::InvalidMtu);
    config.interface.mtu = Some(1280);
    config.validate().unwrap();
    config.interface.addresses.retain(IpNetwork::is_ipv4);
    config.peers[0].allowed_ips.retain(IpNetwork::is_ipv4);
    config.interface.mtu = Some(576);
    assert_eq!(config.validate().unwrap_err().kind, ErrorKind::InvalidMtu);
    config.peers[0].allowed_ips = vec!["10.0.0.0/8".parse().unwrap()];
    config.validate().unwrap();
    config.interface.mtu = Some(575);
    assert_eq!(config.validate().unwrap_err().kind, ErrorKind::InvalidMtu);
}

#[test]
fn untrusted_models_cannot_inject_settings_on_export() {
    let mut config = config();
    config
        .interface
        .search_domains
        .push("example\nPostUp=secret".to_owned());
    assert_eq!(write(&config).unwrap_err().kind, ErrorKind::InvalidDns);
    config.interface.search_domains.clear();
    config.peers[0].endpoint.as_mut().unwrap().host = "server\nPostUp=secret".to_owned();
    assert_eq!(write(&config).unwrap_err().kind, ErrorKind::InvalidEndpoint);
}

#[test]
fn duplicate_peers_and_own_public_key_are_rejected() {
    let mut config = config();
    config.peers.push(config.peers[0].clone());
    assert_eq!(
        config.validate().unwrap_err().kind,
        ErrorKind::DuplicatePeer
    );
    config.peers.pop();
    config.peers[0].public_key = config.interface.private_key.public_key();
    assert_eq!(config.validate().unwrap_err().kind, ErrorKind::OwnPublicKey);
}

#[test]
fn japanese_names_and_dns_names_validate_without_network_requests() {
    validate_name("東京 オフィス").unwrap();
    for name in ["", "  ", "bad\nname", "bad\0name"] {
        assert!(validate_name(name).is_err());
    }
    assert!(validate_name(&"東".repeat(81)).is_err());
    assert!(validate_domain("office.example."));
    assert!(validate_domain("xn--wgv71a.example"));
    for name in [
        "",
        ".",
        "-bad.example",
        "bad-.example",
        "bad..example",
        "bad/name",
        "日本.example",
        "example\nPostUp=x",
    ] {
        assert!(!validate_domain(name));
    }
}

#[test]
fn range_coverage_is_exact_even_for_the_full_ipv6_space() {
    let range = coverage(&"10.0.0.42/24".parse().unwrap());
    assert_eq!(range.first.to_string(), "10.0.0.0");
    assert_eq!(range.last.to_string(), "10.0.0.255");
    assert_eq!(range.address_count, "256");
    assert_eq!(
        coverage(&"0.0.0.0/0".parse().unwrap()).address_count,
        "4294967296"
    );
    assert_eq!(
        coverage(&"::/0".parse().unwrap()).address_count,
        "340282366920938463463374607431768211456"
    );
    assert_eq!(
        coverage(
            &"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"
                .parse()
                .unwrap()
        )
        .address_count,
        "1"
    );
}

#[test]
fn conflicts_distinguish_real_ranges_and_full_tunnel_exclusivity() {
    let private = "10.0.0.0/8".parse().unwrap();
    let within = "10.4.0.0/24".parse().unwrap();
    let other = "192.168.0.0/16".parse().unwrap();
    let ipv6 = "fd00::/8".parse().unwrap();
    assert!(overlaps(&private, &within));
    assert!(!overlaps(&private, &other));
    assert!(!overlaps(&private, &ipv6));
    assert_eq!(route_overlaps(&[private], &[within])[0].active, within);
    assert!(route_overlaps(&[private], &[ipv6]).is_empty());
    assert!(!route_overlaps(&["0.0.0.0/0".parse().unwrap()], &[ipv6]).is_empty());
    assert_eq!(route_overlaps(&[private; 100], &[within; 100]).len(), 32);
}

#[test]
fn split_defaults_get_full_tunnel_safeguards() {
    for routes in [
        vec!["0.0.0.0/1", "128.0.0.0/1"],
        vec!["::/2", "4000::/2", "8000::/1"],
    ] {
        let routes: Vec<IpNetwork> = routes
            .into_iter()
            .map(|route| route.parse().unwrap())
            .collect();
        assert!(routes_all_traffic(&routes));
        assert!(!route_overlaps(&routes, &["fd00::/64".parse().unwrap()]).is_empty());
    }
    let routes: Vec<IpNetwork> = ["0.0.0.0/2", "128.0.0.0/1"]
        .into_iter()
        .map(|route| route.parse().unwrap())
        .collect();
    assert!(!routes_all_traffic(&routes));
}

#[test]
fn server_snippet_routes_only_the_device_addresses_and_contains_no_secrets() {
    let config = config();
    let snippet = server_snippet(&config.public());
    assert!(snippet.contains("AllowedIPs = 10.4.0.2/32, fd00::2/128"));
    assert!(snippet.contains(&config.interface.private_key.public_key().to_string()));
    assert!(!snippet.contains("PrivateKey"));
    assert!(!snippet.contains(config.interface.private_key.expose_base64().as_str()));
}

proptest! {
    #[test]
    fn valid_models_round_trip(
        secret in any::<[u8; 32]>().prop_filter("nonzero secret", |key| *key != [0; 32]),
        public in any::<[u8; 32]>().prop_filter("nonzero public", |key| *key != [0; 32]),
        v4 in any::<u32>().prop_filter("unicast", |address| !Ipv4Addr::from(*address).is_multicast() && *address != 0 && *address != u32::MAX),
        v6 in any::<u128>().prop_filter("unicast", |address| !Ipv6Addr::from(*address).is_multicast() && *address != 0),
        prefix4 in 0_u8..=32,
        prefix6 in 0_u8..=128,
        routes in prop::collection::vec((any::<u32>(), 0_u8..=32), 1..20),
        port in 1_u16..=u16::MAX,
        discovery in any::<bool>(),
        keepalive in prop::option::of(any::<u16>()),
        mtu in 1280_u16..=u16::MAX,
    ) {
        let mut config = config();
        config.interface.private_key = SecretKey::from_bytes(secret).unwrap();
        config.interface.addresses = vec![IpNetwork::new(IpAddr::V4(v4.into()), prefix4).unwrap(), IpNetwork::new(IpAddr::V6(v6.into()), prefix6).unwrap()];
        config.interface.mtu = Some(mtu);
        config.peers[0].public_key = PublicKey::from_bytes(public).unwrap();
        config.peers[0].endpoint = Some(Endpoint { host: "vpn.example".to_owned(), port: if discovery { None } else { Some(port) } });
        config.peers[0].persistent_keepalive = keepalive;
        config.peers[0].allowed_ips = routes.into_iter().map(|(address, prefix)| IpNetwork::new(IpAddr::V4(address.into()), prefix).unwrap()).collect();
        prop_assume!(config.peers[0].public_key != config.interface.private_key.public_key());
        let written = write(&config).unwrap();
        prop_assert_eq!(parse(&written).unwrap(), config);
    }

    #[test]
    fn arbitrary_text_never_panics(input in ".{0,8192}") {
        if let Ok(config) = parse(&input) {
            let output = write(&config).unwrap();
            prop_assert_eq!(parse(&output).unwrap(), config);
        }
    }

    #[test]
    fn overlap_is_symmetric_and_reflexive(a in any::<u32>(), b in any::<u32>(), pa in 0_u8..=32, pb in 0_u8..=32) {
        let left = IpNetwork::new(IpAddr::V4(a.into()), pa).unwrap();
        let right = IpNetwork::new(IpAddr::V4(b.into()), pb).unwrap();
        prop_assert!(overlaps(&left, &left));
        prop_assert_eq!(overlaps(&left, &right), overlaps(&right, &left));
        let left_range = coverage(&left);
        let right_range = coverage(&right);
        prop_assert_eq!(overlaps(&left, &right), left_range.first <= right_range.last && right_range.first <= left_range.last);
    }
}

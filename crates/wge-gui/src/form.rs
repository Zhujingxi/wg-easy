use std::{collections::BTreeMap, net::IpAddr};
use wge_config::{Endpoint, IpNetwork, PublicConfig, PublicPeer, validate_domain, validate_name};
use wge_ipc::{PeerSecretUpdate, SensitiveText};
use zeroize::Zeroizing;

pub type Values = BTreeMap<String, Zeroizing<String>>;
pub type Errors = BTreeMap<String, &'static str>;

pub fn values(config: &PublicConfig, name: &str) -> Values {
    let mut fields = BTreeMap::<String, String>::from([
        ("name".into(), name.into()),
        ("addresses".into(), joined(&config.interface.addresses)),
        ("dns".into(), joined(&config.interface.dns)),
        ("domains".into(), config.interface.search_domains.join(", ")),
        (
            "mtu".into(),
            config
                .interface
                .mtu
                .map(|n| n.to_string())
                .unwrap_or_default(),
        ),
        (
            "port".into(),
            config
                .interface
                .listen_port
                .map(|n| n.to_string())
                .unwrap_or_default(),
        ),
    ]);
    for (index, peer) in config.peers.iter().enumerate() {
        fields.insert(
            key(index, "endpoint"),
            peer.endpoint
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_default(),
        );
        fields.insert(key(index, "public_key"), peer.public_key.to_string());
        fields.insert(key(index, "routes"), joined(&peer.allowed_ips));
        fields.insert(
            key(index, "keepalive"),
            peer.persistent_keepalive
                .map(|n| n.to_string())
                .unwrap_or_default(),
        );
        fields.insert(key(index, "psk"), String::new());
    }
    fields
        .into_iter()
        .map(|(key, value)| (key, Zeroizing::new(value)))
        .collect()
}
pub fn key(peer: usize, field: &str) -> String {
    format!("{peer}.{field}")
}
fn joined<T: ToString>(values: &[T]) -> String {
    values
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}
pub fn split(value: &str) -> impl Iterator<Item = &str> {
    value
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|s| !s.is_empty())
}

pub fn endpoint(value: &str) -> Result<Endpoint, wge_config::ConfigError> {
    if let Ok(address) = value.parse::<IpAddr>() {
        return format!(
            "{}{address}{}:51820",
            if address.is_ipv6() { "[" } else { "" },
            if address.is_ipv6() { "]" } else { "" }
        )
        .parse();
    }
    if !value.contains(':') {
        format!("{value}:51820").parse()
    } else {
        value.parse()
    }
}

pub fn build(
    base: &PublicConfig,
    fields: &Values,
    peers: usize,
    all: bool,
) -> Result<(PublicConfig, Vec<PeerSecretUpdate>), Errors> {
    let get = |key: &str| fields.get(key).map(|s| s.trim()).unwrap_or("");
    let mut errors = Errors::new();
    if validate_name(get("name")).is_err() {
        errors.insert("name".into(), "error_name");
    }
    let addresses: Result<Vec<IpNetwork>, _> = split(get("addresses")).map(str::parse).collect();
    let dns: Result<Vec<IpAddr>, _> = split(get("dns")).map(str::parse).collect();
    if addresses.as_ref().map_or(true, |v| v.is_empty()) {
        errors.insert("addresses".into(), "error_addresses");
    }
    if dns.is_err() {
        errors.insert("dns".into(), "error_dns");
    }
    let domains: Vec<String> = split(get("domains")).map(str::to_owned).collect();
    if domains.iter().any(|d| !validate_domain(d)) {
        errors.insert("domains".into(), "error_domains");
    }
    let mut config = base.clone();
    config.interface.addresses = addresses.unwrap_or_default();
    config.interface.dns = dns.unwrap_or_default();
    config.interface.search_domains = domains;
    config.interface.mtu = parse_number(get("mtu"), "mtu", 576, 65_535, &mut errors);
    config.interface.listen_port = parse_number(get("port"), "port", 0, 65_535, &mut errors);
    config.peers.clear();
    let mut secrets = Vec::new();
    for index in 0..peers {
        let public_key = get(&key(index, "public_key")).parse();
        let endpoint_value = get(&key(index, "endpoint"));
        let endpoint = if endpoint_value.is_empty() && index > 0 {
            None
        } else {
            match endpoint(endpoint_value) {
                Ok(endpoint) => Some(endpoint),
                Err(_) => {
                    errors.insert(key(index, "endpoint"), "error_endpoint");
                    None
                }
            }
        };
        let ranges = if all && index == 0 {
            "0.0.0.0/0, ::/0"
        } else {
            get(&key(index, "routes"))
        };
        let allowed_ips: Result<Vec<IpNetwork>, _> = split(ranges).map(str::parse).collect();
        if allowed_ips.as_ref().map_or(true, |r| r.is_empty()) {
            errors.insert(key(index, "routes"), "error_routes");
        }
        let keepalive_key = key(index, "keepalive");
        let persistent_keepalive =
            parse_number(get(&keepalive_key), &keepalive_key, 0, 65_535, &mut errors);
        match public_key {
            Ok(public_key) => {
                let psk = get(&key(index, "psk"));
                let existing = base
                    .peers
                    .iter()
                    .any(|p| p.public_key == public_key && p.has_preshared_key);
                if !psk.is_empty() {
                    if psk == "-" {
                        secrets.push(PeerSecretUpdate {
                            public_key,
                            value: None,
                        });
                    } else if psk.parse::<wge_config::SecretKey>().is_err() {
                        errors.insert(key(index, "psk"), "error_key");
                    } else {
                        secrets.push(PeerSecretUpdate {
                            public_key,
                            value: Some(SensitiveText::new(psk.to_owned())),
                        });
                    }
                }
                config.peers.push(PublicPeer {
                    public_key,
                    endpoint,
                    allowed_ips: allowed_ips.unwrap_or_default(),
                    persistent_keepalive,
                    has_preshared_key: if psk == "-" {
                        false
                    } else {
                        existing || !psk.is_empty()
                    },
                });
            }
            Err(_) => {
                errors.insert(key(index, "public_key"), "error_key");
            }
        }
    }
    if errors.is_empty()
        && let Err(error) = config.validate()
    {
        let (field, message) = match error.field {
            "Address" => ("addresses", "error_addresses"),
            "DNS" => ("dns", "error_dns"),
            "MTU" => ("mtu", "error_number"),
            "PublicKey" => ("0.public_key", "error_peer_key"),
            "AllowedIPs" => ("0.routes", "error_routes"),
            _ => ("addresses", "error_config"),
        };
        errors.insert(field.into(), message);
    }
    if errors.is_empty() {
        Ok((config, secrets))
    } else {
        Err(errors)
    }
}
fn parse_number(value: &str, key: &str, min: u16, max: u16, errors: &mut Errors) -> Option<u16> {
    if value.is_empty() {
        return None;
    }
    match value.parse::<u16>() {
        Ok(value) if (min..=max).contains(&value) => Some(value),
        _ => {
            errors.insert(key.into(), "error_number");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn server_port_defaults_for_both_ip_families_and_names() {
        for server in ["vpn.example.com", "192.0.2.1", "2001:db8::1"] {
            assert_eq!(endpoint(server).unwrap().port, 51820);
        }
        assert_eq!(endpoint("[2001:db8::1]:1234").unwrap().port, 1234);
        assert!(endpoint("bad server").is_err());
    }
    #[test]
    fn ipv4_import_preserves_small_mtu_and_automatic_port() {
        let text = "[Interface]\nPrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\nAddress = 10.0.0.2/32\nMTU = 576\nListenPort = 0\n[Peer]\nPublicKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\nEndpoint = vpn.example.com:51820\nAllowedIPs = 10.0.0.0/24\n";
        let public = wge_config::parse(text).unwrap().public();
        let mut fields = values(&public, "Tunnel");
        let (roundtrip, _) = build(&public, &fields, 1, false).unwrap();
        assert_eq!(roundtrip, public);
        fields.insert("0.routes".into(), "::/0".to_owned().into());
        assert!(
            build(&public, &fields, 1, false)
                .unwrap_err()
                .contains_key("mtu")
        );
    }
    #[test]
    fn public_form_never_carries_keys_and_new_tunnel_needs_three_values() {
        let text = "[Interface]\nPrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\nEndpoint = vpn.example.com:51820\nAllowedIPs = 0.0.0.0/0, ::/0\n";
        let public = wge_config::parse(text).unwrap().public();
        let fields = values(&public, "自宅");
        assert!(!fields.values().any(|v| v.contains("AQEBAQE")));
        let (roundtrip, secrets) = build(&public, &fields, 1, true).unwrap();
        assert_eq!(roundtrip, public);
        assert!(secrets.is_empty());
        let mut wrong = fields;
        wrong.insert("addresses".into(), "mistake".to_owned().into());
        wrong.insert("0.public_key".into(), "mistake".to_owned().into());
        assert_eq!(build(&public, &wrong, 1, true).unwrap_err().len(), 2);
    }
}

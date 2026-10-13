use std::{
    collections::HashSet,
    fmt::Write,
    net::{IpAddr, SocketAddr},
    str::FromStr,
};

use crate::{
    ConfigError, Endpoint, ErrorKind, InterfaceConfig, IpNetwork, MAX_ADDRESSES, MAX_CONFIG_BYTES,
    MAX_PEERS, MAX_ROUTES, PeerConfig, PublicKey, SecretKey, TunnelConfig, Zeroizing,
    validate_domain,
};

#[derive(Default)]
struct InterfaceDraft {
    private_key: Option<SecretKey>,
    addresses: Vec<IpNetwork>,
    dns: Vec<IpAddr>,
    search_domains: Vec<String>,
    listen_port: Option<u16>,
    mtu: Option<u16>,
    seen: HashSet<&'static str>,
}

#[derive(Default)]
struct PeerDraft {
    public_key: Option<PublicKey>,
    preshared_key: Option<SecretKey>,
    endpoint: Option<Endpoint>,
    srv_host: Option<String>,
    allowed_ips: Vec<IpNetwork>,
    persistent_keepalive: Option<u16>,
    seen: HashSet<&'static str>,
    line: usize,
}

const SRV_COMMENT: &str = "# wg-easy-srv: ";

/// Parse a complete `wg-quick` file. No settings are silently ignored.
pub fn parse(input: &str) -> Result<TunnelConfig, ConfigError> {
    if input.len() > MAX_CONFIG_BYTES {
        return Err(ConfigError::new(ErrorKind::TooLarge, "Configuration"));
    }
    let mut interface = InterfaceDraft::default();
    let mut interface_line = None;
    let mut peers = Vec::<PeerDraft>::new();
    for (offset, line) in input
        .strip_prefix('\u{feff}')
        .unwrap_or(input)
        .lines()
        .enumerate()
    {
        let number = offset + 1;
        if let Some(host) = line.trim_start().strip_prefix(SRV_COMMENT) {
            let peer = peers.last_mut().ok_or_else(|| {
                ConfigError::new(ErrorKind::InvalidEndpoint, "Endpoint").at(number)
            })?;
            if peer.srv_host.is_some() || !validate_domain(host) {
                return Err(ConfigError::new(ErrorKind::InvalidEndpoint, "Endpoint").at(number));
            }
            peer.srv_host = Some(host.to_owned());
            continue;
        }
        let line = line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        if line.eq_ignore_ascii_case("[Interface]") {
            if interface_line.is_some() {
                return Err(ConfigError::new(ErrorKind::DuplicateField, "Interface").at(number));
            }
            interface_line = Some(number);
            continue;
        }
        if line.eq_ignore_ascii_case("[Peer]") {
            if interface_line.is_none() {
                return Err(ConfigError::new(ErrorKind::MissingField, "Interface").at(number));
            }
            if peers.len() == MAX_PEERS {
                return Err(ConfigError::new(ErrorKind::TooManyItems, "Peer").at(number));
            }
            peers.push(PeerDraft {
                line: number,
                ..Default::default()
            });
            continue;
        }
        if line.starts_with('[') {
            return Err(ConfigError::new(ErrorKind::UnsupportedSection, "Section").at(number));
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| ConfigError::new(ErrorKind::Syntax, "Setting").at(number))?;
        let key = key.trim();
        let value = value.trim();
        let key = match_key(key).map_err(|error| error.at(number))?;
        if matches!(key, "PreUp" | "PostUp" | "PreDown" | "PostDown") {
            return Err(ConfigError::new(ErrorKind::ScriptHook, key).at(number));
        }
        if interface_line.is_none() {
            return Err(ConfigError::new(ErrorKind::MissingField, "Interface").at(number));
        }
        let result = if let Some(peer) = peers.last_mut() {
            parse_peer(peer, key, value)
        } else {
            parse_interface(&mut interface, key, value)
        };
        result.map_err(|mut error| {
            error.field = key;
            error.at(number)
        })?;
    }
    let line =
        interface_line.ok_or_else(|| ConfigError::new(ErrorKind::MissingField, "Interface"))?;
    let config = TunnelConfig {
        interface: InterfaceConfig {
            private_key: interface
                .private_key
                .ok_or_else(|| ConfigError::new(ErrorKind::MissingField, "PrivateKey").at(line))?,
            addresses: interface.addresses,
            dns: interface.dns,
            search_domains: interface.search_domains,
            listen_port: interface.listen_port,
            mtu: interface.mtu,
        },
        peers: peers
            .into_iter()
            .map(|peer| {
                let endpoint = if let Some(host) = peer.srv_host {
                    if peer.endpoint.is_none() {
                        return Err(
                            ConfigError::new(ErrorKind::MissingField, "Endpoint").at(peer.line)
                        );
                    }
                    Some(Endpoint { host, port: None })
                } else {
                    peer.endpoint
                };
                Ok(PeerConfig {
                    public_key: peer.public_key.ok_or_else(|| {
                        ConfigError::new(ErrorKind::MissingField, "PublicKey").at(peer.line)
                    })?,
                    preshared_key: peer.preshared_key,
                    endpoint,
                    allowed_ips: peer.allowed_ips,
                    persistent_keepalive: peer.persistent_keepalive,
                })
            })
            .collect::<Result<_, ConfigError>>()?,
    };
    config.validate()?;
    Ok(config)
}

impl FromStr for TunnelConfig {
    type Err = ConfigError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        parse(input)
    }
}

fn match_key(key: &str) -> Result<&'static str, ConfigError> {
    [
        "PrivateKey",
        "Address",
        "DNS",
        "ListenPort",
        "MTU",
        "PublicKey",
        "PresharedKey",
        "Endpoint",
        "AllowedIPs",
        "PersistentKeepalive",
        "PreUp",
        "PostUp",
        "PreDown",
        "PostDown",
        "Table",
        "SaveConfig",
        "FwMark",
    ]
    .into_iter()
    .find(|known| key.eq_ignore_ascii_case(known))
    .ok_or_else(|| ConfigError::new(ErrorKind::UnsupportedField, "Setting"))
}

fn single(seen: &mut HashSet<&'static str>, key: &'static str) -> Result<(), ConfigError> {
    if !seen.insert(key) {
        return Err(ConfigError::new(ErrorKind::DuplicateField, key));
    }
    Ok(())
}

fn parse_interface(
    interface: &mut InterfaceDraft,
    key: &'static str,
    value: &str,
) -> Result<(), ConfigError> {
    if !matches!(key, "Address" | "DNS") {
        single(&mut interface.seen, key)?;
    }
    match key {
        "PrivateKey" => interface.private_key = Some(value.parse()?),
        "Address" => append_networks(&mut interface.addresses, value, MAX_ADDRESSES)?,
        "DNS" => {
            for value in values(value) {
                if interface.dns.len() + interface.search_domains.len() >= MAX_ADDRESSES {
                    return Err(ConfigError::new(ErrorKind::TooManyItems, "DNS"));
                }
                if let Ok(address) = value.parse::<IpAddr>() {
                    interface.dns.push(address);
                } else if validate_domain(value) {
                    interface.search_domains.push(value.to_owned());
                } else {
                    return Err(ConfigError::new(ErrorKind::InvalidDns, "DNS"));
                }
            }
        }
        "ListenPort" => interface.listen_port = Some(number(value, ErrorKind::InvalidPort)?),
        "MTU" => interface.mtu = Some(number(value, ErrorKind::InvalidMtu)?),
        _ => return Err(ConfigError::new(ErrorKind::UnsupportedField, key)),
    }
    Ok(())
}

fn parse_peer(peer: &mut PeerDraft, key: &'static str, value: &str) -> Result<(), ConfigError> {
    if key != "AllowedIPs" {
        single(&mut peer.seen, key)?;
    }
    match key {
        "PublicKey" => peer.public_key = Some(value.parse()?),
        "PresharedKey" => peer.preshared_key = Some(value.parse()?),
        "Endpoint" => {
            let endpoint: Endpoint = value.parse()?;
            if endpoint.port.is_none() || value.parse::<IpAddr>().is_ok() {
                return Err(ConfigError::new(ErrorKind::InvalidEndpoint, "Endpoint"));
            }
            peer.endpoint = Some(endpoint);
        }
        "AllowedIPs" => append_networks(&mut peer.allowed_ips, value, MAX_ROUTES)?,
        "PersistentKeepalive" => {
            peer.persistent_keepalive = Some(number(value, ErrorKind::InvalidKeepalive)?)
        }
        _ => return Err(ConfigError::new(ErrorKind::UnsupportedField, key)),
    }
    Ok(())
}

fn values(value: &str) -> impl Iterator<Item = &str> {
    value.split(',').map(str::trim)
}

fn append_networks(
    dest: &mut Vec<IpNetwork>,
    value: &str,
    maximum: usize,
) -> Result<(), ConfigError> {
    for value in values(value) {
        if dest.len() >= maximum {
            return Err(ConfigError::new(ErrorKind::TooManyItems, "Address"));
        }
        dest.push(
            value
                .parse()
                .map_err(|_| ConfigError::new(ErrorKind::InvalidAddress, "Address"))?,
        );
    }
    Ok(())
}

fn number(value: &str, kind: ErrorKind) -> Result<u16, ConfigError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ConfigError::new(kind, "Setting"));
    }
    value.parse().map_err(|_| ConfigError::new(kind, "Setting"))
}

/// Contains private keys: call only for secure persistence or confirmed export.
pub fn write(config: &TunnelConfig) -> Result<Zeroizing<String>, ConfigError> {
    write_config(config, None)
}

/// Standard export snapshot, retaining discovery comments for wg-easy reimport.
pub fn write_resolved(
    config: &TunnelConfig,
    endpoints: &[Option<SocketAddr>],
) -> Result<Zeroizing<String>, ConfigError> {
    if endpoints.len() != config.peers.len()
        || config.peers.iter().zip(endpoints).any(|(peer, resolved)| {
            peer.endpoint
                .as_ref()
                .is_some_and(|endpoint| endpoint.port.is_none())
                && resolved.is_none()
        })
    {
        return Err(ConfigError::new(ErrorKind::InvalidEndpoint, "Endpoint"));
    }
    for address in endpoints.iter().flatten() {
        address.to_string().parse::<Endpoint>()?.validate()?;
    }
    write_config(config, Some(endpoints))
}

fn write_config(
    config: &TunnelConfig,
    resolved: Option<&[Option<SocketAddr>]>,
) -> Result<Zeroizing<String>, ConfigError> {
    config.validate()?;
    // Reserve before adding secrets: reallocating would leave an unzeroed copy.
    let capacity = 1024
        + (config.interface.addresses.len() + config.interface.dns.len()) * 50
        + config
            .interface
            .search_domains
            .iter()
            .map(|domain| domain.len() + 2)
            .sum::<usize>()
        + config
            .peers
            .iter()
            .map(|peer| {
                256 + peer
                    .endpoint
                    .as_ref()
                    .map_or(0, |endpoint| endpoint.host.len() * 2)
                    + peer.allowed_ips.len() * 50
            })
            .sum::<usize>();
    let mut output = Zeroizing::new(String::with_capacity(capacity));
    output.push_str("[Interface]\nPrivateKey = ");
    output.push_str(&config.interface.private_key.expose_base64());
    output.push('\n');
    list(
        &mut output,
        "Address",
        config.interface.addresses.iter().map(ToString::to_string),
    );
    list(
        &mut output,
        "DNS",
        config
            .interface
            .dns
            .iter()
            .map(ToString::to_string)
            .chain(config.interface.search_domains.iter().cloned()),
    );
    if let Some(port) = config.interface.listen_port {
        writeln!(output, "ListenPort = {port}").expect("writing to a string");
    }
    if let Some(mtu) = config.interface.mtu {
        writeln!(output, "MTU = {mtu}").expect("writing to a string");
    }
    for (index, peer) in config.peers.iter().enumerate() {
        writeln!(output, "\n[Peer]\nPublicKey = {}", peer.public_key).expect("writing to a string");
        if let Some(key) = &peer.preshared_key {
            output.push_str("PresharedKey = ");
            output.push_str(&key.expose_base64());
            output.push('\n');
        }
        if let Some(endpoint) = &peer.endpoint {
            if endpoint.port.is_none() {
                writeln!(output, "{SRV_COMMENT}{}", endpoint.host).expect("writing to a string");
                if let Some(address) = resolved.and_then(|endpoints| endpoints[index]) {
                    writeln!(output, "Endpoint = {address}").expect("writing to a string");
                } else {
                    writeln!(output, "Endpoint = {}:51820", endpoint.host)
                        .expect("writing to a string");
                }
            } else {
                writeln!(output, "Endpoint = {endpoint}").expect("writing to a string");
            }
        }
        list(
            &mut output,
            "AllowedIPs",
            peer.allowed_ips.iter().map(ToString::to_string),
        );
        if let Some(keepalive) = peer.persistent_keepalive {
            writeln!(output, "PersistentKeepalive = {keepalive}").expect("writing to a string");
        }
    }
    if output.len() > MAX_CONFIG_BYTES {
        return Err(ConfigError::new(ErrorKind::TooLarge, "Configuration"));
    }
    Ok(output)
}

fn list(output: &mut String, name: &str, mut values: impl Iterator<Item = String>) {
    if let Some(first) = values.next() {
        output.push_str(name);
        output.push_str(" = ");
        output.push_str(&first);
        for value in values {
            output.push_str(", ");
            output.push_str(&value);
        }
        output.push('\n');
    }
}

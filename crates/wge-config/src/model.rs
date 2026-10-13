use std::{collections::HashSet, net::IpAddr};

use serde::{Deserialize, Serialize};

use crate::{ConfigError, Endpoint, ErrorKind, IpNetwork, PublicKey, SecretKey};

pub const MAX_CONFIG_BYTES: usize = 1024 * 1024;
pub const MAX_PEERS: usize = 256;
pub const MAX_ADDRESSES: usize = 32;
pub const MAX_ROUTES: usize = 4096;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TunnelConfig {
    pub interface: InterfaceConfig,
    pub peers: Vec<PeerConfig>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InterfaceConfig {
    pub private_key: SecretKey,
    pub addresses: Vec<IpNetwork>,
    pub dns: Vec<IpAddr>,
    pub search_domains: Vec<String>,
    pub listen_port: Option<u16>,
    pub mtu: Option<u16>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerConfig {
    pub public_key: PublicKey,
    pub preshared_key: Option<SecretKey>,
    pub endpoint: Option<Endpoint>,
    pub allowed_ips: Vec<IpNetwork>,
    pub persistent_keepalive: Option<u16>,
}

/// Safe for ordinary IPC responses and editor state: no secret material.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicConfig {
    pub interface: PublicInterface,
    pub peers: Vec<PublicPeer>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicInterface {
    pub public_key: PublicKey,
    pub addresses: Vec<IpNetwork>,
    pub dns: Vec<IpAddr>,
    pub search_domains: Vec<String>,
    pub listen_port: Option<u16>,
    pub mtu: Option<u16>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicPeer {
    pub public_key: PublicKey,
    pub has_preshared_key: bool,
    pub endpoint: Option<Endpoint>,
    pub allowed_ips: Vec<IpNetwork>,
    pub persistent_keepalive: Option<u16>,
}

impl TunnelConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.interface.private_key.as_bytes() == &[0; 32] {
            return Err(ConfigError::new(ErrorKind::InvalidKey, "PrivateKey"));
        }
        if self.peers.iter().any(|peer| {
            peer.preshared_key
                .as_ref()
                .is_some_and(|key| key.as_bytes() == &[0; 32])
        }) {
            return Err(ConfigError::new(ErrorKind::InvalidKey, "PresharedKey"));
        }
        self.public().validate()
    }

    pub fn public(&self) -> PublicConfig {
        PublicConfig {
            interface: PublicInterface {
                public_key: self.interface.private_key.public_key(),
                addresses: self.interface.addresses.clone(),
                dns: self.interface.dns.clone(),
                search_domains: self.interface.search_domains.clone(),
                listen_port: self.interface.listen_port,
                mtu: self.interface.mtu,
            },
            peers: self
                .peers
                .iter()
                .map(|peer| PublicPeer {
                    public_key: peer.public_key,
                    has_preshared_key: peer.preshared_key.is_some(),
                    endpoint: peer.endpoint.clone(),
                    allowed_ips: peer.allowed_ips.clone(),
                    persistent_keepalive: peer.persistent_keepalive,
                })
                .collect(),
        }
    }

    pub fn allowed_ips(&self) -> impl Iterator<Item = &IpNetwork> {
        self.peers.iter().flat_map(|peer| &peer.allowed_ips)
    }

    pub fn is_all_traffic(&self) -> bool {
        crate::routes_all_traffic(self.allowed_ips())
    }
}

impl PublicConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        let interface = &self.interface;
        if interface.addresses.is_empty() {
            return Err(ConfigError::new(ErrorKind::MissingAddress, "Address"));
        }
        if interface.addresses.len() > MAX_ADDRESSES
            || interface.dns.len() + interface.search_domains.len() > MAX_ADDRESSES
        {
            return Err(ConfigError::new(ErrorKind::TooManyItems, "Interface"));
        }
        if interface
            .addresses
            .iter()
            .any(|address| !is_unicast(address.ip()))
        {
            return Err(ConfigError::new(ErrorKind::InvalidAddress, "Address"));
        }
        if interface.dns.iter().any(|&address| !is_unicast(address))
            || interface
                .search_domains
                .iter()
                .any(|domain| !validate_domain(domain))
        {
            return Err(ConfigError::new(ErrorKind::InvalidDns, "DNS"));
        }
        let uses_ipv6 = interface.addresses.iter().any(IpNetwork::is_ipv6)
            || self.allowed_ips().any(IpNetwork::is_ipv6)
            || self.is_all_traffic();
        if let Some(mtu) = interface.mtu {
            let minimum = if uses_ipv6 { 1280 } else { 576 };
            if mtu < minimum {
                return Err(ConfigError::new(ErrorKind::InvalidMtu, "MTU"));
            }
        }
        if self.peers.is_empty() {
            return Err(ConfigError::new(ErrorKind::MissingPeer, "Peer"));
        }
        if self.peers.len() > MAX_PEERS || self.allowed_ips().count() > MAX_ROUTES {
            return Err(ConfigError::new(ErrorKind::TooManyItems, "Peer"));
        }
        let mut keys = HashSet::new();
        for peer in &self.peers {
            if peer.public_key == interface.public_key {
                return Err(ConfigError::new(ErrorKind::OwnPublicKey, "PublicKey"));
            }
            if !keys.insert(peer.public_key) {
                return Err(ConfigError::new(ErrorKind::DuplicatePeer, "PublicKey"));
            }
            if peer.allowed_ips.is_empty() {
                return Err(ConfigError::new(ErrorKind::MissingRoutes, "AllowedIPs"));
            }
            if let Some(endpoint) = &peer.endpoint {
                endpoint.validate()?;
            }
        }
        Ok(())
    }

    pub fn allowed_ips(&self) -> impl Iterator<Item = &IpNetwork> {
        self.peers.iter().flat_map(|peer| &peer.allowed_ips)
    }

    pub fn is_all_traffic(&self) -> bool {
        crate::routes_all_traffic(self.allowed_ips())
    }
}

fn is_unicast(address: IpAddr) -> bool {
    !address.is_unspecified()
        && !address.is_multicast()
        && !matches!(address, IpAddr::V4(address) if address.is_broadcast())
}

/// Validates an ASCII DNS name without making a network request.
pub fn validate_domain(value: &str) -> bool {
    let value = value.strip_suffix('.').unwrap_or(value);
    !value.is_empty()
        && value.len() <= 253
        && value.is_ascii()
        && !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

pub fn validate_name(value: &str) -> Result<(), ConfigError> {
    if value.trim().is_empty() || value.chars().count() > 80 || value.chars().any(char::is_control)
    {
        return Err(ConfigError::new(ErrorKind::InvalidName, "Name"));
    }
    Ok(())
}

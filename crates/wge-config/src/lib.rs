//! Tunnel configuration model: parsing, validation and serialization of
//! standard `wg-quick` files. Does no I/O.

#![forbid(unsafe_code)]

mod endpoint;
mod error;
mod keys;
mod model;
mod parser;
mod ranges;

pub use endpoint::Endpoint;
pub use error::{ConfigError, ErrorKind};
pub use ipnetwork::IpNetwork;
pub use keys::{PublicKey, SecretKey};
pub use model::{
    InterfaceConfig, MAX_ADDRESSES, MAX_CONFIG_BYTES, MAX_PEERS, MAX_ROUTES, PeerConfig,
    PublicConfig, PublicInterface, PublicPeer, TunnelConfig, validate_domain, validate_name,
};
pub use parser::{parse, write};
pub use ranges::{
    RangeCoverage, RouteOverlap, coverage, overlaps, route_overlaps, routes_all_traffic,
    server_snippet,
};
pub use zeroize::Zeroizing;

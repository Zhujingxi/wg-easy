use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::{IpNetwork, PublicConfig};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RangeCoverage {
    pub first: IpAddr,
    pub last: IpAddr,
    /// Decimal text also represents the 2^128 addresses in `::/0`.
    pub address_count: String,
}

pub fn coverage(range: &IpNetwork) -> RangeCoverage {
    let bits = if range.is_ipv4() { 32 } else { 128 };
    let host_bits = bits - u32::from(range.prefix());
    let address_count = if host_bits == 128 {
        "340282366920938463463374607431768211456".to_owned()
    } else {
        (1_u128 << host_bits).to_string()
    };
    RangeCoverage {
        first: range.network(),
        last: range.broadcast(),
        address_count,
    }
}

/// True only for intersecting address ranges in the same IP family.
pub fn overlaps(left: &IpNetwork, right: &IpNetwork) -> bool {
    left.is_ipv4() == right.is_ipv4()
        && (left.contains(right.network()) || right.contains(left.network()))
}

/// Treat split default routes as full tunnels too, so they get DNS safeguards.
pub fn routes_all_traffic<'a>(ranges: impl IntoIterator<Item = &'a IpNetwork>) -> bool {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for range in ranges {
        if range.prefix() == 0 {
            return true;
        }
        match (range.network(), range.broadcast()) {
            (IpAddr::V4(first), IpAddr::V4(last)) => {
                v4.push((u128::from(u32::from(first)), u128::from(u32::from(last))))
            }
            (IpAddr::V6(first), IpAddr::V6(last)) => v6.push((u128::from(first), u128::from(last))),
            _ => unreachable!("a network has one address family"),
        }
    }
    covers(&mut v4, u128::from(u32::MAX)) || covers(&mut v6, u128::MAX)
}

fn covers(ranges: &mut [(u128, u128)], maximum: u128) -> bool {
    ranges.sort_unstable();
    let Some(&(0, mut end)) = ranges.first() else {
        return false;
    };
    for &(first, last) in &ranges[1..] {
        if first > end.saturating_add(1) {
            return false;
        }
        end = end.max(last);
    }
    end == maximum
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RouteOverlap {
    pub requested: IpNetwork,
    pub active: IpNetwork,
}

/// Return up to 32 conflict examples. A full tunnel is exclusive across families.
pub fn route_overlaps(requested: &[IpNetwork], active: &[IpNetwork]) -> Vec<RouteOverlap> {
    let exclusive = routes_all_traffic(requested) || routes_all_traffic(active);
    let mut conflicts = Vec::new();
    for requested in requested {
        for active in active {
            if exclusive || overlaps(requested, active) {
                conflicts.push(RouteOverlap {
                    requested: *requested,
                    active: *active,
                });
                if conflicts.len() == 32 {
                    return conflicts;
                }
            }
        }
    }
    conflicts
}

/// Server peers route to this device's addresses, not its entire local subnet.
pub fn server_snippet(config: &PublicConfig) -> String {
    let mut snippet = format!("[Peer]\nPublicKey = {}\n", config.interface.public_key);
    let addresses: Vec<_> = config
        .interface
        .addresses
        .iter()
        .map(|address| {
            format!(
                "{}/{}",
                address.ip(),
                if address.is_ipv4() { 32 } else { 128 }
            )
        })
        .collect();
    if !addresses.is_empty() {
        snippet.push_str("AllowedIPs = ");
        snippet.push_str(&addresses.join(", "));
        snippet.push('\n');
    }
    snippet
}

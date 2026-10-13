use std::{net::SocketAddr, time::Duration};

use hickory_resolver::{
    TokioResolver,
    config::LookupIpStrategy,
    net::{DnsError, NetError, NoRecords},
    proto::{
        op::ResponseCode,
        rr::{RData, rdata::SRV},
    },
};
use wge_config::{Endpoint, TunnelConfig};

use crate::Error;

const MAX_CANDIDATES: usize = 16;
const MAX_TUNNEL_CANDIDATES: usize = 256;

pub(crate) async fn resolve(config: &TunnelConfig) -> Result<Vec<Vec<SocketAddr>>, Error> {
    let future = async {
        let resolver = if config.peers.iter().any(|peer| {
            peer.endpoint
                .as_ref()
                .is_some_and(|endpoint| endpoint.port.is_none())
        }) {
            let mut builder = TokioResolver::builder_tokio()
                .map_err(|_| Error::Resolve("system DNS configuration".into()))?;
            builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
            Some(
                builder
                    .build()
                    .map_err(|_| Error::Resolve("system DNS configuration".into()))?,
            )
        } else {
            None
        };
        let mut result = Vec::with_capacity(config.peers.len());
        let mut count = 0;
        for peer in &config.peers {
            let addresses = match &peer.endpoint {
                Some(endpoint) => resolve_endpoint(endpoint, resolver.as_ref()).await?,
                None => Vec::new(),
            };
            count += addresses.len();
            if count > MAX_TUNNEL_CANDIDATES {
                return Err(Error::Resolve("too many server addresses".into()));
            }
            result.push(addresses);
        }
        Ok(result)
    };
    tokio::time::timeout(Duration::from_secs(10), future)
        .await
        .map_err(|_| Error::Resolve("DNS lookup timed out".into()))?
}

async fn resolve_endpoint(
    endpoint: &Endpoint,
    resolver: Option<&TokioResolver>,
) -> Result<Vec<SocketAddr>, Error> {
    let fail = || Error::Resolve(endpoint.to_string());
    if let Some(port) = endpoint.port {
        let addresses = tokio::net::lookup_host((endpoint.host.as_str(), port))
            .await
            .map_err(|_| fail())?
            .collect();
        return candidates(addresses).ok_or_else(fail);
    }
    let resolver = resolver.ok_or_else(fail)?;
    // An absolute query must not discover a different service through DNS search suffixes.
    let name = format!("_wireguard._udp.{}.", endpoint.host.trim_end_matches('.'));
    let records = match resolver.srv_lookup(name).await {
        Ok(lookup) => lookup
            .answers()
            .iter()
            .filter_map(|record| match &record.data {
                RData::SRV(srv) => Some(srv.clone()),
                _ => None,
            })
            .collect::<Vec<_>>(),
        Err(error) if absent(&error) => {
            let addresses = resolver
                .lookup_ip(format!("{}.", endpoint.host.trim_end_matches('.')))
                .await
                .map_err(|_| fail())?
                .iter()
                .map(|ip| SocketAddr::new(ip, 51820))
                .collect();
            return candidates(addresses).ok_or_else(fail);
        }
        Err(_) => return Err(fail()),
    };
    if records.is_empty()
        || records.len() > MAX_CANDIDATES
        || records.iter().any(|record| {
            record.port == 0 || !wge_config::validate_domain(&record.target.to_utf8())
        })
    {
        return Err(fail());
    }
    let records = order(records, &mut fastrand::Rng::new());
    let mut targets = vec![Vec::new(); records.len()];
    let mut queries = tokio::task::JoinSet::new();
    for (index, record) in records.into_iter().enumerate() {
        let resolver = resolver.clone();
        queries.spawn(async move {
            // A slow or broken backup must not prevent using another target.
            let lookup =
                tokio::time::timeout(Duration::from_secs(2), resolver.lookup_ip(record.target))
                    .await;
            let addresses = match lookup {
                Ok(Ok(lookup)) => candidates(
                    lookup
                        .iter()
                        .map(|ip| SocketAddr::new(ip, record.port))
                        .collect(),
                )
                .unwrap_or_default(),
                _ => Vec::new(),
            };
            (index, addresses)
        });
    }
    while let Some(result) = queries.join_next().await {
        let (index, addresses) = result.map_err(|_| fail())?;
        targets[index] = addresses;
    }
    let mut addresses = targets.into_iter().flatten().collect::<Vec<_>>();
    if addresses.is_empty() || addresses.len() > MAX_CANDIDATES {
        return Err(fail());
    }
    addresses.dedup();
    Ok(addresses)
}

fn absent(error: &NetError) -> bool {
    matches!(
        error,
        NetError::Dns(DnsError::NoRecordsFound(NoRecords {
            response_code: ResponseCode::NXDomain | ResponseCode::NoError,
            ..
        }))
    )
}

fn candidates(addresses: Vec<SocketAddr>) -> Option<Vec<SocketAddr>> {
    if addresses.len() > MAX_CANDIDATES {
        return None;
    }
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for address in addresses {
        if address.to_string().parse::<Endpoint>().is_err() {
            continue;
        }
        let family = if address.is_ipv6() { &mut v6 } else { &mut v4 };
        if !family.contains(&address) {
            family.push(address);
        }
    }
    // Try the other family promptly instead of exhausting one family's addresses.
    let mut result = Vec::new();
    for index in 0..v4.len().max(v6.len()) {
        result.extend(v6.get(index));
        result.extend(v4.get(index));
    }
    (!result.is_empty()).then_some(result)
}

fn order(mut records: Vec<SRV>, rng: &mut fastrand::Rng) -> Vec<SRV> {
    let mut result = Vec::with_capacity(records.len());
    while !records.is_empty() {
        records.sort_by_key(|record| (record.priority, record.weight != 0));
        let priority = records[0].priority;
        let count = records
            .iter()
            .take_while(|record| record.priority == priority)
            .count();
        let total: u32 = records[..count]
            .iter()
            .map(|record| u32::from(record.weight))
            .sum();
        let position = if total == 0 {
            rng.usize(..count)
        } else {
            let choice = rng.u32(0..=total);
            let mut weight = 0;
            records[..count]
                .iter()
                .position(|record| {
                    weight += u32::from(record.weight);
                    weight >= choice
                })
                .unwrap()
        };
        result.push(records.remove(position));
    }
    result
}

/// Resolve discovery endpoints before producing a confirmed standard config export.
pub async fn export(config: &TunnelConfig) -> Result<wge_config::Zeroizing<String>, Error> {
    config
        .validate()
        .map_err(|error| Error::Invalid(error.to_string()))?;
    if !config.peers.iter().any(|peer| {
        peer.endpoint
            .as_ref()
            .is_some_and(|endpoint| endpoint.port.is_none())
    }) {
        return wge_config::write(config).map_err(|error| Error::Invalid(error.to_string()));
    }
    let mut discovery = config.clone();
    for peer in &mut discovery.peers {
        if peer
            .endpoint
            .as_ref()
            .is_some_and(|endpoint| endpoint.port.is_some())
        {
            peer.endpoint = None;
        }
    }
    let endpoints = resolve(&discovery)
        .await?
        .iter()
        .map(|addresses| addresses.first().copied())
        .collect::<Vec<_>>();
    wge_config::write_resolved(config, &endpoints)
        .map_err(|error| Error::Invalid(error.to_string()))
}

#[cfg(test)]
#[path = "endpoint_tests.rs"]
mod tests;

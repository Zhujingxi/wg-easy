use std::net::IpAddr;

use core_foundation::{
    array::CFArray,
    base::{CFType, TCFType},
    data::CFData,
    dictionary::CFDictionary,
    number::CFNumber,
    propertylist::{
        self, CFPropertyList, CFPropertyListSubClass, kCFPropertyListBinaryFormat_v1_0,
        kCFPropertyListImmutable,
    },
    string::CFString,
};
use serde::{Deserialize, Serialize};
use system_configuration::dynamic_store::{SCDynamicStore, SCDynamicStoreBuilder};
use wge_config::TunnelConfig;

use crate::Error;

#[derive(Debug, Default, Serialize, Deserialize)]
pub(crate) struct State {
    servers: Vec<IpAddr>,
    changes: Vec<Change>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Change {
    key: String,
    original: Option<Vec<u8>>,
    installed: Vec<u8>,
}

impl State {
    pub fn servers(&self) -> Vec<IpAddr> {
        self.servers.clone()
    }
}

fn store() -> Result<SCDynamicStore, Error> {
    SCDynamicStoreBuilder::new("wg-easy DNS")
        .build()
        .ok_or_else(|| Error::Dns("Cannot open macOS SystemConfiguration".into()))
}

pub(crate) async fn prepare(
    config: &TunnelConfig,
    name: &str,
    _interface: u32,
) -> Result<State, Error> {
    let servers = config.interface.dns.clone();
    let full = config.is_all_traffic();
    if servers.is_empty() {
        if full {
            return Err(Error::Dns(
                "Add a DNS server in Traffic before connecting an all-traffic tunnel".into(),
            ));
        }
        return Ok(State {
            servers,
            changes: Vec::new(),
        });
    }
    if servers
        .iter()
        .any(|server| server.is_loopback() || server.is_unspecified())
    {
        return Err(Error::Dns(
            "Use a DNS server inside the tunnel, not a local resolver".into(),
        ));
    }
    if !full && config.interface.search_domains.is_empty() {
        return Err(Error::Dns(
            "Add the domains this tunnel's DNS should resolve under Advanced".into(),
        ));
    }
    let store = store()?;
    let key = format!("State:/Network/Service/wg-easy-{name}/DNS");
    if store.get(key.as_str()).is_some() {
        return Err(Error::Dns(
            "Recover the previous tunnel DNS settings before connecting".into(),
        ));
    }
    let resolver = resolver_dictionary(&servers, &config.interface.search_domains, full);
    let mut changes = Vec::new();
    if full {
        // More-specific service resolvers otherwise take precedence over the root domain.
        let keys = store
            .get_keys("^(State|Setup):/Network/Service/[^/]+/DNS$")
            .ok_or_else(|| Error::Dns("Cannot read existing macOS DNS resolvers".into()))?;
        for key in keys.iter() {
            let key = key.to_string();
            let Some(original) = store.get(key.as_str()) else {
                continue;
            };
            let replacement = replace_servers(&original, &servers)?;
            changes.push(Change {
                key,
                original: Some(encode(&original)?),
                installed: encode(&replacement)?,
            });
        }
    }
    changes.push(Change {
        key,
        original: None,
        installed: encode(&resolver)?,
    });
    Ok(State { servers, changes })
}

pub(crate) async fn apply(state: &State) -> Result<(), Error> {
    if state.changes.is_empty() {
        return Ok(());
    }
    let store = store()?;
    for change in &state.changes {
        let current = store.get(change.key.as_str());
        let original = change.original.as_deref().map(decode).transpose()?;
        if current != original {
            return Err(Error::Dns(
                "System DNS changed while connecting. Try connecting again".into(),
            ));
        }
        if !store.set_raw(change.key.as_str(), &decode(&change.installed)?) {
            return Err(Error::Dns(
                "macOS could not apply tunnel DNS settings".into(),
            ));
        }
    }
    Ok(())
}

pub(crate) async fn restore(state: &State) -> Result<(), Error> {
    if state.changes.is_empty() {
        return Ok(());
    }
    let store = store()?;
    for change in state.changes.iter().rev() {
        // Preserve DHCP renewals and user changes that superseded our temporary value.
        if store.get(change.key.as_str()) != Some(decode(&change.installed)?) {
            continue;
        }
        let success = match change.original.as_deref() {
            Some(original) => store.set_raw(change.key.as_str(), &decode(original)?),
            None => store.remove(change.key.as_str()),
        };
        if !success {
            return Err(Error::Dns(
                "macOS could not restore the previous DNS settings".into(),
            ));
        }
    }
    Ok(())
}

fn strings(values: impl IntoIterator<Item = String>) -> CFType {
    let values: Vec<_> = values
        .into_iter()
        .map(|value| CFString::new(&value))
        .collect();
    CFArray::from_CFTypes(&values).as_CFType()
}

fn resolver_dictionary(servers: &[IpAddr], domains: &[String], full: bool) -> CFPropertyList {
    let matches = if full {
        vec![String::new()]
    } else {
        domains.to_vec()
    };
    let orders: Vec<_> = matches.iter().map(|_| CFNumber::from(1_i32)).collect();
    let pairs = vec![
        (
            CFString::new("ServerAddresses"),
            strings(servers.iter().map(ToString::to_string)),
        ),
        (CFString::new("SupplementalMatchDomains"), strings(matches)),
        (
            CFString::new("SupplementalMatchOrders"),
            CFArray::from_CFTypes(&orders).as_CFType(),
        ),
        (
            CFString::new("SupplementalMatchDomainsNoSearch"),
            CFNumber::from(1_i32).as_CFType(),
        ),
        (
            CFString::new("SearchDomains"),
            strings(domains.iter().cloned()),
        ),
        (
            CFString::new("ServerPort"),
            CFNumber::from(53_i32).as_CFType(),
        ),
    ];
    CFDictionary::from_CFType_pairs(&pairs)
        .into_untyped()
        .into_CFPropertyList()
}

fn replace_servers(original: &CFPropertyList, servers: &[IpAddr]) -> Result<CFPropertyList, Error> {
    let dictionary = original
        .downcast::<CFDictionary>()
        .ok_or_else(|| Error::Dns("An existing macOS resolver is not a dictionary".into()))?;
    let (keys, values) = dictionary.get_keys_and_values();
    let mut pairs = Vec::new();
    for (key, value) in keys.into_iter().zip(values) {
        // SAFETY: the dictionary retains these live CF objects; type checks precede casts.
        let key = unsafe { CFType::wrap_under_get_rule(key) }
            .downcast::<CFString>()
            .ok_or_else(|| Error::Dns("An existing macOS resolver has an invalid key".into()))?;
        if matches!(key.to_string().as_str(), "ServerAddresses" | "ServerPort") {
            continue;
        }
        // SAFETY: value is retained by the live dictionary and wrap retains our reference.
        pairs.push((key, unsafe { CFType::wrap_under_get_rule(value) }));
    }
    pairs.push((
        CFString::new("ServerAddresses"),
        strings(servers.iter().map(ToString::to_string)),
    ));
    pairs.push((
        CFString::new("ServerPort"),
        CFNumber::from(53_i32).as_CFType(),
    ));
    Ok(CFDictionary::from_CFType_pairs(&pairs)
        .into_untyped()
        .into_CFPropertyList())
}

fn encode(value: &CFPropertyList) -> Result<Vec<u8>, Error> {
    propertylist::create_data(value.as_CFTypeRef(), kCFPropertyListBinaryFormat_v1_0)
        .map(|data| data.bytes().to_vec())
        .map_err(|error| Error::Dns(format!("Cannot snapshot macOS DNS: {error:?}")))
}

fn decode(value: &[u8]) -> Result<CFPropertyList, Error> {
    let (value, _) =
        propertylist::create_with_data(CFData::from_buffer(value), kCFPropertyListImmutable)
            .map_err(|error| Error::Journal(format!("Invalid macOS DNS snapshot: {error:?}")))?;
    // SAFETY: create_with_data returns one owned non-null property-list reference.
    Ok(unsafe { CFPropertyList::wrap_under_create_rule(value) })
}

#[cfg(test)]
pub(crate) fn smoke_matches(state: &State, applied: bool) -> Result<bool, Error> {
    let store = store()?;
    for change in &state.changes {
        let expected = if applied {
            Some(decode(&change.installed)?)
        } else {
            change.original.as_deref().map(decode).transpose()?
        };
        if store.get(change.key.as_str()) != expected {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolver_snapshot_round_trips_and_replaces_only_servers() {
        let original = resolver_dictionary(
            &["192.0.2.1".parse().unwrap()],
            &["office.example".into()],
            false,
        );
        assert_eq!(decode(&encode(&original).unwrap()).unwrap(), original);
        let replaced = replace_servers(&original, &["fd00::1".parse().unwrap()]).unwrap();
        let expected = resolver_dictionary(
            &["fd00::1".parse().unwrap()],
            &["office.example".into()],
            false,
        );
        assert_eq!(replaced, expected);
        assert_ne!(replaced, original);
    }

    #[test]
    fn full_and_split_scopes_are_distinct_and_journal_is_serializable() {
        let servers = vec!["10.0.0.1".parse().unwrap()];
        let full = resolver_dictionary(&servers, &["office.example".into()], true);
        let split = resolver_dictionary(&servers, &["office.example".into()], false);
        assert_ne!(full, split);
        let state = State {
            servers: servers.clone(),
            changes: vec![Change {
                key: "State:/Network/Service/wg-easy-test/DNS".into(),
                original: None,
                installed: encode(&split).unwrap(),
            }],
        };
        let recovered: State =
            serde_json::from_str(&serde_json::to_string(&state).unwrap()).unwrap();
        assert_eq!(recovered.servers(), servers);
        assert_eq!(decode(&recovered.changes[0].installed).unwrap(), split);
    }
}

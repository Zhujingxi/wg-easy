use std::{io, net::IpAddr, ptr};

use serde::{Deserialize, Serialize};
use wge_config::TunnelConfig;
use windows_sys::{
    Win32::{
        Foundation::{
            ERROR_FILE_NOT_FOUND, ERROR_NO_MORE_ITEMS, ERROR_PATH_NOT_FOUND, ERROR_SUCCESS,
        },
        NetworkManagement::{
            IpHelper::{ConvertInterfaceIndexToLuid, ConvertInterfaceLuidToGuid},
            Ndis::NET_LUID_LH,
        },
        System::Registry::{
            HKEY, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY, KEY_WRITE, REG_CREATED_NEW_KEY,
            REG_DWORD, REG_MULTI_SZ, REG_OPTION_NON_VOLATILE, REG_SZ, RegCloseKey, RegCreateKeyExW,
            RegDeleteTreeW, RegEnumKeyExW, RegOpenKeyExW, RegQueryInfoKeyW, RegQueryValueExW,
            RegSetValueExW,
        },
    },
    core::GUID,
};

use crate::Error;

const LOCAL_POLICY: &str = r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig";
const GROUP_POLICY: &str = r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig";
const OWNER: &str = "wireguardeasy";

#[link(name = "dnsapi")]
unsafe extern "system" {
    fn DnsFlushResolverCache() -> i32;
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) enum State {
    None,
    Policy {
        rule: String,
        servers: Vec<IpAddr>,
        domains: Vec<String>,
    },
}

impl State {
    pub fn servers(&self) -> Vec<IpAddr> {
        match self {
            Self::None => Vec::new(),
            Self::Policy { servers, .. } => servers.clone(),
        }
    }
}

pub(crate) async fn prepare(
    config: &TunnelConfig,
    _name: &str,
    interface: u32,
) -> Result<State, Error> {
    let servers = config.interface.dns.clone();
    let full = config.is_all_traffic();
    if servers.is_empty() {
        if full {
            return Err(Error::Dns(
                "Add a DNS server in Traffic before connecting an all-traffic tunnel".into(),
            ));
        }
        return Ok(State::None);
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
    // Windows ignores the entire local NRPT table when a Group Policy table exists.
    if Key::open(GROUP_POLICY)?.is_some() {
        return Err(Error::Dns("Windows Group Policy controls DNS on this computer. Ask its administrator to allow local tunnel DNS policies".into()));
    }
    let domains = if full {
        vec![".".to_owned()]
    } else {
        config
            .interface
            .search_domains
            .iter()
            .map(|domain| format!(".{}", domain.trim_end_matches('.').to_ascii_lowercase()))
            .collect()
    };
    if let Some(table) = Key::open(LOCAL_POLICY)? {
        for name in table.subkeys()? {
            let Some(rule) = Key::open(&format!("{LOCAL_POLICY}\\{name}"))? else {
                continue;
            };
            let existing = rule.read("Name")?.ok_or_else(|| {
                Error::Dns("An existing Windows DNS policy has no namespace".into())
            })?;
            if existing.0 != REG_MULTI_SZ {
                return Err(Error::Dns(
                    "An existing Windows DNS policy has an invalid namespace".into(),
                ));
            }
            let existing = decode_strings(&existing.1)?;
            if domains
                .iter()
                .any(|domain| existing.iter().any(|other| scopes_overlap(domain, other)))
            {
                return Err(Error::Dns("Another Windows DNS policy already handles these domains. Remove the conflicting policy before connecting".into()));
            }
        }
    }
    let rule = interface_rule(interface)?;
    if Key::open(&policy_path(&rule)?)?.is_some() {
        return Err(Error::Dns(
            "Recover the previous tunnel DNS policy before connecting".into(),
        ));
    }
    Ok(State::Policy {
        rule,
        servers,
        domains,
    })
}

pub(crate) async fn apply(state: &State) -> Result<(), Error> {
    let State::Policy {
        rule,
        servers,
        domains,
    } = state
    else {
        return Ok(());
    };
    let key = Key::create(&policy_path(rule)?)?;
    key.write("Comment", REG_SZ, &encode_strings(&[OWNER.into()], false))?;
    key.write("Version", REG_DWORD, &1_u32.to_le_bytes())?;
    key.write("Name", REG_MULTI_SZ, &encode_strings(domains, true))?;
    let servers = servers
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(";");
    key.write(
        "GenericDNSServers",
        REG_SZ,
        &encode_strings(&[servers], false),
    )?;
    // NRPT override: queries for these namespaces use these servers exclusively.
    key.write("ConfigOptions", REG_DWORD, &8_u32.to_le_bytes())?;
    flush()
}

pub(crate) async fn restore(state: &State) -> Result<(), Error> {
    let State::Policy { rule, .. } = state else {
        return Ok(());
    };
    let path = policy_path(rule)?;
    let Some(key) = Key::open(&path)? else {
        return Ok(());
    };
    let owner = key.read("Comment")?;
    let ours = match owner {
        Some((REG_SZ, value)) => decode_strings(&value)? == [OWNER],
        // A crash may occur after key creation and before its first value write.
        None => key.is_empty()?,
        _ => false,
    };
    if !ours {
        return Err(Error::Dns(
            "The saved tunnel DNS policy is now owned by another application".into(),
        ));
    }
    drop(key);
    let path = wide(&path);
    // SAFETY: the path is a validated owned policy key; the string is terminated.
    let status = unsafe { RegDeleteTreeW(HKEY_LOCAL_MACHINE, path.as_ptr()) };
    if !missing(status) {
        check(status)?;
    }
    flush()
}

fn interface_rule(interface: u32) -> Result<String, Error> {
    let mut luid = NET_LUID_LH::default();
    let mut guid = GUID::default();
    // SAFETY: both output pointers refer to live initialized objects.
    check(unsafe { ConvertInterfaceIndexToLuid(interface, &mut luid) })?;
    // SAFETY: the LUID was obtained from Windows and the output is valid.
    check(unsafe { ConvertInterfaceLuidToGuid(&luid, &mut guid) })?;
    Ok(format!(
        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        guid.data1,
        guid.data2,
        guid.data3,
        guid.data4[0],
        guid.data4[1],
        guid.data4[2],
        guid.data4[3],
        guid.data4[4],
        guid.data4[5],
        guid.data4[6],
        guid.data4[7]
    ))
}

#[cfg(test)]
pub(crate) fn smoke_matches(state: &State, applied: bool) -> Result<bool, Error> {
    let State::Policy {
        rule,
        servers,
        domains,
    } = state
    else {
        return Ok(!applied);
    };
    let key = Key::open(&policy_path(rule)?)?;
    if !applied {
        return Ok(key.is_none());
    }
    let Some(key) = key else {
        return Ok(false);
    };
    let servers = servers
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(";");
    Ok(
        key.read("Name")? == Some((REG_MULTI_SZ, encode_strings(domains, true)))
            && key.read("GenericDNSServers")? == Some((REG_SZ, encode_strings(&[servers], false))),
    )
}

fn policy_path(rule: &str) -> Result<String, Error> {
    let valid = rule.len() == 38
        && rule.bytes().enumerate().all(|(index, byte)| match index {
            0 => byte == b'{',
            37 => byte == b'}',
            9 | 14 | 19 | 24 => byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        });
    if !valid {
        return Err(Error::Journal(
            "Invalid Windows DNS policy identifier".into(),
        ));
    }
    Ok(format!("{LOCAL_POLICY}\\{rule}"))
}

fn scopes_overlap(a: &str, b: &str) -> bool {
    let a = a.trim_matches('.').to_ascii_lowercase();
    let b = b.trim_matches('.').to_ascii_lowercase();
    a.is_empty()
        || b.is_empty()
        || a == b
        || a.ends_with(&format!(".{b}"))
        || b.ends_with(&format!(".{a}"))
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

fn encode_strings(values: &[String], multi: bool) -> Vec<u8> {
    let mut bytes: Vec<u8> = values
        .iter()
        .flat_map(|value| wide(value))
        .flat_map(u16::to_le_bytes)
        .collect();
    if multi {
        bytes.extend_from_slice(&[0, 0]);
    }
    bytes
}

fn decode_strings(bytes: &[u8]) -> Result<Vec<String>, Error> {
    if !bytes.len().is_multiple_of(2) {
        return Err(Error::Dns(
            "Windows DNS policy contains invalid UTF-16".into(),
        ));
    }
    let units: Vec<_> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|part| u16::from_le_bytes(*part))
        .collect();
    units
        .split(|unit| *unit == 0)
        .filter(|part| !part.is_empty())
        .map(|part| {
            String::from_utf16(part)
                .map_err(|_| Error::Dns("Windows DNS policy contains invalid UTF-16".into()))
        })
        .collect()
}

fn flush() -> Result<(), Error> {
    // SAFETY: the system resolver-cache API takes no arguments and retains no state.
    if unsafe { DnsFlushResolverCache() } == 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

fn missing(status: u32) -> bool {
    status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND
}

fn check(status: u32) -> Result<(), Error> {
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(status as i32).into())
    }
}

struct Key(HKEY);

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: Key owns an open registry handle exactly once.
        unsafe { RegCloseKey(self.0) };
    }
}

impl Key {
    fn open(path: &str) -> Result<Option<Self>, Error> {
        let path = wide(path);
        let mut key = ptr::null_mut();
        // SAFETY: path is terminated and key is a valid output pointer.
        let status = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                path.as_ptr(),
                0,
                KEY_READ | KEY_WOW64_64KEY,
                &mut key,
            )
        };
        if missing(status) {
            return Ok(None);
        }
        check(status)?;
        Ok(Some(Self(key)))
    }

    fn create(path: &str) -> Result<Self, Error> {
        let path = wide(path);
        let mut key = ptr::null_mut();
        let mut disposition = 0;
        // SAFETY: input strings live throughout the call; output pointers are valid.
        check(unsafe {
            RegCreateKeyExW(
                HKEY_LOCAL_MACHINE,
                path.as_ptr(),
                0,
                ptr::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_READ | KEY_WRITE | KEY_WOW64_64KEY,
                ptr::null(),
                &mut key,
                &mut disposition,
            )
        })?;
        let key = Self(key);
        if disposition != REG_CREATED_NEW_KEY {
            return Err(Error::Dns(
                "The tunnel DNS policy was created by another process. Try connecting again".into(),
            ));
        }
        Ok(key)
    }

    fn write(&self, name: &str, kind: u32, data: &[u8]) -> Result<(), Error> {
        let name = wide(name);
        // SAFETY: the handle is open and data is valid for the advertised byte length.
        check(unsafe {
            RegSetValueExW(
                self.0,
                name.as_ptr(),
                0,
                kind,
                data.as_ptr(),
                data.len() as u32,
            )
        })
    }

    fn read(&self, name: &str) -> Result<Option<(u32, Vec<u8>)>, Error> {
        let name = wide(name);
        let mut kind = 0;
        let mut length = 0;
        // SAFETY: null data queries only the required size and type.
        let status = unsafe {
            RegQueryValueExW(
                self.0,
                name.as_ptr(),
                ptr::null(),
                &mut kind,
                ptr::null_mut(),
                &mut length,
            )
        };
        if missing(status) {
            return Ok(None);
        }
        check(status)?;
        if length > 65536 {
            return Err(Error::Dns(
                "An existing Windows DNS policy is too large".into(),
            ));
        }
        let mut data = vec![0; length as usize];
        // SAFETY: the allocated buffer has the requested length; Windows checks capacity.
        check(unsafe {
            RegQueryValueExW(
                self.0,
                name.as_ptr(),
                ptr::null(),
                &mut kind,
                data.as_mut_ptr(),
                &mut length,
            )
        })?;
        data.truncate(length as usize);
        Ok(Some((kind, data)))
    }

    fn subkeys(&self) -> Result<Vec<String>, Error> {
        let mut keys = Vec::new();
        for index in 0..4096 {
            let mut name = [0_u16; 256];
            let mut length = name.len() as u32;
            // SAFETY: the output buffer is valid for length UTF-16 units.
            let status = unsafe {
                RegEnumKeyExW(
                    self.0,
                    index,
                    name.as_mut_ptr(),
                    &mut length,
                    ptr::null(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                )
            };
            if status == ERROR_NO_MORE_ITEMS {
                return Ok(keys);
            }
            check(status)?;
            keys.push(
                String::from_utf16(&name[..length as usize])
                    .map_err(|_| Error::Dns("Invalid Windows DNS policy name".into()))?,
            );
        }
        Err(Error::Dns("Too many existing Windows DNS policies".into()))
    }

    fn is_empty(&self) -> Result<bool, Error> {
        let mut subkeys = 0;
        let mut values = 0;
        // SAFETY: requested counts have valid output pointers; other outputs are optional.
        check(unsafe {
            RegQueryInfoKeyW(
                self.0,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null(),
                &mut subkeys,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut values,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        })?;
        Ok(subkeys == 0 && values == 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespaces_match_whole_labels_and_root_covers_everything() {
        assert!(scopes_overlap(".", ".office.example"));
        assert!(scopes_overlap(".office.example", ".HOST.Office.Example"));
        assert!(!scopes_overlap(".office.example", ".otheroffice.example"));
        assert!(!scopes_overlap(".one.example", ".two.example"));
    }

    #[test]
    fn registry_strings_are_utf16_and_double_terminated_for_multi_values() {
        let values = vec![".office.example".into(), ".日本.example".into()];
        let bytes = encode_strings(&values, true);
        assert!(bytes.ends_with(&[0, 0, 0, 0]));
        assert_eq!(decode_strings(&bytes).unwrap(), values);
        assert!(decode_strings(&[1]).is_err());
    }

    #[test]
    fn journal_policy_identifier_cannot_escape_its_owned_key() {
        assert!(policy_path("{00112233-4455-6677-8899-AABBCCDDEEFF}").is_ok());
        for bad in [
            "",
            "..",
            "x\\other",
            "{00112233-4455-6677-8899-AABBCCDDEEFG}",
        ] {
            assert!(policy_path(bad).is_err());
        }
    }
}

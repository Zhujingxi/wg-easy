use crate::Error;
use serde::{Deserialize, Serialize};
use std::{fs, io, net::IpAddr, path::PathBuf};
use wge_config::TunnelConfig;
use zbus::{Connection, Proxy, zvariant::OwnedObjectPath};

#[derive(Debug, Serialize, Deserialize)]
pub(crate) enum State {
    None,
    Resolved {
        interface: u32,
        name: String,
        servers: Vec<IpAddr>,
        domains: Vec<String>,
        all_traffic: bool,
        other_links: Vec<Link>,
        boot: String,
    },
    File {
        path: PathBuf,
        original: Vec<u8>,
        installed: Vec<u8>,
        servers: Vec<IpAddr>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Link {
    index: u32,
    name: String,
    servers: Vec<(i32, Vec<u8>)>,
}

impl State {
    pub fn servers(&self) -> Vec<IpAddr> {
        match self {
            Self::None => Vec::new(),
            Self::Resolved { servers, .. } | Self::File { servers, .. } => servers.clone(),
        }
    }
}

async fn manager(connection: &Connection) -> Result<Proxy<'_>, Error> {
    Proxy::new(
        connection,
        "org.freedesktop.resolve1",
        "/org/freedesktop/resolve1",
        "org.freedesktop.resolve1.Manager",
    )
    .await
    .map_err(dbus_error)
}

fn dbus_error(error: zbus::Error) -> Error {
    Error::Dns(format!(
        "{error}. Check that the system DNS service is running."
    ))
}

pub(crate) async fn prepare(
    config: &TunnelConfig,
    name: &str,
    interface: u32,
) -> Result<State, Error> {
    let all_traffic = config.is_all_traffic();
    let servers = config.interface.dns.clone();
    if servers.is_empty() {
        if all_traffic {
            return Err(Error::Dns(
                "All-traffic tunnels need a DNS server. Add the server's DNS address in Traffic."
                    .into(),
            ));
        }
        return Ok(State::None);
    }
    if servers
        .iter()
        .any(|ip| ip.is_loopback() || ip.is_unspecified())
    {
        return Err(Error::Dns(
            "Use a DNS server inside the tunnel, not a local resolver address.".into(),
        ));
    }
    if !all_traffic && config.interface.search_domains.is_empty() {
        return Err(Error::Dns(
            "Add the domains this tunnel's DNS should resolve under Advanced.".into(),
        ));
    }
    let resolved = async {
        let connection = Connection::system().await.map_err(dbus_error)?;
        let proxy = manager(&connection).await?;
        let dns: Vec<(i32, i32, Vec<u8>)> = proxy.get_property("DNS").await.map_err(dbus_error)?;
        let mut other_links = Vec::<Link>::new();
        if all_traffic {
            // Disable the other link resolvers while the root domain uses this tunnel.
            // Otherwise a more-specific physical DNS domain could bypass it.
            for (index, family, address) in dns {
                if index <= 0 || index as u32 == interface {
                    continue;
                }
                if let Some(link) = other_links.iter_mut().find(|l| l.index == index as u32) {
                    link.servers.push((family, address));
                } else {
                    let name = netconfig::Interface::try_from_index(index as u32)?.name()?;
                    other_links.push(Link {
                        index: index as u32,
                        name,
                        servers: vec![(family, address)],
                    });
                }
            }
        }
        Ok::<_, Error>(State::Resolved {
            interface,
            name: name.to_owned(),
            servers: servers.clone(),
            domains: config.interface.search_domains.clone(),
            all_traffic,
            other_links,
            boot: fs::read_to_string("/proc/sys/kernel/random/boot_id")?,
        })
    }
    .await;
    match resolved {
        Ok(state) => Ok(state),
        Err(_) if all_traffic => {
            // Systems without resolved use the standard libc resolver file.
            let path = fs::canonicalize("/etc/resolv.conf")?;
            let original = fs::read(&path)?;
            if original.len() > 1024 * 1024 {
                return Err(Error::Dns(
                    "System resolver configuration is too large".into(),
                ));
            }
            let mut installed = String::from("# wg-easy: restored when the tunnel stops\n");
            for server in &servers {
                installed.push_str(&format!("nameserver {server}\n"));
            }
            if !config.interface.search_domains.is_empty() {
                installed.push_str(&format!(
                    "search {}\n",
                    config.interface.search_domains.join(" ")
                ));
            }
            Ok(State::File {
                path,
                original,
                installed: installed.into_bytes(),
                servers,
            })
        }
        Err(error) => Err(error),
    }
}

fn encoded_servers(servers: &[IpAddr]) -> Vec<(i32, Vec<u8>)> {
    servers
        .iter()
        .map(|server| match server {
            IpAddr::V4(ip) => (libc::AF_INET, ip.octets().to_vec()),
            IpAddr::V6(ip) => (libc::AF_INET6, ip.octets().to_vec()),
        })
        .collect()
}

pub(crate) async fn apply(state: &State) -> Result<(), Error> {
    match state {
        State::None => Ok(()),
        State::File {
            path, installed, ..
        } => write_resolver(path, installed),
        State::Resolved {
            interface,
            servers,
            domains,
            all_traffic,
            other_links,
            ..
        } => {
            let connection = Connection::system().await.map_err(dbus_error)?;
            let proxy = manager(&connection).await?;
            let index = *interface as i32;
            let _: () = proxy
                .call("SetLinkDNS", &(index, encoded_servers(servers)))
                .await
                .map_err(dbus_error)?;
            let mut domains: Vec<_> = domains.iter().map(|d| (d.as_str(), true)).collect();
            if *all_traffic {
                domains.push((".", true));
            }
            let _: () = proxy
                .call("SetLinkDomains", &(index, domains))
                .await
                .map_err(dbus_error)?;
            let _: () = proxy
                .call("SetLinkDefaultRoute", &(index, *all_traffic))
                .await
                .map_err(dbus_error)?;
            let _: () = proxy
                .call("SetLinkLLMNR", &(index, "no"))
                .await
                .map_err(dbus_error)?;
            let _: () = proxy
                .call("SetLinkMulticastDNS", &(index, "no"))
                .await
                .map_err(dbus_error)?;
            for link in other_links {
                let _: () = proxy
                    .call(
                        "SetLinkDNS",
                        &(link.index as i32, Vec::<(i32, Vec<u8>)>::new()),
                    )
                    .await
                    .map_err(dbus_error)?;
            }
            let _: () = proxy.call("FlushCaches", &()).await.map_err(dbus_error)?;
            Ok(())
        }
    }
}

fn is_same_link(index: u32, name: &str) -> bool {
    netconfig::Interface::try_from_index(index)
        .and_then(|i| i.name())
        .is_ok_and(|actual| actual == name)
}

pub(crate) async fn restore(state: &State) -> Result<(), Error> {
    match state {
        State::None => Ok(()),
        State::File {
            path,
            original,
            installed,
            ..
        } => {
            // Respect a new resolver configuration installed by the network manager.
            if fs::read(path)? == *installed {
                write_resolver(path, original)?;
            }
            Ok(())
        }
        State::Resolved {
            interface,
            name,
            other_links,
            boot,
            ..
        } => {
            if fs::read_to_string("/proc/sys/kernel/random/boot_id")? != *boot {
                return Ok(());
            }
            // resolved's per-link settings vanish when the link is removed or the host reboots.
            let need_restore = other_links.iter().any(|l| is_same_link(l.index, &l.name))
                || is_same_link(*interface, name);
            if !need_restore {
                return Ok(());
            }
            let connection = Connection::system().await.map_err(dbus_error)?;
            let proxy = manager(&connection).await?;
            for link in other_links {
                if !is_same_link(link.index, &link.name) {
                    continue;
                }
                let object: OwnedObjectPath = proxy
                    .call("GetLink", &(link.index as i32,))
                    .await
                    .map_err(dbus_error)?;
                let link_proxy = Proxy::new(
                    &connection,
                    "org.freedesktop.resolve1",
                    object,
                    "org.freedesktop.resolve1.Link",
                )
                .await
                .map_err(dbus_error)?;
                let current: Vec<(i32, Vec<u8>)> =
                    link_proxy.get_property("DNS").await.map_err(dbus_error)?;
                // Do not overwrite a DHCP renewal or user change made while connected.
                if current.is_empty() {
                    let _: () = proxy
                        .call("SetLinkDNS", &(link.index as i32, &link.servers))
                        .await
                        .map_err(dbus_error)?;
                }
            }
            if is_same_link(*interface, name) {
                let _: () = proxy
                    .call("RevertLink", &(*interface as i32,))
                    .await
                    .map_err(dbus_error)?;
            }
            let _: () = proxy.call("FlushCaches", &()).await.map_err(dbus_error)?;
            Ok(())
        }
    }
}

fn write_resolver(path: &std::path::Path, data: &[u8]) -> Result<(), Error> {
    use std::{
        io::Write,
        os::unix::fs::{OpenOptionsExt, PermissionsExt},
    };
    let temporary = path.with_file_name(".wg-easy-resolv.tmp");
    let mode = fs::metadata(path)?.permissions().mode() & 0o777;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temporary)?;
    file.write_all(data)?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    fs::File::open(
        path.parent()
            .ok_or_else(|| io::Error::other("Invalid resolver path"))?,
    )?
    .sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn file_dns_restores_original_and_preserves_external_changes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("resolv.conf");
        fs::write(&path, b"nameserver 192.0.2.1\n").unwrap();
        let state = State::File {
            path: path.clone(),
            original: fs::read(&path).unwrap(),
            installed: b"nameserver 10.0.0.1\n".to_vec(),
            servers: vec![],
        };
        apply(&state).await.unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"nameserver 10.0.0.1\n");
        restore(&state).await.unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"nameserver 192.0.2.1\n");
        apply(&state).await.unwrap();
        fs::write(&path, b"nameserver 192.0.2.2\n").unwrap();
        restore(&state).await.unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"nameserver 192.0.2.2\n");
    }
}

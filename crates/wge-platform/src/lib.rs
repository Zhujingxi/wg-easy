//! Native interface, routing and DNS configuration with crash recovery.

use route_manager::{Route, RouteManager};
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use std::fs::File;
use std::{
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
};
use tun::AbstractDevice;
use wge_config::{IpNetwork, TunnelConfig};

#[cfg(target_os = "linux")]
#[path = "linux_dns.rs"]
mod dns;
#[cfg(target_os = "windows")]
#[path = "windows_dns.rs"]
mod dns;
#[cfg(target_os = "macos")]
#[path = "macos_dns.rs"]
mod dns;
#[cfg(target_os = "linux")]
mod linux_filter;
#[cfg(target_os = "linux")]
mod linux_policy;
#[cfg(all(test, target_os = "linux"))]
mod linux_resolved_test;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
mod macos_filter;
#[cfg(all(test, any(windows, target_os = "macos")))]
mod native_smoke;
#[cfg(windows)]
pub mod windows;
#[cfg(windows)]
mod windows_filter;
#[cfg(windows)]
pub mod windows_service;
#[cfg(windows)]
pub mod windows_storage;
#[cfg(target_os = "linux")]
pub use linux_policy::SOCKET_MARK;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Network configuration failed: {0}")]
    Io(#[from] io::Error),
    #[error("Could not create the tunnel interface: {0}")]
    Tun(#[from] tun::Error),
    #[error("Could not configure the tunnel address: {0}")]
    Address(String),
    #[error("DNS configuration failed: {0}")]
    Dns(String),
    #[error("Invalid recovery journal: {0}")]
    Journal(String),
    #[error("Invalid network configuration: {0}")]
    Invalid(String),
}

impl From<netconfig::Error> for Error {
    fn from(error: netconfig::Error) -> Self {
        Self::Address(error.to_string())
    }
}

/// Ignore unusable address families before installing endpoint bypasses.
pub fn routable_endpoints(endpoints: &[SocketAddr]) -> Result<Vec<SocketAddr>, Error> {
    #[cfg(windows)]
    use windows_sys::Win32::Foundation::{ERROR_NETWORK_UNREACHABLE, ERROR_NOT_FOUND};
    let mut manager = RouteManager::new()?;
    let mut result = Vec::new();
    for endpoint in endpoints {
        let routed = match manager.find_route(&endpoint.ip()) {
            Ok(route) => route.is_some(),
            #[cfg(windows)]
            Err(error)
                if matches!(
                    error.raw_os_error().map(|code| code as u32),
                    Some(ERROR_NOT_FOUND | ERROR_NETWORK_UNREACHABLE)
                ) =>
            {
                false
            }
            Err(error) => return Err(error.into()),
        };
        if routed && !result.contains(endpoint) {
            result.push(*endpoint);
        }
    }
    Ok(result)
}

/// Must be stopped explicitly so DNS and endpoint bypasses are restored.
pub struct Network {
    path: PathBuf,
    journal: Journal,
    #[cfg(windows)]
    filter: Option<windows_filter::Guard>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SavedRoute {
    destination: IpAddr,
    prefix: u8,
    gateway: Option<IpAddr>,
    interface: u32,
    interface_name: String,
    #[cfg(target_os = "linux")]
    table: u8,
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    metric: Option<u32>,
    #[cfg(target_os = "macos")]
    if_scope: bool,
}

impl SavedRoute {
    fn remove(&self, manager: &mut RouteManager) -> Result<(), Error> {
        if let Err(error) = manager.delete(&self.native()) {
            let missing = error.kind() == io::ErrorKind::NotFound;
            #[cfg(unix)]
            let missing = missing || error.raw_os_error() == Some(libc::ESRCH);
            if missing && !manager.list()?.iter().any(|route| self.matches(route)) {
                return Ok(());
            }
            return Err(io::Error::new(
                error.kind(),
                format!(
                    "Could not remove route {}/{} on {}: {error}",
                    self.destination, self.prefix, self.interface_name
                ),
            )
            .into());
        }
        Ok(())
    }

    fn native(&self) -> Route {
        let route = Route::new(self.destination, self.prefix).with_if_index(self.interface);
        let route = if let Some(gateway) = self.gateway {
            route.with_gateway(gateway)
        } else {
            route
        };
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        let route = if let Some(metric) = self.metric {
            route.with_metric(metric)
        } else {
            route
        };
        #[cfg(target_os = "macos")]
        let route = route.with_if_scope(self.if_scope);
        #[cfg(target_os = "linux")]
        let route = route.with_table(self.table);
        route
    }

    fn matches(&self, route: &Route) -> bool {
        let matches = route.destination() == self.destination
            && route.prefix() == self.prefix
            && route.gateway().filter(|ip| !ip.is_unspecified())
                == self.gateway.filter(|ip| !ip.is_unspecified())
            && route.if_index() == Some(self.interface);
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        let matches = matches && route.metric() == self.metric;
        #[cfg(target_os = "macos")]
        let matches = matches && route.if_scope() == self.if_scope;
        #[cfg(target_os = "linux")]
        let matches = matches && route.table() == self.table;
        matches
    }
}

#[derive(Serialize, Deserialize)]
struct Journal {
    version: u32,
    interface_name: String,
    routes: Vec<SavedRoute>,
    #[serde(default)]
    displaced_routes: Vec<SavedRoute>,
    dns: dns::State,
    #[cfg(target_os = "linux")]
    full_tunnel_policy: bool,
    #[cfg(target_os = "macos")]
    #[serde(default)]
    filter: Option<macos_filter::State>,
}

impl Network {
    pub fn interface_name(&self) -> &str {
        &self.journal.interface_name
    }

    /// Configures native networking. Call only after daemon-side validation.
    pub async fn create(
        config: &TunnelConfig,
        name: &str,
        endpoints: &[SocketAddr],
        recovery: &Path,
        listen_port: u16,
    ) -> Result<(Self, tun::AsyncDevice), Error> {
        if name.is_empty()
            || name.len() > 15
            || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(Error::Invalid("Invalid interface name".into()));
        }
        prepare_directory(recovery)?;
        let path = recovery.join(format!("{name}.json"));
        if path.exists() {
            return Err(Error::Journal(
                "Recover the previous network state before connecting".into(),
            ));
        }
        let mut cfg = tun::Configuration::default();
        cfg.mtu(config.interface.mtu.unwrap_or(1420)).up();
        #[cfg(not(target_os = "macos"))]
        cfg.tun_name(name);
        #[cfg(target_os = "macos")]
        cfg.platform_config(|p| {
            p.enable_routing(false);
        });
        #[cfg(windows)]
        {
            let dll = std::env::current_exe()?
                .parent()
                .ok_or_else(|| Error::Invalid("Cannot locate the bundled driver".into()))?
                .join("wintun.dll");
            cfg.platform_config(|p| {
                p.wintun_file(dll.as_os_str());
                p.wait_for_interfaces(
                    true,
                    config.is_all_traffic()
                        || config.interface.addresses.iter().any(|a| a.is_ipv6()),
                    std::time::Duration::from_secs(10),
                );
            });
        }
        #[cfg(target_os = "linux")]
        if config.is_all_traffic() {
            linux_policy::check_available()?;
        }
        let device = tun::create_as_async(&cfg)?;
        let index = u32::try_from(device.tun_index()?)
            .map_err(|_| Error::Invalid("Invalid tunnel interface index".into()))?;
        let interface = netconfig::Interface::try_from_index(index)?;
        let actual_name = interface.name()?;
        #[cfg(windows)]
        interface.set_mtu(config.interface.mtu.unwrap_or(1420).into())?;
        for address in &config.interface.addresses {
            #[cfg(target_os = "macos")]
            macos::add_address(&actual_name, address).map_err(|error| {
                Error::Address(format!(
                    "Could not assign tunnel address {address} on {actual_name}: {error}"
                ))
            })?;
            #[cfg(not(target_os = "macos"))]
            interface.add_address(
                address
                    .to_string()
                    .parse()
                    .map_err(|_| Error::Invalid("Invalid tunnel address".into()))?,
            )?;
        }
        let dns = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            dns::prepare(config, &actual_name, index),
        )
        .await
        .map_err(|_| Error::Dns("The system DNS service did not respond".into()))??;
        let mut routes = plan_routes(config, endpoints, &dns.servers(), &actual_name, index)?;
        let mut displaced_routes = Vec::new();
        if config.is_all_traffic() {
            plan_physical_overrides(
                endpoints,
                &actual_name,
                index,
                &mut routes,
                &mut displaced_routes,
            )?;
        }
        #[cfg(target_os = "macos")]
        let filter = if config.is_all_traffic() {
            Some(macos_filter::prepare(&actual_name, endpoints, listen_port)?)
        } else {
            None
        };
        #[cfg(not(target_os = "macos"))]
        let _ = listen_port;
        let mut network = Self {
            path,
            journal: Journal {
                version: 1,
                interface_name: actual_name,
                routes: Vec::new(),
                displaced_routes,
                dns,
                #[cfg(target_os = "linux")]
                full_tunnel_policy: false,
                #[cfg(target_os = "macos")]
                filter,
            },
            #[cfg(windows)]
            filter: None,
        };
        network.save()?;
        let result = async {
            #[cfg(target_os = "linux")]
            if config.is_all_traffic() {
                network.journal.full_tunnel_policy = true;
                network.save()?;
                linux_filter::install(&network.journal.interface_name)?;
            }
            #[cfg(target_os = "macos")]
            if let Some(filter) = &network.journal.filter {
                macos_filter::apply(filter)?;
            }
            #[cfg(windows)]
            if config.is_all_traffic() {
                network.filter = Some(windows_filter::Guard::install(index, endpoints)?);
            }
            let mut manager = RouteManager::new()?;
            for original in &network.journal.displaced_routes {
                original.remove(&mut manager)?;
            }
            for route in routes {
                // Record intent first, so a crash at any instruction remains recoverable.
                network.journal.routes.push(route.clone());
                network.save()?;
                manager.add(&route.native()).map_err(|error| {
                    io::Error::new(
                        error.kind(),
                        format!(
                            "Could not add route {}/{} on {}: {error}",
                            route.destination, route.prefix, route.interface_name
                        ),
                    )
                })?;
            }
            #[cfg(target_os = "linux")]
            if config.is_all_traffic() {
                linux_policy::install()?;
            }
            tokio::time::timeout(
                std::time::Duration::from_secs(15),
                dns::apply(&network.journal.dns),
            )
            .await
            .map_err(|_| Error::Dns("The system DNS service did not respond".into()))??;
            Ok::<_, Error>(())
        }
        .await;
        if let Err(error) = result {
            if let Err(cleanup) = network.cleanup().await {
                return Err(Error::Journal(format!(
                    "{error}; cleanup needs retry: {cleanup}"
                )));
            }
            return Err(error);
        }
        Ok((network, device))
    }

    fn save(&self) -> Result<(), Error> {
        write_journal(&self.path, &self.journal)
    }

    pub async fn stop(mut self) -> Result<(), Error> {
        self.cleanup().await
    }

    async fn cleanup(&mut self) -> Result<(), Error> {
        // Keep the tunnel routes until DNS has been restored.
        tokio::time::timeout(
            std::time::Duration::from_secs(15),
            dns::restore(&self.journal.dns),
        )
        .await
        .map_err(|_| {
            Error::Dns("The system DNS service did not respond during cleanup".into())
        })??;
        #[cfg(target_os = "linux")]
        if self.journal.full_tunnel_policy {
            linux_policy::remove()?;
        }
        let mut manager = RouteManager::new()?;
        for saved in self.journal.routes.iter().rev() {
            // Interface indexes can be recycled after a crash or reboot.
            let same_interface = netconfig::Interface::try_from_index(saved.interface)
                .and_then(|i| i.name())
                .is_ok_and(|name| name == saved.interface_name);
            if same_interface && manager.list()?.iter().any(|route| saved.matches(route)) {
                saved.remove(&mut manager)?;
            }
        }
        for saved in &self.journal.displaced_routes {
            let same_interface = netconfig::Interface::try_from_index(saved.interface)
                .and_then(|i| i.name())
                .is_ok_and(|name| name == saved.interface_name);
            if same_interface
                && !manager
                    .list()?
                    .iter()
                    .any(|r| r.destination() == saved.destination && r.prefix() == saved.prefix)
            {
                manager.add(&saved.native()).map_err(|error| {
                    io::Error::new(
                        error.kind(),
                        format!(
                            "Could not restore route {}/{} on {}: {error}",
                            saved.destination, saved.prefix, saved.interface_name
                        ),
                    )
                })?;
            }
        }
        #[cfg(target_os = "macos")]
        if let Some(filter) = &self.journal.filter {
            macos_filter::restore(filter)?;
        }
        #[cfg(target_os = "linux")]
        if self.journal.full_tunnel_policy {
            linux_filter::remove(&self.journal.interface_name)?;
        }
        #[cfg(windows)]
        self.filter.take();
        fs::remove_file(&self.path)?;
        sync_directory(self.path.parent().unwrap())?;
        Ok(())
    }
}

/// gotatun can release its last tun handle after its stop future returns.
pub async fn wait_for_interface_removal(name: &str) -> Result<(), Error> {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        // Windows can retain name/LUID mappings after an adapter leaves the IP stack.
        while netconfig::list_interfaces()?
            .iter()
            .any(|interface| interface.name().is_ok_and(|current| current == name))
        {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        Ok::<_, Error>(())
    })
    .await
    .map_err(|_| {
        Error::Io(io::Error::new(
            io::ErrorKind::TimedOut,
            "The previous tunnel interface has not been released",
        ))
    })?
}

fn plan_routes(
    config: &TunnelConfig,
    endpoints: &[SocketAddr],
    dns_servers: &[IpAddr],
    name: &str,
    index: u32,
) -> Result<Vec<SavedRoute>, Error> {
    let mut manager = RouteManager::new()?;
    let existing = manager.list()?;
    let mut planned = Vec::new();
    #[cfg(target_os = "linux")]
    let table = if config.is_all_traffic() {
        linux_policy::TABLE
    } else {
        254
    };
    for endpoint in endpoints {
        #[cfg(target_os = "linux")]
        if config.is_all_traffic() {
            continue;
        }
        let addr = endpoint.ip();
        if !config.is_all_traffic() && !config.allowed_ips().any(|r| r.contains(addr)) {
            continue;
        }
        let route = manager.find_route(&addr)?.ok_or_else(|| {
            Error::Invalid(format!(
                "No network route to server {addr}. Check this computer's connection."
            ))
        })?;
        let if_index = route
            .if_index()
            .ok_or_else(|| Error::Invalid("The server route has no interface".into()))?;
        let if_name = netconfig::Interface::try_from_index(if_index)?.name()?;
        let bypass = SavedRoute {
            destination: addr,
            prefix: host_prefix(addr),
            gateway: route.gateway(),
            interface: if_index,
            interface_name: if_name,
            #[cfg(target_os = "linux")]
            table: 254,
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            metric: Some(42760),
            #[cfg(target_os = "macos")]
            if_scope: false,
        };
        // An existing host route already bypasses all less-specific tunnel routes.
        if !existing
            .iter()
            .any(|r| r.destination() == addr && r.prefix() == host_prefix(addr))
            && !planned
                .iter()
                .any(|r: &SavedRoute| r.destination == addr && r.prefix == host_prefix(addr))
        {
            planned.push(bypass);
        }
    }
    for range in tunnel_ranges(config) {
        if range.prefix() == host_prefix(range.ip())
            && endpoints.iter().any(|e| range.contains(e.ip()))
        {
            return Err(Error::Invalid(
                "A server endpoint cannot also be a tunnel host route".into(),
            ));
        }
        let route = SavedRoute {
            destination: range.network(),
            prefix: range.prefix(),
            gateway: None,
            interface: index,
            interface_name: name.to_owned(),
            #[cfg(target_os = "linux")]
            table,
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            metric: Some(42760),
            #[cfg(target_os = "macos")]
            if_scope: false,
        };
        if !planned.iter().any(|r| {
            r.destination == route.destination && r.prefix == route.prefix && r.interface == index
        }) {
            planned.push(route);
        }
    }
    for &server in dns_servers {
        if endpoints.iter().any(|e| e.ip() == server) {
            return Err(Error::Invalid(
                "The DNS address must differ from the public server endpoint".into(),
            ));
        }
        if !config.is_all_traffic() && !config.allowed_ips().any(|r| r.contains(server)) {
            return Err(Error::Invalid(format!(
                "DNS server {server} is outside this tunnel's traffic ranges"
            )));
        }
        let route = SavedRoute {
            destination: server,
            prefix: host_prefix(server),
            gateway: None,
            interface: index,
            interface_name: name.to_owned(),
            #[cfg(target_os = "linux")]
            table,
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            metric: Some(42760),
            #[cfg(target_os = "macos")]
            if_scope: false,
        };
        if !planned.iter().any(|r| {
            r.destination == route.destination && r.prefix == route.prefix && r.interface == index
        }) {
            planned.push(route);
        }
    }
    Ok(planned)
}

fn plan_physical_overrides(
    endpoints: &[SocketAddr],
    name: &str,
    index: u32,
    planned: &mut Vec<SavedRoute>,
    displaced: &mut Vec<SavedRoute>,
) -> Result<(), Error> {
    #[cfg(target_os = "linux")]
    {
        let _ = (endpoints, name, index, planned, displaced);
    }
    #[cfg(not(target_os = "linux"))]
    {
        let mut manager = RouteManager::new()?;
        let local = netconfig::list_addresses()?;
        for route in manager.list()? {
            let Some(interface) = route.if_index() else {
                continue;
            };
            let destination = route.destination();
            if interface == index
                || route.prefix() == 0
                || destination.is_loopback()
                || destination.is_multicast()
            {
                continue;
            }
            let interface_name = netconfig::Interface::try_from_index(interface)?.name()?;
            // Darwin delivers local non-loopback addresses through lo0 too.
            #[cfg(target_os = "macos")]
            if interface_name == "lo0" {
                continue;
            }
            if route.prefix() == host_prefix(destination) {
                if local.iter().any(|network| {
                    network.addr() == destination
                        || is_local_broadcast(destination, network.addr(), network.prefix_len())
                }) || endpoints.iter().any(|e| e.ip() == destination)
                {
                    continue;
                }
                if destination == IpAddr::V4(std::net::Ipv4Addr::BROADCAST) {
                    continue;
                }
                let original = SavedRoute {
                    destination,
                    prefix: route.prefix(),
                    gateway: route.gateway(),
                    interface,
                    interface_name,
                    #[cfg(target_os = "windows")]
                    metric: route.metric(),
                    #[cfg(target_os = "macos")]
                    if_scope: route.if_scope(),
                };
                displaced.push(original);
                add_override(planned, destination, route.prefix(), name, index);
            } else {
                // More-specific child routes beat physical routes without deleting them.
                let prefix = route.prefix() + 1;
                let (left, right) = split_network(destination, route.prefix());
                add_override(planned, left, prefix, name, index);
                add_override(planned, right, prefix, name, index);
            }
        }
    }
    Ok(())
}

#[cfg(any(not(target_os = "linux"), test))]
fn is_local_broadcast(destination: IpAddr, address: IpAddr, prefix: u8) -> bool {
    address.is_ipv4()
        && prefix < 31
        && IpNetwork::new(address, prefix).is_ok_and(|network| network.broadcast() == destination)
}

#[cfg(not(target_os = "linux"))]
fn add_override(
    routes: &mut Vec<SavedRoute>,
    destination: IpAddr,
    prefix: u8,
    name: &str,
    interface: u32,
) {
    if routes
        .iter()
        .any(|r| r.destination == destination && r.prefix == prefix && r.interface == interface)
    {
        return;
    }
    routes.push(SavedRoute {
        destination,
        prefix,
        gateway: None,
        interface,
        interface_name: name.to_owned(),
        #[cfg(target_os = "windows")]
        metric: Some(42760),
        #[cfg(target_os = "macos")]
        if_scope: false,
    });
}

#[cfg(any(not(target_os = "linux"), test))]
fn split_network(address: IpAddr, prefix: u8) -> (IpAddr, IpAddr) {
    match address {
        IpAddr::V4(address) => {
            let network =
                u32::from(address) & (u32::MAX.checked_shl(32 - prefix as u32).unwrap_or(0));
            (
                std::net::Ipv4Addr::from(network).into(),
                std::net::Ipv4Addr::from(network | (1 << (31 - prefix))).into(),
            )
        }
        IpAddr::V6(address) => {
            let network =
                u128::from(address) & (u128::MAX.checked_shl(128 - prefix as u32).unwrap_or(0));
            (
                std::net::Ipv6Addr::from(network).into(),
                std::net::Ipv6Addr::from(network | (1 << (127 - prefix))).into(),
            )
        }
    }
}

fn host_prefix(ip: IpAddr) -> u8 {
    if ip.is_ipv4() { 32 } else { 128 }
}

fn tunnel_ranges(config: &TunnelConfig) -> Vec<IpNetwork> {
    let mut ranges = Vec::new();
    for range in config.allowed_ips() {
        if range.prefix() != 0 {
            ranges.push(*range);
        }
    }
    if config.is_all_traffic() {
        // Cover both families even when a config only specifies 0.0.0.0/0.
        ranges.extend(
            ["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"]
                .map(|s| s.parse::<IpNetwork>().unwrap()),
        );
    }
    ranges
}

/// Replays journals before any tunnel can start; never reconnects a tunnel.
pub async fn recover(directory: &Path) -> Result<(), Error> {
    if !directory.exists() {
        return Ok(());
    }
    prepare_directory(directory)?;
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path.extension().is_none_or(|ext| ext != "json") {
            continue;
        }
        let journal = read_journal(&path)?;
        Network {
            path,
            journal,
            #[cfg(windows)]
            filter: None,
        }
        .cleanup()
        .await?;
    }
    Ok(())
}

/// Local interface networks for the editor's overlap warnings.
pub async fn local_networks() -> Result<Vec<IpNetwork>, Error> {
    netconfig::list_addresses()?
        .into_iter()
        .map(|n| {
            n.to_string()
                .parse()
                .map_err(|_| Error::Invalid("Invalid local network address".into()))
        })
        .collect()
}

#[cfg(windows)]
fn prepare_directory(path: &Path) -> Result<(), Error> {
    windows_storage::private_directory(path)?;
    Ok(())
}

#[cfg(unix)]
fn prepare_directory(path: &Path) -> Result<(), Error> {
    if !path.exists() {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(path)?;
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(Error::Journal(
            "Recovery path must be a private directory".into(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid has no arguments or ownership requirements.
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
            return Err(Error::Journal(
                "Recovery directory must be owned by the service with mode 0700".into(),
            ));
        }
    }
    Ok(())
}

fn write_journal(path: &Path, journal: &Journal) -> Result<(), Error> {
    let temporary = path.with_extension("tmp");
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(&temporary)?;
    serde_json::to_writer(&mut file, journal).map_err(|e| Error::Journal(e.to_string()))?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    #[cfg(not(windows))]
    fs::rename(&temporary, path)?;
    #[cfg(windows)]
    windows::replace_file(&temporary, path)?;
    sync_directory(path.parent().unwrap())?;
    Ok(())
}

fn read_journal(path: &Path) -> Result<Journal, Error> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() || file.metadata()?.len() > 1024 * 1024 {
        return Err(Error::Journal(
            "Recovery journal is not a small regular file".into(),
        ));
    }
    let mut data = String::new();
    file.take(1024 * 1024 + 1).read_to_string(&mut data)?;
    let journal: Journal =
        serde_json::from_str(&data).map_err(|e| Error::Journal(e.to_string()))?;
    if journal.version != 1
        || journal
            .routes
            .iter()
            .any(|r| r.prefix > host_prefix(r.destination) || r.interface_name.is_empty())
    {
        return Err(Error::Journal("Unknown version or invalid route".into()));
    }
    Ok(journal)
}

fn sync_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    File::open(path)?.sync_all()?;
    #[cfg(windows)]
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wge_config::{InterfaceConfig, PeerConfig, SecretKey};

    pub(super) fn configuration() -> TunnelConfig {
        TunnelConfig {
            interface: InterfaceConfig {
                private_key: SecretKey::from_bytes([1; 32]).unwrap(),
                addresses: vec!["10.0.0.1/24".parse().unwrap()],
                dns: vec![],
                search_domains: vec![],
                listen_port: None,
                mtu: None,
            },
            peers: vec![PeerConfig {
                public_key: SecretKey::from_bytes([2; 32]).unwrap().public_key(),
                preshared_key: None,
                endpoint: Some("192.0.2.1:51820".parse().unwrap()),
                allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
                persistent_keepalive: None,
            }],
        }
    }

    #[test]
    fn network_state_and_errors_can_cross_async_tasks() {
        fn send_sync<T: Send + Sync>() {}
        send_sync::<Network>();
        send_sync::<Error>();
    }

    #[tokio::test]
    async fn interface_removal_wait_checks_live_interfaces() {
        let interface = netconfig::list_interfaces().unwrap().remove(0);
        let name = interface.name().unwrap();
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(30),
                wait_for_interface_removal(&name),
            )
            .await
            .is_err()
        );
        wait_for_interface_removal("wge-missing").await.unwrap();
    }

    #[test]
    fn saved_on_link_routes_match_unspecified_gateways_in_both_families() {
        for (destination, prefix, gateway) in [
            ("198.18.246.53", 32, "0.0.0.0"),
            ("fd42:7767:66::53", 128, "::"),
        ] {
            let saved = SavedRoute {
                destination: destination.parse().unwrap(),
                prefix,
                gateway: None,
                interface: 7,
                interface_name: "wge-test".into(),
                #[cfg(target_os = "linux")]
                table: 254,
                #[cfg(any(target_os = "linux", target_os = "windows"))]
                metric: Some(42760),
                #[cfg(target_os = "macos")]
                if_scope: false,
            };
            let native = saved.native();
            assert!(saved.matches(&native));
            assert!(saved.matches(&native.clone().with_gateway(gateway.parse().unwrap())));
            assert!(!saved.matches(&native.clone().with_gateway(destination.parse().unwrap())));
            assert!(!saved.matches(&native.with_if_index(8)));
        }
    }

    #[test]
    fn local_broadcasts_exclude_point_to_point_hosts_and_ipv6() {
        let destination = "10.1.15.255".parse().unwrap();
        assert!(is_local_broadcast(
            destination,
            "10.1.0.4".parse().unwrap(),
            20
        ));
        for (address, prefix) in [("10.1.16.4", 20), ("10.1.15.254", 31), ("10.1.15.255", 32)] {
            assert!(!is_local_broadcast(
                destination,
                address.parse().unwrap(),
                prefix
            ));
        }
        let ipv6 = "fd00::ffff:ffff:ffff:ffff".parse().unwrap();
        assert!(!is_local_broadcast(ipv6, "fd00::1".parse().unwrap(), 64));
    }

    #[test]
    fn ipv4_default_also_captures_ipv6_without_requiring_an_ipv6_address() {
        let ranges = tunnel_ranges(&configuration());
        for ip in ["8.8.8.8", "192.0.2.1", "2001:4860:4860::8888", "fd00::53"] {
            assert!(ranges.iter().any(|r| r.contains(ip.parse().unwrap())));
        }
    }

    #[test]
    fn physical_route_splits_cover_both_halves_of_each_family() {
        assert_eq!(
            split_network("192.0.2.0".parse().unwrap(), 24),
            ("192.0.2.0".parse().unwrap(), "192.0.2.128".parse().unwrap())
        );
        assert_eq!(
            split_network("fd00::".parse().unwrap(), 64),
            (
                "fd00::".parse().unwrap(),
                "fd00::8000:0:0:0".parse().unwrap()
            )
        );
    }

    #[test]
    fn journal_has_no_keys_and_rejects_unknown_version() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("wge-test.json");
        let journal = Journal {
            version: 1,
            interface_name: "wge-test".into(),
            routes: vec![],
            displaced_routes: vec![],
            #[cfg(not(target_os = "macos"))]
            dns: dns::State::None,
            #[cfg(target_os = "macos")]
            dns: dns::State::default(),
            #[cfg(target_os = "linux")]
            full_tunnel_policy: false,
            #[cfg(target_os = "macos")]
            filter: None,
        };
        write_journal(&path, &journal).unwrap();
        let text = fs::read_to_string(&path).unwrap();
        assert!(!text.contains("private_key"));
        assert!(!text.contains("preshared"));
        assert_eq!(read_journal(&path).unwrap().interface_name, "wge-test");
        fs::write(&path, text.replace("\"version\":1", "\"version\":2")).unwrap();
        assert!(read_journal(&path).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn journal_refuses_symlinks_and_public_directories() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target");
        fs::write(&target, b"untouched").unwrap();
        let path = directory.path().join("wge-test.json");
        symlink(&target, &path).unwrap();
        assert!(read_journal(&path).is_err());
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(prepare_directory(directory.path()).is_err());
        assert_eq!(fs::read(target).unwrap(), b"untouched");
    }
}

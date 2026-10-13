use crate::storage::{Store, StoredTunnel};
use std::{collections::HashMap, future::Future, path::PathBuf};
use wge_config::{InterfaceConfig, PeerConfig, SecretKey, TunnelConfig};
use wge_ipc::*;

const MAX_TUNNELS_PER_ACCOUNT: usize = 128;
const MAX_DRAFTS_PER_ACCOUNT: usize = 16;

/// The daemon owns the handle, including when every GUI client has disconnected.
pub trait Network: Send + Sync {
    type Handle: Send + Sync;
    fn start(
        &mut self,
        config: &TunnelConfig,
        name: &str,
    ) -> impl Future<Output = Result<Self::Handle, String>> + Send;
    fn status(handle: &Self::Handle) -> impl Future<Output = TunnelStatus> + Send;
    fn stop(handle: Self::Handle) -> impl Future<Output = Result<(), String>> + Send;
    fn local_networks(&self) -> impl Future<Output = Vec<wge_config::IpNetwork>> + Send;
}
struct Entry<H> {
    stored: StoredTunnel,
    saved: bool,
    running: Option<H>,
    failure: Option<ApiError>,
}
pub struct Service<N: Network> {
    store: Store,
    entries: HashMap<TunnelId, Entry<N::Handle>>,
    network: N,
}
impl<N: Network> Service<N> {
    pub fn open(directory: PathBuf, network: N) -> std::io::Result<Self> {
        let store = Store::open(directory)?;
        let mut entries = HashMap::new();
        for stored in store.load_all()? {
            // Never restore an active handle from disk: restart always means off.
            entries.insert(
                stored.id.clone(),
                Entry {
                    stored,
                    saved: true,
                    running: None,
                    failure: None,
                },
            );
        }
        Ok(Self {
            store,
            entries,
            network,
        })
    }
    pub async fn handle(&mut self, owner: &str, request: Request) -> Response {
        match self.execute(owner, request).await {
            Ok(response) => response,
            Err(error) => Response::Error(error),
        }
    }
    async fn execute(&mut self, owner: &str, request: Request) -> Result<Response, ApiError> {
        match request {
            Request::List => {
                let mut tunnels = Vec::new();
                for entry in self
                    .entries
                    .values()
                    .filter(|entry| entry.stored.owner == owner)
                {
                    tunnels.push(Self::view(entry).await);
                }
                tunnels.sort_by(|a, b| a.name.cmp(&b.name).then(a.id.0.cmp(&b.id.0)));
                Ok(Response::Snapshot(Snapshot {
                    tunnels,
                    local_networks: self.network.local_networks().await,
                }))
            }
            Request::BeginDraft => {
                self.check_quota(owner)?;
                let mut bytes = zeroize::Zeroizing::new([0; 32]);
                getrandom::fill(&mut *bytes).map_err(|_| internal())?;
                let private_key = SecretKey::from_bytes(*bytes).map_err(|_| internal())?;
                let config = TunnelConfig {
                    interface: InterfaceConfig {
                        private_key,
                        addresses: vec![],
                        dns: vec!["1.1.1.1".parse().expect("constant IP")],
                        search_domains: vec![],
                        listen_port: None,
                        mtu: None,
                    },
                    peers: vec![],
                };
                let number = self
                    .entries
                    .values()
                    .filter(|entry| entry.stored.owner == owner)
                    .count()
                    + 1;
                self.insert_draft(owner, format!("Tunnel {number}"), config)
                    .await
            }
            Request::Import { name, config } => {
                self.check_quota(owner)?;
                validate_name(&name)?;
                let config = wge_config::parse(config.expose())
                    .map_err(|error| ApiError::new(ErrorCode::Validation, error.to_string()))?;
                self.insert_draft(owner, name, config).await
            }
            Request::Get { id } => Ok(Response::Tunnel(Self::view(self.entry(owner, &id)?).await)),
            Request::Save {
                id,
                name,
                config,
                preshared_keys,
            } => {
                validate_name(&name)?;
                let entry = self.entry(owner, &id)?;
                require_off(entry)?;
                if entry.stored.config.interface.private_key.public_key()
                    != config.interface.public_key
                {
                    return Err(ApiError::new(
                        ErrorCode::Validation,
                        "The private key cannot be changed through this command",
                    ));
                }
                if preshared_keys.len() > config.peers.len() {
                    return Err(validation("Unexpected preshared key update"));
                }
                let mut seen = std::collections::HashSet::new();
                for update in &preshared_keys {
                    if !seen.insert(update.public_key)
                        || !config
                            .peers
                            .iter()
                            .any(|peer| peer.public_key == update.public_key)
                    {
                        return Err(validation("Unexpected preshared key update"));
                    }
                }
                let mut peers = Vec::with_capacity(config.peers.len());
                for peer in config.peers {
                    let previous = entry
                        .stored
                        .config
                        .peers
                        .iter()
                        .find(|old| old.public_key == peer.public_key);
                    let preshared_key = if let Some(update) = preshared_keys
                        .iter()
                        .find(|update| update.public_key == peer.public_key)
                    {
                        update
                            .value
                            .as_ref()
                            .map(|secret| secret.expose().parse())
                            .transpose()
                            .map_err(|_| {
                                validation("The preshared key must be a valid WireGuard key")
                            })?
                    } else {
                        previous.and_then(|old| old.preshared_key.clone())
                    };
                    peers.push(PeerConfig {
                        public_key: peer.public_key,
                        preshared_key,
                        endpoint: peer.endpoint,
                        allowed_ips: peer.allowed_ips,
                        persistent_keepalive: peer.persistent_keepalive,
                    });
                }
                let interface = config.interface;
                let config = TunnelConfig {
                    interface: InterfaceConfig {
                        private_key: entry.stored.config.interface.private_key.clone(),
                        addresses: interface.addresses,
                        dns: interface.dns,
                        search_domains: interface.search_domains,
                        listen_port: interface.listen_port,
                        mtu: interface.mtu,
                    },
                    peers,
                };
                config
                    .validate()
                    .map_err(|error| validation(error.to_string()))?;
                let stored = StoredTunnel {
                    owner: owner.into(),
                    id: id.clone(),
                    name,
                    config,
                };
                self.store.save(&stored).map_err(|_| internal())?;
                let entry = self.entries.get_mut(&id).expect("authorized entry exists");
                entry.stored = stored;
                entry.saved = true;
                entry.failure = None;
                Ok(Response::Tunnel(Self::view(entry).await))
            }
            Request::Delete { id } => {
                let entry = self.entry(owner, &id)?;
                require_off(entry)?;
                if entry.saved {
                    self.store.remove(owner, &id).map_err(|_| internal())?;
                }
                self.entries.remove(&id);
                Ok(Response::Ok)
            }
            Request::DiscardDraft { id } => {
                let entry = self.entry(owner, &id)?;
                if entry.saved {
                    return Err(validation("Saved tunnels cannot be discarded as drafts"));
                }
                self.entries.remove(&id);
                Ok(Response::Ok)
            }
            Request::Connect { id } => {
                let entry = self.entry(owner, &id)?;
                if entry.running.is_some() {
                    return Ok(Response::Tunnel(Self::view(entry).await));
                }
                if !entry.saved {
                    return Err(validation("Save the tunnel before connecting"));
                }
                // Conflicts are global across users because all tunnels share OS routes.
                for active in self
                    .entries
                    .values()
                    .filter(|other| other.running.is_some())
                {
                    if let Some((requested_range, active_range)) =
                        conflicting_ranges(&entry.stored.config, &active.stored.config)
                    {
                        return Err(ApiError {
                            code: ErrorCode::Conflict,
                            message: "The traffic ranges overlap an active tunnel".into(),
                            conflict: Some(RouteConflict {
                                tunnel_name: active.stored.name.clone(),
                                requested_range,
                                active_range,
                            }),
                        });
                    }
                }
                let name = format!("wge{}", &id.0[..10]);
                let config = entry.stored.config.clone();
                let result = self.network.start(&config, &name).await;
                let entry = self.entries.get_mut(&id).expect("authorized entry exists");
                match result {
                    Ok(handle) => {
                        entry.running = Some(handle);
                        entry.failure = None;
                    }
                    Err(_error) => {
                        // OS error strings can contain provider data; the protocol exposes a safe diagnostic.
                        let error = ApiError::new(
                            ErrorCode::Network,
                            "The tunnel could not start. Check the server address, network access and service permissions.",
                        );
                        entry.failure = Some(error.clone());
                        return Err(error);
                    }
                }
                Ok(Response::Tunnel(Self::view(entry).await))
            }
            Request::Disconnect { id } => {
                self.entry(owner, &id)?;
                let entry = self.entries.get_mut(&id).expect("authorized entry exists");
                if let Some(handle) = entry.running.take()
                    && N::stop(handle).await.is_err()
                {
                    let error = ApiError::new(
                        ErrorCode::Network,
                        "Some network settings could not be restored. Restart the service to retry recovery.",
                    );
                    entry.failure = Some(error.clone());
                    return Err(error);
                }
                entry.failure = None;
                Ok(Response::Tunnel(Self::view(entry).await))
            }
            Request::RevealPrivateKey { id } => {
                let entry = self.entry(owner, &id)?;
                Ok(Response::Secret(SensitiveText::new(
                    entry
                        .stored
                        .config
                        .interface
                        .private_key
                        .expose_base64()
                        .to_string(),
                )))
            }
            Request::Export { id, confirmed } => {
                let entry = self.entry(owner, &id)?;
                if !confirmed {
                    return Err(validation(
                        "Confirm that the exported file contains a private key",
                    ));
                }
                let text = wge_config::write(&entry.stored.config)
                    .map_err(|_| validation("Save a complete tunnel before exporting"))?;
                Ok(Response::Secret(SensitiveText::new(text.to_string())))
            }
        }
    }
    fn check_quota(&self, owner: &str) -> Result<(), ApiError> {
        let mut total = 0;
        let mut drafts = 0;
        for entry in self
            .entries
            .values()
            .filter(|entry| entry.stored.owner == owner)
        {
            total += 1;
            if !entry.saved {
                drafts += 1;
            }
        }
        if total >= MAX_TUNNELS_PER_ACCOUNT || drafts >= MAX_DRAFTS_PER_ACCOUNT {
            return Err(ApiError::new(
                ErrorCode::Busy,
                "Too many open tunnels. Close an unused draft or remove a tunnel.",
            ));
        }
        Ok(())
    }
    async fn insert_draft(
        &mut self,
        owner: &str,
        name: String,
        config: TunnelConfig,
    ) -> Result<Response, ApiError> {
        let mut bytes = [0; 16];
        getrandom::fill(&mut bytes).map_err(|_| internal())?;
        let id = TunnelId(bytes.iter().map(|byte| format!("{byte:02x}")).collect());
        let entry = Entry {
            stored: StoredTunnel {
                owner: owner.into(),
                id: id.clone(),
                name,
                config,
            },
            saved: false,
            running: None,
            failure: None,
        };
        let tunnel = Self::view(&entry).await;
        self.entries.insert(id, entry);
        Ok(Response::Tunnel(tunnel))
    }
    fn entry(&self, owner: &str, id: &TunnelId) -> Result<&Entry<N::Handle>, ApiError> {
        if !id.is_valid() {
            return Err(validation("Invalid tunnel ID"));
        }
        self.entries
            .get(id)
            .filter(|entry| entry.stored.owner == owner)
            .ok_or_else(|| ApiError::new(ErrorCode::NotFound, "Tunnel not found"))
    }
    async fn view(entry: &Entry<N::Handle>) -> Tunnel {
        let mut status = if let Some(handle) = &entry.running {
            N::status(handle).await
        } else {
            TunnelStatus::default()
        };
        if let Some(error) = &entry.failure {
            status.state = ConnectionState::Error;
            status.error = Some(error.clone());
        }
        Tunnel {
            id: entry.stored.id.clone(),
            name: entry.stored.name.clone(),
            config: entry.stored.config.public(),
            status,
            saved: entry.saved,
        }
    }
    pub async fn shutdown(&mut self) {
        for entry in self.entries.values_mut() {
            if let Some(handle) = entry.running.take() {
                let _ = N::stop(handle).await;
            }
        }
    }
}
fn validate_name(name: &str) -> Result<(), ApiError> {
    wge_config::validate_name(name).map_err(|error| validation(error.to_string()))
}

fn require_off<H>(entry: &Entry<H>) -> Result<(), ApiError> {
    if entry.running.is_some() {
        return Err(ApiError::new(
            ErrorCode::Busy,
            "Disconnect this tunnel before editing or deleting it",
        ));
    }
    Ok(())
}
fn validation(message: impl Into<String>) -> ApiError {
    ApiError::new(ErrorCode::Validation, message)
}
fn internal() -> ApiError {
    ApiError::new(
        ErrorCode::Internal,
        "The service could not securely read or save the tunnel",
    )
}
fn conflicting_ranges(a: &TunnelConfig, b: &TunnelConfig) -> Option<(String, String)> {
    let all_traffic = a.is_all_traffic() || b.is_all_traffic();
    for requested in a.allowed_ips() {
        for active in b.allowed_ips() {
            if all_traffic
                || requested.contains(active.network())
                || active.contains(requested.network())
            {
                return Some((requested.to_string(), active.to_string()));
            }
        }
    }
    None
}

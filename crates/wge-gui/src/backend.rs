use std::{path::PathBuf, sync::mpsc, time::Duration};
use tokio::sync::mpsc::{UnboundedSender, unbounded_channel};
use wge_ipc::{Client, ConnectionState, Request, Response, SensitiveText, Snapshot, TunnelId};

pub enum Intent {
    Refresh,
    Edit,
    Action,
    SaveConnect,
    DeleteAfterDisconnect,
    Reveal(TunnelId, u64),
    Export(PathBuf),
}
// IPC requests are infrequent; keeping their payload inline avoids another allocation.
#[allow(clippy::large_enum_variant)]
pub enum Command {
    Request(Request, Intent),
    ImportFile(PathBuf),
    ImportText(SensitiveText),
    ImportImage(zeroize::Zeroizing<Vec<u8>>),
    Scan,
}
#[allow(clippy::large_enum_variant)]
pub enum Event {
    Reply(Intent, Response),
    Offline,
    #[cfg(target_os = "linux")]
    TrayReady(bool),
    Error(&'static str),
    Open,
    Quit,
    Toggle(TunnelId, bool),
}
#[derive(Clone)]
pub struct Backend(pub UnboundedSender<Command>);
impl Backend {
    pub fn send(&self, request: Request, intent: Intent) {
        let _ = self.0.send(Command::Request(request, intent));
    }
    pub fn command(&self, command: Command) {
        let _ = self.0.send(command);
    }
}

pub fn start(events: mpsc::Sender<Event>) -> Backend {
    let (tx, mut rx) = unbounded_channel();
    std::thread::spawn(move || {
        let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        else {
            let _ = events.send(Event::Offline);
            return;
        };
        runtime.block_on(async move {
            #[cfg(target_os = "linux")]
            let tray = tokio::time::timeout(Duration::from_secs(2),crate::tray::start(events.clone())).await.ok().flatten();
            #[cfg(target_os = "linux")]
            let _ = events.send(Event::TrayReady(tray.is_some()));
            let mut client = None;
            let mut delay = Duration::from_secs(1);
            let mut previous = Vec::new();
            let mut refresh_pending = false;
            loop {
                let command = if std::mem::take(&mut refresh_pending) {
                    Command::Request(Request::List, Intent::Refresh)
                } else { tokio::select! {
                    command = rx.recv() => match command { Some(command) => command, None => break },
                    _ = tokio::time::sleep(delay) => Command::Request(Request::List, Intent::Refresh),
                }};
                let (request, intent) = match command {
                    Command::Request(request, intent) => (request, intent),
                    command => {
                        let imported = match command {
                            Command::ImportFile(path) => crate::import::open(&path),
                            Command::ImportText(text) => Ok(text),
                            Command::ImportImage(bytes) => crate::import::decode_image(&bytes),
                            Command::Scan => crate::import::screen(),
                            Command::Request(..) => unreachable!(),
                        };
                        match imported {
                            Ok(config) => (Request::Import { name: rust_i18n::t!("imported_name").into_owned(), config }, Intent::Edit),
                            Err(message) => { let _ = events.send(Event::Error(message)); continue; }
                        }
                    }
                };
                let mutates = !matches!(&request, Request::List | Request::ListAfter { .. } | Request::Get { .. } | Request::RevealPrivateKey { .. } | Request::Export { .. });
                if client.is_none() { client = Client::connect_default().await.ok(); }
                let response = match &mut client {
                    Some(client) => match client.request(request).await {
                        Ok(response)=>Some(response),
                        Err(error)=>{
                            if matches!(error,wge_ipc::TransportError::Version|wge_ipc::TransportError::Invalid) {let _=events.send(Event::Error("api_protocol"));}
                            None
                        }
                    },
                    None => None,
                };
                match response {
                    Some(response) => {
                        refresh_pending = mutates;
                        if let Response::Snapshot(snapshot) = &response {
                            delay = if snapshot.tunnels.iter().any(|t| !matches!(t.status.state, ConnectionState::Off | ConnectionState::Error)) { Duration::from_secs(1) } else { Duration::from_secs(5) };
                            let encoded = serde_json::to_vec(snapshot).unwrap_or_default();
                            if encoded == previous && matches!(intent,Intent::Refresh) { continue; }
                            previous = encoded;
                            #[cfg(target_os = "linux")]
                            if let Some(tray) = &tray {
                                let snapshot = snapshot.clone();
                                tray.update(|tray| {tray.snapshot = snapshot;tray.online=true;}).await;
                            }
                        }
                        if let Intent::Export(path) = &intent
                            && let Response::Secret(secret) = response {
                                let message = if crate::import::write_export(path, &secret).is_ok() { "export_done" } else { "export_write_error" };
                                let _ = events.send(Event::Error(message));
                                continue;
                            }
                        let _ = events.send(Event::Reply(intent, response));
                    }
                    None => {
                        client = None; previous.clear();
                        #[cfg(target_os="linux")]
                        if let Some(tray)=&tray {tray.update(|tray|tray.online=false).await;}
                        let _ = events.send(Event::Offline); delay = Duration::from_secs(5);
                    }
                }
            }
        });
    });
    let backend = Backend(tx);
    backend.send(Request::List, Intent::Refresh);
    backend
}

pub fn active(snapshot: &Snapshot) -> bool {
    snapshot
        .tunnels
        .iter()
        .any(|t| t.status.state == ConnectionState::Connected)
}

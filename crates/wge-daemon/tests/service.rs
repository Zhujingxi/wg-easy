use std::{future::ready, path::PathBuf};
use wge_config::{IpNetwork, TunnelConfig};
use wge_daemon::service::{Network, Service};
use wge_ipc::*;

struct TestNetwork;
impl Network for TestNetwork {
    type Handle = ();
    fn start(
        &mut self,
        _: &TunnelConfig,
        _: &str,
    ) -> impl std::future::Future<Output = Result<(), String>> + Send {
        ready(Ok(()))
    }
    fn status(_: &()) -> impl std::future::Future<Output = TunnelStatus> + Send {
        ready(TunnelStatus {
            state: ConnectionState::Connecting,
            ..Default::default()
        })
    }
    fn stop(_: ()) -> impl std::future::Future<Output = Result<(), String>> + Send {
        ready(Ok(()))
    }
    fn local_networks(&self) -> impl std::future::Future<Output = Vec<IpNetwork>> + Send {
        ready(vec![])
    }
}
fn configuration(range: &str) -> SensitiveText {
    SensitiveText::new(format!(
        "[Interface]\nPrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\nAddress = 10.8.0.2/24, fd00::2/64\n\n[Peer]\nPublicKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\nEndpoint = example.com:51820\nAllowedIPs = {range}\n"
    ))
}
async fn saved(service: &mut Service<TestNetwork>, owner: &str, name: &str, range: &str) -> Tunnel {
    let Response::Tunnel(draft) = service
        .handle(
            owner,
            Request::Import {
                name: name.into(),
                config: configuration(range),
            },
        )
        .await
    else {
        panic!("import failed")
    };
    let Response::Tunnel(tunnel) = service
        .handle(
            owner,
            Request::Save {
                id: draft.id,
                name: draft.name,
                config: draft.config,
                preshared_keys: vec![],
            },
        )
        .await
    else {
        panic!("save failed")
    };
    tunnel
}
fn directory() -> (tempfile::TempDir, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("tunnels");
    (temp, path)
}
#[tokio::test]
async fn owners_are_isolated_and_restart_never_reconnects() {
    let (_temp, path) = directory();
    let mut service = Service::open(path.clone(), TestNetwork).unwrap();
    let tunnel = saved(&mut service, "1000", "日本の家", "10.8.0.0/24").await;
    assert!(matches!(
        service
            .handle(
                "1001",
                Request::Get {
                    id: tunnel.id.clone()
                }
            )
            .await,
        Response::Error(ApiError {
            code: ErrorCode::NotFound,
            ..
        })
    ));
    assert!(matches!(
        service
            .handle(
                "1001",
                Request::RevealPrivateKey {
                    id: tunnel.id.clone()
                }
            )
            .await,
        Response::Error(_)
    ));
    assert!(
        matches!(service.handle("1001",Request::List).await,Response::Snapshot(Snapshot{tunnels,..}) if tunnels.is_empty())
    );
    assert!(matches!(
        service
            .handle(
                "1000",
                Request::Connect {
                    id: tunnel.id.clone()
                }
            )
            .await,
        Response::Tunnel(Tunnel {
            status: TunnelStatus {
                state: ConnectionState::Connecting,
                ..
            },
            ..
        })
    ));
    drop(service);
    let mut service = Service::open(path, TestNetwork).unwrap();
    let Response::Tunnel(restored) = service.handle("1000", Request::Get { id: tunnel.id }).await
    else {
        panic!()
    };
    assert_eq!(restored.name, "日本の家");
    assert_eq!(restored.status.state, ConnectionState::Off);
}
#[tokio::test]
async fn overlapping_tunnels_save_but_only_disjoint_tunnels_connect() {
    let (_temp, path) = directory();
    let mut service = Service::open(path, TestNetwork).unwrap();
    let first = saved(&mut service, "1000", "Home", "10.8.0.0/24").await;
    let second = saved(&mut service, "1000", "Work", "10.8.0.128/25").await;
    let third = saved(&mut service, "1000", "Office", "10.9.0.0/24").await;
    let full = saved(&mut service, "1000", "All", "::/0").await;
    assert!(matches!(
        service
            .handle(
                "1000",
                Request::Connect {
                    id: first.id.clone()
                }
            )
            .await,
        Response::Tunnel(_)
    ));
    let Response::Error(error) = service
        .handle("1000", Request::Connect { id: second.id })
        .await
    else {
        panic!()
    };
    assert_eq!(error.code, ErrorCode::Conflict);
    assert_eq!(error.conflict.unwrap().tunnel_name, "Home");
    assert!(matches!(
        service
            .handle("1000", Request::Connect { id: third.id })
            .await,
        Response::Tunnel(_)
    ));
    assert!(matches!(
        service
            .handle("1000", Request::Connect { id: full.id })
            .await,
        Response::Error(ApiError {
            code: ErrorCode::Conflict,
            ..
        })
    ));
    assert!(matches!(
        service
            .handle(
                "1000",
                Request::Delete {
                    id: first.id.clone()
                }
            )
            .await,
        Response::Error(ApiError {
            code: ErrorCode::Busy,
            ..
        })
    ));
    service
        .handle(
            "1000",
            Request::Disconnect {
                id: first.id.clone(),
            },
        )
        .await;
    assert!(matches!(
        service
            .handle("1000", Request::Delete { id: first.id })
            .await,
        Response::Ok
    ));
}
#[tokio::test]
async fn secrets_require_explicit_actions_and_import_refuses_hooks() {
    let (_temp, path) = directory();
    let mut service = Service::open(path, TestNetwork).unwrap();
    let tunnel = saved(&mut service, "1000", "Home", "10.8.0.0/24").await;
    let public = serde_json::to_string(&tunnel).unwrap();
    assert!(!public.contains("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="));
    assert!(matches!(
        service
            .handle(
                "1000",
                Request::Export {
                    id: tunnel.id.clone(),
                    confirmed: false
                }
            )
            .await,
        Response::Error(_)
    ));
    assert!(
        matches!(service.handle("1000",Request::Export{id:tunnel.id.clone(),confirmed:true}).await,Response::Secret(text) if text.expose().contains("PrivateKey"))
    );
    assert!(
        matches!(service.handle("1000",Request::RevealPrivateKey{id:tunnel.id}).await,Response::Secret(text) if text.expose().starts_with("AQEB"))
    );
    let text = SensitiveText::new(format!(
        "{}\nPostUp = touch /tmp/unsafe\n",
        configuration("10.8.0.0/24").expose()
    ));
    assert!(matches!(
        service
            .handle(
                "1000",
                Request::Import {
                    name: "bad".into(),
                    config: text
                }
            )
            .await,
        Response::Error(ApiError {
            code: ErrorCode::Validation,
            ..
        })
    ));
}
#[tokio::test]
async fn invalid_edit_does_not_destroy_saved_configuration() {
    let (_temp, path) = directory();
    let mut service = Service::open(path.clone(), TestNetwork).unwrap();
    let tunnel = saved(&mut service, "1000", "Home", "10.8.0.0/24").await;
    let mut invalid = tunnel.config.clone();
    invalid.interface.addresses.clear();
    assert!(matches!(
        service
            .handle(
                "1000",
                Request::Save {
                    id: tunnel.id.clone(),
                    name: "bad".into(),
                    config: invalid,
                    preshared_keys: vec![]
                }
            )
            .await,
        Response::Error(_)
    ));
    let mut service = Service::open(path, TestNetwork).unwrap();
    assert!(
        matches!(service.handle("1000",Request::Get{id:tunnel.id}).await,Response::Tunnel(Tunnel{name,..}) if name=="Home")
    );
}
#[tokio::test]
async fn drafts_are_bounded_and_not_persisted() {
    let (_temp, path) = directory();
    let mut service = Service::open(path.clone(), TestNetwork).unwrap();
    for _ in 0..16 {
        assert!(matches!(
            service.handle("1000", Request::BeginDraft).await,
            Response::Tunnel(_)
        ));
    }
    assert!(matches!(
        service.handle("1000", Request::BeginDraft).await,
        Response::Error(ApiError {
            code: ErrorCode::Busy,
            ..
        })
    ));
    let mut service = Service::open(path, TestNetwork).unwrap();
    assert!(
        matches!(service.handle("1000",Request::List).await,Response::Snapshot(Snapshot{tunnels,..}) if tunnels.is_empty())
    );
}
#[cfg(unix)]
#[test]
fn storage_refuses_symlinks_and_world_readable_directories() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let (temp, path) = directory();
    std::fs::create_dir(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(Service::open(path.clone(), TestNetwork).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    let link = temp.path().join("link");
    symlink(&path, &link).unwrap();
    assert!(Service::open(link, TestNetwork).is_err());
}

#[cfg(unix)]
#[tokio::test]
async fn unix_socket_authenticates_and_serves_real_frames() {
    let (temp, path) = directory();
    let service = Service::open(path, TestNetwork).unwrap();
    let socket = temp.path().join("control.sock");
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let endpoint = socket.clone();
    let task = tokio::spawn(async move {
        wge_daemon::server::serve_unix(service, &endpoint, async {
            let _ = stopped.await;
        })
        .await
        .unwrap()
    });
    let mut client = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            if let Ok(client) = Client::connect(socket.to_str().unwrap()).await {
                break client;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert!(matches!(
        client.request(Request::BeginDraft).await.unwrap(),
        Response::Tunnel(Tunnel { saved: false, .. })
    ));
    let Response::Snapshot(snapshot) = client.request(Request::List).await.unwrap() else {
        panic!()
    };
    assert_eq!(snapshot.tunnels.len(), 1);
    let mut second = Client::connect(socket.to_str().unwrap()).await.unwrap();
    let Response::Snapshot(snapshot) = second.request(Request::List).await.unwrap() else {
        panic!()
    };
    assert_eq!(snapshot.tunnels.len(), 1);
    stop.send(()).unwrap();
    task.await.unwrap();
    assert!(!socket.exists());
}

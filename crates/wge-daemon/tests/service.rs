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
    ) -> impl std::future::Future<Output = Result<(), ApiError>> + Send {
        ready(Ok(()))
    }
    fn status(_: &()) -> impl std::future::Future<Output = TunnelStatus> + Send {
        ready(TunnelStatus {
            state: ConnectionState::Connecting,
            ..Default::default()
        })
    }
    fn stop(_: ()) -> impl std::future::Future<Output = Result<(), ApiError>> + Send {
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
async fn saved<N: Network>(
    service: &mut Service<N>,
    owner: &str,
    name: &str,
    range: &str,
) -> Tunnel {
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
async fn omitted_endpoint_ports_survive_save_and_service_restart() {
    let (_temp, path) = directory();
    let mut service = Service::open(path.clone(), TestNetwork).unwrap();
    let mut tunnel = saved(&mut service, "1000", "Discovery", "10.8.0.0/24").await;
    tunnel.config.peers[0].endpoint = Some("vpn.example".parse().unwrap());
    let Response::Tunnel(saved) = service
        .handle(
            "1000",
            Request::Save {
                id: tunnel.id.clone(),
                name: tunnel.name,
                config: tunnel.config.clone(),
                preshared_keys: vec![],
            },
        )
        .await
    else {
        panic!("save failed")
    };
    assert_eq!(saved.config, tunnel.config);
    drop(service);
    let mut service = Service::open(path, TestNetwork).unwrap();
    let Response::Tunnel(restored) = service.handle("1000", Request::Get { id: tunnel.id }).await
    else {
        panic!("restore failed")
    };
    assert_eq!(restored.config, tunnel.config);
    assert_eq!(restored.status.state, ConnectionState::Off);
}

#[tokio::test]
async fn connected_discovery_export_uses_the_working_ipv6_endpoint_without_dns() {
    struct Connected;
    impl Network for Connected {
        type Handle = wge_config::PublicKey;
        async fn start(
            &mut self,
            config: &TunnelConfig,
            _: &str,
        ) -> Result<Self::Handle, ApiError> {
            Ok(config.peers[0].public_key)
        }
        async fn status(key: &Self::Handle) -> TunnelStatus {
            TunnelStatus {
                state: ConnectionState::Connected,
                peers: vec![PeerStatus {
                    public_key: *key,
                    endpoint: Some("[2001:db8::5]:443".into()),
                    last_handshake_unix: Some(1),
                    rx_bytes: 0,
                    tx_bytes: 0,
                }],
                error: None,
            }
        }
        async fn stop(_: Self::Handle) -> Result<(), ApiError> {
            Ok(())
        }
        async fn local_networks(&self) -> Vec<IpNetwork> {
            vec![]
        }
    }
    let (_temp, path) = directory();
    let mut service = Service::open(path, Connected).unwrap();
    let mut tunnel = saved(&mut service, "1000", "Discovery", "10.8.0.0/24").await;
    tunnel.config.peers[0].endpoint = Some("vpn.example".parse().unwrap());
    assert!(matches!(
        service
            .handle(
                "1000",
                Request::Save {
                    id: tunnel.id.clone(),
                    name: tunnel.name,
                    config: tunnel.config.clone(),
                    preshared_keys: vec![],
                }
            )
            .await,
        Response::Tunnel(_)
    ));
    assert!(matches!(
        service
            .handle(
                "1000",
                Request::Connect {
                    id: tunnel.id.clone()
                }
            )
            .await,
        Response::Tunnel(_)
    ));
    let Response::Secret(exported) = service
        .handle(
            "1000",
            Request::Export {
                id: tunnel.id,
                confirmed: true,
            },
        )
        .await
    else {
        panic!("export failed")
    };
    assert!(
        exported
            .expose()
            .contains("# wg-easy-srv: vpn.example\nEndpoint = [2001:db8::5]:443")
    );
    assert_eq!(
        wge_config::parse(exported.expose()).unwrap().public(),
        tunnel.config
    );
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
            code: ErrorCode::ScriptHook,
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

struct FallibleNetwork {
    start_error: Option<ErrorCode>,
    stop_fails: bool,
}
impl Network for FallibleNetwork {
    type Handle = bool;
    fn start(
        &mut self,
        _: &TunnelConfig,
        _: &str,
    ) -> impl std::future::Future<Output = Result<bool, ApiError>> + Send {
        ready(match self.start_error.take() {
            Some(code) => Err(ApiError::new(code, "Injected start failure")),
            None => Ok(self.stop_fails),
        })
    }
    fn status(_: &bool) -> impl std::future::Future<Output = TunnelStatus> + Send {
        TestNetwork::status(&())
    }
    fn stop(fails: bool) -> impl std::future::Future<Output = Result<(), ApiError>> + Send {
        ready(if fails {
            Err(ApiError::new(
                ErrorCode::Internal,
                "Injected cleanup failure",
            ))
        } else {
            Ok(())
        })
    }
    fn local_networks(&self) -> impl std::future::Future<Output = Vec<IpNetwork>> + Send {
        ready(vec![])
    }
}

fn assert_error(response: Response, expected: ErrorCode) {
    let Response::Error(error) = response else {
        panic!("Expected error, got {response:?}")
    };
    assert_eq!(error.code, expected);
}

#[tokio::test]
async fn failed_cleanup_stays_visible_and_blocks_mutation_until_recovery() {
    let (_temp, path) = directory();
    let mut service = Service::open(
        path,
        FallibleNetwork {
            start_error: None,
            stop_fails: true,
        },
    )
    .unwrap();
    let tunnel = saved(&mut service, "1000", "Home", "10.8.0.0/24").await;
    let other = saved(&mut service, "1000", "Work", "10.9.0.0/24").await;
    assert!(matches!(
        service
            .handle(
                "1000",
                Request::Connect {
                    id: tunnel.id.clone()
                }
            )
            .await,
        Response::Tunnel(_)
    ));
    for _ in 0..2 {
        assert_error(
            service
                .handle(
                    "1000",
                    Request::Disconnect {
                        id: tunnel.id.clone(),
                    },
                )
                .await,
            ErrorCode::Recovery,
        );
        let Response::Tunnel(status) = service
            .handle(
                "1000",
                Request::Get {
                    id: tunnel.id.clone(),
                },
            )
            .await
        else {
            panic!()
        };
        assert_eq!(status.status.state, ConnectionState::Error);
        assert_eq!(status.status.error.unwrap().code, ErrorCode::Recovery);
    }
    assert_error(
        service
            .handle("1000", Request::Connect { id: other.id })
            .await,
        ErrorCode::Recovery,
    );
    assert_error(
        service
            .handle(
                "1000",
                Request::Delete {
                    id: tunnel.id.clone(),
                },
            )
            .await,
        ErrorCode::Recovery,
    );
    assert_error(
        service
            .handle(
                "1000",
                Request::Save {
                    id: tunnel.id,
                    name: tunnel.name,
                    config: tunnel.config,
                    preshared_keys: vec![],
                },
            )
            .await,
        ErrorCode::Recovery,
    );
    assert_eq!(
        service.shutdown().await.unwrap_err().code,
        ErrorCode::Recovery
    );
}

#[tokio::test]
async fn only_partial_start_failure_requires_global_recovery() {
    for code in [ErrorCode::Recovery, ErrorCode::Internal] {
        let (_temp, path) = directory();
        let mut service = Service::open(
            path,
            FallibleNetwork {
                start_error: Some(code),
                stop_fails: false,
            },
        )
        .unwrap();
        let tunnel = saved(&mut service, "1000", "Home", "10.8.0.0/24").await;
        let other = saved(&mut service, "1000", "Work", "10.9.0.0/24").await;
        assert_error(
            service
                .handle("1000", Request::Connect { id: tunnel.id })
                .await,
            code,
        );
        let result = service
            .handle("1000", Request::Connect { id: other.id })
            .await;
        if code == ErrorCode::Recovery {
            assert_error(result, ErrorCode::Recovery);
        } else {
            assert!(matches!(result, Response::Tunnel(_)));
        }
    }
}

#[tokio::test]
async fn shutdown_reports_cleanup_failure() {
    let (_temp, path) = directory();
    let mut service = Service::open(
        path,
        FallibleNetwork {
            start_error: None,
            stop_fails: true,
        },
    )
    .unwrap();
    let tunnel = saved(&mut service, "1000", "Home", "10.8.0.0/24").await;
    assert!(matches!(
        service
            .handle("1000", Request::Connect { id: tunnel.id })
            .await,
        Response::Tunnel(_)
    ));
    assert_eq!(
        service.shutdown().await.unwrap_err().code,
        ErrorCode::Recovery
    );
}

#[tokio::test]
async fn other_accounts_cannot_mutate_or_export_tunnels() {
    let (_temp, path) = directory();
    let mut service = Service::open(path, TestNetwork).unwrap();
    let tunnel = saved(&mut service, "1000", "Home", "10.8.0.0/24").await;
    for request in [
        Request::Connect {
            id: tunnel.id.clone(),
        },
        Request::Disconnect {
            id: tunnel.id.clone(),
        },
        Request::Delete {
            id: tunnel.id.clone(),
        },
        Request::RevealPrivateKey {
            id: tunnel.id.clone(),
        },
        Request::Export {
            id: tunnel.id.clone(),
            confirmed: true,
        },
        Request::Save {
            id: tunnel.id.clone(),
            name: "Stolen".into(),
            config: tunnel.config,
            preshared_keys: vec![],
        },
    ] {
        assert_error(service.handle("1001", request).await, ErrorCode::NotFound);
    }
    assert!(matches!(
        service.handle("1000", Request::Get { id: tunnel.id }).await,
        Response::Tunnel(_)
    ));
}

#[tokio::test]
async fn conflicts_do_not_expose_another_accounts_tunnel() {
    let (_temp, path) = directory();
    let mut service = Service::open(path, TestNetwork).unwrap();
    let private = saved(&mut service, "1000", "Private company", "10.8.0.0/24").await;
    let other = saved(&mut service, "1001", "Home", "10.8.0.0/24").await;
    service
        .handle("1000", Request::Connect { id: private.id })
        .await;
    let Response::Error(error) = service
        .handle("1001", Request::Connect { id: other.id })
        .await
    else {
        panic!()
    };
    assert_eq!(error.code, ErrorCode::Conflict);
    assert!(error.conflict.is_none());
    assert!(
        !serde_json::to_string(&error)
            .unwrap()
            .contains("Private company")
    );
}

#[tokio::test]
async fn large_collections_use_bounded_pages_without_losing_tunnels() {
    let (_temp, path) = directory();
    let mut service = Service::open(path, TestNetwork).unwrap();
    let ranges = (0..4096)
        .map(|index| format!("2fff:abcd:abcd:abcd:abcd:abcd:abcd:{index:04x}/128"))
        .collect::<Vec<_>>()
        .join(", ");
    let mut expected = std::collections::HashSet::new();
    for index in 0..8 {
        let tunnel = saved(&mut service, "1000", &format!("Tunnel {index}"), &ranges).await;
        expected.insert(tunnel.id);
    }
    let mut request = Request::List;
    let mut seen = std::collections::HashSet::new();
    let mut pages = 0;
    loop {
        let response = service.handle("1000", request).await;
        assert!(frame_length(&response).unwrap() <= MAX_FRAME_BYTES);
        let Response::Snapshot(snapshot) = response else {
            panic!()
        };
        pages += 1;
        for tunnel in snapshot.tunnels {
            assert!(seen.insert(tunnel.id));
        }
        let Some(after) = snapshot.next_page else {
            break;
        };
        request = Request::ListAfter { after };
    }
    assert!(pages > 1);
    assert_eq!(seen, expected);
}

#[cfg(unix)]
#[tokio::test]
async fn server_shutdown_waits_for_network_changes_and_reports_cleanup_errors() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tokio::sync::Notify;

    struct PendingNetwork {
        entered: Arc<Notify>,
        release: Arc<Notify>,
        stopped: Arc<AtomicUsize>,
        fail_stop: bool,
    }
    impl Network for PendingNetwork {
        type Handle = (Arc<AtomicUsize>, bool);
        async fn start(&mut self, _: &TunnelConfig, _: &str) -> Result<Self::Handle, ApiError> {
            self.entered.notify_one();
            self.release.notified().await;
            Ok((self.stopped.clone(), self.fail_stop))
        }
        fn status(_: &Self::Handle) -> impl std::future::Future<Output = TunnelStatus> + Send {
            TestNetwork::status(&())
        }
        async fn stop((stopped, fail): Self::Handle) -> Result<(), ApiError> {
            stopped.fetch_add(1, Ordering::SeqCst);
            if fail {
                Err(ApiError::new(
                    ErrorCode::Recovery,
                    "Injected cleanup failure",
                ))
            } else {
                Ok(())
            }
        }
        async fn local_networks(&self) -> Vec<IpNetwork> {
            vec![]
        }
    }

    for fail_stop in [false, true] {
        let (temp, path) = directory();
        let socket = temp.path().join("control.sock");
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let stopped = Arc::new(AtomicUsize::new(0));
        let mut service = Service::open(
            path,
            PendingNetwork {
                entered: entered.clone(),
                release: release.clone(),
                stopped: stopped.clone(),
                fail_stop,
            },
        )
        .unwrap();
        let owner = rustix::process::geteuid().as_raw().to_string();
        let tunnel = saved(&mut service, &owner, "Pending", "10.8.0.0/24").await;
        let (stop, shutdown) = tokio::sync::oneshot::channel();
        let endpoint = socket.clone();
        let mut server = tokio::spawn(async move {
            wge_daemon::server::serve_unix(service, &endpoint, async {
                let _ = shutdown.await;
            })
            .await
        });
        let mut client = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if let Ok(client) = Client::connect(socket.to_str().unwrap()).await {
                    break client;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let connect =
            tokio::spawn(async move { client.request(Request::Connect { id: tunnel.id }).await });
        tokio::time::timeout(std::time::Duration::from_secs(2), entered.notified())
            .await
            .unwrap();
        stop.send(()).unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), &mut server)
                .await
                .is_err()
        );
        assert_eq!(stopped.load(Ordering::SeqCst), 0);
        release.notify_one();
        let result = tokio::time::timeout(std::time::Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result.is_err(), fail_stop);
        assert_eq!(stopped.load(Ordering::SeqCst), 1);
        assert!(!socket.exists());
        let _ = connect.await.unwrap();
    }
}

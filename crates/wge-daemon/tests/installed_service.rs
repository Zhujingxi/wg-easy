//! Opt-in acceptance tests against the installed service in disposable CI VMs.

use anyhow::{Context, bail, ensure};
use std::{path::PathBuf, time::Duration};
use wge_ipc::{Client, ConnectionState, ErrorCode, Request, Response, Tunnel, TunnelId};

fn state_path() -> anyhow::Result<PathBuf> {
    ensure!(
        std::env::var("WGE_INSTALLED_SERVICE_TEST").as_deref() == Ok("1"),
        "Run installed-service tests only in a disposable CI machine"
    );
    std::env::var_os("WGE_SERVICE_SMOKE_STATE")
        .map(PathBuf::from)
        .context("Set WGE_SERVICE_SMOKE_STATE to a temporary public-ID file")
}

async fn client() -> anyhow::Result<Client> {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Ok(client) = Client::connect_default().await {
                return client;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .context("The installed service did not become available")
}

fn tunnel(response: Response) -> anyhow::Result<Tunnel> {
    match response {
        Response::Tunnel(tunnel) => Ok(tunnel),
        Response::Error(error) => bail!("Service rejected the test request: {:?}", error.code),
        _ => bail!("Unexpected service response"),
    }
}

async fn remove(client: &mut Client, id: &TunnelId) -> anyhow::Result<()> {
    tunnel(
        client
            .request(Request::Disconnect { id: id.clone() })
            .await?,
    )?;
    ensure!(
        matches!(
            client.request(Request::Delete { id: id.clone() }).await?,
            Response::Ok
        ),
        "The service did not remove the test tunnel"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires an installed service in a disposable native CI machine"]
async fn installed_service_connect_and_leave_running() -> anyhow::Result<()> {
    let state_path = state_path()?;
    ensure!(
        !state_path.exists(),
        "A previous service smoke test still needs cleanup"
    );
    let mut client = client().await?;
    let mut draft = tunnel(client.request(Request::BeginDraft).await?)?;
    let id = draft.id.clone();
    let result = async {
        draft.config.interface.addresses = vec!["198.18.254.2/32".parse()?];
        draft.config.interface.dns.clear();
        draft.config.peers = vec![wge_config::PublicPeer {
            public_key: wge_config::PublicKey::from_bytes([2; 32])?,
            has_preshared_key: false,
            endpoint: Some("127.0.0.1:51820".parse()?),
            allowed_ips: vec!["198.18.254.1/32".parse()?],
            persistent_keepalive: Some(1),
        }];
        // Saving twice exercises replacement of the persisted file on every OS.
        for name in ["CI service smoke", "CI service smoke saved"] {
            draft = tunnel(
                client
                    .request(Request::Save {
                        id: id.clone(),
                        name: name.into(),
                        config: draft.config,
                        preshared_keys: vec![],
                    })
                    .await?,
            )?;
        }
        ensure!(
            matches!(client.request(Request::Export { id: id.clone(), confirmed: false }).await?,
            Response::Error(error) if error.code == ErrorCode::Validation),
            "Export did not require confirmation"
        );
        let Response::Secret(exported) = client
            .request(Request::Export {
                id: id.clone(),
                confirmed: true,
            })
            .await?
        else {
            bail!("Confirmed export did not return a standard configuration");
        };
        let exported = wge_config::parse(exported.expose())?;
        ensure!(
            exported.public() == draft.config,
            "Exported configuration changed"
        );
        let running = tunnel(client.request(Request::Connect { id: id.clone() }).await?)?;
        ensure!(
            matches!(
                running.status.state,
                ConnectionState::Connecting | ConnectionState::NoHandshake
            ),
            "An unreachable peer must not report Connected"
        );
        std::fs::write(&state_path, &id.0)?;
        Ok::<_, anyhow::Error>(())
    }
    .await;
    if result.is_err() {
        let _ = remove(&mut client, &id).await;
        let _ = std::fs::remove_file(&state_path);
    }
    result?;
    drop(client);
    let mut client = self::client().await?;
    let running = tunnel(client.request(Request::Get { id }).await?)?;
    ensure!(
        matches!(
            running.status.state,
            ConnectionState::Connecting | ConnectionState::NoHandshake
        ),
        "Closing the GUI connection stopped its active tunnel"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "run after the installed service has been restarted by the native service manager"]
async fn installed_service_restart_is_off() -> anyhow::Result<()> {
    let state_path = state_path()?;
    let id = TunnelId(std::fs::read_to_string(&state_path)?);
    ensure!(
        id.is_valid(),
        "Invalid public tunnel ID in service smoke state"
    );
    let mut client = client().await?;
    let restored = tunnel(client.request(Request::Get { id: id.clone() }).await?)?;
    let was_off = restored.saved && restored.status.state == ConnectionState::Off;
    remove(&mut client, &id).await?;
    std::fs::remove_file(state_path)?;
    ensure!(was_off, "Restart automatically connected a saved tunnel");
    Ok(())
}

//! Privileged background service. Installers register this executable with the OS.
#![forbid(unsafe_code)]

use std::path::PathBuf;
use wge_daemon::{native::NativeNetwork, service::Service, storage::private_directory};

async fn service(
    state: PathBuf,
    shutdown: impl std::future::Future<Output = ()>,
) -> anyhow::Result<()> {
    private_directory(&state)?;
    let recovery = state.join("recovery");
    private_directory(&recovery)?;
    wge_platform::recover(&recovery).await?;
    let service = Service::open(state.join("tunnels"), NativeNetwork { recovery })?;
    #[cfg(unix)]
    {
        let endpoint = std::path::Path::new(wge_ipc::DEFAULT_ENDPOINT);
        let directory = endpoint
            .parent()
            .expect("fixed service endpoint has a parent");
        let mut builder = std::fs::DirBuilder::new();
        use std::os::unix::fs::DirBuilderExt;
        #[cfg(target_os = "linux")]
        builder.mode(0o755);
        #[cfg(target_os = "macos")]
        builder.mode(0o750);
        match builder.create(directory) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
        wge_daemon::server::serve_unix(service, endpoint, shutdown).await?;
    }
    #[cfg(windows)]
    wge_daemon::server::serve_windows(service, shutdown).await?;
    Ok(())
}

#[cfg(unix)]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if rustix::process::geteuid().as_raw() != 0 {
        anyhow::bail!("The background service must be started by the system service manager");
    }
    #[cfg(target_os = "linux")]
    let state = PathBuf::from("/var/lib/wireguardeasy");
    #[cfg(target_os = "macos")]
    let state = PathBuf::from("/Library/Application Support/WireguardEasy");
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let shutdown = async {
        tokio::select! {_=tokio::signal::ctrl_c()=>{},_=terminate.recv()=>{}}
    };
    service(state, shutdown).await
}

#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    wge_platform::windows_service::run_service(windows_main)
        .map_err(|error| anyhow::anyhow!(error.to_string()))
}
#[cfg(windows)]
fn windows_main(stop: tokio::sync::oneshot::Receiver<()>) {
    let result = (|| -> anyhow::Result<()> {
        let state = std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .ok_or_else(|| anyhow::anyhow!("The service data directory is unavailable"))?
            .join("WireguardEasy");
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        runtime.block_on(service(state, async {
            let _ = stop.await;
        }))
    })();
    if result.is_err() {
        eprintln!("The background service could not start or restore its network settings");
        std::process::exit(1);
    }
}

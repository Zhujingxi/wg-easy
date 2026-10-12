use crate::service::{Network, Service};
use std::{future::Future, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{Mutex, Semaphore},
};
use wge_ipc::{ApiError, ErrorCode, Request, Response, read_frame, write_frame};

const MAX_CLIENTS: usize = 32;
async fn client<S, N, F>(mut stream: S, identity: F, service: Arc<Mutex<Service<N>>>)
where
    S: AsyncRead + AsyncWrite + Unpin,
    N: Network,
    F: Fn(&S) -> std::io::Result<String> + Send,
{
    loop {
        let request = match tokio::time::timeout(
            Duration::from_secs(120),
            read_frame::<_, Request>(&mut stream),
        )
        .await
        {
            Ok(Ok(request)) => request,
            Ok(Err(wge_ipc::TransportError::Version)) => {
                let _ = tokio::time::timeout(
                    Duration::from_secs(10),
                    write_frame(
                        &mut stream,
                        &Response::Error(ApiError::new(
                            ErrorCode::Protocol,
                            "Install matching versions of the app and service",
                        )),
                    ),
                )
                .await;
                break;
            }
            _ => break,
        };
        let Ok(owner) = identity(&stream) else {
            break;
        };
        let response = service.lock().await.handle(&owner, request).await;
        if !matches!(
            tokio::time::timeout(Duration::from_secs(10), write_frame(&mut stream, &response))
                .await,
            Ok(Ok(()))
        ) {
            break;
        }
    }
}

#[cfg(unix)]
pub async fn serve_unix<N: Network + 'static>(
    service: Service<N>,
    endpoint: &std::path::Path,
    shutdown: impl Future<Output = ()>,
) -> std::io::Result<()> {
    use std::{
        fs::{self, OpenOptions},
        os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    };
    let directory = endpoint
        .parent()
        .ok_or_else(|| std::io::Error::other("Missing socket directory"))?;
    let metadata = fs::symlink_metadata(directory)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o022 != 0
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "Unsafe socket directory",
        ));
    }
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(directory.join("daemon.lock"))?;
    rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive)?;
    match fs::symlink_metadata(endpoint) {
        Ok(metadata)
            if metadata.file_type().is_socket()
                && metadata.uid() == rustix::process::geteuid().as_raw() =>
        {
            fs::remove_file(endpoint)?
        }
        Ok(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "Unsafe socket path",
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let listener = tokio::net::UnixListener::bind(endpoint)?;
    #[cfg(target_os = "linux")]
    let socket_mode = 0o666;
    #[cfg(target_os = "macos")]
    let socket_mode = 0o660;
    fs::set_permissions(endpoint, fs::Permissions::from_mode(socket_mode))?;
    let service = Arc::new(Mutex::new(service));
    let permits = Arc::new(Semaphore::new(MAX_CLIENTS));
    let mut clients = tokio::task::JoinSet::new();
    tokio::pin!(shutdown);
    let result = loop {
        tokio::select! {
            _=&mut shutdown=>break Ok(()),
            result=listener.accept()=>{
                let (stream,_) = match result {
                    Ok(accepted) => accepted,
                    Err(error) => break Err(error),
                };
                let Ok(permit)=permits.clone().try_acquire_owned() else {continue};
                let Ok(credentials) = stream.peer_cred() else { continue };
                let identity=credentials.uid().to_string();
                let service=service.clone();
                clients.spawn(async move {let _permit=permit;client(stream,move |_|Ok(identity.clone()),service).await;});
            }
            Some(_)=clients.join_next(),if !clients.is_empty()=>{}
        }
    };
    drop(listener);
    // Let a network transaction complete before stopping handles; never cancel it halfway.
    let mut service = service.lock().await;
    clients.abort_all();
    while clients.join_next().await.is_some() {}
    let cleanup = service
        .shutdown()
        .await
        .map_err(|error| std::io::Error::other(error.message));
    let removed = fs::remove_file(endpoint);
    drop(lock);
    cleanup?;
    result?;
    removed
}

#[cfg(windows)]
pub async fn serve_windows<N: Network + 'static>(
    service: Service<N>,
    shutdown: impl Future<Output = ()>,
) -> std::io::Result<()> {
    let service = Arc::new(Mutex::new(service));
    let permits = Arc::new(Semaphore::new(MAX_CLIENTS));
    let mut clients = tokio::task::JoinSet::new();
    // The first-instance flag refuses a pipe name occupied by another process.
    let mut server = wge_platform::windows::create_pipe(true)?;
    tokio::pin!(shutdown);
    let result = loop {
        tokio::select! {
            _=&mut shutdown=>break Ok(()),
            connected=server.connect()=>{
                if let Err(error) = connected { break Err(error); }
                let next = match wge_platform::windows::create_pipe(false) {
                    Ok(next) => next,
                    Err(error) => break Err(error),
                };
                let stream=std::mem::replace(&mut server,next);
                let Ok(permit)=permits.clone().try_acquire_owned() else {continue};
                let service=service.clone();
                clients.spawn(async move {let _permit=permit;client(stream,wge_platform::windows::pipe_owner,service).await;});
            }
            Some(_)=clients.join_next(),if !clients.is_empty()=>{}
        }
    };
    drop(server);
    let mut service = service.lock().await;
    clients.abort_all();
    while clients.join_next().await.is_some() {}
    service
        .shutdown()
        .await
        .map_err(|error| std::io::Error::other(error.message))?;
    result
}

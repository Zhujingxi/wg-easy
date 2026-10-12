use crate::service::{Network, Service};
use std::{future::Future, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{Mutex, Semaphore},
};
use wge_ipc::{ApiError, ErrorCode, Request, Response, read_frame, write_frame};

const MAX_CLIENTS: usize = 32;
async fn client<S, N>(mut stream: S, owner: String, service: Arc<Mutex<Service<N>>>)
where
    S: AsyncRead + AsyncWrite + Unpin,
    N: Network,
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
                let _ = write_frame(
                    &mut stream,
                    &Response::Error(ApiError::new(
                        ErrorCode::Protocol,
                        "Install matching versions of the app and service",
                    )),
                )
                .await;
                break;
            }
            _ => break,
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
    fs::set_permissions(endpoint, fs::Permissions::from_mode(0o660))?;
    let service = Arc::new(Mutex::new(service));
    let permits = Arc::new(Semaphore::new(MAX_CLIENTS));
    let mut clients = tokio::task::JoinSet::new();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _=&mut shutdown=>break,
            result=listener.accept()=>{
                let (stream,_)=result?;
                let Ok(permit)=permits.clone().try_acquire_owned() else {continue};
                let identity=stream.peer_cred()?.uid().to_string();
                let service=service.clone();
                clients.spawn(async move {let _permit=permit;client(stream,identity,service).await;});
            }
            Some(_)=clients.join_next(),if !clients.is_empty()=>{}
        }
    }
    drop(listener);
    // Let a network transaction complete before stopping handles; never cancel it halfway.
    let mut service = service.lock().await;
    clients.abort_all();
    while clients.join_next().await.is_some() {}
    service.shutdown().await;
    fs::remove_file(endpoint)?;
    drop(lock);
    Ok(())
}

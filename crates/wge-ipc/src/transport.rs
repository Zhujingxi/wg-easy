use crate::{Envelope, MAX_FRAME_BYTES, PROTOCOL_VERSION, Request, Response};
use serde::{Serialize, de::DeserializeOwned};
use std::{io, time::Duration};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("The background service is unavailable: {0}")]
    Io(#[from] io::Error),
    #[error("The local message exceeds the size limit")]
    TooLarge,
    #[error("The local message is invalid")]
    Invalid,
    #[error("The app and service use different protocol versions")]
    Version,
    #[error("The background service did not respond in time")]
    Timeout,
}

pub async fn read_frame<R: AsyncRead + Unpin, T: DeserializeOwned>(
    reader: &mut R,
) -> Result<T, TransportError> {
    let length = reader.read_u32().await? as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(TransportError::TooLarge);
    }
    let mut bytes = Zeroizing::new(vec![0; length]);
    reader.read_exact(&mut bytes).await?;
    let envelope: Envelope<T> =
        serde_json::from_slice(&bytes).map_err(|_| TransportError::Invalid)?;
    if envelope.version != PROTOCOL_VERSION {
        return Err(TransportError::Version);
    }
    Ok(envelope.body)
}

pub async fn write_frame<W: AsyncWrite + Unpin, T: Serialize>(
    writer: &mut W,
    value: &T,
) -> Result<(), TransportError> {
    let envelope = Envelope::new(value);
    let length = frame_length(value)?;
    // A fixed slice cannot reallocate and leave an unwiped previous secret buffer.
    let mut bytes = Zeroizing::new(vec![0; length]);
    let mut remaining = bytes.as_mut_slice();
    serde_json::to_writer(&mut remaining, &envelope).map_err(|_| TransportError::Invalid)?;
    if !remaining.is_empty() {
        return Err(TransportError::Invalid);
    }
    writer.write_u32(bytes.len() as u32).await?;
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    Ok(())
}

/// The encoded size, checked against the frame limit without allocating a payload.
pub fn frame_length<T: Serialize>(value: &T) -> Result<usize, TransportError> {
    let mut size = FrameSize::default();
    serde_json::to_writer(&mut size, &Envelope::new(value)).map_err(|_| {
        if size.too_large {
            TransportError::TooLarge
        } else {
            TransportError::Invalid
        }
    })?;
    Ok(size.length)
}

#[derive(Default)]
struct FrameSize {
    length: usize,
    too_large: bool,
}

impl io::Write for FrameSize {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        match self.length.checked_add(bytes.len()) {
            Some(length) if length <= MAX_FRAME_BYTES => {
                self.length = length;
                Ok(bytes.len())
            }
            _ => {
                self.too_large = true;
                Err(io::Error::other("Local message exceeds the size limit"))
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(unix)]
type LocalStream = tokio::net::UnixStream;
#[cfg(windows)]
type LocalStream = interprocess::os::windows::named_pipe::tokio::DuplexPipeStream<
    interprocess::os::windows::named_pipe::pipe_mode::Bytes,
>;

pub struct Client {
    stream: LocalStream,
}
impl Client {
    pub async fn connect_default() -> Result<Self, TransportError> {
        Self::connect(crate::DEFAULT_ENDPOINT).await
    }
    pub async fn connect(endpoint: &str) -> Result<Self, TransportError> {
        #[cfg(unix)]
        let stream = {
            let stream = LocalStream::connect(endpoint).await?;
            // A privileged endpoint must belong to the installed service.
            if endpoint == crate::DEFAULT_ENDPOINT && stream.peer_cred()?.uid() != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "The service identity is invalid",
                )
                .into());
            }
            stream
        };
        #[cfg(windows)]
        let stream = {
            use windows_service::{
                service::{ServiceAccess, ServiceState},
                service_manager::{ServiceManager, ServiceManagerAccess},
            };
            let stream = tokio::time::timeout(
                Duration::from_secs(5),
                LocalStream::connect_by_path(endpoint),
            )
            .await
            .map_err(|_| TransportError::Timeout)??;
            if endpoint == crate::DEFAULT_ENDPOINT {
                let manager =
                    ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
                        .map_err(|_| TransportError::Invalid)?;
                let service = manager
                    .open_service("wireguardeasy", ServiceAccess::QUERY_STATUS)
                    .map_err(|_| TransportError::Invalid)?;
                let status = service
                    .query_status()
                    .map_err(|_| TransportError::Invalid)?;
                if status.current_state != ServiceState::Running
                    || status.process_id != Some(stream.server_process_id()?)
                {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "The service identity is invalid",
                    )
                    .into());
                }
            }
            stream
        };
        Ok(Self { stream })
    }
    pub async fn request(&mut self, request: Request) -> Result<Response, TransportError> {
        tokio::time::timeout(Duration::from_secs(45), async {
            let list = matches!(request, Request::List);
            write_frame(&mut self.stream, &request).await?;
            let response = read_frame(&mut self.stream).await?;
            if !list {
                return Ok(response);
            }
            let Response::Snapshot(mut snapshot) = response else {
                return Ok(response);
            };
            while let Some(after) = snapshot.next_page.take() {
                write_frame(
                    &mut self.stream,
                    &Request::ListAfter {
                        after: after.clone(),
                    },
                )
                .await?;
                match read_frame(&mut self.stream).await? {
                    Response::Snapshot(page) => {
                        if page
                            .next_page
                            .as_ref()
                            .is_some_and(|next| next.0 <= after.0)
                        {
                            return Err(TransportError::Invalid);
                        }
                        snapshot.tunnels.extend(page.tunnels);
                        snapshot.next_page = page.next_page;
                    }
                    Response::Error(error) => return Ok(Response::Error(error)),
                    _ => return Err(TransportError::Invalid),
                }
            }
            snapshot
                .tunnels
                .sort_by(|a, b| a.name.cmp(&b.name).then(a.id.0.cmp(&b.id.0)));
            Ok(Response::Snapshot(snapshot))
        })
        .await
        .map_err(|_| TransportError::Timeout)?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn frame_roundtrip_and_version() {
        let (mut a, mut b) = tokio::io::duplex(2048);
        write_frame(&mut a, &Request::List).await.unwrap();
        assert!(matches!(read_frame(&mut b).await.unwrap(), Request::List));
        let bytes = br#"{"version":99,"body":{"command":"list"}}"#;
        a.write_u32(bytes.len() as u32).await.unwrap();
        a.write_all(bytes).await.unwrap();
        assert!(matches!(
            read_frame::<_, Request>(&mut b).await,
            Err(TransportError::Version)
        ));
    }
    #[tokio::test]
    async fn rejects_size_before_allocating_payload() {
        let (mut a, mut b) = tokio::io::duplex(16);
        a.write_u32((MAX_FRAME_BYTES + 1) as u32).await.unwrap();
        assert!(matches!(
            read_frame::<_, Request>(&mut b).await,
            Err(TransportError::TooLarge)
        ));
    }
    #[tokio::test]
    async fn truncated_payload_is_not_accepted() {
        let (mut a, mut b) = tokio::io::duplex(16);
        a.write_u32(8).await.unwrap();
        a.write_all(b"{}").await.unwrap();
        drop(a);
        assert!(matches!(
            read_frame::<_, Request>(&mut b).await,
            Err(TransportError::Io(_))
        ));
    }
    #[tokio::test]
    async fn secret_frames_roundtrip_newlines_and_unicode() {
        let (mut sender, mut receiver) = tokio::io::duplex(2048);
        let text = "PrivateKey = sensitive\n# 日本語\n";
        write_frame(
            &mut sender,
            &Response::Secret(crate::SensitiveText::new(text.into())),
        )
        .await
        .unwrap();
        let Response::Secret(secret) = read_frame(&mut receiver).await.unwrap() else {
            panic!()
        };
        assert_eq!(secret.expose(), text);
    }

    #[tokio::test]
    async fn oversized_outbound_frame_writes_nothing() {
        let mut bytes = Vec::new();
        let value = "x".repeat(MAX_FRAME_BYTES);
        assert!(matches!(
            write_frame(&mut bytes, &value).await,
            Err(TransportError::TooLarge)
        ));
        assert!(bytes.is_empty());
    }

    #[test]
    fn malformed_secret_is_rejected_without_echoing_payload() {
        for text in [r#""not a secret encoding!""#, r#""/w==""#] {
            let error = serde_json::from_str::<crate::SensitiveText>(text).unwrap_err();
            assert!(!error.to_string().contains(text));
        }
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn client_assembles_list_pages_and_rejects_repeated_cursors() {
        for repeat in [false, true] {
            let (stream, mut server) = tokio::net::UnixStream::pair().unwrap();
            let mut client = Client { stream };
            let cursor = crate::TunnelId("1".repeat(32));
            let task = tokio::spawn(async move {
                assert!(matches!(
                    read_frame(&mut server).await.unwrap(),
                    Request::List
                ));
                write_frame(
                    &mut server,
                    &Response::Snapshot(crate::Snapshot {
                        next_page: Some(cursor.clone()),
                        local_networks: vec!["192.168.1.0/24".parse().unwrap()],
                        ..Default::default()
                    }),
                )
                .await
                .unwrap();
                assert!(
                    matches!(read_frame(&mut server).await.unwrap(), Request::ListAfter { after } if after == cursor)
                );
                write_frame(
                    &mut server,
                    &Response::Snapshot(crate::Snapshot {
                        next_page: repeat.then_some(cursor),
                        ..Default::default()
                    }),
                )
                .await
                .unwrap();
            });
            let result = client.request(Request::List).await;
            if repeat {
                assert!(matches!(result, Err(TransportError::Invalid)));
            } else {
                let Response::Snapshot(snapshot) = result.unwrap() else {
                    panic!()
                };
                assert!(snapshot.next_page.is_none());
                assert_eq!(snapshot.local_networks.len(), 1);
            }
            task.await.unwrap();
        }
    }
}

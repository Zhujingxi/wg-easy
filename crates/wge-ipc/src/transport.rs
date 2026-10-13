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
    let bytes = Zeroizing::new(
        serde_json::to_vec(&Envelope::new(value)).map_err(|_| TransportError::Invalid)?,
    );
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(TransportError::TooLarge);
    }
    writer.write_u32(bytes.len() as u32).await?;
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(unix)]
type LocalStream = tokio::net::UnixStream;
#[cfg(windows)]
type LocalStream = tokio::net::windows::named_pipe::NamedPipeClient;

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
        let stream = tokio::net::windows::named_pipe::ClientOptions::new().open(endpoint)?;
        Ok(Self { stream })
    }
    pub async fn request(&mut self, request: Request) -> Result<Response, TransportError> {
        tokio::time::timeout(Duration::from_secs(45), async {
            write_frame(&mut self.stream, &request).await?;
            read_frame(&mut self.stream).await
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
}

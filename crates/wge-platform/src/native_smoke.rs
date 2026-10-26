//! Opt-in tests for an isolated, elevated Windows/macOS CI VM.

use std::{io, path::Path, sync::mpsc, thread, time::Duration};
use tokio::{net::UdpSocket, time::timeout};
use tun::AbstractDevice;
use wge_config::{InterfaceConfig, PeerConfig, SecretKey, TunnelConfig};

use crate::{Error, Network, RouteManager, dns, read_journal, recover};

struct RecoveryWatchdog {
    done: Option<mpsc::Sender<()>>,
    thread: Option<thread::JoinHandle<Result<(), String>>>,
}

impl RecoveryWatchdog {
    fn start(directory: &Path) -> Self {
        let directory = directory.to_owned();
        let (done, waiting) = mpsc::channel();
        let thread = thread::spawn(move || {
            let _ = waiting.recv_timeout(Duration::from_secs(30));
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| e.to_string())?;
            let mut last_error = String::new();
            for _ in 0..3 {
                match runtime
                    .block_on(async { timeout(Duration::from_secs(15), recover(&directory)).await })
                {
                    Ok(Ok(())) => return Ok(()),
                    Ok(Err(error)) => last_error = error.to_string(),
                    Err(error) => last_error = error.to_string(),
                }
            }
            Err(last_error)
        });
        Self {
            done: Some(done),
            thread: Some(thread),
        }
    }

    fn finish(&mut self) -> Result<(), String> {
        if let Some(done) = self.done.take() {
            let _ = done.send(());
        }
        match self.thread.take() {
            Some(thread) => thread
                .join()
                .map_err(|_| "Recovery watchdog panicked".to_owned())?,
            None => Ok(()),
        }
    }
}

impl Drop for RecoveryWatchdog {
    fn drop(&mut self) {
        // Runs before the temporary directory disappears, including on panic.
        if let Err(error) = self.finish() {
            eprintln!("Native smoke recovery failed: {error}");
        }
    }
}

#[test]
fn recovery_watchdog_runs_without_an_outer_runtime() {
    let directory = tempfile::tempdir().unwrap();
    let mut watchdog = RecoveryWatchdog::start(&directory.path().join("recovery"));
    watchdog.finish().unwrap();
    watchdog.finish().unwrap();
}

fn require(condition: bool, message: &str) -> Result<(), Error> {
    if condition {
        Ok(())
    } else {
        Err(Error::Invalid(format!("Native smoke: {message}")))
    }
}

async fn traffic(device: &tun::AsyncDevice) -> Result<(), Error> {
    for (source, destination, version) in [
        ("198.18.245.1:0", "198.18.246.53:5353", 4),
        ("[fd42:7767:65::1]:0", "[fd42:7767:66::53]:5353", 6),
    ] {
        let socket = timeout(Duration::from_secs(4), async {
            loop {
                match UdpSocket::bind(source).await {
                    Ok(socket) => return Ok::<_, io::Error>(socket),
                    Err(error) if error.kind() == io::ErrorKind::AddrNotAvailable => {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                    Err(error) => return Err(error),
                }
            }
        })
        .await
        .map_err(io::Error::other)??;
        let payload = b"wg-easy native full-tunnel smoke";
        socket.send_to(payload, destination).await?;
        let mut packet = vec![0; 65_535];
        let count = timeout(Duration::from_secs(4), async {
            loop {
                let count = device.recv(&mut packet).await?;
                if count > 40 && packet[0] >> 4 == version && packet[..count].ends_with(payload) {
                    return Ok::<_, io::Error>(count);
                }
            }
        })
        .await
        .map_err(io::Error::other)??;
        packet.truncate(count);
        // Equal-length address/port swaps preserve IP and UDP checksums.
        let (addresses, ports) = if version == 4 {
            (12..20, 20..24)
        } else {
            (8..40, 40..44)
        };
        let half = addresses.len() / 2;
        let (left, right) = packet[addresses].split_at_mut(half);
        left.swap_with_slice(right);
        let (left, right) = packet[ports].split_at_mut(2);
        left.swap_with_slice(right);
        device.send(&packet).await?;
        let mut response = [0; 128];
        let count = timeout(Duration::from_secs(4), socket.recv(&mut response))
            .await
            .map_err(io::Error::other)??;
        require(
            &response[..count] == payload,
            "IPv4/IPv6 did not return through tun",
        )?;
    }
    Ok(())
}

async fn round(directory: &Path, crash: bool) -> Result<(), Error> {
    let endpoint = UdpSocket::bind("127.0.0.1:0").await?;
    let transport = UdpSocket::bind("127.0.0.1:0").await?;
    let config = TunnelConfig {
        interface: InterfaceConfig {
            private_key: SecretKey::from_bytes([7; 32]).unwrap(),
            addresses: vec![
                "198.18.245.1/32".parse().unwrap(),
                "fd42:7767:65::1/128".parse().unwrap(),
            ],
            dns: vec![
                "198.18.246.53".parse().unwrap(),
                "fd42:7767:66::53".parse().unwrap(),
            ],
            search_domains: vec![],
            listen_port: Some(transport.local_addr()?.port()),
            mtu: Some(1420),
        },
        peers: vec![PeerConfig {
            public_key: SecretKey::from_bytes([8; 32]).unwrap().public_key(),
            preshared_key: None,
            endpoint: Some(endpoint.local_addr()?.to_string().parse().unwrap()),
            allowed_ips: vec!["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()],
            persistent_keepalive: None,
        }],
    };
    let (network, device) = Network::create(
        &config,
        "wge-smoke",
        &[endpoint.local_addr()?],
        directory,
        transport.local_addr()?.port(),
    )
    .await?;
    let journal = read_journal(&network.path)?;
    let index = device.tun_index()? as u32;
    let check = async {
        let addresses = netconfig::Interface::try_from_index(index)?.addresses()?;
        require(
            config.interface.addresses.iter().all(|expected| {
                addresses
                    .iter()
                    .any(|actual| actual.addr() == expected.ip())
            }),
            "native tunnel addresses are missing",
        )?;
        require(
            dns::smoke_matches(&journal.dns, true)?,
            "native DNS policy was not installed",
        )?;
        #[cfg(target_os = "macos")]
        require(
            crate::macos_filter::smoke_matches(journal.filter.as_ref().unwrap(), true)?,
            "PF anchor/reference was not installed",
        )?;
        #[cfg(windows)]
        require(network.filter.is_some(), "WFP session was not installed")?;
        transport
            .send_to(b"endpoint", endpoint.local_addr()?)
            .await?;
        let mut reply = [0; 32];
        let count = timeout(Duration::from_secs(2), endpoint.recv(&mut reply))
            .await
            .map_err(io::Error::other)??;
        require(
            &reply[..count] == b"endpoint",
            "encrypted endpoint bypass was blocked",
        )?;
        traffic(&device).await
    }
    .await;
    let cleanup = if crash {
        // Simulate loss of process-owned interface/WFP handles, retaining the durable journal.
        drop(network);
        drop(device);
        recover(directory).await
    } else {
        let result = network.stop().await;
        drop(device);
        result
    };
    cleanup?;
    check?;
    require(
        dns::smoke_matches(&journal.dns, false)?,
        "DNS was not restored",
    )?;
    #[cfg(target_os = "macos")]
    require(
        crate::macos_filter::smoke_matches(journal.filter.as_ref().unwrap(), false)?,
        "PF anchor/reference was not removed",
    )?;
    require(
        std::fs::read_dir(directory)?.next().is_none(),
        "recovery journal remains",
    )?;
    let routes = RouteManager::new()?.list()?;
    require(
        !journal
            .routes
            .iter()
            .any(|saved| routes.iter().any(|route| saved.matches(route))),
        "owned routes remain after cleanup",
    )
}

#[tokio::test]
#[ignore = "temporarily replaces system routes/DNS; requires an isolated elevated Windows/macOS VM and WGE_NATIVE_NETWORK_TEST=1"]
async fn native_full_tunnel_smoke() {
    assert_eq!(
        std::env::var("WGE_NATIVE_NETWORK_TEST").as_deref(),
        Ok("1"),
        "Run only in an isolated disposable VM"
    );
    let directory = tempfile::tempdir().unwrap();
    let recovery = directory.path().join("recovery");
    let mut watchdog = RecoveryWatchdog::start(&recovery);
    let outcome = timeout(Duration::from_secs(25), async {
        round(&recovery, false).await?;
        round(&recovery, true).await
    })
    .await;
    let recovered = watchdog.finish();
    recovered.expect("Recovery watchdog must restore host networking");
    outcome
        .expect("Native smoke timed out")
        .expect("Native networking smoke failed");
}

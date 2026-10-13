use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};
use wge_config::PeerConfig;

const ATTEMPT: Duration = Duration::from_secs(10);
const RECENT_HANDSHAKE: Duration = Duration::from_secs(180);

#[derive(Debug, PartialEq)]
pub(crate) enum Action {
    None,
    Keepalive(Option<u16>),
    Switch(SocketAddr),
    Refresh,
}

pub(crate) struct PeerEndpoint {
    pub key: [u8; 32],
    addresses: Vec<SocketAddr>,
    discovery: bool,
    keepalive: Option<u16>,
    candidate: usize,
    attempts: usize,
    probing: bool,
    exhausted: bool,
    since: Instant,
}

impl PeerEndpoint {
    pub fn new(peer: &PeerConfig, addresses: Vec<SocketAddr>, now: Instant) -> Self {
        Self {
            key: *peer.public_key.as_bytes(),
            discovery: peer
                .endpoint
                .as_ref()
                .is_some_and(|endpoint| endpoint.port.is_none()),
            keepalive: peer.persistent_keepalive.filter(|interval| *interval > 0),
            probing: !addresses.is_empty(),
            addresses,
            candidate: 0,
            attempts: 1,
            exhausted: false,
            since: now,
        }
    }

    pub fn advance(&mut self, handshake: Option<Duration>, now: Instant) -> Action {
        if self.addresses.is_empty() {
            return Action::None;
        }
        if handshake.is_some_and(|age| age <= RECENT_HANDSHAKE) {
            self.exhausted = false;
            self.attempts = 0;
            if self.probing {
                self.probing = false;
                return Action::Keepalive(self.keepalive);
            }
            return Action::None;
        }
        if self.exhausted {
            return Action::None;
        }
        if !self.probing {
            self.probing = true;
            self.since = now;
            self.attempts = 1;
            return Action::Keepalive(Some(1));
        }
        if now.duration_since(self.since) < ATTEMPT {
            return Action::None;
        }
        if self.attempts < self.addresses.len() {
            self.candidate = (self.candidate + 1) % self.addresses.len();
            self.attempts += 1;
            self.since = now;
            return Action::Switch(self.addresses[self.candidate]);
        }
        if self.discovery {
            return Action::Refresh;
        }
        self.probing = false;
        self.exhausted = true;
        Action::Keepalive(self.keepalive)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(discovery: bool, now: Instant) -> PeerEndpoint {
        let peer = PeerConfig {
            public_key: wge_config::PublicKey::from_bytes([2; 32]).unwrap(),
            preshared_key: None,
            endpoint: Some(
                if discovery {
                    "vpn.example"
                } else {
                    "vpn.example:51820"
                }
                .parse()
                .unwrap(),
            ),
            allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
            persistent_keepalive: Some(25),
        };
        PeerEndpoint::new(
            &peer,
            vec![
                "[2001:db8::1]:42".parse().unwrap(),
                "192.0.2.1:42".parse().unwrap(),
            ],
            now,
        )
    }

    #[test]
    fn tries_the_other_family_then_refreshes_discovery() {
        let now = Instant::now();
        let mut endpoint = endpoint(true, now);
        assert_eq!(
            endpoint.advance(None, now + Duration::from_secs(9)),
            Action::None
        );
        assert_eq!(
            endpoint.advance(None, now + ATTEMPT),
            Action::Switch("192.0.2.1:42".parse().unwrap())
        );
        assert_eq!(endpoint.advance(None, now + ATTEMPT * 2), Action::Refresh);
    }

    #[test]
    fn healthy_connections_restore_keepalive_and_stay_stable() {
        let now = Instant::now();
        let mut endpoint = endpoint(true, now);
        assert_eq!(
            endpoint.advance(Some(Duration::ZERO), now),
            Action::Keepalive(Some(25))
        );
        assert_eq!(
            endpoint.advance(
                Some(Duration::from_secs(180)),
                now + Duration::from_secs(500)
            ),
            Action::None
        );
        let later = now + Duration::from_secs(501);
        assert_eq!(
            endpoint.advance(Some(Duration::from_secs(181)), later),
            Action::Keepalive(Some(1))
        );
        assert_eq!(
            endpoint.advance(Some(Duration::from_secs(190)), later + ATTEMPT),
            Action::Switch("192.0.2.1:42".parse().unwrap())
        );
        assert_eq!(
            endpoint.advance(Some(Duration::ZERO), later + ATTEMPT),
            Action::Keepalive(Some(25))
        );
    }

    #[test]
    fn explicit_ports_finish_without_dns_refresh_or_permanent_probes() {
        let now = Instant::now();
        let mut endpoint = endpoint(false, now);
        endpoint.advance(None, now + ATTEMPT);
        assert_eq!(
            endpoint.advance(None, now + ATTEMPT * 2),
            Action::Keepalive(Some(25))
        );
        assert_eq!(endpoint.advance(None, now + ATTEMPT * 3), Action::None);
    }
}

#![forbid(unsafe_code)]

use gotatun::{
    packet::{Packet, PacketBufPool},
    udp::{
        UdpRecv, UdpSend,
        socket::{SockOpt, UdpSocket},
    },
};
use std::{net::SocketAddr, time::Duration};
use tokio::time::timeout;

#[tokio::test]
async fn udp_receiver_survives_an_unreachable_peer() {
    for bind in ["127.0.0.1:0", "[::1]:0", "[::]:0"] {
        let bind: SocketAddr = bind.parse().unwrap();
        let mut socket = UdpSocket::bind(
            bind,
            SockOpt {
                only_v6: bind.is_ipv6().then_some(!bind.ip().is_unspecified()),
                ..Default::default()
            },
        )
        .unwrap();
        let local = if bind.ip().is_unspecified() {
            SocketAddr::from(([127, 0, 0, 1], socket.local_addr().unwrap().port()))
        } else {
            socket.local_addr().unwrap()
        };
        let peer = tokio::net::UdpSocket::bind((local.ip(), 0)).await.unwrap();
        let offline = peer.local_addr().unwrap();
        drop(peer);
        let mut pool = PacketBufPool::new(1);

        socket
            .send_to(Packet::from_bytes(b"probe".as_slice().into()), offline)
            .await
            .unwrap();
        // Wait for the loopback ICMP error; receiving must stay pending, not fail.
        assert!(
            timeout(Duration::from_millis(250), socket.recv_from(&mut pool))
                .await
                .is_err()
        );

        let peer = tokio::net::UdpSocket::bind((local.ip(), 0)).await.unwrap();
        peer.send_to(b"still receiving", local).await.unwrap();
        let mut packets = Vec::new();
        timeout(
            Duration::from_secs(5),
            socket.recv_many_from(&mut Default::default(), &mut pool, &mut packets),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(packets.len(), 1);
        assert_eq!(&*packets[0].0, b"still receiving");
        assert_eq!(packets[0].1, peer.local_addr().unwrap());
    }
}

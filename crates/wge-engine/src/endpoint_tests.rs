use super::*;
use hickory_resolver::proto::op::ResponseCode;
#[path = "../tests/support/dns.rs"]
mod dns;
use dns::{DnsFixture, srv};

#[tokio::test]
async fn discovers_both_families_and_respects_priorities() {
    let fixture = DnsFixture::bind("127.0.0.1:0").await;
    fixture.zone.lock().unwrap().srv =
        vec![srv(10, 1, 80, "vpn.test."), srv(0, 1, 443, "server.test.")];
    let endpoint = "vpn.test".parse().unwrap();
    let result = resolve_endpoint(&endpoint, Some(&fixture.resolver))
        .await
        .unwrap();
    assert_eq!(
        result,
        [
            "[2001:db8::1]:443",
            "192.0.2.1:443",
            "[2001:db8::2]:80",
            "192.0.2.2:80"
        ]
        .map(|address| address.parse::<SocketAddr>().unwrap())
    );
    assert_eq!(fixture.zone.lock().unwrap().srv_queries, 1);
}

#[tokio::test]
async fn absent_records_fall_back_but_dns_errors_do_not() {
    let fixture = DnsFixture::bind("127.0.0.1:0").await;
    let endpoint = "vpn.test".parse().unwrap();
    for code in [ResponseCode::NXDomain, ResponseCode::NoError] {
        {
            let mut zone = fixture.zone.lock().unwrap();
            zone.srv_code = code;
            zone.srv.clear();
        }
        let result = resolve_endpoint(&endpoint, Some(&fixture.resolver))
            .await
            .unwrap();
        assert_eq!(
            result,
            [
                "[2001:db8::2]:51820".parse().unwrap(),
                "192.0.2.2:51820".parse().unwrap()
            ]
        );
    }
    for code in [ResponseCode::ServFail, ResponseCode::Refused] {
        fixture.zone.lock().unwrap().srv_code = code;
        assert!(
            resolve_endpoint(&endpoint, Some(&fixture.resolver))
                .await
                .is_err()
        );
    }
    fixture.zone.lock().unwrap().silent = true;
    assert!(
        resolve_endpoint(&endpoint, Some(&fixture.resolver))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn ipv6_only_changed_records_and_unavailable_services() {
    let fixture = DnsFixture::bind("[::1]:0").await;
    let endpoint = "vpn.test.".parse().unwrap();
    {
        let mut zone = fixture.zone.lock().unwrap();
        zone.addresses
            .insert("server.test.".into(), vec!["2001:db8::3".parse().unwrap()]);
        zone.srv = vec![srv(0, 0, 53, "server.test.")];
    }
    assert_eq!(
        resolve_endpoint(&endpoint, Some(&fixture.resolver))
            .await
            .unwrap(),
        ["[2001:db8::3]:53".parse().unwrap()]
    );
    {
        let mut zone = fixture.zone.lock().unwrap();
        zone.addresses
            .insert("server.test.".into(), vec!["2001:db8::4".parse().unwrap()]);
        zone.srv = vec![srv(0, 0, 443, "server.test.")];
    }
    assert_eq!(
        resolve_endpoint(&endpoint, Some(&fixture.resolver))
            .await
            .unwrap(),
        ["[2001:db8::4]:443".parse().unwrap()]
    );
    for record in [srv(0, 0, 443, "."), srv(0, 0, 0, "server.test.")] {
        fixture.zone.lock().unwrap().srv = vec![record];
        assert!(
            resolve_endpoint(&endpoint, Some(&fixture.resolver))
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn explicit_ports_and_literals_never_query_srv() {
    let fixture = DnsFixture::bind("127.0.0.1:0").await;
    for endpoint in [
        "127.0.0.1:443",
        "[::1]:443",
        "127.0.0.1",
        "::1",
        "localhost:443",
    ] {
        assert!(
            !resolve_endpoint(&endpoint.parse().unwrap(), Some(&fixture.resolver))
                .await
                .unwrap()
                .is_empty()
        );
    }
    assert_eq!(fixture.zone.lock().unwrap().srv_queries, 0);
}

#[tokio::test]
async fn a_slow_target_does_not_hide_a_working_backup() {
    let fixture = DnsFixture::bind("127.0.0.1:0").await;
    {
        let mut zone = fixture.zone.lock().unwrap();
        zone.srv = vec![srv(0, 1, 80, "slow.test."), srv(1, 1, 443, "server.test.")];
        zone.silent_names.push("slow.test.".into());
    }
    let endpoint = "vpn.test".parse().unwrap();
    let result = resolve_endpoint(&endpoint, Some(&fixture.resolver))
        .await
        .unwrap();
    assert_eq!(result.len(), 2);
    assert!(result.iter().all(|address| address.port() == 443));
}

#[test]
fn weights_are_randomized_within_priority_and_zero_weights_are_supported() {
    let records = vec![
        srv(1, 65535, 1, "a.test."),
        srv(0, 1, 2, "b.test."),
        srv(0, 9, 3, "c.test."),
    ];
    let mut rng = fastrand::Rng::with_seed(1);
    let mut heavy = 0;
    for _ in 0..1000 {
        let result = order(records.clone(), &mut rng);
        assert_eq!(result[2].priority, 1);
        if result[0].port == 3 {
            heavy += 1;
        }
    }
    assert!(
        (700..950).contains(&heavy),
        "weighted selection count: {heavy}"
    );
    assert_eq!(
        order(
            vec![srv(0, 0, 1, "a.test."), srv(0, 0, 2, "b.test.")],
            &mut rng
        )
        .len(),
        2
    );
    assert!(candidates(vec!["[::]:443".parse().unwrap()]).is_none());
    assert!(candidates(vec!["127.0.0.1:443".parse().unwrap(); MAX_CANDIDATES + 1]).is_none());
}

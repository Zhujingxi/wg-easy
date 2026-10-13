use hickory_resolver::{
    TokioResolver,
    config::{LookupIpStrategy, NameServerConfig, ResolveHosts, ResolverConfig},
    net::runtime::TokioRuntimeProvider,
    proto::{
        op::{Message, OpCode, ResponseCode},
        rr::{
            Name, RData, Record, RecordType,
            rdata::{A, AAAA, SRV},
        },
    },
};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::net::UdpSocket;

pub struct Zone {
    pub srv: Vec<SRV>,
    pub addresses: HashMap<String, Vec<IpAddr>>,
    pub srv_code: ResponseCode,
    pub silent: bool,
    pub silent_names: Vec<String>,
    pub srv_queries: usize,
}

pub struct DnsFixture {
    pub zone: Arc<Mutex<Zone>>,
    pub resolver: TokioResolver,
    task: tokio::task::JoinHandle<()>,
}

pub fn srv(priority: u16, weight: u16, port: u16, target: &str) -> SRV {
    SRV::new(priority, weight, port, Name::from_ascii(target).unwrap())
}

impl DnsFixture {
    pub async fn bind(address: &str) -> Self {
        let socket = UdpSocket::bind(address).await.unwrap();
        let address: SocketAddr = socket.local_addr().unwrap();
        let zone = Arc::new(Mutex::new(Zone {
            srv: vec![srv(0, 100, 443, "server.test.")],
            addresses: HashMap::from([
                (
                    "server.test.".into(),
                    vec!["192.0.2.1".parse().unwrap(), "2001:db8::1".parse().unwrap()],
                ),
                (
                    "vpn.test.".into(),
                    vec!["192.0.2.2".parse().unwrap(), "2001:db8::2".parse().unwrap()],
                ),
            ]),
            srv_code: ResponseCode::NoError,
            silent: false,
            silent_names: Vec::new(),
            srv_queries: 0,
        }));
        let data = zone.clone();
        let task = tokio::spawn(async move {
            let mut buffer = [0; 4096];
            loop {
                let (count, source) = socket.recv_from(&mut buffer).await.unwrap();
                let query = Message::from_vec(&buffer[..count]).unwrap();
                let mut response = Message::response(query.metadata.id, OpCode::Query);
                response.metadata.authoritative = true;
                response.metadata.recursion_desired = true;
                response.metadata.recursion_available = true;
                {
                    let mut zone = data.lock().unwrap();
                    if zone.silent
                        || query
                            .queries
                            .iter()
                            .any(|query| zone.silent_names.contains(&query.name().to_utf8()))
                    {
                        continue;
                    }
                    for question in &query.queries {
                        response.add_query(question.clone());
                        if question.query_type() == RecordType::SRV {
                            zone.srv_queries += 1;
                            response.metadata.response_code = zone.srv_code;
                            if zone.srv_code == ResponseCode::NoError {
                                for record in &zone.srv {
                                    response.add_answer(Record::from_rdata(
                                        question.name().clone(),
                                        1,
                                        RData::SRV(record.clone()),
                                    ));
                                }
                            }
                        } else {
                            for address in zone
                                .addresses
                                .get(&question.name().to_utf8())
                                .into_iter()
                                .flatten()
                            {
                                let record = match (question.query_type(), address) {
                                    (RecordType::A, IpAddr::V4(ip)) => RData::A(A(*ip)),
                                    (RecordType::AAAA, IpAddr::V6(ip)) => RData::AAAA(AAAA(*ip)),
                                    _ => continue,
                                };
                                response.add_answer(Record::from_rdata(
                                    question.name().clone(),
                                    1,
                                    record,
                                ));
                            }
                        }
                    }
                }
                socket
                    .send_to(&response.to_vec().unwrap(), source)
                    .await
                    .unwrap();
            }
        });
        let mut server = NameServerConfig::udp(address.ip());
        server.connections[0].port = address.port();
        let config = ResolverConfig::from_name_servers(vec![server]);
        let mut builder =
            TokioResolver::builder_with_config(config, TokioRuntimeProvider::default());
        let options = builder.options_mut();
        options.ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
        options.use_hosts_file = ResolveHosts::Never;
        options.cache_size = 0;
        options.attempts = 1;
        options.timeout = Duration::from_millis(100);
        Self {
            zone,
            resolver: builder.build().unwrap(),
            task,
        }
    }
}

impl Drop for DnsFixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

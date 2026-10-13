//! Native, atomic nftables containment while a full tunnel is active.

use std::io;

use netlink_packet_core::{NLM_F_ACK, NLM_F_APPEND, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REQUEST};
use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_NETFILTER};

use crate::linux_policy::SOCKET_MARK;

// Linux UAPI: linux/netfilter/nf_tables.h and linux/netfilter/nfnetlink.h.
const SUBSYSTEM: u16 = 10;
const FAMILY: u8 = 1; // NFPROTO_INET includes IPv4 and IPv6.
const NEW_TABLE: u16 = 0;
const GET_TABLE: u16 = 1;
const DEL_TABLE: u16 = 2;
const NEW_CHAIN: u16 = 3;
const NEW_RULE: u16 = 6;
const NESTED: u16 = 1 << 15;
const OWNER: &[u8] = b"wg-easy full-tunnel v1";
const CHAIN: &str = "egress";

#[derive(Default)]
struct Attributes(Vec<u8>);

impl Attributes {
    fn bytes(&mut self, kind: u16, data: &[u8]) -> &mut Self {
        let length = 4 + data.len();
        self.0.extend_from_slice(&(length as u16).to_ne_bytes());
        self.0.extend_from_slice(&kind.to_ne_bytes());
        self.0.extend_from_slice(data);
        self.0.resize(self.0.len().next_multiple_of(4), 0);
        self
    }

    fn text(&mut self, kind: u16, value: &str) -> &mut Self {
        let mut value = value.as_bytes().to_vec();
        value.push(0);
        self.bytes(kind, &value)
    }

    fn number(&mut self, kind: u16, value: u32) -> &mut Self {
        self.bytes(kind, &value.to_be_bytes())
    }

    fn nested(&mut self, kind: u16, value: &Self) -> &mut Self {
        self.bytes(kind | NESTED, &value.0)
    }
}

struct Message {
    kind: u16,
    flags: u16,
    attributes: Attributes,
}

fn encode(kind: u16, flags: u16, sequence: u32, family: u8, attributes: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(20 + attributes.len());
    bytes.extend_from_slice(&((20 + attributes.len()) as u32).to_ne_bytes());
    bytes.extend_from_slice(&kind.to_ne_bytes());
    bytes.extend_from_slice(&(flags | NLM_F_REQUEST).to_ne_bytes());
    bytes.extend_from_slice(&sequence.to_ne_bytes());
    bytes.extend_from_slice(&0_u32.to_ne_bytes());
    bytes.extend_from_slice(&[family, 0]);
    bytes.extend_from_slice(&SUBSYSTEM.to_be_bytes());
    bytes.extend_from_slice(attributes);
    bytes
}

fn exchange(messages: Vec<Message>, atomic: bool) -> io::Result<Vec<Vec<u8>>> {
    let mut socket = Socket::new(NETLINK_NETFILTER)?;
    socket.bind_auto()?;
    socket.connect(&SocketAddr::new(0, 0))?;
    let mut bytes = Vec::new();
    if atomic {
        bytes.extend(encode(16, 0, 0, 0, &[])); // NFNL_MSG_BATCH_BEGIN
    }
    for (index, message) in messages.iter().enumerate() {
        bytes.extend(encode(
            SUBSYSTEM << 8 | message.kind,
            message.flags | NLM_F_ACK,
            index as u32 + 1,
            FAMILY,
            &message.attributes.0,
        ));
    }
    if atomic {
        bytes.extend(encode(17, 0, messages.len() as u32 + 1, 0, &[]));
    }
    socket.send(&bytes, 0)?;
    let mut acknowledged = vec![false; messages.len()];
    let mut replies = Vec::new();
    while acknowledged.iter().any(|done| !done) {
        let (bytes, sender) = socket.recv_from_full()?;
        if sender.port_number() != 0 {
            continue;
        }
        let mut offset = 0;
        while offset < bytes.len() {
            let header = bytes
                .get(offset..offset + 16)
                .ok_or_else(|| io::Error::other("Truncated nftables response"))?;
            let length = u32::from_ne_bytes(header[0..4].try_into().unwrap()) as usize;
            let kind = u16::from_ne_bytes(header[4..6].try_into().unwrap());
            let sequence = u32::from_ne_bytes(header[8..12].try_into().unwrap());
            if length < 16 {
                return Err(io::Error::other("Invalid nftables response length"));
            }
            let payload = bytes
                .get(offset + 16..offset + length)
                .ok_or_else(|| io::Error::other("Truncated nftables response payload"))?;
            if kind == 2 {
                let error = payload
                    .get(..4)
                    .ok_or_else(|| io::Error::other("Truncated nftables acknowledgement"))?;
                let error = i32::from_ne_bytes(error.try_into().unwrap());
                if error != 0 {
                    return Err(io::Error::from_raw_os_error(-error));
                }
                if let Some(done) = sequence
                    .checked_sub(1)
                    .and_then(|s| acknowledged.get_mut(s as usize))
                {
                    *done = true;
                }
            } else if kind == SUBSYSTEM << 8 | NEW_TABLE {
                replies.push(payload.to_vec());
            }
            offset += length.next_multiple_of(4);
        }
    }
    Ok(replies)
}

fn table_name(interface: &str) -> io::Result<String> {
    if interface.is_empty()
        || interface.len() > 15
        || !interface
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err(io::Error::other("Invalid full-tunnel filter interface"));
    }
    Ok(format!("wg_easy_{interface}"))
}

fn expression(list: &mut Attributes, name: &str, data: &Attributes) {
    let mut value = Attributes::default();
    value.text(1, name).nested(2, data); // NFTA_EXPR_NAME, NFTA_EXPR_DATA
    list.nested(1, &value); // NFTA_LIST_ELEM
}

fn compare(list: &mut Attributes, data: &[u8]) {
    let mut value = Attributes::default();
    value.bytes(1, data); // NFTA_DATA_VALUE
    let mut comparison = Attributes::default();
    comparison.number(1, 1).number(2, 0).nested(3, &value); // SREG, EQ, DATA
    expression(list, "cmp", &comparison);
}

fn meta(list: &mut Attributes, key: u32, data: &[u8]) {
    let mut value = Attributes::default();
    value.number(1, 1).number(2, key); // NFTA_META_DREG, NFTA_META_KEY
    expression(list, "meta", &value);
    compare(list, data);
}

fn payload(list: &mut Attributes, base: u32, offset: u32, data: &[u8]) {
    let mut value = Attributes::default();
    value
        .number(1, 1)
        .number(2, base)
        .number(3, offset)
        .number(4, data.len() as u32);
    expression(list, "payload", &value);
    compare(list, data);
}

fn allow(table: &str, mut expressions: Attributes) -> Message {
    let mut verdict = Attributes::default();
    verdict.number(1, 1); // NFTA_VERDICT_CODE: NF_ACCEPT
    let mut data = Attributes::default();
    data.nested(2, &verdict); // NFTA_DATA_VERDICT
    let mut immediate = Attributes::default();
    immediate.number(1, 0).nested(2, &data); // NFTA_IMMEDIATE_DREG: verdict, DATA
    expression(&mut expressions, "immediate", &immediate);
    let mut attributes = Attributes::default();
    attributes
        .text(1, table)
        .text(2, CHAIN)
        .nested(4, &expressions);
    Message {
        kind: NEW_RULE,
        flags: NLM_F_CREATE | NLM_F_APPEND,
        attributes,
    }
}

pub(crate) fn install(interface: &str) -> io::Result<()> {
    let table = table_name(interface)?;
    let mut attributes = Attributes::default();
    attributes.text(1, &table).bytes(6, OWNER); // NFTA_TABLE_NAME, USERDATA
    let mut messages = vec![Message {
        kind: NEW_TABLE,
        flags: NLM_F_CREATE | NLM_F_EXCL,
        attributes,
    }];
    let mut hook = Attributes::default();
    // Postrouting sees the final output interface, including sockets bound to an uplink.
    hook.number(1, 4).number(2, i32::MAX as u32); // POST_ROUTING, priority
    let mut chain = Attributes::default();
    chain
        .text(1, &table)
        .text(3, CHAIN)
        .nested(4, &hook)
        .number(5, 0)
        .text(7, "filter");
    messages.push(Message {
        kind: NEW_CHAIN,
        flags: NLM_F_CREATE | NLM_F_EXCL,
        attributes: chain,
    });
    for name in ["lo", interface] {
        let mut expressions = Attributes::default();
        let mut name = name.as_bytes().to_vec();
        name.push(0);
        meta(&mut expressions, 7, &name); // NFT_META_OIFNAME
        messages.push(allow(&table, expressions));
    }
    let mut wireguard = Attributes::default();
    meta(&mut wireguard, 3, &SOCKET_MARK.to_ne_bytes()); // NFT_META_MARK
    meta(&mut wireguard, 16, &[17]); // NFT_META_L4PROTO: UDP
    messages.push(allow(&table, wireguard));
    for (family, ports) in [(2, [0, 68, 0, 67]), (10, [2, 34, 2, 35])] {
        let mut dhcp = Attributes::default();
        meta(&mut dhcp, 15, &[family]); // NFT_META_NFPROTO
        meta(&mut dhcp, 16, &[17]);
        payload(&mut dhcp, 2, 0, &ports); // UDP client/server ports
        messages.push(allow(&table, dhcp));
    }
    for kind in [133, 135, 136] {
        let mut control = Attributes::default();
        meta(&mut control, 15, &[10]);
        meta(&mut control, 16, &[58]); // ICMPv6
        payload(&mut control, 1, 7, &[255]); // Required NDP hop limit
        payload(&mut control, 2, 0, &[kind, 0]); // Router solicitation / neighbor discovery
        messages.push(allow(&table, control));
    }
    for kind in [131, 132, 143] {
        let mut multicast = Attributes::default();
        meta(&mut multicast, 15, &[10]);
        meta(&mut multicast, 16, &[58]);
        payload(&mut multicast, 1, 7, &[1]); // MLD reports retain solicited-node membership.
        payload(&mut multicast, 1, 24, &[0xff, 0x02]);
        payload(&mut multicast, 2, 0, &[kind, 0]);
        messages.push(allow(&table, multicast));
    }
    exchange(messages, true)?;
    Ok(())
}

pub(crate) fn installed(interface: &str) -> io::Result<bool> {
    let mut attributes = Attributes::default();
    attributes.text(1, &table_name(interface)?);
    let replies = match exchange(
        vec![Message {
            kind: GET_TABLE,
            flags: 0,
            attributes,
        }],
        false,
    ) {
        Ok(replies) => replies,
        // Unsupported nftables cannot hold our table; a failed start still needs cleanup.
        Err(error)
            if matches!(
                error.raw_os_error(),
                Some(libc::ENOENT | libc::EAFNOSUPPORT | libc::EPROTONOSUPPORT | libc::EOPNOTSUPP)
            ) =>
        {
            return Ok(false);
        }
        Err(error) => return Err(error),
    };
    for reply in replies {
        let mut offset = 4; // nfgenmsg
        while offset < reply.len() {
            let header = reply
                .get(offset..offset + 4)
                .ok_or_else(|| io::Error::other("Truncated nftables table"))?;
            let length = u16::from_ne_bytes(header[..2].try_into().unwrap()) as usize;
            let kind = u16::from_ne_bytes(header[2..4].try_into().unwrap()) & !NESTED;
            if length < 4 {
                return Err(io::Error::other("Invalid nftables attribute length"));
            }
            let value = reply
                .get(offset + 4..offset + length)
                .ok_or_else(|| io::Error::other("Truncated nftables attribute"))?;
            if kind == 6 && value == OWNER {
                return Ok(true);
            }
            offset += length.next_multiple_of(4);
        }
    }
    Err(io::Error::other(
        "The full-tunnel nftables table belongs to another application",
    ))
}

pub(crate) fn remove(interface: &str) -> io::Result<()> {
    if installed(interface)? {
        let mut attributes = Attributes::default();
        attributes.text(1, &table_name(interface)?);
        exchange(
            vec![Message {
                kind: DEL_TABLE,
                flags: 0,
                attributes,
            }],
            true,
        )?;
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn assert_ownership_collision() {
    let interface = "wge-foreign";
    let mut foreign = Attributes::default();
    foreign
        .text(1, &table_name(interface).unwrap())
        .bytes(6, b"another application");
    exchange(
        vec![Message {
            kind: NEW_TABLE,
            flags: NLM_F_CREATE | NLM_F_EXCL,
            attributes: foreign,
        }],
        true,
    )
    .unwrap();
    assert_eq!(
        install(interface).unwrap_err().raw_os_error(),
        Some(libc::EEXIST)
    );
    assert!(remove(interface).is_err());
    assert!(
        installed(interface)
            .unwrap_err()
            .to_string()
            .contains("another application")
    );
    let mut attributes = Attributes::default();
    attributes.text(1, &table_name(interface).unwrap());
    exchange(
        vec![Message {
            kind: DEL_TABLE,
            flags: 0,
            attributes,
        }],
        true,
    )
    .unwrap();
    assert!(!installed(interface).unwrap());
}

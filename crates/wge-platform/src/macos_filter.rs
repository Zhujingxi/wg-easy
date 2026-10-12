//! Temporary PF containment for a full tunnel, including route changes.
use crate::Error;
use pfctl::{
    AnchorChange, AnchorKind, Direction, DropAction, FilterRule, FilterRuleAction,
    FilterRuleBuilder, Icmp6Type, IcmpType, Interface, PfCtl, Port, Proto, RulesetKind,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io, mem,
    net::SocketAddr,
    os::fd::AsRawFd,
    ptr,
};

#[derive(Serialize, Deserialize)]
pub(crate) struct State {
    anchor: String,
    interface: String,
    endpoints: Vec<SocketAddr>,
    port: u16,
    uid: u32,
    pid: i32,
    process_name: String,
    boot: i64,
    previous_tokens: Vec<u64>,
}

fn failure(error: impl std::fmt::Display) -> Error {
    Error::Invalid(format!(
        "Could not protect full-tunnel traffic with the system firewall: {error}"
    ))
}

pub(crate) fn prepare(
    interface: &str,
    endpoints: &[SocketAddr],
    port: u16,
) -> Result<State, Error> {
    let mut pf = PfCtl::new().map_err(failure)?;
    let anchor = format!("wg-easy-{interface}");
    if pf
        .anchor_exists(&anchor, AnchorKind::Filter)
        .map_err(failure)?
    {
        return Err(failure("Recover the previous tunnel before connecting"));
    }
    let file = open_pf()?;
    if skipped_interfaces(&file)?.iter().any(|name| name != "lo0") {
        return Err(failure(
            "PF is configured to skip a network interface. Remove that skip rule before connecting.",
        ));
    }
    let mut process_name = [0_u8; 64];
    // PF records the kernel's process name, which can differ from an executable basename.
    // SAFETY: the current PID and writable buffer are valid throughout proc_name.
    if unsafe {
        libc::proc_name(
            std::process::id() as i32,
            process_name.as_mut_ptr().cast(),
            process_name.len() as u32,
        )
    } <= 0
    {
        return Err(failure("Cannot identify the daemon process"));
    }
    let process_name =
        String::from_utf8_lossy(process_name.split(|b| *b == 0).next().unwrap_or_default())
            .into_owned();
    Ok(State {
        anchor,
        interface: interface.to_owned(),
        endpoints: endpoints.to_vec(),
        port,
        uid: unsafe { libc::geteuid() },
        pid: std::process::id() as i32,
        process_name,
        boot: boot_time()?,
        previous_tokens: tokens(&file)?.into_iter().map(|t| t.value).collect(),
    })
}

fn rule(builder: &FilterRuleBuilder) -> Result<FilterRule, Error> {
    builder.build().map_err(failure)
}

fn rules(state: &State) -> Result<Vec<FilterRule>, Error> {
    let pass = FilterRuleAction::Pass;
    let mut rules = vec![
        rule(
            FilterRuleBuilder::default()
                .action(pass)
                .interface("lo0")
                .quick(true),
        )?,
        rule(
            FilterRuleBuilder::default()
                .action(pass)
                .interface(state.interface.as_str())
                .quick(true),
        )?,
    ];
    for endpoint in &state.endpoints {
        // UID plus the exclusively bound local port identifies the daemon's UDP socket.
        rules.push(rule(
            FilterRuleBuilder::default()
                .action(pass)
                .direction(Direction::Out)
                .proto(Proto::Udp)
                .user(state.uid)
                .from(Port::from(state.port))
                .to(*endpoint)
                .quick(true),
        )?);
        rules.push(rule(
            FilterRuleBuilder::default()
                .action(pass)
                .direction(Direction::In)
                .proto(Proto::Udp)
                .user(state.uid)
                .from(*endpoint)
                .to(Port::from(state.port))
                .quick(true),
        )?);
    }
    // These control packets keep the physical link usable; ordinary traffic remains contained.
    for (source, destination) in [(68, 67), (546, 547)] {
        rules.push(rule(
            FilterRuleBuilder::default()
                .action(pass)
                .direction(Direction::Out)
                .proto(Proto::Udp)
                .user(0u32)
                .from(Port::from(source))
                .to(Port::from(destination))
                .quick(true),
        )?);
        rules.push(rule(
            FilterRuleBuilder::default()
                .action(pass)
                .direction(Direction::In)
                .proto(Proto::Udp)
                .from(Port::from(destination))
                .to(Port::from(source))
                .quick(true),
        )?);
    }
    for kind in [
        Icmp6Type::RouterSol,
        Icmp6Type::RouterAdv,
        Icmp6Type::NeighbrSol,
        Icmp6Type::NeighbrAdv,
    ] {
        rules.push(rule(
            FilterRuleBuilder::default()
                .action(pass)
                .proto(Proto::IcmpV6)
                .icmp_type(Some(IcmpType::Icmp6(kind)))
                .quick(true),
        )?);
    }
    // Snooping switches require listener reports to keep neighbor-discovery multicast flowing.
    for kind in [
        Icmp6Type::ListenerReport,
        Icmp6Type::ListenerDone,
        Icmp6Type::ListenerReportV2,
    ] {
        rules.push(rule(
            FilterRuleBuilder::default()
                .action(pass)
                .direction(Direction::Out)
                .proto(Proto::IcmpV6)
                .to(pfctl::Ip::Net(
                    "ff02::/16".parse().expect("fixed multicast prefix"),
                ))
                .icmp_type(Some(IcmpType::Icmp6(kind)))
                .quick(true),
        )?);
    }
    rules.push(rule(
        FilterRuleBuilder::default()
            .action(pass)
            .direction(Direction::In)
            .proto(Proto::IcmpV6)
            .from(pfctl::Ip::Net(
                "fe80::/10".parse().expect("fixed link-local prefix"),
            ))
            .icmp_type(Some(IcmpType::Icmp6(Icmp6Type::ListenerQuery)))
            .quick(true),
    )?);
    rules.push(rule(
        FilterRuleBuilder::default()
            .action(FilterRuleAction::Drop(DropAction::Drop))
            .quick(true),
    )?);
    Ok(rules)
}

pub(crate) fn apply(state: &State) -> Result<(), Error> {
    let file = open_pf()?;
    let mut token = 0u64;
    // Journal already records PID and existing references, so this token is recoverable even
    // if the process dies before the next instruction. Other PF users retain their references.
    ioctl(
        &file,
        request(0x4000_0000, 8, mem::size_of::<u64>()),
        &mut token,
    )?;
    let mut pf = PfCtl::new().map_err(failure)?;
    pf.add_anchor_first(&state.anchor).map_err(failure)?;
    let mut changes = AnchorChange::default();
    changes.set_filter_rules(rules(state)?);
    pf.set_rules(&state.anchor, changes).map_err(failure)?;
    // Existing PF states bypass new rules; stateless rules prevent new physical bypass states.
    pf.clear_interface_states(Interface::Any).map_err(failure)?;
    Ok(())
}

pub(crate) fn restore(state: &State) -> Result<(), Error> {
    if boot_time()? != state.boot {
        return Ok(());
    }
    let mut pf = PfCtl::new().map_err(failure)?;
    if pf
        .anchor_exists(&state.anchor, AnchorKind::Filter)
        .map_err(failure)?
    {
        pf.flush_rules(&state.anchor, RulesetKind::Filter)
            .map_err(failure)?;
        pf.try_remove_anchor(&state.anchor, AnchorKind::Filter)
            .map_err(failure)?;
    }
    let file = open_pf()?;
    for token in tokens(&file)? {
        let value = token.value;
        if owns_token(state, &token) {
            let mut removal = [value, 0u64];
            ioctl(
                &file,
                request(0xc000_0000, 9, mem::size_of_val(&removal)),
                &mut removal,
            )?;
        }
    }
    Ok(())
}

fn owns_token(state: &State, token: &Token) -> bool {
    let value = token.value;
    token.pid == state.pid
        && token.name() == state.process_name
        && !state.previous_tokens.contains(&value)
}

#[cfg(test)]
pub(crate) fn smoke_matches(state: &State, applied: bool) -> Result<bool, Error> {
    let mut pf = PfCtl::new().map_err(failure)?;
    let anchor = pf
        .anchor_exists(&state.anchor, AnchorKind::Filter)
        .map_err(failure)?;
    let reference = tokens(&open_pf()?)?
        .iter()
        .any(|token| owns_token(state, token));
    Ok(anchor == applied && reference == applied)
}

fn open_pf() -> Result<File, Error> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/pf")
        .map_err(Into::into)
}
const fn request(direction: u64, number: u8, size: usize) -> libc::c_ulong {
    direction | ((size as u64) << 16) | ((b'D' as u64) << 8) | number as u64
}

fn ioctl<T>(file: &File, request: libc::c_ulong, data: &mut T) -> Result<(), Error> {
    // SAFETY: callers pair each ioctl number with its documented, initialized native ABI.
    if unsafe { libc::ioctl(file.as_raw_fd(), request, data as *mut T) } < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Token {
    value: u64,
    timestamp: u64,
    pid: i32,
    name: [u8; 64],
}
impl Token {
    fn name(&self) -> String {
        String::from_utf8_lossy(self.name.split(|b| *b == 0).next().unwrap_or_default())
            .into_owned()
    }
}
#[repr(C)]
struct TokenList {
    size: i32,
    buffer: *mut Token,
}

fn tokens(file: &File) -> Result<Vec<Token>, Error> {
    let request = request(0xc000_0000, 5, mem::size_of::<TokenList>());
    let mut list = TokenList {
        size: 0,
        buffer: ptr::null_mut(),
    };
    if let Err(error) = ioctl(file, request, &mut list) {
        if matches!(&error, Error::Io(e) if e.raw_os_error() == Some(libc::ENOENT)) {
            return Ok(Vec::new());
        }
        return Err(error);
    }
    if list.size < 0 || list.size > 1024 * 1024 {
        return Err(failure("Invalid PF reference count"));
    }
    let count = list.size as usize / mem::size_of::<Token>();
    let mut tokens = vec![
        Token {
            value: 0,
            timestamp: 0,
            pid: 0,
            name: [0; 64]
        };
        count
    ];
    list.buffer = tokens.as_mut_ptr();
    ioctl(file, request, &mut list)?;
    tokens.truncate(list.size as usize / mem::size_of::<Token>());
    Ok(tokens)
}

#[repr(C)]
#[derive(Clone, Copy)]
struct PfInterface {
    name: [u8; 16],
    packets: [u64; 8],
    bytes: [u64; 8],
    zeroed_at: u64,
    flags: i32,
    states: i32,
    rules: i32,
}
#[repr(C)]
struct InterfaceList {
    name: [u8; 16],
    buffer: *mut PfInterface,
    element_size: i32,
    size: i32,
    zero: i32,
    flags: i32,
}

fn skipped_interfaces(file: &File) -> Result<Vec<String>, Error> {
    let request = request(0xc000_0000, 87, mem::size_of::<InterfaceList>());
    let mut list = InterfaceList {
        name: [0; 16],
        buffer: ptr::null_mut(),
        element_size: mem::size_of::<PfInterface>() as i32,
        size: 0,
        zero: 0,
        flags: 0,
    };
    ioctl(file, request, &mut list)?;
    if list.size < 0 || list.size > 65536 {
        return Err(failure("Invalid PF interface count"));
    }
    let mut interfaces = vec![
        PfInterface {
            name: [0; 16],
            packets: [0; 8],
            bytes: [0; 8],
            zeroed_at: 0,
            flags: 0,
            states: 0,
            rules: 0
        };
        list.size as usize + 8
    ];
    list.size = interfaces.len() as i32;
    list.buffer = interfaces.as_mut_ptr();
    ioctl(file, request, &mut list)?;
    interfaces.truncate(list.size as usize);
    Ok(interfaces
        .into_iter()
        .filter(|i| i.flags & 0x100 != 0)
        .map(|i| {
            String::from_utf8_lossy(i.name.split(|b| *b == 0).next().unwrap_or_default())
                .into_owned()
        })
        .collect())
}

fn boot_time() -> Result<i64, Error> {
    let mut value = libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    let mut size = mem::size_of_val(&value);
    // SAFETY: the sysctl writes one timeval; no new value is supplied.
    if unsafe {
        libc::sysctlbyname(
            c"kern.boottime".as_ptr(),
            (&mut value as *mut libc::timeval).cast(),
            &mut size,
            ptr::null_mut(),
            0,
        )
    } < 0
    {
        return Err(io::Error::last_os_error().into());
    }
    Ok(value.tv_sec)
}

const _: () = assert!(mem::size_of::<Token>() == 84);
const _: () = assert!(mem::size_of::<TokenList>() == 16);
const _: () = assert!(mem::size_of::<PfInterface>() == 168);
const _: () = assert!(mem::size_of::<InterfaceList>() == 40);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_releases_only_references_acquired_by_the_recorded_process() {
        let state = State {
            anchor: "wg-easy-utun9".into(),
            interface: "utun9".into(),
            endpoints: vec![
                "192.0.2.1:51820".parse().unwrap(),
                "[2001:db8::1]:51820".parse().unwrap(),
            ],
            port: 30000,
            uid: 0,
            pid: 42,
            process_name: "wg-easy-daemon".into(),
            boot: 123,
            previous_tokens: vec![1],
        };
        let mut token = Token {
            value: 2,
            timestamp: 123,
            pid: 42,
            name: [0; 64],
        };
        token.name[..state.process_name.len()].copy_from_slice(state.process_name.as_bytes());
        assert!(owns_token(&state, &token));
        token.value = 1;
        assert!(!owns_token(&state, &token));
        token.value = 2;
        token.pid = 43;
        assert!(!owns_token(&state, &token));
        token.pid = 42;
        token.name[0] = b'x';
        assert!(!owns_token(&state, &token));
        let policy = rules(&state).unwrap();
        let last = FilterRuleBuilder::default()
            .action(FilterRuleAction::Drop(DropAction::Drop))
            .quick(true)
            .build()
            .unwrap();
        assert_eq!(policy.last(), Some(&last));
    }
}

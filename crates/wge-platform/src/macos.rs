//! Darwin's IPv6 address ABI includes flags and address lifetimes.
use crate::Error;
use std::{
    io, mem,
    net::Ipv6Addr,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};
use wge_config::IpNetwork;

#[repr(C)]
struct Alias6 {
    name: [libc::c_char; libc::IFNAMSIZ],
    address: libc::sockaddr_in6,
    destination: libc::sockaddr_in6,
    mask: libc::sockaddr_in6,
    flags: libc::c_int,
    lifetime: libc::in6_addrlifetime,
}

fn sockaddr(address: Ipv6Addr) -> libc::sockaddr_in6 {
    libc::sockaddr_in6 {
        sin6_len: mem::size_of::<libc::sockaddr_in6>() as u8,
        sin6_family: libc::AF_INET6 as u8,
        sin6_port: 0,
        sin6_flowinfo: 0,
        sin6_addr: libc::in6_addr {
            s6_addr: address.octets(),
        },
        sin6_scope_id: 0,
    }
}

pub(crate) fn add_address(name: &str, address: &IpNetwork) -> Result<(), Error> {
    let IpNetwork::V6(address) = address else {
        return netconfig::Interface::try_from_name(name)?
            .add_address(
                address
                    .to_string()
                    .parse()
                    .map_err(|_| Error::Invalid("Invalid tunnel address".into()))?,
            )
            .map_err(Into::into);
    };
    if name.len() >= libc::IFNAMSIZ {
        return Err(Error::Invalid("Invalid interface name".into()));
    }
    // SAFETY: creating a datagram control socket has no borrowed arguments.
    let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: this function owns the newly created descriptor.
    let socket = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut request = Alias6 {
        name: [0; libc::IFNAMSIZ],
        address: sockaddr(address.ip()),
        destination: sockaddr(Ipv6Addr::UNSPECIFIED),
        mask: sockaddr(address.mask()),
        flags: 0x0020,
        lifetime: libc::in6_addrlifetime {
            ia6t_expire: 0,
            ia6t_preferred: 0,
            ia6t_vltime: u32::MAX,
            ia6t_pltime: u32::MAX,
        },
    };
    for (slot, byte) in request.name.iter_mut().zip(name.bytes()) {
        *slot = byte as libc::c_char;
    }
    // _IOW('i', 26, struct in6_aliasreq), with Apple's 64-bit ABI.
    const ADD_ADDRESS: libc::c_ulong = 0x8000_0000
        | ((mem::size_of::<Alias6>() as libc::c_ulong) << 16)
        | ((b'i' as libc::c_ulong) << 8)
        | 26;
    // SAFETY: request matches the kernel's in6_aliasreq and lives through ioctl.
    if unsafe { libc::ioctl(socket.as_raw_fd(), ADD_ADDRESS, &request) } < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

const _: () = assert!(mem::size_of::<Alias6>() == 128);

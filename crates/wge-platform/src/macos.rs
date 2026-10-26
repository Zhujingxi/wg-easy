//! Darwin address ioctls require a socket matching the address family.
use crate::Error;
use std::{
    io, mem,
    net::{Ipv4Addr, Ipv6Addr},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};
use wge_config::IpNetwork;

#[repr(C)]
struct Alias4 {
    name: [libc::c_char; libc::IFNAMSIZ],
    address: libc::sockaddr_in,
    destination: libc::sockaddr_in,
    mask: libc::sockaddr_in,
}

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

fn sockaddr4(address: Ipv4Addr) -> libc::sockaddr_in {
    libc::sockaddr_in {
        sin_len: mem::size_of::<libc::sockaddr_in>() as u8,
        sin_family: libc::AF_INET as u8,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(address.octets()),
        },
        sin_zero: [0; 8],
    }
}

pub(crate) fn add_address(name: &str, address: &IpNetwork) -> Result<(), Error> {
    if name.len() >= libc::IFNAMSIZ {
        return Err(Error::Invalid("Invalid interface name".into()));
    }
    let mut interface_name = [0; libc::IFNAMSIZ];
    for (slot, byte) in interface_name.iter_mut().zip(name.bytes()) {
        *slot = byte as libc::c_char;
    }
    let family = if address.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    // SAFETY: creating a datagram control socket has no borrowed arguments.
    let fd = unsafe { libc::socket(family, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: this function owns the newly created descriptor.
    let socket = unsafe { OwnedFd::from_raw_fd(fd) };
    if let IpNetwork::V4(address) = address {
        let request = Alias4 {
            name: interface_name,
            address: sockaddr4(address.ip()),
            destination: sockaddr4(address.ip()),
            mask: sockaddr4(address.mask()),
        };
        // SIOCAIFADDR: _IOW('i', 26, struct ifaliasreq), on an IPv4 control socket.
        const ADD_ADDRESS: libc::c_ulong = 0x8040_691a;
        // SAFETY: request matches Darwin's IPv4 ifaliasreq and lives through ioctl.
        if unsafe { libc::ioctl(socket.as_raw_fd(), ADD_ADDRESS, &request) } < 0 {
            return Err(io::Error::last_os_error().into());
        }
        return Ok(());
    }
    let IpNetwork::V6(address) = address else {
        unreachable!()
    };
    let request = Alias6 {
        name: interface_name,
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
const _: () = assert!(mem::size_of::<Alias4>() == 64);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_sockaddr_has_darwin_header_and_network_order_address() {
        let address = Ipv4Addr::new(198, 18, 245, 1);
        let native = sockaddr4(address);
        assert_eq!(native.sin_len, 16);
        assert_eq!(native.sin_family, libc::AF_INET as u8);
        assert_eq!(native.sin_addr.s_addr.to_ne_bytes(), address.octets());
        assert_eq!(native.sin_port, 0);
    }
}

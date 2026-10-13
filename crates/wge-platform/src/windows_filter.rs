//! A dynamic WFP session contains active full-tunnel traffic across route changes.

use std::{
    io,
    net::{IpAddr, SocketAddr},
    os::windows::ffi::OsStrExt,
    ptr,
};

use windows_sys::{
    Win32::{
        Foundation::HANDLE,
        NetworkManagement::{
            IpHelper::ConvertInterfaceIndexToLuid, Ndis::NET_LUID_LH, WindowsFilteringPlatform::*,
        },
        System::Rpc::{RPC_C_AUTHN_WINNT, UuidCreate},
    },
    core::GUID,
};

use crate::Error;

pub(crate) struct Guard {
    engine: HANDLE,
}

// SAFETY: WFP engine handles are RPC handles usable across threads. After install,
// this owner makes no further calls except closing the session exactly once.
unsafe impl Send for Guard {}
unsafe impl Sync for Guard {}

impl Drop for Guard {
    fn drop(&mut self) {
        // SAFETY: this owner holds the unique live engine handle.
        unsafe { FwpmEngineClose0(self.engine) };
    }
}

impl Guard {
    pub(crate) fn install(interface_index: u32, endpoints: &[SocketAddr]) -> Result<Self, Error> {
        if endpoints.is_empty() {
            return Err(Error::Invalid(
                "An all-traffic tunnel needs a server endpoint".into(),
            ));
        }
        let mut luid = NET_LUID_LH::default();
        // SAFETY: luid is a valid output pointer for the given native interface index.
        check(unsafe { ConvertInterfaceIndexToLuid(interface_index, &mut luid) })?;
        // SAFETY: ConvertInterfaceIndexToLuid initialized the union's Value representation.
        let mut interface = unsafe { luid.Value };
        let app = AppId::current()?;
        let mut name = wide("wg-easy active tunnel");
        let session = FWPM_SESSION0 {
            displayData: FWPM_DISPLAY_DATA0 {
                name: name.as_mut_ptr(),
                description: ptr::null_mut(),
            },
            flags: FWPM_SESSION_FLAG_DYNAMIC,
            ..Default::default()
        };
        let mut engine = ptr::null_mut();
        // SAFETY: the local RPC session copies its configuration and returns an owned handle.
        check(unsafe {
            FwpmEngineOpen0(
                ptr::null(),
                RPC_C_AUTHN_WINNT,
                ptr::null(),
                &session,
                &mut engine,
            )
        })?;
        let guard = Self { engine };
        // SAFETY: the engine is live; failure drops it and aborts partial configuration.
        check(unsafe { FwpmTransactionBegin0(engine, 0) })?;
        let sublayer = guid()?;
        let description = FWPM_SUBLAYER0 {
            subLayerKey: sublayer,
            displayData: FWPM_DISPLAY_DATA0 {
                name: name.as_mut_ptr(),
                description: ptr::null_mut(),
            },
            weight: u16::MAX,
            ..Default::default()
        };
        // SAFETY: all sublayer fields remain valid throughout this copying API call.
        check(unsafe { FwpmSubLayerAdd0(engine, &description, ptr::null_mut()) })?;
        for layer in [
            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
            FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
        ] {
            let tunnel = condition(
                FWPM_CONDITION_IP_LOCAL_INTERFACE,
                FWP_UINT64,
                FWP_CONDITION_VALUE0_0 {
                    uint64: &mut interface,
                },
            );
            add(
                engine,
                sublayer,
                layer,
                "wg-easy tunnel",
                100,
                FWP_ACTION_PERMIT,
                &mut [tunnel],
            )?;
            let mut loopback = condition(
                FWPM_CONDITION_FLAGS,
                FWP_UINT32,
                FWP_CONDITION_VALUE0_0 {
                    uint32: FWP_CONDITION_FLAG_IS_LOOPBACK,
                },
            );
            loopback.matchType = FWP_MATCH_FLAGS_ALL_SET;
            add(
                engine,
                sublayer,
                layer,
                "wg-easy loopback",
                100,
                FWP_ACTION_PERMIT,
                &mut [loopback],
            )?;
            add(
                engine,
                sublayer,
                layer,
                "wg-easy contain physical traffic",
                1,
                FWP_ACTION_BLOCK,
                &mut [],
            )?;
        }
        for &endpoint in endpoints {
            let mut address = Address::new(endpoint.ip());
            let mut conditions = endpoint_conditions(endpoint, app.0, &mut address);
            for layer in [layer(endpoint.ip()), receive_layer(endpoint.ip())] {
                add(
                    engine,
                    sublayer,
                    layer,
                    "wg-easy encrypted endpoint",
                    100,
                    FWP_ACTION_PERMIT,
                    &mut conditions,
                )?;
            }
        }
        control_traffic(engine, sublayer)?;
        // SAFETY: commit atomically exposes the complete policy, including all permit rules.
        check(unsafe { FwpmTransactionCommit0(engine) })?;
        Ok(guard)
    }
}

fn control_traffic(engine: HANDLE, sublayer: GUID) -> Result<(), Error> {
    for (server, client, port) in [("255.255.255.255", 68, 67), ("ff02::1:2", 546, 547)] {
        let ip: IpAddr = server.parse().expect("fixed DHCP address");
        let mut address = Address::new(ip);
        let mut conditions = [
            protocol(17),
            port_condition(FWPM_CONDITION_IP_LOCAL_PORT, client),
            port_condition(FWPM_CONDITION_IP_REMOTE_PORT, port),
            address.condition(),
        ];
        add(
            engine,
            sublayer,
            layer(ip),
            "wg-easy DHCP control",
            100,
            FWP_ACTION_PERMIT,
            &mut conditions,
        )?;
        // Replies are sent from the assigned DHCP server, not the discovery address.
        add(
            engine,
            sublayer,
            receive_layer(ip),
            "wg-easy DHCP reply",
            100,
            FWP_ACTION_PERMIT,
            &mut conditions[..3],
        )?;
    }
    // ICMPv6 encodes type/code in the local/remote port conditions at ALE layers.
    // These control messages are required to reach a server over an IPv6 uplink.
    for kind in [133, 135, 136] {
        let mut conditions = [
            protocol(58),
            port_condition(FWPM_CONDITION_IP_LOCAL_PORT, kind),
            port_condition(FWPM_CONDITION_IP_REMOTE_PORT, 0),
        ];
        add(
            engine,
            sublayer,
            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            "wg-easy IPv6 neighbor discovery",
            100,
            FWP_ACTION_PERMIT,
            &mut conditions,
        )?;
        if kind != 133 {
            add(
                engine,
                sublayer,
                FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
                "wg-easy IPv6 neighbor discovery reply",
                100,
                FWP_ACTION_PERMIT,
                &mut conditions,
            )?;
        }
    }
    let mut multicast = FWP_V6_ADDR_AND_MASK {
        addr: [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        prefixLength: 16,
    };
    for kind in [131, 132, 143] {
        let mut conditions = [
            protocol(58),
            port_condition(FWPM_CONDITION_IP_LOCAL_PORT, kind),
            port_condition(FWPM_CONDITION_IP_REMOTE_PORT, 0),
            condition(
                FWPM_CONDITION_IP_REMOTE_ADDRESS,
                FWP_V6_ADDR_MASK,
                FWP_CONDITION_VALUE0_0 {
                    v6AddrMask: &mut multicast,
                },
            ),
        ];
        add(
            engine,
            sublayer,
            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            "wg-easy IPv6 multicast listener report",
            100,
            FWP_ACTION_PERMIT,
            &mut conditions,
        )?;
    }
    let mut link_local = FWP_V6_ADDR_AND_MASK {
        addr: [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        prefixLength: 10,
    };
    for kind in [130, 134, 137] {
        let mut conditions = [
            protocol(58),
            port_condition(FWPM_CONDITION_IP_LOCAL_PORT, kind),
            port_condition(FWPM_CONDITION_IP_REMOTE_PORT, 0),
            condition(
                FWPM_CONDITION_IP_REMOTE_ADDRESS,
                FWP_V6_ADDR_MASK,
                FWP_CONDITION_VALUE0_0 {
                    v6AddrMask: &mut link_local,
                },
            ),
        ];
        add(
            engine,
            sublayer,
            FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
            "wg-easy IPv6 link control",
            100,
            FWP_ACTION_PERMIT,
            &mut conditions,
        )?;
    }
    Ok(())
}

fn layer(address: IpAddr) -> GUID {
    if address.is_ipv4() {
        FWPM_LAYER_ALE_AUTH_CONNECT_V4
    } else {
        FWPM_LAYER_ALE_AUTH_CONNECT_V6
    }
}

fn receive_layer(address: IpAddr) -> GUID {
    if address.is_ipv4() {
        FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4
    } else {
        FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6
    }
}

fn endpoint_conditions(
    endpoint: SocketAddr,
    app: *mut FWP_BYTE_BLOB,
    address: &mut Address,
) -> [FWPM_FILTER_CONDITION0; 4] {
    [
        protocol(17),
        port_condition(FWPM_CONDITION_IP_REMOTE_PORT, endpoint.port()),
        address.condition(),
        condition(
            FWPM_CONDITION_ALE_APP_ID,
            FWP_BYTE_BLOB_TYPE,
            FWP_CONDITION_VALUE0_0 { byteBlob: app },
        ),
    ]
}

fn condition(
    field: GUID,
    kind: FWP_DATA_TYPE,
    value: FWP_CONDITION_VALUE0_0,
) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: field,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: kind,
            Anonymous: value,
        },
    }
}

fn protocol(value: u8) -> FWPM_FILTER_CONDITION0 {
    condition(
        FWPM_CONDITION_IP_PROTOCOL,
        FWP_UINT8,
        FWP_CONDITION_VALUE0_0 { uint8: value },
    )
}

fn port_condition(field: GUID, value: u16) -> FWPM_FILTER_CONDITION0 {
    condition(field, FWP_UINT16, FWP_CONDITION_VALUE0_0 { uint16: value })
}

enum Address {
    V4(u32),
    V6(FWP_BYTE_ARRAY16),
}

impl Address {
    fn new(address: IpAddr) -> Self {
        match address {
            IpAddr::V4(address) => Self::V4(u32::from(address)),
            IpAddr::V6(address) => Self::V6(FWP_BYTE_ARRAY16 {
                byteArray16: address.octets(),
            }),
        }
    }

    fn condition(&mut self) -> FWPM_FILTER_CONDITION0 {
        match self {
            Self::V4(address) => condition(
                FWPM_CONDITION_IP_REMOTE_ADDRESS,
                FWP_UINT32,
                FWP_CONDITION_VALUE0_0 { uint32: *address },
            ),
            Self::V6(address) => condition(
                FWPM_CONDITION_IP_REMOTE_ADDRESS,
                FWP_BYTE_ARRAY16_TYPE,
                FWP_CONDITION_VALUE0_0 {
                    byteArray16: address,
                },
            ),
        }
    }
}

fn add(
    engine: HANDLE,
    sublayer: GUID,
    layer: GUID,
    name: &str,
    mut weight: u64,
    action: FWP_ACTION_TYPE,
    conditions: &mut [FWPM_FILTER_CONDITION0],
) -> Result<(), Error> {
    let mut name = wide(name);
    let filter = FWPM_FILTER0 {
        filterKey: guid()?,
        displayData: FWPM_DISPLAY_DATA0 {
            name: name.as_mut_ptr(),
            description: ptr::null_mut(),
        },
        layerKey: layer,
        subLayerKey: sublayer,
        weight: FWP_VALUE0 {
            r#type: FWP_UINT64,
            Anonymous: FWP_VALUE0_0 {
                uint64: &mut weight,
            },
        },
        action: FWPM_ACTION0 {
            r#type: action,
            ..Default::default()
        },
        numFilterConditions: conditions.len() as u32,
        filterCondition: conditions.as_mut_ptr(),
        ..Default::default()
    };
    // SAFETY: all condition backing values and filter fields are live for this copying call.
    check(unsafe { FwpmFilterAdd0(engine, &filter, ptr::null_mut(), ptr::null_mut()) })
}

fn guid() -> Result<GUID, Error> {
    let mut guid = GUID::default();
    // SAFETY: guid is a valid output pointer; this is an identifier, not a cryptographic key.
    check(unsafe { UuidCreate(&mut guid) } as u32)?;
    Ok(guid)
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

fn check(status: u32) -> Result<(), Error> {
    if status == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(status as i32).into())
    }
}

struct AppId(*mut FWP_BYTE_BLOB);

impl AppId {
    fn current() -> Result<Self, Error> {
        let executable: Vec<u16> = std::env::current_exe()?
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect();
        let mut id = ptr::null_mut();
        // SAFETY: executable is terminated and id is a valid output pointer.
        check(unsafe { FwpmGetAppIdFromFileName0(executable.as_ptr(), &mut id) })?;
        Ok(Self(id))
    }
}

impl Drop for AppId {
    fn drop(&mut self) {
        // SAFETY: WFP allocated this blob; the API frees it and nulls the owner's pointer.
        unsafe { FwpmFreeMemory0((&mut self.0 as *mut *mut FWP_BYTE_BLOB).cast()) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn same_guid(a: GUID, b: GUID) -> bool {
        (a.data1, a.data2, a.data3, a.data4) == (b.data1, b.data2, b.data3, b.data4)
    }

    #[test]
    fn encrypted_endpoint_exception_has_no_broad_application_or_address_bypass() {
        for endpoint in ["192.0.2.1:51820", "[2001:db8::1]:443"] {
            let endpoint: SocketAddr = endpoint.parse().unwrap();
            let mut address = Address::new(endpoint.ip());
            let mut app = FWP_BYTE_BLOB::default();
            let conditions = endpoint_conditions(endpoint, &mut app, &mut address);
            assert_eq!(conditions.len(), 4);
            assert!(same_guid(
                conditions[0].fieldKey,
                FWPM_CONDITION_IP_PROTOCOL
            ));
            assert!(same_guid(
                conditions[1].fieldKey,
                FWPM_CONDITION_IP_REMOTE_PORT
            ));
            assert!(same_guid(
                conditions[2].fieldKey,
                FWPM_CONDITION_IP_REMOTE_ADDRESS
            ));
            assert!(same_guid(conditions[3].fieldKey, FWPM_CONDITION_ALE_APP_ID));
            assert!(
                conditions
                    .iter()
                    .all(|condition| condition.matchType == FWP_MATCH_EQUAL)
            );
            // SAFETY: endpoint_conditions set these exact discriminated union members.
            unsafe {
                assert_eq!(conditions[0].conditionValue.Anonymous.uint8, 17);
                assert_eq!(
                    conditions[1].conditionValue.Anonymous.uint16,
                    endpoint.port()
                );
                assert_eq!(
                    conditions[3].conditionValue.Anonymous.byteBlob,
                    &mut app as *mut _
                );
            }
        }
    }
}

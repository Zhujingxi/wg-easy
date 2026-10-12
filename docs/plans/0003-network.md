# 0003: Native tunnel engine, routes and DNS

Status: done

## Goal

Run the built-in gotatun engine with one native tun interface per active tunnel,
real peer statistics, IPv4 and IPv6 routes, scoped DNS and recoverable cleanup.
Daemon ownership and cross-tunnel overlap checks are in the service plan.

## Approach

Resolve endpoints under one ten-second deadline before changing routes. Create
tun with the chosen `tun` crate, configure additional addresses through native
OS APIs, and keep the network state private to the service. The macOS IPv6
address ioctl uses Apple's complete alias structure because netconfig 0.4 omits
its flags and lifetime fields. On Windows, locate the bundled signed Wintun DLL
beside the daemon and use the interface index, since its friendly name is not
its canonical adapter name. Disable tun's macOS subprocess route configuration.

Install exact endpoint bypasses before allowed ranges. Full tunnels capture
both IP families even if only one has an address. Linux uses a dedicated route
table with native policy rules: marked WireGuard sockets use the physical main
table, an unreachable guard prevents endpoint loops, and locally generated
unmarked packets use the tunnel. This also captures more-specific LAN/DNS
routes and respects strict reverse-path filtering on incoming encrypted UDP.
An atomic native nftables inet filter checks final egress after routing/NAT:
Linux can send directly on a socket-bound interface even when policy lookup
returns unreachable. The filter permits the tunnel, loopback, marked WireGuard
UDP and narrow DHCP/IPv6 link maintenance, and blocks other physical egress.
Its table carries an ownership marker and is journaled before installation;
normal stop and crash recovery remove it without touching other tables.

Windows and macOS override existing physical ranges and contain later network
changes with native filters, installed only while a full tunnel is active.
Windows WFP uses a dynamic, atomic session allowing the tunnel, loopback,
required link control packets and only the daemon executable's encrypted UDP
endpoints. Both connection and receive/accept layers are covered. macOS PF uses
a first, quick anchor with stateless rules; its daemon exception requires root,
the exclusively bound local UDP port and exact endpoint. Existing states are
cleared so preexisting physical connections cannot bypass the policy. Existing
PF skip-interface rules are rejected. PF enable references are owned individually,
journaled before acquisition and recovered using process identity and boot time.
Other users' references and firewall rules are retained. This is active-tunnel
containment, not a persistent kill switch; normal shutdown removes the filters.
All three platforms preserve IPv6 multicast listener maintenance alongside
neighbor discovery so multicast snooping does not silently break the uplink.

DNS uses systemd-resolved per-link routing domains on Linux, an owned NRPT policy
on Windows and supplemental SystemConfiguration resolvers on macOS. Full tunnels
require explicit non-loopback DNS and capture both default families. Linux can
atomically replace the existing resolv.conf target when resolved is unavailable.
Split DNS requires explicit domains and servers covered by the tunnel ranges.
Full-tunnel DNS suppresses physical resolvers; restoration preserves later OS
changes. A server endpoint cannot also be the tunnel's DNS server.

Record cleanup intent in a private, fsynced journal before persistent changes.
Rollback partial startup and replay journals on daemon startup. No keys enter
journals. Restore DNS, routes and displaced host routes before removing filters.
Windows journals use a write-through atomic rename. IPC impersonation and SCM
helpers keep unavoidable unsafe Windows operations in the platform crate.
Windows recovery directories are created atomically with a protected SYSTEM and
Administrators access list. Existing directories must have the expected owner
and permissions; native handle checks reject reparse points before journal I/O.

The engine returns public peer identities, endpoints, byte counters and handshake
age. All peers need a recent handshake for Connected. Temporary keepalives
initiate handshakes without probes; an internal bounded task restores the user's
interval independently of GUI polling. Transient inspected PSK copies are zeroed.
No shell commands, connectivity probes, telemetry or automatic tunnel restoration
at login/reboot are introduced.

## Dependencies

`route_manager` wraps native route APIs; `netconfig` wraps interface APIs; `libc`
supplies missing native calls. Linux's netlink crates are already route_manager
transitives and provide policy routing and nftables without additional
dependencies or command-line tools. `serde` and `serde_json` encode public
recovery journals. `zbus` uses only its Tokio backend for systemd-resolved.
`windows-sys` supplies DNS, pipe identity, WFP and atomic file APIs;
`windows-service` supplies SCM registration/control. `system-configuration` and
`core-foundation` supply macOS DNS. macOS-only `pfctl` 0.7.0 uses native ioctls,
not the command-line program; its MIT/Apache source is vendored with two small
public methods for first-anchor insertion and read-only existence checks, plus
standard IPv6 multicast listener type values for narrow link-maintenance rules.
`x25519-dalek` supplies gotatun's key input type, and `zeroize` clears temporary
PSK copies. `tempfile` and `socket2` are test-only helpers.

## Validation

Linux engine/platform tests and clippy with warnings denied pass. Privileged
operations run in isolated user/network namespaces guarded against host use:

- Real tun client and gotatun peer exchange encrypted IPv4 and IPv6 UDP with a
  preshared key, report handshakes and byte counters, and remove the interface
  and journal at disconnect.
- Full-tunnel policy captures IPv4/IPv6 LAN DNS traffic despite physical routes,
  bypasses the endpoint only for marked transport, blocks sockets explicitly
  bound to the physical interface, and replays crash recovery. Physical packets
  flow again after cleanup; foreign nftables tables survive ownership collisions.
- Journal tests check version rejection, secret exclusion, private permissions
  and symlink rejection. DNS tests restore originals and preserve external edits.
- Native macOS arm64 and Windows GNU platform all-target checks and clippy pass;
  tests also assert that network state and errors remain Send + Sync.
- The namespace harness measures payload throughput, idle CPU and RSS and can
  emit JSON through WGE_METRICS_PATH. Debug measurements are not release claims.
- A local release run with the patched engine measured 1,565 Mbps payload,
  0.035% idle CPU and 7.8 MB RSS. This is a two-peer loopback harness with a
  4 MiB payload, not a physical link benchmark or a cross-machine budget.

Native Windows WFP/NRPT/SCM and macOS PF/SystemConfiguration behavior still need
privileged smoke tests on those operating systems; cross-compilation cannot
establish runtime behavior. The opt-in `native_full_tunnel_smoke` test now covers
real dual-stack tun packets, native DNS/filter application, normal cleanup and
journal recovery, with a separate recovery watchdog. See
`docs/native-network-smoke.md` for elevated disposable-VM commands and limits.
PF token ownership now uses the kernel process name rather than assuming it
matches the executable's basename. Windows service stop delivery uses a Tokio
oneshot so a failed service startup cannot strand a blocking receiver thread.
Vendored pfctl emits two upstream warnings in its
unused NAT pool code; wg-easy uses only stateless filtering rules.

## Resolved checks and remaining limits

Wintun 0.14.1's bundled licence section 3(d) permits redistribution of the
unchanged signed DLL alongside software using its documented API. Official ZIP
SHA-256: `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`.
The delivery plan owns inclusion and licence notices. Unsigned macOS service
installation also belongs to delivery.

Gotatun 0.9.2 is vendored with a narrow memory-lifecycle patch: retained PSKs,
update and parsing buffers are zeroed on replacement/drop, secret debug fields
are redacted, and session-constructor temporary key arrays are cleared. Wire
cryptography is unchanged. All 78 upstream unit tests and our real PSK namespace
test pass. See vendor/gotatun/WG-EASY-PATCH.md for the precise changes, source
checksum and MPL-2.0 redistribution requirements. X25519 already enables
zeroization, and AWS-LC owns the session cipher context cleanup.

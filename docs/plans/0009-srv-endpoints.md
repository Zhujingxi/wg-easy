# 0009: Automatic DNS SRV endpoints

Status: done

## Goal

Enter a hostname without a port and discover `_wireguard._udp.<hostname>`.
SRV supplies the target and port; A and AAAA supply IPv4 and IPv6 candidates.
Changes to DNS must not require editing clients. Explicit ports bypass SRV.

## Approach

Represent an omitted port explicitly. Bare IP addresses use port 51820 without
discovery. Only NXDOMAIN or a successful empty SRV answer permits the ordinary
hostname:51820 fallback; timeouts, SERVFAIL, port zero and the SRV unavailable
target `.` fail. Order SRV records by priority and RFC 2782 weight, resolve both
address families, and try other candidates if a handshake does not succeed.
Keep the existing ten-second resolution deadline and bound candidate counts to
16 per peer and 256 per tunnel. Resolve SRV targets concurrently with bounded
waits so a broken backup cannot hide a working target.
Use the computer's configured DNS servers, never a public resolver fallback.

Preserve discovery with a per-peer `# wg-easy-srv: <hostname>` comment beside a
standard `Endpoint = host:port` line. Ordinary configs retain explicit ports.
Local persistence uses hostname:51820 as the compatibility fallback; confirmed
export resolves discovery endpoints to a usable address and port and retains
the comment so reimport into wg-easy preserves discovery. Other clients ignore
the comment and use the exported snapshot. Connected tunnels export their working
endpoints without DNS queries. Bump IPC version for optional ports.

Install bypasses for all resolved candidates before configuring tunnel DNS and
routes. A daemon-owned task temporarily sends WireGuard keepalives, waits for
handshakes and tries alternative addresses (including the other IP family).
Restore configured keepalive after success or a bounded initial attempt.
Keep a working endpoint stable. When a discovery peer has no recent handshake
and its candidates have been exhausted, restore networking and reconnect with
fresh DNS. This full reconnect rebuilds platform filters and bypass routes and
allows bootstrap DNS to work even when the broken tunnel owned system DNS.
Retry failed discovery with a bounded delay. Disconnect joins the worker so
network changes and cleanup cannot be cancelled halfway through. Before a
reconnect, wait for gotatun's asynchronously released interface to disappear.
Retrying retains the original status deadline so failures do not remain
Connecting indefinitely.

The recovery reconnect briefly interrupts all peers in that tunnel and restores
ordinary networking while reconnecting, consistent with the absence of a kill
switch. No periodic DNS requests while a connection is healthy, no automatic
startup after reboot, no arbitrary URL schemes and no server configuration UI.

## Dependencies

Add `hickory-resolver` with only Tokio and system-config features for maintained,
cross-platform SRV DNS protocol handling; the standard library only resolves
addresses. Add the already-transitive `fastrand` for RFC 2782 weighted ordering
(not cryptography). Test-only `rustix`, already transitive, safely binds a private
resolver configuration inside an isolated mount namespace. No HTTP, encrypted
DNS or public resolver presets are used.

## Validation

Completed on Linux:

- Formatting, workspace check/test/build and all-target Clippy with warnings
  denied pass. Config property tests include discovery endpoints, and daemon
  tests preserve discovery across save/restart and export the connected IPv6
  endpoint without DNS. IPC moves to version 2 for optional ports.
- Local DNS fixtures cover SRV priorities/weights, A/AAAA, an IPv6 DNS server,
  absent records, unavailable service, invalid ports, DNS failures and a slow
  target alongside a working backup. Recovery tests cover healthy endpoints,
  family failover, stale handshakes and bounded explicit-port probes.
- The real Linux namespace suite passes: encrypted IPv4/IPv6 payloads, full
  tunnel containment, crash recovery, IPv6-to-IPv4 endpoint failover, then a
  changed SRV target and port recovering through an IPv6-only server after the
  real three-minute handshake expiry. It also verifies that repeated failed
  discovery attempts show NoHandshake and that disconnect removes journals and
  interfaces. Reconnect now waits for asynchronous interface release.
- Native GPUI acceptance passes under Xvfb/software Vulkan, including English,
  Japanese, editor handlers, QR and clipboard input. The new hint fits its field.
- cargo-deny passes advisories/licences/sources/bans; cargo-audit reports no
  vulnerabilities with existing upstream warnings. Hickory 0.26.3 avoids the
  advisories affecting 0.25.2; no advisory exceptions were added.
- Windows GNU engine/daemon all-target check and Clippy with warnings denied
  pass. Native Windows/macOS networking was not run, and macOS was not compiled
  in this environment.
- CI fuzzing explicitly selects the Linux GNU target because the prebuilt
  cargo-fuzz tool defaults to musl, which cannot run the address sanitizer.
  The corrected command passed locally with 4.6 million inputs in 61 seconds.

## Open questions

None for implementation. Live privileged Windows/macOS acceptance remains an
OS-specific verification step; cross-compilation is not runtime evidence.

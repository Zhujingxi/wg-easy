# Verification

This file records what was actually checked. Cross-compilation confirms types
and target-specific code paths compile; it does not establish native OS behavior.

## Configuration and service

- 21 parser/model/property tests cover generated round trips, arbitrary input,
IPv4/IPv6, route unions, RFC7748 public key derivation, script rejection,
configuration injection, redacted keys and public editor data.
- Local service tests cover authentication, per-account visibility, bounded
messages/drafts, restart-off behavior, active route conflicts, confirmed export,
atomic save preservation and private storage permissions.
- A fuzz target exercises parse/validate/write/parse. Local smoke input ran without
coverage instrumentation; CI uses nightly cargo-fuzz with AddressSanitizer.
- The actual daemon lifecycle passed inside isolated Linux user/mount/network
namespaces: create, save twice, confirmed export, native connect, close/reopen IPC,
service restart, verify Off, delete, and verify empty recovery/storage directories.

## Linux networking

Real gotatun peers exchange encrypted IPv4 and IPv6 UDP payloads through a native
tun interface in an isolated namespace. The tests also verify PSKs, recent
handshake status, byte counters and route/interface cleanup.

A separate namespace test verifies that full-tunnel policy captures more-specific
LAN DNS routes for both address families, excludes WireGuard's marked endpoint
sockets, and removes exact journaled policy/routing entries after simulated crash
recovery. These tests refuse to run in the host network namespace.

Measurements produced by the namespace test describe the two-engine test harness,
not just one production daemon. CI stores throughput, idle CPU and RSS as JSON
artifacts. Package builds separately store compressed size and SHA256 checksums.
No budgets are asserted before representative release measurements exist.

## Desktop and native platforms

The desktop plan records GPUI dependency provenance, Linux runtime/GPU measurements,
Japanese rendering and the exact extent of IME checks. Windows/macOS checks and
remaining hardware checks are recorded in the native networking plan.

Native Linux acceptance also passes under Xvfb with Mesa software Vulkan. It
exercises actual clipboard text and image import, a visible-screen QR, translated
component menus, Japanese input-handler composition, PSK clearing and late key
responses. This does not exercise an OS Japanese candidate-picker.

Installer CI runs the installed service lifecycle on all three operating systems.
Windows/macOS additionally run the opt-in native full-tunnel checks described in
[native-network-smoke.md](native-network-smoke.md). Successful cross-checks are
kept distinct from these runtime tests and from physical desktop acceptance.

## Dependencies and secret lifetime

The QR decoder uses rqrr 0.11 and a patched lru release. cargo-deny checks the
license allow-list, dependency sources and advisories. Six unmaintained transitive
dependencies required by the chosen stack have individual documented exceptions;
no vulnerability advisory is suppressed. cargo-audit also reports an old glib
soundness warning in Cargo.lock, but cargo tree confirms that GTK/glib is absent
from Linux, Windows and macOS builds (Linux uses ksni).

Application-owned secret buffers are zeroized and key Debug output is redacted.
The vendored gotatun patch addresses retained PSKs and diagnostic formatting.
GPUI does not offer secure erasure of its text/renderer allocations; revealed keys
and typed PSKs can leave toolkit-owned memory copies. The application clears
editable text, undo history and its own secret state when leaving the editor.

Before a release, exercise these flows on each actual OS:

- Install as administrator, then launch the app as an ordinary user.
- Add a tunnel using only the three required fields; verify a real handshake.
- Connect two disjoint tunnels and reject an overlapping one.
- Verify DNS and IPv6 during full tunneling, including a network/interface change.
- Stop normally and terminate the daemon unexpectedly; verify route/DNS recovery.
- Type Japanese with the native IME and switch application language.
- Import from config text/file, QR image, clipboard image, drop and screen scan.
- Reveal/hide, export with confirmation, edit/rename/delete and cancel actions.
- Close the window, use the tray, quit the UI, reboot and check login startup.
- Remove the package and confirm the service stops while private configs remain.

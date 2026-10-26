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
- A nightly cargo-fuzz/AddressSanitizer run exercised parse/validate/write/parse
for 61 seconds: 5,434,791 inputs completed without a crash or round-trip failure.
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

Real systemd-resolved 255.4 also passed in private user/mount/PID/network
namespaces with its own system bus. Actual DNS queries verify split-domain
selection, IPv6-only full-tunnel DNS, suppression of more-specific physical
resolver domains, normal restoration, crash-journal recovery and preservation
of later external DNS changes. The fixtures pass with umask 022. This test
verifies resolver selection; the separate engine test verifies encrypted traffic.

Measurements produced by the namespace test describe the two-engine test harness,
not just one production daemon. CI stores throughput, idle CPU and RSS as JSON
artifacts. Package builds separately store compressed size and SHA256 checksums.
No budgets are asserted before representative release measurements exist.
The local Debian archive is 13,769,138 bytes and the CI archive is 13,765,828 bytes
(both 13.1 MiB). Exact source revisions, sizes and checksums are recorded under
[measurements](measurements/). The downloaded CI artifact's digest, contents,
notices and executable modes were also verified without installation.

On a Core i9-13900K with Rust 1.97.1, the local release harness measured
1,683.7 Mbit/s, 0.038% idle CPU and 7,692,288 bytes RSS. This is encrypted
loopback traffic between two userspace engines, not a WAN benchmark.

## Desktop and native platforms

The desktop plan records GPUI dependency provenance, Linux runtime/GPU measurements,
Japanese rendering and the exact extent of IME checks. Windows/macOS checks and
remaining hardware checks are recorded in the native networking plan.

Native Linux acceptance also passes under Xvfb with Mesa software Vulkan. It
exercises actual clipboard text and image import, a visible-screen QR,
component-menu translations, Japanese input-handler composition, PSK clearing
and late key responses. Keyboard tests exercise Tab through scrolled editor/preview controls
and verify that focused controls are visible without overriding manual scrolling.
This does not exercise an OS Japanese candidate-picker.

Windows/macOS installer jobs run the installed service lifecycle and
the native full-tunnel checks described in
[native-network-smoke.md](native-network-smoke.md). Successful cross-checks are
kept distinct from these runtime tests and from physical desktop acceptance.

All workflows now select GitHub-hosted runners, with Windows/macOS enabled by
default ([plan 0010](plans/0010-github-actions.md)). The following results describe
earlier CI runs; changing the runner configuration does not establish a new pass.

Previously, GitHub-hosted runners could not start because of an account billing/spending
limit. Linux verification was moved to the user's Proxmox self-hosted runner.
Only builds and isolated tests are authorized there. Desktop builds provision
dependencies inside disposable containers; Debian installation/service steps are
excluded from the workflow. The self-hosted security audit passed, and
[package CI](https://github.com/Zhujingxi/wg-easy/actions/runs/38291071314)
for PR head `ee7403f` built and uploaded the Debian package. The network job
compiled its release test binaries, then stopped at the explicit `/dev/net/tun`
prerequisite. Both tunnel and real-resolver CI require that device to be exposed
in the guest; those namespace runtime checks passed locally.
The CI fuzz job failed before running tests: the first attempt could not download
Rust, and its retry could not download GitHub actions after repeated TLS failures.
The ASan fuzz evidence above is from the completed local run.
Workspace CI also stopped before compilation: first at the Rust manifest download,
then at the Ubuntu container pull after three connection resets. The completed
local workspace, Clippy and desktop checks remain the available evidence for
those checks. See the [Check run](https://github.com/Zhujingxi/wg-easy/actions/runs/38291071488)
for both attempts; it is not a passing CI run.
No native Windows/macOS installer or runtime pass is claimed.
Locally, full Windows GNU daemon and GUI executables linked, including AWS-LC
assembly and the application icon resources; daemon/IPC/GUI all-target checks
and strict Clippy passed. Platform checks and strict Clippy also passed for
Windows GNU and macOS arm64. The Linux Debian
package was built and its contents, executable modes, dependencies and notices
inspected. The daemon lifecycle was tested in isolated namespaces; actual Debian
package installation, upgrade and removal were not run.

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
- Remove the Debian/MSI package and confirm the service stops while private configs remain.
- On macOS, unload the LaunchDaemon before manually removing application/service files.

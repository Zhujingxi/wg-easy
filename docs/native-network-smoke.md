# Native networking smoke tests

The platform crate includes an ignored `native_full_tunnel_smoke` test for
Windows and macOS. Run it elevated in a disposable CI VM, with no other VPN
active. It temporarily replaces the VM's default routes and DNS, so ordinary
network access pauses while the test is running. It requires the explicit
environment flag `WGE_NATIVE_NETWORK_TEST=1`.

The test creates a real dual-stack tun interface, applies full-tunnel routes,
installs NRPT/WFP on Windows or SystemConfiguration/PF on macOS, and verifies the
native DNS state. It captures IPv4 and IPv6 UDP packets from the OS through tun,
injects replies, and checks the endpoint's local transport remains reachable.
It then verifies DNS, routes, owned PF references and journals are restored.
A second round drops interface/process-owned handles before replaying the
journal, exercising crash recovery.

A separate thread waits for completion or a 30-second deadline, then retries
journal recovery up to three times. It also runs during panic unwinding, before
the temporary recovery directory disappears. The main operation has a 25-second
timeout. The watchdog uses native APIs and no child processes. This is a backup
for test failures; an unresponsive OS API still requires the CI VM to be discarded.

## Windows

Build the platform tests with the same toolchain and architecture used for the
release. Copy the unmodified, signed Wintun DLL from the package input beside
the test executable, as production locates it beside the daemon executable.
With the default Cargo target directory, an elevated PowerShell session runs:

```powershell
cargo test -p wge-platform --lib --no-run
Copy-Item path\to\wintun.dll target\debug\deps\wintun.dll
$env:WGE_NATIVE_NETWORK_TEST = '1'
cargo test -p wge-platform native_smoke::native_full_tunnel_smoke -- --ignored --nocapture --test-threads=1
```

If `CARGO_TARGET_DIR` or `--target` changes the output layout, use the executable
directory reported by Cargo. The installed-service smoke test is separate; the
platform test does not require an installed wg-easy service.

## macOS

Build as the ordinary CI user, then run the resulting test executable as root;
this avoids giving root a separate Rust toolchain/cache:

```sh
cargo test -p wge-platform --lib --no-run
sudo env WGE_NATIVE_NETWORK_TEST=1 /absolute/path/to/wge_platform-HASH native_smoke::native_full_tunnel_smoke --ignored --nocapture --test-threads=1
```

Use the executable path reported by Cargo; CI can extract it from Cargo's JSON
compiler-artifact messages. Existing PF rules that skip physical interfaces
cause a deliberate failure before changes are applied.

## Coverage limits

The runtime smoke needs the actual target OS; cross-compilation does not run it.
The test checks native filter installation and traffic through tun. It does not
simulate a DHCP renewal, physical-interface handover or every policy installed
by other firewalls. The endpoint bypass is local to the VM, so the test sends no
traffic to an external WireGuard server. Linux uses the existing isolated network
namespace tests, including physical-route/DNS containment and a complete
userspace WireGuard handshake with a preshared key.

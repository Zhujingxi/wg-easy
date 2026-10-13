# WireGuard Easy

A native desktop client for WireGuard. Set up a tunnel on one screen, then use
one switch to connect. Built with Rust, GPUI and a bundled userspace WireGuard
engine.

**This is not the [wg-easy/wg-easy](https://github.com/wg-easy/wg-easy) server
project.** It connects this computer to a server; it does not configure servers.

## Set up a tunnel

Install the package for your operating system and open **WireGuard Easy**. Choose
**Add tunnel** and enter the address assigned to this device, the server address
and the server's public key. Copy this device's public peer snippet to your
server configuration, then choose **Save and connect**.

The key pair and the other defaults are filled in for you. The app shows
**Connected** only after a recent handshake. The traffic preview explains which
addresses use the tunnel and warns about overlapping ranges.

- **All traffic** carries IPv4, IPv6 and DNS through the tunnel.
- For a split tunnel, enter the desired ranges. If you add DNS servers, also enter
  the domains they resolve under **Advanced**.
- Several tunnels can run together when their traffic ranges do not overlap.
- Paste or drop a `wg-quick` configuration, or import a QR image. The same editor
  opens so you can check the result before connecting. Script hooks are refused.
- Export asks for confirmation because the file contains a private key. Treat it
  like a password.

Closing the window leaves tunnels running in the background service. You can
reopen the app or use its tray menu to disconnect. Starting the app at login is
optional and off by default; it opens only the tray. Tunnels always start off
after a reboot or service restart.

The interface is available in English and Japanese. Every function is available
in the window, including on desktops without a tray.

Enter a server hostname without a port, such as `vpn.example.com`, to discover
`_wireguard._udp.vpn.example.com` DNS SRV records automatically. SRV provides the
target hostname and port; its A and AAAA records provide IPv4 and IPv6 addresses.
For example:

```dns
_wireguard._udp.vpn.example.com. 300 IN SRV 0 100 51820 server.example.com.
server.example.com.             300 IN A    203.0.113.10
server.example.com.             300 IN AAAA 2001:db8::10
```

Missing SRV records fall back to the entered hostname on port 51820. An explicit
`hostname:port` or IP address bypasses SRV. Failed handshakes try alternative
addresses; discovery tunnels reconnect with fresh DNS after exhausting them.
Healthy connections stay on their working endpoint. A reconnect briefly restores
ordinary networking and interrupts all peers in that tunnel. Changing the server
public key still requires editing the client. DNS caches can delay DNS changes.

Exports contain a resolved endpoint snapshot for standard WireGuard clients.
A `# wg-easy-srv:` comment preserves automatic discovery when reimported here;
other clients use the snapshot. Existing imported `hostname:port` endpoints keep
their explicit port; remove the port in the editor to enable discovery.

## Installers

The **Packages** workflow builds these unsigned installers and SHA256 checksums:

| Platform | Package | Background service |
|---|---|---|
| Linux | `wireguardeasy-desktop_…_amd64.deb` | systemd |
| Windows | `wireguardeasy-desktop_…_x64.msi`, includes Wintun | Windows service |
| macOS | `wireguardeasy-desktop_…_universal.pkg` | launchd |

The installers request administrator permission for the service. The desktop app
runs as your ordinary account. Windows may display a SmartScreen prompt. macOS
requires approval for an unsigned download in System Settings and a restart
after installation; screen QR scanning also requires Screen Recording permission.

Linux packages target Ubuntu 24.04+ or Debian 13+ desktops with systemd and a working GPU.
The package manager installs the native graphics, resolver and Japanese font
libraries as dependencies. The app itself never downloads components.

Private configs remain in service-owned storage when the package is removed.
They are not stored in the desktop's preferences directory.

## Develop

Rust edition 2024, with the minimum compiler version declared in `Cargo.toml`.
On Debian/Ubuntu, install the usual C/C++ build toolchain plus `cmake`, `clang`,
`pkg-config`, `libxkbcommon-dev`, `libxkbcommon-x11-dev`, `libwayland-dev`,
`libxcb1-dev`, `libegl1-mesa-dev`, `libgbm-dev`, `libfontconfig1-dev`, `libvulkan-dev`,
`libpipewire-0.3-dev`, `libclang-dev` and `libasound2-dev`. Then:

```sh
cargo build --workspace --locked
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
```

The native UI needs a GPU/display session. Building the GUI does not install the
privileged service. Use a package to test the complete desktop/service flow;
network tests use isolated Linux namespaces and refuse to alter the host network.

```sh
WGE_HOST_NETNS="$(readlink /proc/self/ns/net)" \
WGE_HOST_MNTNS="$(readlink /proc/self/ns/mnt)" \
  unshare --user --map-root-user --mount --net \
  cargo test -p wge-engine -p wge-platform -- namespace_ --ignored --nocapture --test-threads=1
```

With `/dev/net/tun`, `systemd-resolved` and `dbus-daemon` already available,
`./scripts/test-resolved.sh` checks DNS using a private resolver and system bus
inside user, mount, PID and network namespaces. Run it as an ordinary user.

See [the PRD](docs/PRD.md), [implementation plans](docs/plans/README.md) and
[verification notes](docs/verification.md) for scope and the evidence behind
platform support. Linux CI runs builds in disposable containers, isolated network
tests, dependency/license audits and config fuzzing, and retains tunnel/package
measurements. Windows/macOS builds and native checks are manual opt-in jobs;
GitHub-hosted execution currently requires restoring the account billing allowance.

## Architecture

The privileged daemon owns keys, interfaces, WireGuard engines, routing, DNS and
crash recovery. The unprivileged GPUI app uses typed local IPC; it never links the
engine or platform crate. Ordinary IPC data contains public keys only. Explicit
reveal/export operations carry short-lived zeroizing secret buffers.

No accounts, telemetry, server management, shell hooks, self-updater or CLI.
Application binaries use native OS APIs and never execute system commands.

The application is MIT licensed. Every installer includes dependency notices and
the exact corresponding source revision. The bundled gotatun engine is MPL-2.0;
its small memory-lifecycle patch and original notices are included in `vendor/`.
Wintun is redistributed unchanged with its upstream binary license on Windows.

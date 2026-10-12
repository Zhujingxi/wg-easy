# wg-easy

A simple, clean desktop client for WireGuard. One package to install, a tunnel
set up on one screen, and one switch to connect.

Not related to the server project of the same name (`wg-easy/wg-easy`).

## Scope

**In**

- Desktop: Linux, Windows, macOS.
- WireGuard built in (userspace). The user installs nothing else.
- Tunnels are created and edited in the UI. Nobody has to be handed a file.
- Several tunnels active at once.
- An option to start the app at login, off by default. It starts in the tray
  with no window. Tunnels stay off after a reboot until the user switches them
  on.
- IPv4 and IPv6 for tunnel addresses, routes, DNS and endpoints.
- Import and export of standard `wg-quick` config files.
- QR code import from an image file, pasted image or dropped image, and by
  scanning a QR code visible on the screen.
- English and Japanese.

**Out (non-goals)**

- Kill switch.
- Command line interface.
- Self-updater.
- Mobile.
- Configuring or managing the server side. A separate TUI tool covers that.
- `PreUp` / `PostUp` / `PreDown` / `PostDown` script hooks.
- Telemetry and accounts.
- Code signing of releases.

When a feature is declined, add it to this list.

Everything in scope is for v1, with one priority. See `docs/PRD.md`.

## Philosophy

1. **One job.** Connect this computer to WireGuard tunnels.
2. **Easy and fast setup.** One screen, grouped fields, defaults filled in. Not
   a wizard that asks one question at a time.
3. **Standard files in, standard files out.** No proprietary config format.
4. **Every setting is a cost.** Add an option only when a safe default is
   impossible. Rarely used options go under "Advanced".
5. **Honest status.** Show "Connected" only after a recent handshake.
   Otherwise say what is wrong and what to try, in plain language.
6. **Fast means the tunnel.** Performance is throughput and near-zero idle CPU.
   The GUI is a remote control and can be closed.

## Tech stack

| Area | Choice |
|---|---|
| Language | Rust, edition 2024, for everything |
| GUI | GPUI with the GPUI Kit component library |
| Tray | `tray-icon` on Windows and macOS, `ksni` on Linux |
| WireGuard | `gotatun` (userspace), default `aws-lc-rs` crypto backend |
| Tun device | `tun` crate; Wintun (`wintun.dll`, bundled) on Windows |
| Async runtime | `tokio` |
| Translations | `rust-i18n` |
| QR | `rqrr` to read, `qrcode` to write |
| Licence | MIT |

Do not propose Slint, iced, egui or a webview (Tauri, Electron) for the GUI.
They were considered and rejected.

The GUI, tray, translation and QR crates are chosen but not yet added to
`Cargo.toml`. See `docs/plans/README.md` for what to verify first.

## Architecture

Two processes, shipped in one package per OS:

- **Daemon** (`wg-easy-daemon`): privileged. Owns tunnels, private keys, tun
  devices, routes and DNS. Registered with systemd, launchd or the Windows
  service manager at install time. Keeps running when the window is closed.
- **GUI** (`wg-easy`): unprivileged. A thin client of the daemon over a Unix
  socket (Linux, macOS) or named pipe (Windows).

### Crates

| Crate | Kind | Role |
|---|---|---|
| `wge-config` | lib | Config model, parser, validator and writer for `wg-quick` files. No I/O. |
| `wge-engine` | lib | Tunnel engine. Wraps `gotatun` behind our own types. |
| `wge-platform` | lib | Tun device, routes and DNS for each OS. |
| `wge-ipc` | lib | Versioned request, response and event types for the socket. |
| `wge-daemon` | bin | The privileged service. |
| `wge-gui` | bin | The desktop app. |

Dependencies point one way: `wge-gui` uses `wge-ipc` and `wge-config` only. It
never links the engine or the platform layer.

## Add-tunnel screen

One screen with three groups. Editing a tunnel reuses it.

| Group | Fields | Filled in automatically |
|---|---|---|
| This device | Name, address in the tunnel | Key pair; public key shown with a copy button |
| Server | Address and port, public key | Nothing |
| Traffic | "All traffic" switch or a list of ranges (AllowedIPs), DNS | "All traffic" on |

- Only three values must be typed: server address, server public key, this
  device's tunnel address.
- Preshared key, keepalive, MTU and extra peers are under "Advanced".
- Each field has a one-line hint and is validated as the user types.
- A live preview shows the traffic path, what each range covers (with overlap
  warnings), and the snippet the server needs for this device.
- One button, "Save and connect", which reports a handshake or the specific
  problem.
- Pasting a config, or dropping a config file or QR image, fills the same
  screen.

## Rules for several active tunnels

- Each active tunnel has its own interface and engine instance.
- Active tunnels may not have overlapping ranges. A tunnel whose ranges overlap
  an active tunnel's does not start, and the error names that tunnel and the
  overlapping ranges.
- An "all traffic" tunnel overlaps everything, so it can only be active alone.
- Overlapping tunnels can both be saved. The check runs when one is switched
  on.
- An "all traffic" tunnel's DNS becomes the system DNS. Any other tunnel's DNS
  applies only to its own domains.

## Guard rails

**Security**

- The daemon treats the GUI as untrusted and validates every request.
- IPC has typed commands only, and checks the caller's identity on the socket
  or pipe.
- Private keys live in the daemon. They leave it only when the user clicks
  "Show" on the masked key, or on an explicit export after a confirmation.
  Never log them. Zero them in memory. `Debug` output for key types is
  redacted.
- No home-made crypto.
- `#![forbid(unsafe_code)]` in every crate except `wge-platform`.
- Never run external programs (`ip`, `netsh`, `resolvconf`, ...). Use OS APIs.
- No network traffic other than the tunnels themselves.

**Correctness**

- No leaks while an "all traffic" tunnel is up: DNS and IPv6 use the tunnel,
  and traffic to the server endpoint does not loop back into it.
- If the daemon crashes, it restores routes and DNS when it restarts.
- `wge-config` gets fuzzing and round-trip property tests.
- Tunnel tests run in Linux network namespaces. CI runs on all three OSes.

**Dependencies**

- `Cargo.lock` is committed.
- `cargo-deny` and `cargo-audit` run in CI, including a licence allow-list.
- Keep the dependency count low, most of all in the daemon.

**Text**

- Every user-visible string goes through the translation layer. No string
  literals in UI code.

## Working here

- Product requirements are in `docs/PRD.md`.
- Plans live in `docs/plans/`. Read `docs/plans/README.md` before starting a
  feature, and write a plan for anything larger than a small fix.
- Build: `cargo build --workspace`. Check: `cargo check --workspace`.
  Test: `cargo test --workspace`.
- Match the surrounding code. Keep comments short and about why.
- Do not add a dependency without saying why in the plan or commit message.

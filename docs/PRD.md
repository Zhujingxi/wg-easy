# wg-easy: Product Requirements

Status: draft
Last updated: 2026-10-12

The technical stack and engineering rules are in `AGENTS.md`. This document says
what the product is and what it must do.

## 1. Summary

wg-easy is a desktop app that connects a computer to WireGuard tunnels. The
user installs one package, sets up a tunnel on a single screen, and connects
with one switch. It runs on Linux, Windows and macOS.

## 2. Problem

Setting up a WireGuard client today asks too much of a non-expert:

- Existing clients expect a ready-made config file, or a raw text editor.
- On some systems the user must install kernel modules or command line tools
  first.
- The words (AllowedIPs, endpoint, public key) are not explained, and mistakes
  show up only as "it doesn't work".
- A tunnel can look "on" while no traffic passes.

## 3. Target user

A person who has the details of a WireGuard server (its address and public
key) and needs to connect a desktop computer to it. They may run the server
themselves or have been given the details by someone who does.

They are not assumed to know what a CIDR range is, and they are not handed a
config file.

## 4. Goals

1. **One install.** WireGuard is built in. Nothing else to install.
2. **Easy and fast setup.** A new tunnel takes one screen and three typed
   values.
3. **Understandable.** Settings are explained and shown visually while the
   user edits them.
4. **Honest.** The app shows whether the tunnel is really working, and says
   what is wrong when it is not.
5. **Light.** Disk and memory use are kept as low as the chosen stack allows.
   These are not hard limits.

## 5. Non-goals

- Kill switch.
- Command line interface.
- Self-updater.
- Mobile apps.
- Configuring or managing the server side. A separate terminal (TUI) tool
  covers that.
- Script hooks (`PreUp`, `PostUp`, `PreDown`, `PostDown`).
- Telemetry and user accounts.
- Signed releases.

## 6. Requirements

Every requirement below is for v1. They all have the same priority.

### 6.1 Install and platform

| ID | Requirement |
|---|---|
| IN-1 | Runs on Linux, Windows and macOS desktops. |
| IN-2 | One package per OS contains everything: the app, the background service, and on Windows the tun driver. |
| IN-3 | No kernel module, `wireguard-tools` or other program has to be installed by the user. |
| IN-4 | The installer registers the background service. The app itself never runs with administrator rights. |
| IN-5 | Tunnels keep running when the window is closed. |
| IN-6 | A setting lets the user start the app when they log in. It is off by default. When started this way the app shows only the tray icon, not the window. |
| IN-7 | Platforms are built in this order: Linux, then Windows, then macOS. |

### 6.2 Add and edit a tunnel

One screen with three groups. It is not a wizard that asks one question at a
time. Editing a tunnel reuses the same screen.

| Group | Fields | Filled in automatically |
|---|---|---|
| This device | Name, address in the tunnel | Key pair; public key shown with a copy button |
| Server | Address and port, public key | Nothing |
| Traffic | "All traffic" switch or a list of ranges (AllowedIPs), DNS | "All traffic" on |

| ID | Requirement |
|---|---|
| AT-1 | A tunnel can be created entirely in the UI, with no file. |
| AT-2 | The app generates the key pair and shows the public key with a copy button. |
| AT-3 | Only three values must be typed: server address, server public key, this device's tunnel address. Everything else has a default. |
| AT-4 | The user can choose "all traffic" or enter their own list of ranges (AllowedIPs). |
| AT-5 | Each field has a one-line hint saying what it is and where to get it. |
| AT-6 | Fields are validated as the user types. Errors appear next to the field in plain language. |
| AT-7 | Preshared key, keepalive, MTU and extra peers are available under a collapsed "Advanced" section. |
| AT-8 | One button, "Save and connect", saves the tunnel, connects, and reports a handshake or the specific problem. |
| AT-9 | An existing tunnel can be edited, renamed and deleted. |
| AT-10 | The tunnel's private key appears as a masked block. It is shown only after the user clicks "Show", and can be hidden again. |

### 6.3 Live preview

Shown beside the form and updated as the user types.

| ID | Requirement |
|---|---|
| PV-1 | Each range shows what it covers, for example `10.0.0.0/24` as "10.0.0.0 to 10.0.0.255, 256 addresses". |
| PV-2 | A warning appears when a range overlaps the local network or another tunnel's ranges. |
| PV-3 | A diagram shows this computer, the tunnel and the server, and which traffic goes through the tunnel. |
| PV-4 | The snippet the server needs for this device is shown as text with a copy button. |
| PV-5 | The same snippet is shown as a QR code. |

### 6.4 Import and export

Import is a shortcut into the add-tunnel screen, not a separate flow.

| ID | Requirement |
|---|---|
| IE-1 | Pasting a standard `wg-quick` config, or dropping a config file, fills the add-tunnel screen. |
| IE-2 | Dropping, pasting or opening an image of a QR code fills the add-tunnel screen. |
| IE-3 | A tunnel can be exported as a standard `wg-quick` config file. |
| IE-4 | Export asks for confirmation, because the file contains the private key. |
| IE-5 | Script hook lines in an imported config are refused, with a visible notice. |
| IE-6 | Scan a QR code that is visible on the screen. |

### 6.5 Connect and status

| ID | Requirement |
|---|---|
| CS-1 | The main window lists all tunnels, each with one switch. |
| CS-2 | "Connected" is shown only after a recent handshake. Before that the state is "Connecting". |
| CS-3 | When there is no handshake, the app says so and suggests what to check. |
| CS-4 | A tunnel's detail view shows the last handshake time, data sent and received, and the server address. |
| CS-5 | A tray icon shows the overall state and lets the user switch tunnels and open the window. |
| CS-6 | Every function works without the tray, because some desktops show none. |
| CS-7 | Tunnels do not reconnect after a reboot. Every tunnel is off until the user switches it on. |

### 6.6 Several tunnels

| ID | Requirement |
|---|---|
| MT-1 | Several tunnels can be active at the same time. |
| MT-2 | Active tunnels may not have overlapping ranges. If a tunnel's ranges overlap those of a tunnel that is already active, it does not start. |
| MT-3 | The error names the active tunnel and the ranges that overlap. |
| MT-4 | An "all traffic" tunnel overlaps every other tunnel, so it can only be active alone. |
| MT-5 | Tunnels with overlapping ranges can both be saved. The check applies when a tunnel is switched on. |
| MT-6 | Each tunnel's DNS applies while that tunnel is active. An "all traffic" tunnel's DNS becomes the system DNS; any other tunnel's DNS applies only to its own domains. |

### 6.7 Network

| ID | Requirement |
|---|---|
| NW-1 | IPv4 and IPv6 are both supported for tunnel addresses, ranges, DNS and the server address. |
| NW-2 | While an "all traffic" tunnel is up, DNS and IPv6 traffic also use the tunnel. |
| NW-3 | When a tunnel is switched off, routes and DNS return to what they were. |
| NW-4 | If the background service crashes, it restores routes and DNS when it restarts. |
| NW-5 | A server hostname without a port automatically discovers `_wireguard._udp.<hostname>` DNS SRV records and resolves IPv4 and IPv6 targets. Explicit ports bypass SRV. Missing records fall back to port 51820; DNS failures are reported. |
| NW-6 | Failed discovery endpoints try alternative addresses and reconnect with fresh DNS after exhausting candidates. Healthy connections stay stable. Exported standard configs contain a resolved endpoint snapshot and a comment preserving discovery for wg-easy reimport. |

### 6.8 Language

| ID | Requirement |
|---|---|
| LN-1 | The UI is available in English and Japanese. |
| LN-2 | Japanese text can be typed into fields (tunnel names). |
| LN-3 | Adding a language needs only a new translation file. |

### 6.9 Security and privacy

| ID | Requirement |
|---|---|
| SP-1 | Private keys stay in the background service. They leave it only when the user clicks "Show" or exports the tunnel. |
| SP-2 | Private keys are masked in the UI until the user clicks "Show", and are never written to logs. |
| SP-3 | The app makes no network connections other than the tunnels. |
| SP-4 | Imported files cannot make the app run commands. |

### 6.10 Performance

| ID | Requirement |
|---|---|
| PF-1 | Tunnel traffic never passes through the UI process. |
| PF-2 | An idle tunnel uses close to no CPU. |
| PF-3 | Throughput, idle CPU, memory and package size are measured in CI and tracked over time. |

No numeric budgets are set yet. They will be set after the first real
measurements.

## 7. Constraints

- Rust for all code; GPUI for the UI; `gotatun` for WireGuard. See `AGENTS.md`.
- Licence: MIT.
- Releases are not signed. Windows shows a SmartScreen warning at install.
  macOS blocks the app until the user approves it in System Settings.
- GPUI needs a working GPU as far as is known. There is no fallback UI.

## 8. Risks

| Risk | Effect | Mitigation |
|---|---|---|
| GPUI is young and its API changes. | Rework in the UI. | The UI is a thin client; the service does not depend on it. |
| GPUI memory use is unmeasured. | The app may be heavier than hoped. | Measure an empty window first. |
| Japanese input in GPUI is unverified. | LN-2 may need extra work. | Test in the first prototype. |
| Unsigned macOS builds. | Install is not "easy" on macOS, and registering the service is harder. | Document the manual step; revisit signing if macOS matters. |
| Antivirus false alarms on unsigned Windows builds. | Users cannot install. | Publish checksums; revisit signing if it happens. |
| The name is shared with an existing server project. | Users confuse the two; package names are taken. | Say "not related" in the README; pick package names that differ. |

## 9. Open questions

1. What numeric budgets apply to PF-3, once measured?

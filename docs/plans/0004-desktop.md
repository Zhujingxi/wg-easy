# 0004: Native desktop client

Status: done

## Goal

Implement the PRD's Linux-first native desktop, with the same GPUI views on
Windows and macOS. Use a quiet warm-white canvas, ink typography, emerald
connection state, generous spacing, and a persistent live-preview sidebar.
The user edits one grouped form. Native dialogs, accessible Kit inputs and
buttons provide keyboard navigation and Japanese input.

## Scope and approach

The GUI links only config and IPC project crates. A Tokio worker owns the IPC
connection; the render thread never performs blocking service I/O. Lists and
editor DTOs contain public material only. The daemon generates draft keys and
parses imports. Only explicit Show or confirmed export asks for private keys.
A revealed secret is dropped on Hide, switching views, or closing the window.
All interface text goes through rust-i18n English and Japanese catalogues.

Use GPUI Kit's inputs and buttons, native file dialogs and clipboard APIs,
`rqrr` and `qrcode` for image import/server QR preview, `xcap` for user-triggered
screen capture, `ksni` on Linux and `tray-icon` on macOS/Windows. The tray lives
in the GUI process: a second UI IPC client is unnecessary, and the window is
created only when requested. OS login registration writes standard per-user
desktop/LaunchAgent files or the Windows Run registry key, off by default, with
`--background` for tray-only startup. No auto-launch helper invokes a shell.

Dependencies: gpui-kit provides the chosen GPUI/component stack and assets;
rust-i18n localizes app text; image/rqrr/qrcode decode and render the required
QR workflows; xcap implements explicitly requested screen capture without
shell commands; winreg safely registers Windows login startup; ksni/tray-icon
implement native tray integration; tokio provides the existing async IPC
runtime; serde/serde_json store only language/login preferences; directories
locates per-user settings; zeroize clears explicit exports and revealed keys.
The app instantiates no network client and sends no network traffic. GPUI
contains transitive HTTP client code, which this application never invokes.

## Dependency verification

Checked 2026-10-12 against the published archives and upstream repository:

- GPUI Kit is maintained at https://github.com/longbridge/gpui-kit.
  Its `.github/workflows/release-gpui.yml` and `script/bump-gpui.ts` publish
  the `gpui-pre-*` snapshots from Zed. Thus these are Longbridge-published
  snapshots, not official releases of the stale `gpui` package.
- `gpui-kit =0.7.2` pins `gpui-pre =0.3.8`. The published GPUI package records
  upstream Zed revision `279fe070bb389b79652e52065b2f001edcc0b11b` in
  `[package.metadata.gpui-pre]`. The crates.io ownership endpoint could not
  be reached from this environment; provenance is supported by the upstream
  publishing workflow and packaged revision metadata, not an owner API claim.
- Linux `tray-icon` has a GTK dependency; use ksni's StatusNotifier D-Bus API.
- This host has X11 DISPLAY=:0. Native startup, memory and Japanese input
  results are recorded below. Source support alone is not evidence of a
  successful hardware/IME test.

## Validation

- Linux `cargo build -p wge-gui` and all twelve normal tests pass: IPv4/IPv6
  endpoint defaults, public form conversion, QR config round-trip/rejection,
  commented config import, non-overwriting export, login defaults and quoting,
  complete English/Japanese key parity, and imported IPv4 MTU/automatic port
  preservation, and TIFF clipboard decoding. Strict all-target Clippy also passes on Linux and Windows GNU.
- The explicitly invoked native `desktop-preview` acceptance binary uses
  synthetic public fixtures only in its test source. It captures an empty Kit
  window, tunnel list, English/Japanese editor at 1280×800, and Japanese editor
  at 1120×800. Mandatory fields and the fixed Save and connect bar remain visible.
  Production views receive only daemon responses.
- The native harness drives GPUI's input handler through marked hiragana,
  conversion to kanji and commit (`じたく` → `自宅`). CJK font fallback renders
  correctly. This is a real input-handler test, but not an OS candidate-picker
  test: this host has no Japanese conversion engine configured.
- Delayed private-key replies are rejected after changing editors or reopening
  the window. Existing drafts are discarded on window close; drafts created by
  pending imports are discarded when no window remains. A save already
  requested still connects after the window is closed.
- A real `--background` process stays alive with no application window. With an
  unavailable tray D-Bus address it exits cleanly, leaving no invisible process.
- Linux debug-build measurements after two seconds: empty GPUI+Kit window
  277,424 KiB RSS (271 MiB); real desktop fixture 286,416 KiB (280 MiB). Tray-only
  after three seconds: 75,580 KiB (74 MiB); CPU over a five-second idle sample was
  below the process clock's resolution (0.00%). These are host measurements,
  not release budgets. The tray stays in the GUI process: it does not create a
  window or retain editor state, and measured background memory is much lower.
- With Vulkan/EGL drivers deliberately unavailable, GPUI reports `Failed to
  create surface for any enabled backend`. There is no unsupported fallback UI.
- Windows GNU cross-check passes. Linux-to-macOS cross-check is blocked in the
  upstream `gpui-pre-apple` build script: it does not produce the required
  `stitched_shaders.metal` on a non-Apple host. Native macOS CI is required.
- Application source forbids unsafe code, uses no runtime subprocesses or
  network clients, and links no engine/platform crate. Imports and exports use
  bounded buffers; application-owned text and clipboard-image buffers zeroize
  on drop. Explicit exports create new files (0600 on Unix)
  and never overwrite an existing path.

Local native artifacts: `/home/jingxi/Desktop/wge-artifacts/gui/`.
Run the native check explicitly with
`WGE_PREVIEW_DIR=<artifact-directory> cargo test -p wge-gui --test desktop-preview`.

## Desktop audit follow-up

- Keyboard and native context-menu paste share the same config/QR import path;
  ordinary text still pastes into its focused field. Oversized pasted configs
  fail before IPC. TIFF is explicitly enabled for macOS clipboard images.
- The native acceptance harness checks real GPUI clipboard text/image reads,
  scans a generated QR displayed on the screen, and verifies a masked PSK
  reaches the form conversion correctly. It preserves the previous clipboard.
- Component Cut/Copy/Paste/Select All labels are extended from this app's English
  and Japanese catalogs. Language choices use `available_locales!()`; adding a
  complete locale file, including `language_name` and the namespaced component
  labels, requires no Rust changes. Removed unused marketing translations.
- Relative handshake age refreshes once per second while the tunnel list is
  visible, even if the daemon snapshot is unchanged. No timer remains after
  the view is dropped.
- Temporary form values zeroize, and reading InputState's borrowed Rope avoids
  an extra SharedString copy. Cancel, replacement, save and window close clear
  PSK fields and their undo history, and drop revealed keys. GPUI's Rope,
  SharedString and text-layout caches offer no secure erase API; copies used
  to render an explicitly revealed key cannot be guaranteed wiped. QR decoder
  image storage and the OS clipboard likewise have no secure erase guarantee.
  The app never writes a private key or PSK to the clipboard on its own.
- `rqrr` is upgraded to 0.11, replacing `lru` 0.16 with 0.18.2 to address
  RUSTSEC-2026-0253. QR unit, clipboard and screen tests pass after the upgrade.
- Xvfb with Mesa software Vulkan passes all native assertions, with 243,864 KiB
  empty-window and 269,816 KiB desktop RSS in this debug run. Bare Xvfb lacks an
  EWMH window list, so the explicit headless mode captures its isolated virtual
  monitor. No window manager or physical GPU is required. CI can run:

  ```sh
  WGE_PREVIEW_DIR=artifacts/gui WGE_PREVIEW_HEADLESS=1 \
  VK_DRIVER_FILES=/usr/share/vulkan/icd.d/lvp_icd.json \
  LIBGL_ALWAYS_SOFTWARE=1 xvfb-run -a -s '-screen 0 1280x900x24' \
  cargo test -p wge-gui --test desktop-preview --locked
  ```

  Some Mesa packages name the driver file `lvp_icd.x86_64.json`; use the
  installed `lvp_icd*.json` path. The harness prints RSS to stdout and saves
  raw memory reports and screenshots to the artifact directory.

## Application icons

The application badge uses the same Lucide Waypoints geometry as the sidebar,
white on the ink background. `assets/icon.svg` is the vector source; PNG, ICO
and ICNS variants cover desktop launchers, Windows resources and macOS bundles.
The source attribution and Lucide/Feather terms are included in
`assets/LICENSE-LUCIDE`. ICO sizes are 16–256 pixels; ICNS includes Retina
variants up to 1024 pixels. No generated-image service is used.

`embed-resource` 3 is added as a build dependency, already present transitively,
to compile the Windows icon resource at build time. Resource ID 1 matches
GPUI's native window icon loader. The release GUI uses the Windows subsystem,
so normal and tray-only startup do not open a console window. No runtime
subprocess is added. Pillow reopens the generated containers successfully;
MinGW windres produces a valid `.rsrc` object and the Windows GNU Clippy build
compiles the resource.

## Open questions

Numeric performance budgets remain the PRD's open question. OS Japanese IME
candidate selection, Wayland screen-capture permission behavior, and native
Windows/macOS tray/login behavior still need desktop acceptance runs. macOS
requires its screen-recording permission for QR scanning. These checks are not
claimed by the Linux preview or the Windows cross-check.

## Integrated service and PRD audit

The editor now preserves imported IPv4-only default routes, half-default routes,
default routes on extra peers, and peers without an endpoint. Only the canonical
dual-family default on the first peer enables the all-traffic switch. A new draft
still requires its server address. Blank optional peer rows are ignored; partial
rows are validated, and invalid advanced fields expand Advanced on submission.
Every extra peer can be removed without losing later peers. Stored PSK hints follow
the peer's current public key. Self/duplicate peer keys highlight the offending
row, and clearing a touched required field keeps its error visible.

An active tunnel offers **Disconnect and edit**. Confirmed deletion disconnects
before deleting. Both operations stop on a recovery error; closing the window
after confirming deletion still completes it. Successful actions clear old
notices, and the worker refreshes status/tray immediately after every mutation,
including failed starts. Default routes also receive local-network overlap
warnings.

The service contracts were checked against the actual daemon implementation and
its integration tests: drafts contain a generated name/key and DNS default;
Save returns an Off saved tunnel; Connect returns the engine's honest state;
failed Disconnect returns Recovery and continues blocking mutation. GUI native
assertions drive production handlers with typed responses and verify edit/save/
connect/delete order, error stops, rename, clearing an old error, middle-peer
removal and opening Advanced on an invalid extra peer. These assertions do not
claim a live privileged-daemon GUI session.

| PRD UI requirements | Implementation and evidence |
|---|---|
| IN-5–6, CS-5–7 | Windowless tray lifecycle, explicit quit mode, off-by-default native login registration; background process and missing-tray runs. Daemon owns tunnel/reboot state. |
| AT-1–4 | BeginDraft, generated public key and copy, one grouped editor; unit test fills exactly three values and checks default port/routes. |
| AT-5–7, AT-9 | Shared hinted/validated fields, Advanced, same edit/rename form, safe active edit/delete chains; unit and native command assertions. |
| AT-8, CS-1–4 | Save then Connect, switches and translated engine states/errors, handshake age and byte counters; native handler assertions and screenshot fixtures, daemon state tests. |
| AT-10, SP-1–2 | Explicit Reveal intent, masked block, generation guard and clearing; native PSK/reveal tests. Toolkit memory-copy limits documented above. |
| PV-1–5, MT-2–5 | Config range coverage/overlap functions, path diagram, public snippet/copy/QR; native previews, QR round trip and shared config tests. Daemon enforces exclusivity on Connect. |
| IE-1–6, SP-4 | File/drop/clipboard imports enter the editor, confirmed protected export, typed hook refusal, screen capture; parser, file, clipboard/image and native screen-QR assertions. |
| NW-1 | Shared IPv4/IPv6 parsing and default endpoint port; form round trips preserve imported route/endpoint choices. |
| LN-1–3 | Complete locale files and runtime locale discovery; EN/JA screenshots/key parity and native Japanese composition. OS IME picker remains a desktop acceptance check. |
| SP-3, PF-1 | No network client or engine/platform GUI dependency; Tokio owns IPC only. |
| PF-3 | Native harness emits RSS and screenshots; package CI owns throughput, idle CPU and package size tracking. |

Native keyboard assertions dispatch real Tab, Space and Enter events: Tab moves
from the server key to the traffic switch, Space toggles it, and Tab/Enter from
DNS opens Advanced. The existing Kit focus traversal and activation work without
custom app keybindings. Network containment/recovery, installation and native
Windows/macOS behavior are verified by their owning workstreams, not simulated
by GUI screenshots.

The pinned toolkit does not scroll a newly focused control into view: a native
reproduction tabbed to an input at y=970 in a 400-pixel viewport. A shared small
wrapper now reveals fields, buttons and tunnel rows on focus entry in the three
scroll regions. It uses GPUI's existing focus/layout/scroll APIs, adds no dependency,
and leaves manual scrolling alone while focus stays on the same control. Native
acceptance tabs through Advanced to the PSK and DNS-domain fields and checks their
actual bounds, then tabs to the preview copy button and activates it with Enter.
A separate native reproduction verifies a visible control does not change the
scroll offset; the acceptance suite verifies manual scrolling is preserved.
Linux and Windows GNU strict all-target Clippy pass after the integration.

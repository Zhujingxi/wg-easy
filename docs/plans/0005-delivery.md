# 0005: Installable desktop packages and release verification

Status: in progress

## Goal

Ship one unsigned package per desktop OS with the GUI, privileged service,
translations, icons and Windows Wintun runtime. Build, test and audit on all
three platforms; retain measured performance artifacts without inventing budgets.

## Approach

Linux uses a Debian package with a systemd unit, desktop entry and icon. Windows
uses a WiX MSI with native ServiceInstall/ServiceControl records and private
ProgramData storage. macOS uses an unsigned Installer package with an application
bundle and a LaunchDaemon. The macOS package requests a restart so launchd reads
the installed service without the app spawning launchctl or requiring code signing.
The GUI never requests elevation. Runtime binaries do not execute external tools.
Build/installer scripts use the platform packaging and service-management tools;
these are packaging operations, not tunnel configuration.

The Linux socket authenticates kernel UIDs and the Windows pipe authenticates
SIDs. Local accounts may manage their own tunnels; traffic conflicts are checked
across accounts. Installer-owned service directories cannot be modified by GUI
users. On Linux use a local-user socket with a non-writable parent; on macOS use
the system staff group. Windows installer ACLs restrict stored keys to SYSTEM and
Administrators. Uninstall stops the service before removing files and keeps
private configurations unless the user deliberately removes them.

CI checks formatting, all workspace tests and Clippy on Linux, Windows and macOS.
Linux also runs real engines inside network namespaces, fuzzes the parser with
nightly instrumentation, and records tunnel throughput/idle CPU/RSS. Release jobs
record each package's compressed size and attach SHA256 checksums. cargo-deny
checks a documented license allow-list; cargo-audit checks the committed lockfile.

Build-only dependencies/tools: dpkg-deb to produce Debian archives, WiX to produce
MSI service records, and Apple's pkgbuild/productbuild for the native Installer.
Wintun0.14.1 is downloaded at build time from the official site, verified against a
pinned SHA256, and bundled unchanged with the upstream redistribution license.
No runtime downloads or self-updater.

Build-time cargo-about generates the dependency license notices included in every
installer. SOURCE.txt points to the exact source revision, including the modified
MPL-2.0 gotatun sources and retained notices. Windows service recovery restarts a
failed daemon so its journal can restore native network state.

Release binaries use thin LTO and strip symbol tables. Linux packages declare
their actual glibc 2.39 baseline and directly linked graphics libraries. Debian
upgrades stop the old service before replacement and start the new executable.
Native icon and Lucide license files are shared by all package formats.

## Tests

Inspect package contents and permissions; exercise service start/stop in isolated
CI runners. Require workspace checks for every OS, native networking namespace
checks on Linux, and smoke-test the real desktop on Linux. Preserve exact scope of
manual GPU/IME and native OS testing in the release checklist.

Package jobs install their artifact and run the actual daemon's authenticated
create/save/export/connect lifecycle, close/reopen IPC, restart the service and
verify the saved tunnel stays off. Linux tests reinstall/upgrade as well. Native
Windows/macOS full-tunnel smoke checks exercise DNS, filters, IPv4/IPv6 tun traffic
and journal restoration in disposable runners with a recovery watchdog.

The Linux daemon lifecycle also passed locally in isolated user, mount and network
namespaces, using temporary service directories and a real tun interface. Desktop
acceptance under Xvfb/software Vulkan verifies clipboard and screen QR import,
Japanese input-handler composition, component translation and secret-state cleanup.

## Out of scope

Code signing, publishing a release without review, telemetry, accounts, CLI and
automatic reconnect are excluded by the PRD.

## Open questions

The first CI runs establish measured budgets. Native Windows/macOS networking
and Japanese IME input require their actual desktops; cross-compilation alone
cannot establish their runtime behavior.

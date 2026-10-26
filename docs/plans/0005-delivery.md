# 0005: Installable desktop packages and release verification

Status: done

CI runner configuration below is historical; [plan 0010](0010-github-actions.md)
replaces it with GitHub-hosted runners and all three platforms enabled by default.

Implementation is complete. Native platform and installer acceptance remains
pending where listed below and in [verification](../verification.md).

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
Administrators. Debian/MSI uninstall stops the service before removing files and
keeps private configurations unless the user deliberately removes them. macOS
removal requires manually unloading the LaunchDaemon and removing its files.

CI checks formatting, all workspace tests and Clippy on Linux by default.
Windows/macOS jobs are manual opt-in while hosted runners are billing-blocked.
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

The persistent Linux runner builds in disposable Ubuntu containers and never
installs the application or starts its service. Build libraries are installed
only inside those containers; network checks use unprivileged namespaces.
Optional hosted Windows/macOS package jobs install their artifact and run the
actual daemon's authenticated create/save/export/connect lifecycle, close/reopen
IPC, restart the service and verify the saved tunnel stays off. Their native
full-tunnel smoke checks exercise DNS, filters, IPv4/IPv6 tun traffic and journal
restoration in disposable runners with a recovery watchdog.

The Linux daemon lifecycle also passed locally in isolated user, mount and network
namespaces, using temporary service directories and a real tun interface. Desktop
acceptance under Xvfb/software Vulkan verifies clipboard and screen QR import,
Japanese input-handler composition, component translation and secret-state cleanup.
A real systemd-resolved service also passes split/full DNS, restoration and crash
recovery checks using a private system bus and resolver inside isolated namespaces
([plan 0008](0008-resolved-verification.md)).

## Out of scope

Code signing, publishing a release without review, telemetry, accounts, CLI and
automatic reconnect are excluded by the PRD.

## Open questions

The first representative measurements will establish budgets. Local release
tunnel measurements and a real Debian archive are recorded in verification.md.
GitHub-hosted runners are blocked by account billing. Linux verification uses
the user's Proxmox runner with labels `self-hosted, linux, x64, wg-easy-ci`.
Only builds and isolated tests are authorized on that persistent guest; the
Debian install smoke is excluded from the workflow. Hosted Windows/macOS jobs
are available through the optional manual input. Native Windows/macOS installer/network acceptance and
OS Japanese candidate-picker checks remain explicit release-validation limits.
Cross-compilation is not runtime evidence.

# 0011: Repair CI and installer failures

Status: done

## Goal

Restore all Check and Packages jobs on GitHub-hosted Linux, Windows and macOS,
and fix defects uncovered by the checks without weakening them.

## Approach

- Update vulnerable locked dependencies to patched compatible releases.
- Review new maintenance advisories and document any unavoidable transitive
  dependencies using the existing advisory policy.
- Adopt current Clippy suggestions in the Linux tray and Windows DNS decoder.
- Give the Windows installer's permanent private-state directory and
  multi-file unversioned license bundle stable component GUIDs, and exercise
  packaging and native service checks. WiX cannot generate GUIDs for these.
- Fix further reproducible failures in the connected code as they surface.
- Match absent and unspecified on-link gateways consistently when recovering
  owned routes; Windows reports these as `0.0.0.0` or `::`. Test both families
  and preserve the interface and real-gateway ownership checks. Include the
  destination and interface in route-install errors for actionable diagnosis.
- Preserve local subnet-broadcast host routes alongside the existing limited
  broadcast exception. Windows rejects moving its broadcast host route to the
  tunnel; WFP/PF still contain ordinary physical-interface traffic. Test subnet
  broadcasts without treating `/31`, `/32` or IPv6 addresses as broadcasts.
- Wait for native interface removal between smoke rounds, using the same helper
  as engine reconnects, so the second round cannot reopen an adapter being torn
  down asynchronously.
- Enumerate live IP interfaces in that helper, rather than consulting Windows'
  persistent interface-name/LUID mapping. Test waiting for a live interface and
  immediate completion for an absent name.
- Save packaging build caches even if subsequent native acceptance fails, so
  repairing a runtime failure does not require rebuilding unchanged dependencies.
- Preserve gotatun's fatal I/O error in engine status and show public status in
  installed-service acceptance failures, so failures identify their actual cause.
- Accept a route deletion's missing-route error only after a fresh table confirms
  that saved route is absent, covering kernel/interface cleanup races. Preserve
  ownership checks and include destination/interface details for other deletion
  errors. Exercise repeated deletion against a real route in a Linux namespace.
- Exclude the macOS loopback interface from physical-route overrides. Local
  IPv6 addresses can have host routes on `lo0` without themselves being loopback
  IPs, and must remain locally delivered rather than displaced into the tunnel.
- Preserve native IPv6 link-local routes as well as loopback/multicast routes.
  Link-scoped subnets cannot move to a different interface. Test this policy with
  Darwin's embedded interface scope and ordinary IPv4/global IPv6 subnets.
- Match PF token ownership using the kernel's `MAXCOMLEN` byte limit instead of
  userspace `proc_name`'s longer `pbi_name`. Test this using the actual long
  test-binary name; retain PID and pre-existing-token checks.
- Retain the installed-service client's last connection error and capture the
  macOS LaunchDaemon's stderr during CI acceptance, so startup/access failures
  can be diagnosed. Add the stderr path only to the CI-installed plist before
  its first bootstrap; avoid launchctl debug and its extra startup kickstart.
  Bound service-management commands to 30 seconds and print launchd state on exit.
- Set the IPC socket directory's group explicitly to the service's effective
  group after validating its ownership and permissions. macOS otherwise inherits
  `/var/run`'s group rather than the LaunchDaemon's `staff` group, denying GUI
  access to the restricted directory/socket. Test correcting a different group
  as root and assert the bound socket's group in the Unix IPC integration test.
- Disable Windows UDP ICMP connection-reset reporting at socket creation, so
  probing an offline peer cannot terminate the receiver and then the tunnel.
  Keep other setup/I/O errors visible. Test receiving after a closed-port probe
  with IPv4, IPv6 and dual-stack sockets in the regular workspace suite.
- Construct the native smoke watchdog's timeout inside its Tokio runtime,
  so recovery can restore routes/DNS rather than panic before it runs. Cover
  watchdog startup and repeated cleanup with an unprivileged regression test.
- Use an IPv4 control socket for Darwin IPv4 address ioctls instead of
  netconfig's IPv6 socket. Keep point-to-point destination and native ABI fields
  explicit; test the IPv4 sockaddr header and byte order.
- Mark the Darwin IPv6 peer destination absent (`AF_UNSPEC`), rather than
  advertising `::` as an explicit peer. The kernel restricts explicit peers to
  `/128` and installs a peer host route. Native acceptance uses `/64` to exercise
  normal IPv6 subnet addresses. Include address/route-restoration error context.

No new product features or dependencies are planned.

## Validation

All nine GitHub Actions checks pass on implementation commit `ae083bd`:

- Check run [40404489591](https://github.com/Zhujingxi/wg-easy/actions/runs/40404489591):
  formatting, workspace check/test/Clippy/build on Linux, Windows and macOS;
  cargo-deny/cargo-audit; parser fuzzing; encrypted IPv4/IPv6 namespace tests;
  real systemd-resolved integration; native desktop acceptance.
- Packages run [40404489571](https://github.com/Zhujingxi/wg-easy/actions/runs/40404489571):
  Debian, Windows MSI and universal macOS Installer builds. Windows and macOS
  native full-tunnel DNS/filtering/recovery tests and installed-service lifecycle
  tests pass, including leaving a tunnel running after GUI disconnect and
  verifying saved tunnels stay off after a service restart.

Local Rust 1.99.1 checks also passed: formatting, workspace check/test/Clippy/build,
security checks, Linux namespace traffic/recovery, resolver integration and
native desktop acceptance using Xvfb/software Vulkan. Focused regressions cover
route ownership and repeated deletion, broadcast/link-local route policy,
interface liveness, watchdog startup, Darwin address ABI, PF ownership, fatal
engine status and receiving UDP after probing an unreachable peer.

The socket-directory regression fails before group correction and passes after
it as root in a disposable Linux container. Unix IPC integration passes as root
and as an unprivileged user, including the socket-group assertion. Hosted macOS
acceptance confirms the unprivileged client can connect to the installed daemon.

No existing checks were disabled, no dependencies were added, and the application
retains its default AWS-LC backend. Verification covers disposable hosted VMs;
physical desktop hardware was not part of this repair.

## Open questions

None for this CI repair.

# 0011: Repair CI and installer failures

Status: in progress

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

Run formatting, workspace check/test/Clippy/build, cargo-deny, cargo-audit,
and relevant native Linux tests locally. Use GitHub Actions for Windows/macOS
builds, installers, native networking and installed-service lifecycle tests.
Keep all existing security and acceptance checks enabled.

Local Rust 1.99.1 verification passes: formatting, workspace check/test/Clippy/
build (81 tests), cargo-deny, cargo-audit, all three Linux namespace tests,
real systemd-resolved integration and native desktop acceptance using
Xvfb/software Vulkan. All six hosted Check jobs and Linux packaging passed
on the initial repair commit. Windows packaging then exposed a second invalid
auto-generated GUID in the unversioned license bundle. With both GUIDs fixed,
the MSI builds; the Windows native smoke then exposed the watchdog's runtime
panic, which also prevented restoring DNS for artifact upload. Native networking
and installed-service checks remain to be verified after the watchdog repair.
The watchdog regression reproduces the original reactor panic and passes with
the fix using the actual watchdog source and platform recovery function in a
temporary Linux harness. Windows platform tests also cross-check and pass
Clippy with warnings denied; native Windows execution remains a hosted check.
After that repair, native setup reports Windows error 5010 (object already
exists), while recovery and artifact upload work. The route matching regression
passes for absent/unspecified gateways in IPv4 and IPv6 and rejects real gateway
and interface mismatches. Platform unit tests, Windows cross-target Clippy and
the Linux encrypted IPv4/IPv6 cleanup namespace test pass after the route repair.
The macOS package builds, then its native smoke fails with `EINVAL` from the
IPv4 address ioctl through netconfig's IPv6 control socket. The replacement
uses Darwin's 64-byte IPv4 alias request on an IPv4 socket. Darwin cross-target
check and Clippy pass, including the sockaddr ABI regression; native execution
must be verified on the hosted macOS runner.
Route context narrowed Windows error 5010 to the runner's local subnet broadcast
(`10.1.15.255/32`), which the override planner attempted to migrate. Subnet
broadcasts now remain OS-owned. Platform unit tests and Windows/macOS cross-target
Clippy pass after this change; native acceptance remains a hosted check.
The Windows smoke now passes its traffic and route/DNS cleanup checks, then
times out on interface removal. That wait now checks the live IP-interface
table rather than retained name/LUID mappings. Its live/absent-interface test
passes locally, as do platform unit tests and Linux/Windows/macOS Clippy checks.
Windows native networking now passes on `9fe4e5d`, and MSI installation and
restart-off behavior pass. The installed-service test then observes a failed
tunnel after reconnecting its client. The engine now preserves the device's
fatal I/O error and the acceptance assertion includes public status. The error
accessor unit test, engine/daemon tests, core Clippy and Linux namespace tests for
an unreachable peer and encrypted IPv4/IPv6 cleanup all pass. Windows still needs
to report its underlying installed-service failure on the next hosted run.
macOS on `9fe4e5d` reaches setup but reports `EEXIST`. Its IPv6 alias request
declared `::` as an explicit point-to-point peer. The corrected request marks
that field absent and native acceptance now exercises a `/64`. Apple's
`bsd/netinet6/in6.c` validates explicit peer destinations only with `/128`.
Platform unit tests and Darwin/Windows cross-target Clippy pass; the next native
run will confirm setup and any remaining error now includes address/restore-route
context.
The new unreachable-peer namespace fixture now explicitly sets its recovery
directory to `0700`, matching the other fixtures. Hosted runners' umask exposed
that missing fixture setup; the production privacy check remains unchanged.
The failure reproduces locally with umask `022`; the corrected fixture passes
under that same umask, and engine Clippy/formatting checks pass.
On `4eb95a0` all six Check jobs, Linux packaging and Windows packaging (including
native networking and installed-service lifecycle) pass. macOS alone reports
`ESRCH` during native networking. Confirmed-absent route deletion is now idempotent;
the real namespace test deletes a route twice and reinstalls it before checking
full-tunnel traffic and recovery. That test, platform unit tests and all three
platform Clippy checks pass locally; macOS native confirmation is pending.
The next macOS error identifies a local IPv6 link-local host route on `lo0` as
the route incorrectly selected for displacement. The planner now excludes that
interface, in addition to loopback IP addresses. Darwin/Windows platform Clippy
and formatting pass; the existing native smoke is the regression for this case.
After preserving `lo0`, macOS reports an unreachable route while trying to move
the physical link's scoped `fe80:7::/64` subnet to utun. Link-local IPv6 routes
now remain on their original link under the existing firewall containment.
The route-policy regression, platform unit tests and all three platform Clippy
checks pass; native macOS verification remains pending.
Native macOS now completes address and route setup but cannot recognize its PF
reference. Apple's kernel writes only `MAXCOMLEN` (16) bytes of the process
command to PF tokens; userspace `proc_name` can return a longer name. Applying
the kernel's byte limit fixes ownership matching for long executable names,
including the platform test binary. The new process-identity regression
cross-checks and passes Darwin Clippy; hosted native confirmation is pending.
On `e670996` the macOS native smoke passes, including address/route/DNS setup,
PF reference ownership and crash cleanup. Package installation then succeeds,
but the installed-service client times out before making its first request.
The retry helper now reports its last connection error, and the CI LaunchDaemon
run captures startup stderr. Acceptance-test compilation, daemon Clippy, workflow
YAML parsing and lifecycle shell syntax pass locally; the service diagnosis is
pending hosted execution.
Windows on `c63e24a` intermittently stops the installed-service tunnel with
`channel closed`. Its closed loopback UDP endpoint can produce a Windows
ICMP connection-reset receive error, which ends gotatun's buffered receiver
and closes the tunnel channel. Socket creation now disables that Windows
reporting using `SIO_UDP_CONNRESET`; no general I/O errors are suppressed.
The new UDP regression, engine/daemon tests and engine Clippy pass locally.
Windows socket code also cross-checks and passes Clippy using the ring backend
for this compilation-only check; the product continues using AWS-LC.
Native Windows validation and macOS installed-service diagnostics remain pending.
On `ac77165` all six Check jobs and Linux/Windows packaging pass, including the
new UDP regression and Windows installed-service lifecycle. macOS native
networking also passes. Its package job hits the one-hour limit in the new
diagnostic `kickstart`, immediately after `launchctl debug` reports configuration;
no service test runs. CI now captures first-launch stderr with a temporary
`StandardErrorPath` entry instead, and bounds launchctl calls so this failure
cannot hide subsequent diagnostics for an hour. The shipped plist is unchanged.
The first `3f94268` macOS job lost runner communication during native networking
and uploaded no logs. A rerun passes native networking, then reports IPC
`PermissionDenied` while launchd confirms the daemon remains running. The socket
directory now explicitly uses the service's effective group, correcting macOS
parent-group inheritance without relaxing its `0750`/`0660` access policy or
peer authentication. The privileged group-correction regression fails before
the fix in a disposable Linux container and passes afterward. The Unix IPC
integration passes as both root and an unprivileged user, including the socket
group assertion. Daemon tests, formatting and Clippy pass. Native macOS
confirmation is pending.

## Open questions

Further failures may be hidden behind the currently failing steps.

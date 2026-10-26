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
- Construct the native smoke watchdog's timeout inside its Tokio runtime,
  so recovery can restore routes/DNS rather than panic before it runs. Cover
  watchdog startup and repeated cleanup with an unprivileged regression test.
- Use an IPv4 control socket for Darwin IPv4 address ioctls instead of
  netconfig's IPv6 socket. Keep point-to-point destination and native ABI fields
  explicit; test the IPv4 sockaddr header and byte order.

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
is verified on the hosted macOS runner.
Route context narrowed Windows error 5010 to the runner's local subnet broadcast
(`10.1.15.255/32`), which the override planner attempted to migrate. Subnet
broadcasts now remain OS-owned. Platform unit tests and Windows/macOS cross-target
Clippy pass after this change; native acceptance remains a hosted check.
The Windows smoke now passes its traffic and route/DNS cleanup checks, then
times out on interface removal. That wait now checks the live IP-interface
table rather than retained name/LUID mappings. Its live/absent-interface test
passes locally, as do platform unit tests and Linux/Windows/macOS Clippy checks.

## Open questions

Further failures may be hidden behind the currently failing steps.

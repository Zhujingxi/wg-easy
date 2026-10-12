# 0007: Service trust-boundary review

Status: done

## Goal

Review the integrated daemon and IPC implementation for account isolation,
bounded requests, secret lifetime, atomic storage and network recovery failures.
Fix concrete issues with focused regression tests without changing the UI API.

## Approach

- Bound serialized frames before allocation. Serialize into exact-capacity
  zeroizing buffers so reallocation cannot leave secret copies behind.
- Encode explicit secret transfers as Base64 on the wire, keeping ordinary
  private config responses out of serde JSON's unzeroized escape scratch buffer.
  The encoded value is still secret and is zeroized. Add the existing workspace
  `base64` dependency to IPC for this codec; no home-made encoding or crypto.
- Read stored files into fixed-size zeroizing buffers and borrow their UTF-8
  contents. Use the native Windows durable atomic replacement helper.
- Create Windows service directories atomically with protected SYSTEM/Administrators
  permissions, then verify their owner, ACL and non-reparse identity through a native
  handle. Reuse the helper for tunnel storage and recovery journals.
- Page large tunnel lists within the existing IPC frame bound. The IPC client
  assembles pages transparently; the UI still receives one complete snapshot.
  Cross-account conflict errors omit the other account's private name and ranges.
- Validate public models before merging private keys, and keep failure recovery
  states visible until service restart restores the journal.
- Scan sorted route ranges when checking conflicts, avoiding quadratic work on
  large disjoint configurations while holding the service mutex.
- Ensure server error exits finish network shutdown instead of cancelling an
  in-flight network change; continue authenticating named-pipe callers after read.

## Native service follow-up

- Explicitly set socket-directory access after validating its owner and type;
  launchd's 0077 umask must not remove the staff group's traversal permission.
- Replace the Windows shutdown bridge's blocking receive with a Tokio oneshot.
  A listener failure must be able to shut down the runtime before SCM sends Stop.
- Exercise server shutdown while a network mutation holds the service lock,
  including cleanup failure propagation.
- Add opt-in installed-service tests for disposable native CI machines. The first
  phase saves and activates a narrow split tunnel, tests explicit export and a
  second GUI connection, and records only its public tunnel ID. After the CI
  service-manager restart, the second phase verifies the tunnel is off and removes
  it. Loopback is the peer endpoint; system DNS and default routes are untouched.

## Validation

- `cargo test -p wge-daemon -p wge-ipc`: 26 tests pass, including explicit
  secret round trips, oversized outbound frames, repeated pagination cursors,
  large tunnel collections, cross-account mutations/conflicts, sorted range
  intersection, failed shutdown, pending network changes and persistent recovery status.
  Two installed-service tests remain ignored by default. Both passed against the
  actual daemon and TUN in isolated Linux user/mount/network namespaces with
  temporary `/run` and `/var/lib`, including graceful restart, startup-off and
  empty storage/recovery journals after cleanup. Native installer CI still needs
  to verify the package/service-manager integration on every OS.
- Strict Clippy passes for daemon/IPC on Linux, and IPC on Windows.
- IPC all-target checks pass for Windows GNU and macOS arm64. The Windows
  private-directory helper passes the platform all-target check; native ACL
  descriptor tests are included for Windows CI.
- Full Windows GNU daemon/IPC all-target checks, strict Clippy and the actual
  daemon executable link pass with MinGW and NASM, including AWS-LC assembly.
  macOS full-daemon cross-compilation still requires its C toolchain/SDK.
- Packaging/CI were reviewed read-only. MSI creates a matching protected state
  ACL; runtime storage now also verifies it. Native Windows/macOS DNS, filter,
  installation and service runtime checks remain necessary.
- Windows storage tests require an elevated account whose default owner is
  Administrators, or SYSTEM, matching the installed service's security model.

## Installed-service CI commands

Set `WGE_INSTALLED_SERVICE_TEST=1` and `WGE_SERVICE_SMOKE_STATE` to an absolute
path for a temporary public tunnel-ID file. Use the same ordinary desktop account
for both test phases. The installer owns the privileged service account.

```text
cargo test -p wge-daemon --test installed_service installed_service_connect_and_leave_running --locked -- --ignored --exact --nocapture
```

Restart the installed service through systemd, SCM or launchd, then run:

```text
cargo test -p wge-daemon --test installed_service installed_service_restart_is_off --locked -- --ignored --exact --nocapture
```

The second phase deletes the test tunnel before checking its result. Run it for
cleanup whenever the public-ID file exists. These tests do not claim native
execution until their installer CI jobs pass.

## Out of scope

Platform networking changes remain in plan 0003. Package changes remain in
plan 0005. This review does not claim native Windows/macOS runtime validation.

## Open questions

None.

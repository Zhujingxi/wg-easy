# 0008: Isolated Linux resolver integration evidence

Status: done

## Goal

Exercise the production systemd-resolved D-Bus path with the real resolver:
split domains, full-tunnel DNS selection, restoration and journal replay.
Existing namespace tests cover packet routing but use no DNS service.

## Approach

A test-only harness starts dbus-daemon and systemd-resolved inside fresh user,
mount, PID and network namespaces. A private tmpfs hides the host's /run,
including its system bus and resolver state. Private resolver configuration
removes fallback servers. The host resolver and services are never contacted.
The service runs as the mapped ordinary user so no host account changes or
privileged installation are needed. The Rust integration test uses production
prepare/apply/restore/recover functions and checks actual D-Bus properties and
queries. No fake resolver API and no new crate dependency.

## Validation

Run only through the isolation harness. Verify namespace identities before any
network change, require a private D-Bus address and a harness opt-in flag, and
bound startup and query deadlines. PID-namespace teardown kills every helper.
Record the installed resolver version and observed results in the final evidence.
Native Windows/macOS verification and package installation remain out of scope.

Run `./scripts/test-resolved.sh` as an ordinary user from the repository root.
It uses the existing `/lib/systemd/systemd-resolved` and `dbus-daemon`; it installs
nothing. `WGE_RESOLVED_BINARY` may point to an extracted resolver binary instead.
The harness builds its test, then starts the helpers only after isolating their
filesystem and network. The system bus daemon finishes startup before the
resolver launches. A 60-second outer timeout bounds the entire isolated run.

The test passed with systemd-resolved **255.4-1ubuntu8.17**, including under
umask 022. Actual queries through the real UDP stub select the tunnel's IPv4 DNS
for its split domain and the physical DNS for other domains. With full tunneling,
an IPv6-only upstream handles every domain, including the physical interface's
more-specific domain. Normal stop and durable journal replay restore the
physical DNS. A separately applied DNS change survives cleanup.

The DNS fixtures bind locally assigned addresses on isolated interfaces. They
establish real resolver selection and IPv4/IPv6 DNS protocol use; encrypted
transport and physical-route containment remain covered by the separate network
namespace tests. Those existing tests should use the `namespace_` name filter;
the resolver test deliberately refuses to run without this private-service harness.

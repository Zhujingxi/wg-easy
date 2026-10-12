# 0002: Authenticated local service and tunnel ownership

Status: done

## Goal

Keep private keys and tunnel lifetime in a privileged service. Expose a bounded,
versioned, typed local protocol to an unprivileged desktop app. Persist ordinary
wg-quick files privately, validate every edit, enforce active route conflicts,
and start with every tunnel off after a service restart.

## Approach

The service generates keys before editing starts. Public DTOs never contain
private or preshared keys; explicit reveal and confirmed export return a
zeroizing, redacted text type. Imports become temporary drafts and pass the same
validation as UI edits. Each authenticated OS user owns their own saved tunnels.
Writes are atomic and synced, and IDs rather than names determine storage paths.
The service refuses editing/deleting a connected tunnel until it is disconnected.

IPC uses a four-byte length followed by versioned JSON, capped at 1 MiB, with
request timeouts and a limit on concurrent clients. Unix peer credentials and a
restricted socket directory protect the service. Windows named-pipe wiring and native caller identity checks arrive with plan
0003; this layer provides the portable protocol and service state. Errors have stable codes so the GUI translates them.

Dependencies: serde/serde_json for typed framing and metadata; zeroize for secret
buffers; getrandom for OS-generated private keys/opaque IDs; Tokio io-util/sync
for bounded local transport; rustix for safe Unix credentials and secure file
opens. Native Windows identity/service helpers belong in wge-platform, the only
crate that permits unsafe code.

## PR boundaries

1. Configuration/parser and public model.
2. IPC, secure storage, validated service logic and tests.
3. Native tunnel engine/platform integration and service executable.
4. Desktop GUI, translations, QR, tray and login integration.
5. Installers, CI, namespace/performance checks and release documentation.

Each change is reviewed and tested before the next layer is published. No PR is
merged automatically; the PR stack remains available for review.

## Tests

Bounded framing, incompatible versions, secrets redacted from Debug, permission
checks, isolated per-user persistence, atomic reload, malformed edits, confirmed
export, draft lifecycle and route-conflict behavior. Test engine behavior with
real network namespaces separately from service state tests.

## Out of scope

No CLI, reconnect-on-boot, remote API, server administration or script execution.

## Results

21 config tests and 13 IPC/service tests pass, including actual Unix socket
framing and authenticated per-account draft visibility. Strict Clippy passes.
Windows transport authentication and OS service entry points are integrated in
0003 together with the native platform helpers.

## Open questions

Native Windows/macOS runtime checks need their respective CI runners. Host
network mutations must only run in isolated test namespaces.

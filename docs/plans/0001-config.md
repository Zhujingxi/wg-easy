# 0001: Standard WireGuard configurations

Status: done

## Goal

Implement the shared, I/O-free configuration boundary for importing, editing,
validating and exporting standard `wg-quick` files. Support both IP families,
multiple peers, private-key redaction and zeroization, public editing models,
range previews, overlap checks and the server-side peer snippet.

## Scope

This plan owns `wge-config` and its fuzz target. Daemon storage, IPC transport,
network changes and rendering belong to later plans. Hooks and unsupported
`wg-quick` settings are explicitly refused rather than silently dropped.

## Approach

- Use small typed models and a line-oriented parser with bounded input. Preserve
  interface host bits and report fields and line numbers without quoting secrets.
- Store private and preshared keys in zeroizing types with redacted `Debug`.
  Public models contain no private keys. Export must be explicitly requested and
  returns a zeroizing string; callers are responsible for confirmation.
- Parse IPv4, bracketed IPv6 and DNS-name endpoints without DNS lookups.
- Keep validation reusable at the daemon trust boundary. Accept repeated list
  fields; reject duplicate singleton fields, malformed values and unknown fields.
- Describe CIDR coverage numerically; handle the full IPv6 address count without
  integer overflow. Treat default routes as conflicting with every other tunnel,
  including a tunnel using the other IP family.
- Use existing `base64`, `ipnetwork` and `thiserror`. Add `serde` for public IPC
  models, `zeroize` for secret lifetime management and `x25519-dalek` for public
  key derivation, avoiding custom cryptography. Key generation remains in the
  daemon so this crate performs no I/O. Add `proptest` only for tests and
  `libfuzzer-sys` only to the separate fuzz package.

## Validation

Unit tests cover real-format imports, rejection and redaction, dual-stack values,
repeated fields, host-bit preservation, endpoint syntax, range coverage and
cross-family default-route conflicts. Property tests exercise parse/write
round trips and arbitrary input. A cargo-fuzz target repeats the same boundary
checks on raw byte input. Run `cargo test -p wge-config` and strict Clippy.

## Open questions

None. The crate performs no filesystem, network or random-source access.

## Results

The crate implements all planned boundaries and helpers. Public IPC models have
no secret fields. Export reserves its buffer before writing keys so reallocation
cannot leave an unzeroed secret copy. Full-tunnel detection includes split default
routes, and full tunnels require an IPv6-safe MTU.

Validation passed: 21 unit/property tests, strict Clippy, the standalone fuzz
package build and 2,000 libFuzzer smoke iterations. The host has neither nightly
Rust nor `cargo-fuzz`; those smoke iterations were not coverage instrumented.
The documented nightly fuzz command remains the sustained fuzzing check for CI.

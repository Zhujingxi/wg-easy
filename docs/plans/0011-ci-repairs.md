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
auto-generated GUID in the unversioned license bundle; native installer checks
remain to be verified after that repair.

## Open questions

Further failures may be hidden behind the currently failing steps.

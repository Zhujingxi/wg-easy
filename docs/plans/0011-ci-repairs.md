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
- Give the Windows installer's permanent private-state directory a stable
  component GUID, and exercise packaging and native service checks.
- Fix further reproducible failures in the connected code as they surface.

No new product features or dependencies are planned.

## Validation

Run formatting, workspace check/test/Clippy/build, cargo-deny, cargo-audit,
and relevant native Linux tests locally. Use GitHub Actions for Windows/macOS
builds, installers, native networking and installed-service lifecycle tests.
Keep all existing security and acceptance checks enabled.

## Open questions

Further failures may be hidden behind the currently failing steps.

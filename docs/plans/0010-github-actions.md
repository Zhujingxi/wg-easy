# 0010: GitHub-hosted CI

Status: done

## Goal

Run all checks and packaging on GitHub-hosted runners, with Linux, Windows and
macOS enabled by default. Remove Blacksmith and the former persistent-runner
container setup.

## Approach

- Keep the existing Check and Packages workflows, commands and artifacts.
- Use Ubuntu 24.04, Windows and macOS hosted runners for the platform matrices,
  and Ubuntu 24.04 for security, network and fuzz jobs.
- Install Linux build libraries directly in each disposable VM using its normal
  Ubuntu repositories. Keep Linux networking tests inside private namespaces;
  install the resolver prerequisites and allow unprivileged namespaces in that VM.
- Remove manual platform selection and same-repository PR restrictions now that
  jobs run on disposable hosted machines with read-only repository permissions.
- Update current CI documentation while preserving historical verification evidence.

No application changes, new dependencies or repository billing changes.

## Validation

Both workflows pass actionlint 1.7.12 and `git diff --check`. A YAML comparison
against the previous revision verifies all jobs use hosted runners, both matrices
include all three platforms, and existing check commands, actions and artifacts
are preserved (apart from container setup/cleanup and the TUN prerequisite text).
Application tests are unchanged and were not rerun locally for this CI-only change.
The requested admin merge may precede completed hosted builds; no new native
runtime pass is claimed here.

## Open questions

Hosted execution still depends on the repository's GitHub Actions allowance.

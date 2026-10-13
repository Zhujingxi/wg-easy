# Plans

One file per plan, written before the work starts. `AGENTS.md` at the repository
root holds the scope and the rules; plans hold how a specific piece gets built.

## Convention

- File name: `NNNN-short-name.md`, numbered in order, for example
  `0001-config-parser.md`.
- Start each plan with this header:

  ```markdown
  # NNNN: Title

  Status: draft | accepted | in progress | done | dropped
  ```

- Then cover: goal, what is out of scope, the approach, how it will be tested,
  and open questions.
- Keep the plan current while the work is in progress. When it is done, set the
  status and leave the file in place.
- Add a row to the index below.

## Index

| Plan | Status |
|---|---|
| [0001: Configuration foundation](0001-config.md) | done |
| [0002: Local service](0002-service.md) | done |
| [0003: Native networking](0003-network.md) | done |
| [0004: Native desktop](0004-desktop.md) | done |
| [0005: Delivery and verification](0005-delivery.md) | done |
| [0007: Service trust-boundary review](0007-service-review.md) | done |
| [0008: Real Linux resolver verification](0008-resolved-verification.md) | done |
| [0009: Automatic DNS SRV endpoints](0009-srv-endpoints.md) | done |

## Initial feasibility checks

- **GPUI:** the empty Linux debug window measured 271 MiB RSS; tray-only startup
  measured 74 MiB. The tray stays in the GUI process without creating a window.
  Plan 0004 records the pinned Longbridge GPUI Kit/GPUI snapshot provenance.
- **Graphics:** native acceptance passes with Mesa software Vulkan under Xvfb.
  With no usable graphics backend, GPUI cannot open a window; there is no fallback UI.
- **Japanese:** font fallback, marked-text conversion and commit through GPUI's
  real input handler pass. OS candidate-picker acceptance remains a hardware check.
- **Linux tray:** ksni uses StatusNotifier D-Bus; the GTK-backed tray-icon path
  is excluded from Linux builds.
- **Wintun:** the pinned, signed prebuilt DLL permits unchanged redistribution
  with its license. Packages verify its SHA256 and include the original notice.
- **macOS service:** the unsigned Installer package installs a LaunchDaemon and
  requests reboot. The application itself never invokes a service-management command.
- **Names:** installer names use `wireguardeasy-desktop`; the repository is
  `Zhujingxi/wg-easy`. These workspace crates are not published to crates.io.

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
| [0007: Service trust-boundary review](0007-service-review.md) | done |

## To verify before the first plans

These are still guesses or unchecked. Settle each one early, and record the
result in the plan that depends on it.

- **GPUI memory:** measure an empty window on Linux. No real number exists yet.
- **GPUI dependency:** the `gpui` crate on crates.io is stale (0.2.2), and GPUI
  Kit pins a crate named `gpui-pre`. Confirm who publishes it before depending
  on it.
- **GPUI without a GPU:** find out what happens in a VM or over remote desktop.
- **Japanese input:** confirm IME and font fallback work in GPUI text fields on
  Linux.
- **Tray process:** decide whether the tray lives in the GUI process or in a
  small separate one, based on the measured memory.
- **`wintun.dll` licence:** read the redistribution terms of the prebuilt DLL
  before the first Windows build.
- **Pure Rust tray on Linux:** confirm `tray-icon` pulls in GTK there, which is
  the reason for using `ksni` instead.
- **macOS service install:** find a way to register the daemon from an unsigned
  app without running external programs.
- **Package names:** the GitHub name `wg-easy/wg-easy` is taken, and the crate
  name on crates.io is unchecked.

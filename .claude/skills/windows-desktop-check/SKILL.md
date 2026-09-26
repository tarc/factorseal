---
name: windows-desktop-check
description: Build FactorSeal natively on Windows from WSL2 and check FactorSeal Desktop's approval popup there (foreground or taskbar flash, pending request in the vault, WSL grant cap, UI Automation tree, hangs). Use when a task needs a Windows build of Desktop or the CLI, or verifying Desktop's approval popup, the WSL broker, or native SecretSpec requests on Windows.
---

# Windows Desktop checks from WSL2

Read `scripts/windows-desktop-check/README.md` first; it describes every
script, the flow, and the pitfalls. This file is the order of work.

## Build

- `./scripts/windows-desktop-check/build-windows.sh check` for clippy and
  Desktop's tests natively (safe while Desktop runs).
- `./scripts/windows-desktop-check/build-windows.sh --broker` for release
  binaries. If it refuses because Desktop is running, ask the user to quit
  Desktop from its tray icon, then rerun.
- Never try to cross-compile Desktop from WSL; its renderer needs Windows.

## Check the approval popup

The user must do the steps only a person can. Give them the exact commands,
say which shell they run in, and wait for them.

1. Ask the user to start Desktop and unlock the vault. On this setup they
   start it from an elevated PowerShell:
   `cd <windows copy>; .\target\release\factorseal-desktop.exe`
2. Run `./scripts/windows-desktop-check/check.sh popup` (or `--delay 10` and
   ask them to bring another app to the front, for the "behind" case). Tell
   them to leave the popup alone until the result prints.
3. Read `popup.png` and `taskbar.png` from the printed paths yourself instead
   of asking for screenshots.
4. Ask the user to approve (or deny). After approving, run
   `check.sh grant --key <key from step 2>`.

If `check.sh` says the vault is sealed, ask the user to unlock and rerun
promptly; it seals itself after a few idle minutes.

## Inspect

- UI Automation: `uia-dump.ps1 -Out <file>`. From WSL it sees only window
  frames while Desktop is elevated; ask the user to run it from an elevated
  PowerShell, then read the file.
- Hangs or crashes: start `proc-watch.ps1 -Out <file> -Seconds 600` from WSL
  in the background before the user launches Desktop, and ask them to set
  `$env:FACTORSEAL_TIMINGS = '1'` and redirect stderr to a file.

## Rules

- A change to Desktop's UI is committed only after it was seen working in a
  native Windows build.
- Report what the scripts measured (pass/fail lines, screenshots, grant
  lifetime); do not infer popup behavior from code alone.

# OmniLaunch Full App Test Plan

Date: 2026-04-13  
Repository: `C:\Users\hendrizzzz\Desktop\USB APP\omnilaunch`  
Scope: Full-system validation of OmniLaunch, not only Phase 17.2 fixes

## Purpose

This plan is meant to answer one question:

**Does the app actually work end-to-end on real machines and real USB workflows?**

It covers:

- build/package validation
- first-run setup
- unlock flows
- workspace launch
- session capture/edit/save
- app import
- security toggles
- quit/cleanup behavior
- USB-specific failure cases
- recovery paths
- environment and hardware variation

## Test Strategy

Use three layers:

1. **Build/packaging checks**
2. **Core functional smoke tests**
3. **Edge, failure, and hostile-environment tests**

Do not call the release validated until all **P0** and **P1** tests pass on real hardware.

## Environments To Test

## Host Machines

- **PC-A Home/Admin**
  - Windows 10 or 11
  - local admin rights
  - SSD system drive
- **PC-B Restricted/School-like**
  - standard user, no admin
  - antivirus / Windows Defender active
  - shared-machine style environment
- **PC-C Secondary machine**
  - different hardware than PC-A
  - used to validate portability, USB serial behavior, and host independence

## USB Devices

- **USB-1 Main test drive**
  - the primary removable drive for repeated tests
- **USB-2 Secondary drive**
  - used for clone / serial mismatch / “different device” validation

## App Samples To Use

Use a mix of real-world names and storage patterns:

- `Visual Studio Code`
- `Google Chrome`
- `OBS Studio`
- one app with **no AppData**
- one app with a **large AppData** tree
- one app with **spaces** in the name
- one app with **punctuation or special characters** if available

## Test Data

Use dummy accounts only:

- test Gmail or dummy login for browser auth
- test GitHub/test site login
- fake workspace tabs
- disposable VS Code settings/extensions if possible

## Evidence To Collect

For every major suite, capture:

- pass/fail
- machine name
- USB device used
- timestamp
- screenshot or short screen recording for failures
- console/app logs when relevant
- resulting folder state on USB for import/AppData tests

Recommended proof artifacts:

- screenshot of `npm run build`
- screenshot of launch-ready screen
- screenshot of import results screen
- folder snapshots of `AppData/`, `Apps/`, `BrowserProfile/`
- note whether `.bak-*` folders were created

## Exit Criteria

Minimum ship bar:

- all **P0** tests pass
- all **P1** tests pass
- no unresolved P1/P2 findings remain
- build succeeds
- package succeeds
- at least one real removable-drive smoke cycle passes

## Priority Levels

- **P0**: release blocker
- **P1**: high-value functional requirement
- **P2**: important but not necessarily blocking
- **P3**: polish / confidence / compatibility

---

## Suite A: Build And Packaging

### A-01 Build

- Priority: `P0`
- Steps:
  1. Run `npm run build`
- Expected:
  - main, preload, and renderer all build successfully
  - no build errors

### A-02 Package

- Priority: `P1`
- Steps:
  1. Run `npm run package`
- Expected:
  - distributable zip is created
  - packaged app starts

### A-03 Fresh packaged launch

- Priority: `P0`
- Steps:
  1. Launch packaged app from USB
- Expected:
  - app opens
  - no crash on startup

---

## Suite B: First-Run Setup

### B-01 First run on removable drive

- Priority: `P0`
- Steps:
  1. Use a clean USB with no existing vault
  2. Launch app
- Expected:
  - app enters Setup flow
  - removable-drive wording is shown
  - PIN setup is available
  - hidden master-password path is used internally

### B-02 First run on local/non-removable mode if available

- Priority: `P2`
- Steps:
  1. Run in local dev mode or forced local mode if supported
- Expected:
  - password setup path works

### B-03 Setup with no desktop apps

- Priority: `P1`
- Steps:
  1. Complete setup
  2. Skip app additions
  3. Capture only browser session
- Expected:
  - vault saves successfully
  - setup completes

### B-04 Setup with desktop apps

- Priority: `P1`
- Steps:
  1. Add an `.exe`
  2. Add a folder shortcut if supported
  3. Continue setup
- Expected:
  - added items persist into workspace

### B-05 Setup browser capture

- Priority: `P0`
- Steps:
  1. Open browser
  2. Log into at least one site
  3. Open multiple tabs
  4. Save and finish
- Expected:
  - capture succeeds
  - saved tabs count is accurate

### B-06 Close browser before saving during setup

- Priority: `P1`
- Steps:
  1. Open browser in setup
  2. Close browser manually before saving
- Expected:
  - disconnect handling triggers
  - user sees recovery guidance
  - app does not get stuck

---

## Suite C: Unlock Flows

### C-01 PIN unlock success

- Priority: `P0`
- Steps:
  1. Set up removable vault with PIN
  2. Restart app
  3. Enter correct PIN
- Expected:
  - unlock succeeds
  - launch starts automatically

### C-02 PIN unlock failure

- Priority: `P1`
- Steps:
  1. Enter wrong PIN
- Expected:
  - clear error shown
  - PIN dots reset
  - app remains usable

### C-03 Password unlock success

- Priority: `P0`
- Steps:
  1. Use local-password flow or hardware-mismatch flow
  2. Enter correct master password
- Expected:
  - unlock succeeds

### C-04 Password unlock failure

- Priority: `P1`
- Steps:
  1. Enter wrong password
- Expected:
  - error shown
  - password field clears or remains recoverable

### C-05 Fast Boot success

- Priority: `P1`
- Steps:
  1. Enable Fast Boot
  2. Relaunch on same USB
- Expected:
  - bypasses PIN prompt
  - workspace auto-launches

### C-06 Hardware mismatch / serial mismatch

- Priority: `P0`
- Steps:
  1. Move vault to different removable drive or simulate serial mismatch
  2. Relaunch
- Expected:
  - PIN/Fast Boot fail safely
  - password path is shown
  - no corrupt state

### C-07 Factory reset

- Priority: `P1`
- Steps:
  1. Trigger reset from unlock screen
  2. Confirm wipe
- Expected:
  - vault files removed
  - app returns to setup state

---

## Suite D: Workspace Launch

### D-01 Launch browser-only workspace

- Priority: `P0`
- Steps:
  1. Save a browser-only workspace
  2. Unlock
- Expected:
  - tabs load
  - ready screen appears

### D-02 Launch app-only workspace

- Priority: `P1`
- Steps:
  1. Save workspace with desktop app(s) only
  2. Unlock
- Expected:
  - desktop apps launch
  - launch progress completes

### D-03 Launch mixed workspace

- Priority: `P0`
- Steps:
  1. Save browser tabs + desktop apps
  2. Unlock
- Expected:
  - all enabled items launch
  - ready screen shows completed items

### D-04 Launch with zero enabled items

- Priority: `P2`
- Steps:
  1. Disable all tabs/apps
  2. Launch
- Expected:
  - app goes to ready state without hanging

### D-05 Launch status correctness

- Priority: `P2`
- Steps:
  1. Launch a mixed workspace
  2. Observe progress and loaded item names
- Expected:
  - progress bar advances reasonably
  - names shown are understandable

### D-06 Desktop app launch failure

- Priority: `P1`
- Steps:
  1. Configure an invalid or missing app path
  2. Launch
- Expected:
  - launch error is visible
  - app doesn’t crash

---

## Suite E: Settings / Dashboard

### E-01 Open settings from ready screen

- Priority: `P1`
- Steps:
  1. Launch workspace
  2. Open settings
- Expected:
  - dashboard opens
  - current workspace state is loaded

### E-02 Save workspace changes

- Priority: `P1`
- Steps:
  1. Add/remove/enable/disable apps or tabs
  2. Save changes
- Expected:
  - changes persist
  - returning flow works

### E-03 Cancel settings

- Priority: `P2`
- Steps:
  1. Change fields
  2. Cancel
- Expected:
  - unsaved changes do not silently persist
  - app returns to previous screen correctly

---

## Suite F: Session Save / Edit / Recapture

### F-01 Save current session from ready screen

- Priority: `P1`
- Steps:
  1. Launch workspace
  2. Open extra tabs in browser
  3. Click Save Session
- Expected:
  - current browser state is saved
  - save success appears

### F-02 Edit existing session on USB

- Priority: `P0`
- Steps:
  1. Open settings
  2. Start session edit on removable-drive vault
  3. Modify tabs/logins
  4. Save
- Expected:
  - no password prompt shown for USB case
  - save succeeds

### F-03 Recapture session on USB

- Priority: `P1`
- Steps:
  1. Start recapture
  2. Build a fresh tab set
  3. Save
- Expected:
  - updated tabs persist

### F-04 Session save with browser closed unexpectedly

- Priority: `P1`
- Steps:
  1. Enter edit or recapture mode
  2. Close browser manually before saving
- Expected:
  - error/recovery path is shown
  - app is not stuck

### F-05 Cached-password unavailable edge case

- Priority: `P2`
- Steps:
  1. If reproducible, simulate session flow after internal reset/restart
  2. Attempt USB session save without cached password
- Expected:
  - clear error shown
  - no corruption

---

## Suite G: App Import

### G-01 Scan for importable apps

- Priority: `P1`
- Steps:
  1. Open import modal
  2. Scan installed apps
- Expected:
  - app list loads
  - already-imported indicators make sense

### G-02 Import binary only

- Priority: `P1`
- Steps:
  1. Select an app
  2. Disable data import
  3. Import
- Expected:
  - app imported
  - app config added to workspace

### G-03 Import with AppData

- Priority: `P0`
- Steps:
  1. Select app with AppData
  2. Enable data import
  3. Import
- Expected:
  - binary imported
  - AppData copied to USB
  - imported app launches with expected profile state

### G-04 Import app with spaces in name

- Priority: `P0`
- Example:
  - `Visual Studio Code`
- Expected:
  - AppData path is sanitized
  - launch uses imported data

### G-05 Reopen scanner after import

- Priority: `P1`
- Steps:
  1. Import an app
  2. Close import modal
  3. Reopen scan
- Expected:
  - app shows as already imported

### G-06 Partial import failure

- Priority: `P1`
- Steps:
  1. Select multiple apps
  2. Force one to fail if possible
- Expected:
  - results screen shows mixed success/failure
  - successful imports remain usable

### G-07 Full import failure

- Priority: `P1`
- Steps:
  1. Force all selected imports to fail
- Expected:
  - results screen appears
  - modal is closable
  - app is not stuck in importing state

### G-08 Import close guard

- Priority: `P1`
- Steps:
  1. Start a long import
  2. Attempt to close the app window
- Expected:
  - warning dialog appears
  - user can keep app open
  - if user chooses close anyway, app closes intentionally

### G-09 Import progress listener cleanup

- Priority: `P2`
- Steps:
  1. Open and close import modal multiple times
  2. Run import again
- Expected:
  - no duplicated progress events
  - no obvious listener leak behavior

---

## Suite H: Security Toggles

### H-01 Enable PIN

- Priority: `P1`
- Steps:
  1. Set or update PIN
- Expected:
  - unlock works with new PIN

### H-02 Disable PIN while Fast Boot is off

- Priority: `P0`
- Steps:
  1. On USB vault, ensure Fast Boot is off
  2. Try disabling PIN
- Expected:
  - blocked in UI
  - backend also rejects if bypass attempted

### H-03 Disable Fast Boot while PIN is off

- Priority: `P0`
- Steps:
  1. On USB vault, ensure PIN is off
  2. Try disabling Fast Boot
- Expected:
  - blocked in UI
  - backend also rejects if bypass attempted

### H-04 Toggle clear cache on exit

- Priority: `P1`
- Steps:
  1. Turn clear-cache on
  2. Quit and relaunch
  3. Turn clear-cache off
  4. Quit and relaunch again
- Expected:
  - on: extracted app cache wiped
  - off: extracted app cache retained for faster next launch

---

## Suite I: Quit / Cleanup / Relaunch

### I-01 Normal quit from ready screen

- Priority: `P0`
- Steps:
  1. Launch workspace
  2. Click Quit
- Expected:
  - browser closes
  - desktop apps close if configured
  - sync completes
  - app exits cleanly

### I-02 Double-click quit protection

- Priority: `P2`
- Steps:
  1. Click Quit repeatedly
- Expected:
  - app does not double-trigger broken cleanup

### I-03 Relaunch after clean quit

- Priority: `P0`
- Steps:
  1. Quit cleanly
  2. Reopen app
- Expected:
  - saved state persists

### I-04 Minimize button

- Priority: `P3`
- Steps:
  1. Click minimize
- Expected:
  - window minimizes

### I-05 Window close button when idle

- Priority: `P2`
- Steps:
  1. Click window close while not importing
- Expected:
  - app closes cleanly

---

## Suite J: USB-Specific Data Behavior

### J-01 Legacy raw-name + sanitized conflict

- Priority: `P0`
- Steps:
  1. Create a legacy raw-name AppData folder
  2. Ensure sanitized folder also exists
  3. Launch app
- Expected:
  - raw folder is used
  - sanitized backup attempt occurs
  - app still launches

### J-02 Backup rename failure

- Priority: `P2`
- Steps:
  1. Simulate sanitized backup rename failure if possible
     - lock folder
     - permissions issue
- Expected:
  - warning logged
  - launch still proceeds using raw path

### J-03 AppData persistence across sessions

- Priority: `P0`
- Steps:
  1. Launch imported portable-data app
  2. Change settings/login/data
  3. Quit cleanly
  4. Relaunch
- Expected:
  - changes persist

### J-04 BrowserProfile persistence across sessions

- Priority: `P0`
- Steps:
  1. Save browser-authenticated session
  2. Relaunch later
- Expected:
  - auth/session state persists as expected

### J-05 USB yank / kill-cord behavior

- Priority: `P0`
- Steps:
  1. Launch workspace
  2. Remove USB unexpectedly
- Expected:
  - app exits
  - sensitive local traces are wiped as much as possible
  - no undefined hung state

---

## Suite K: File System And Host Cleanup

### K-01 Local browser traces wiped

- Priority: `P1`
- Steps:
  1. Run session
  2. Quit cleanly
  3. Inspect temp directories
- Expected:
  - QuickPass browser temp profile removed

### K-02 Local app data wiped

- Priority: `P1`
- Steps:
  1. Run portable-data app
  2. Quit cleanly
  3. Inspect `QuickPass-AppData-*` temp dirs
- Expected:
  - wiped after sync

### K-03 Cache policy respected

- Priority: `P1`
- Steps:
  1. Compare temp `QuickPass-App-*` extracted app cache with clear-cache on/off
- Expected:
  - behavior matches toggle

### K-04 No unexpected host persistence

- Priority: `P1`
- Steps:
  1. Run full session on shared-machine-like host
  2. Quit
  3. Inspect obvious temp and user-data locations
- Expected:
  - no easy-to-find leftover OmniLaunch auth/session data outside intended cache policy

---

## Suite L: Negative And Hostile Cases

### L-01 Low free space on USB

- Priority: `P2`
- Steps:
  1. Attempt large import with limited remaining USB space
- Expected:
  - failure is surfaced
  - app is not stuck

### L-02 Locked target folder or file

- Priority: `P2`
- Steps:
  1. Lock imported app data or backup target if possible
- Expected:
  - warning/error shown or logged
  - app does not crash unpredictably

### L-03 Antivirus / Defender active

- Priority: `P2`
- Steps:
  1. Run import and launch on a host with realtime protection active
- Expected:
  - no unexplained silent failure

### L-04 Standard user / no admin rights

- Priority: `P1`
- Steps:
  1. Run full setup/unlock/import/launch flow as non-admin
- Expected:
  - normal user workflow still works

### L-05 Slow USB / large profile

- Priority: `P2`
- Steps:
  1. Use large AppData/browser state
  2. Observe import and sync times
- Expected:
  - long operations remain recoverable
  - progress is visible

### L-06 Unexpected app crash during session

- Priority: `P2`
- Steps:
  1. Kill launched app process unexpectedly
- Expected:
  - sync-on-exit handling stays sane
  - future relaunches still work

### L-07 Unexpected OmniLaunch crash / restart

- Priority: `P2`
- Steps:
  1. Force-close app during an active session if safe to do in test copy
- Expected:
  - next launch is recoverable
  - no permanent lockout

---

## Suite M: Cross-Machine / Outside Validation

These are the “outside test cases” that help prove the app beyond one machine.

### M-01 Same USB on second host

- Priority: `P0`
- Goal:
  - prove portability
- Expected:
  - unlock still works
  - workspace launches on second machine

### M-02 Same USB after multiple clean cycles

- Priority: `P1`
- Goal:
  - prove no gradual corruption
- Steps:
  1. Repeat full open/use/save/quit cycle at least 5 times

### M-03 Different Windows account on same host

- Priority: `P2`
- Goal:
  - prove host-user independence

### M-04 Different removable drive copy

- Priority: `P1`
- Goal:
  - validate expected hardware mismatch behavior

### M-05 Public/shared-computer style test

- Priority: `P1`
- Goal:
  - prove zero-footprint assumptions as much as practical

---

## Recommended Execution Order

Run tests in this order:

1. Suite A: Build and package
2. Suite B: First-run setup
3. Suite C: Unlock flows
4. Suite D: Workspace launch
5. Suite F: Session edit/save flows
6. Suite G: App import
7. Suite H: Security toggles
8. Suite I: Quit and relaunch
9. Suite J: USB-specific data behavior
10. Suite K: Cleanup verification
11. Suite L: Negative/hostile tests
12. Suite M: Outside/cross-machine proof

## Minimal Must-Pass Set Before You Trust It

If you want the smallest high-value subset first, do these:

- `A-01`, `A-02`, `A-03`
- `B-01`, `B-05`
- `C-01`, `C-05`, `C-06`
- `D-03`
- `F-02`
- `G-03`, `G-04`, `G-07`
- `H-02`, `H-03`, `H-04`
- `I-01`, `I-03`
- `J-01`, `J-03`, `J-05`
- `K-01`, `K-02`
- `M-01`, `M-02`

## Final Recommendation

Treat this as a **release validation plan**, not just a bugfix checklist.

The most important proof points are:

- the app works on a real removable drive
- imported app data survives relaunch
- USB users cannot lock themselves out
- session save/edit works on USB
- quit/cleanup actually removes local traces
- host-to-host portability works in practice

If you want, I can next turn this into:

1. a shorter **day-by-day execution checklist**, or  
2. a **pass/fail QA template** you can fill out while testing.

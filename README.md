# Wipesnap

Portable workspace orchestration for Windows.

Wipesnap provisions a portable workspace from USB/NVMe-style storage. It launches saved browser tabs and desktop applications, runs managed profiles from host temp storage for performance, syncs supported data back to the portable drive, and performs guarded best-effort cleanup on exit.

Current product focus: desktop MVP hardening. The production path is vault setup/unlock, manual workspace launch, save current session, quit/sync-back/cleanup, workspace health, and sanitized diagnostics. Cloud sync, phone enrollment, provider selection, and phone planner cloud flows are staging/experimental surfaces and are not production-ready by default.

## Current Architecture

- **Encrypted workspace config:** `vault.json` stores workspace configuration with AES-256-GCM and PBKDF2-SHA512 key derivation.
- **Drive detection:** Wipesnap queries `Win32_LogicalDisk` through PowerShell/CIM first and falls back to `vol <drive>` for a volume serial when CIM is unavailable.
- **Convenience unlock:** optional PIN and Fast Boot store encrypted helper material in `vault.meta.json` using the Windows volume serial reported by the host. This is convenience binding, not raw USB hardware identity.
- **Browser orchestration:** Playwright launches the Chrome channel with a persistent Chromium profile copied from `BrowserProfile/` to host temp and synced back on close. Edge/default-browser fallback is not claimed in the desktop MVP.
- **Desktop app import:** imported app binaries are compressed as `Apps/<storage-id>.tar.zst`, extracted to host temp on launch, and described by Manifest V2 metadata.
- **App support tiers:** verified, best-effort, launch-only, needs-adapter, and unsupported tiers keep data-portability claims conservative.
- **Host cleanup:** Wipesnap attempts to wipe temp browser profiles, runtime profiles, imported AppData copies, and app caches with ownership/path checks.
- **Diagnostics:** each run can write structured launch, readiness, sync, and cleanup diagnostics.
- **Cloud/phone staging:** Firebase and Cloudflare transport code can carry app-encrypted sanitized snapshots and patches when explicitly configured for staging. Phone remains a safe preset editor, not a launch control plane; desktop remains launch authority.

## Product Surface Classification

| Surface | Status |
| --- | --- |
| Vault setup/unlock, manual launch, browser/profile lifecycle, save current session, quit/sync-back/cleanup, workspace health, sanitized diagnostics, guarded stale AppData cleanup | Production MVP |
| Host app scan/import, launch-only host references, clear-cache behavior, PIN/Fast Boot, app support tiers | Advanced local |
| Firebase hosted planner, Cloudflare Pages/Workers/D1 provider, desktop cloud sync upload/download/apply, phone enrollment/key grants | Disabled staging |
| Trusted auto-import, trusted auto-launch, phone planner cloud flows, provider selection, owner/request/key-grant IDs, local draft/dev flows | Experimental/advanced |

Staging or advanced surfaces are hidden from the default dashboard. Developers can reveal them only with an ignored local `wipesnap.local.json` beside the vault/app root; do not ship or commit that file.

## Important Storage Notes

Encrypted workspace vault:

- `vault.json` stores workspace config and saved tab URLs using AES-256-GCM with PBKDF2-SHA512 key derivation.
- Main-owned launch capability records are stored in the encrypted vault payload when present.

Helper metadata:

- `vault.meta.json` stores plaintext status flags such as PIN/FastBoot availability, clear-cache preference, sanitized unlock status, and encrypted PIN/FastBoot helper ciphertext.
- `vault.state.json` stores durable helper state such as PIN lockout.
- Helper metadata is not the encrypted workspace vault and should not contain launch authority or pre-unlock app summaries.

Stored beside the vault and potentially sensitive:

- `BrowserProfile/` browser profile data.
- `Apps/` imported app archives and manifests.
- `AppData/` imported AppData payloads.
- `run-diagnostics.json` launch, readiness, sync, and cleanup diagnostics.

Vault encryption does not fully cover `BrowserProfile/`, `Apps/`, `AppData/`, imported app payloads, browser sessions, host temp caches, or diagnostics. Wipesnap reduces ordinary residue, but it does not guarantee zero residue and does not provide privacy against a compromised host.

## Reset And Cleanup Scope

Factory reset is unauthenticated by design. The reset token is anti-misfire sequencing only, not authorization. Factory reset deletes exactly `vault.json`, `vault.meta.json`, and `vault.state.json`; it does not delete `Apps/`, `AppData/`, `BrowserProfile/`, imported archives, browser profiles, host caches, or diagnostics.

Normal shutdown cleanup closes the managed browser, closes only owned or safely identified desktop app processes, wipes Wipesnap Electron temp data, wipes local browser profile temp copies, wipes imported AppData temp copies, and wipes stale runtime-only app profiles. App binary cache cleanup is controlled by `clearCacheOnExit`; when disabled, extracted app binary caches may persist for faster relaunch. Cleanup is best-effort host-residue reduction, not a zero-residue guarantee.

If sync-back or cleanup fails, is deferred, or is unknown, do not treat the workspace as fully synced or safe to unplug until diagnostics are reviewed and the remaining action is resolved.

## Windows Compatibility Status

Wipesnap targets Windows 10 and Windows 11, but Phase 34 treats host compatibility as a matrix of expectations, automated coverage, and manual validation still needed. Do not infer real-hardware validation from the presence of a code path or automated fixture.

Tracked Phase 34 matrix summary:

| Area | Expected behavior | Validation status |
| --- | --- | --- |
| Windows 10/11, admin/non-admin | Use Windows primitives without requiring elevation; denied operations degrade to failed, blocked, deferred, unavailable, or needs-attention states. | Automated coverage is partial; real-host validation still needed. |
| Locked-down corporate hosts | Denied registry, PowerShell/CIM, process, or file operations must not leak raw commands, registry data, paths, or authority to renderer status. | Automated sanitization coverage is partial; managed-host smoke still needed. |
| Slow or yanked removable drive | Launch, sync-back, cleanup, and diagnostics must not be presented as synced or safe when the drive is unavailable, failed, running, deferred, blocked, or unknown. | Diagnostics tests cover several simulated states; physical yank tests still needed. |
| Chrome and browser profile lifecycle | Chrome-channel launch is the MVP path. Missing profiles need attention when tabs exist; copy-in failure blocks browser launch to protect the portable profile; copy-out failure remains action-needed. | Automated diagnostics and copy-in fail-closed coverage; real Chrome-missing/locked-profile smoke still needed. |
| App processes and ownership | Wipesnap may close only owned or safely identified processes; ambiguous, launch-only, or unmanaged processes are skipped or deferred. | Process-control tests cover handler states; real long-running app smoke still needed. |
| AppData and path escape cleanup | Cleanup must fail closed on symlink, junction, or path escape risk and never delete arbitrary host data. | Automated stale AppData guard coverage; NTFS junction manual smoke still needed. |
| Redirected known folders, AV, file locks, missing primitives | Health and diagnostics should show broken/needs-attention/failure without raw path or command leakage. | Automated coverage is partial; OneDrive/AV/missing-primitive smoke still needed. |
| Corrupt, oversized, missing, or stale diagnostics/cleanup selections | Renderer receives sanitized metadata-only status, and stale selected cleanup items are revalidated before deletion. | Automated coverage. |
| Partial lifecycle outcomes | Sync success plus cleanup blocked/deferred/failed, or cleanup success plus sync failed/unknown, remains action-needed rather than synced/safe. | Automated diagnostics coverage. |

Some worktrees may also contain a fuller local planning matrix at `docs/phase-34-windows-compatibility-matrix.md`. The `docs/` directory is ignored by this repository policy, so that file is a local planning artifact unless it is intentionally force-added in a future docs policy change.

Legacy compatibility names still recognized in one pass:

- `.quickpass-app.json` imported-app manifests are read for old vaults; new manifests use `.wipesnap-app.json`.
- `QuickPass-*` temp/profile/cache directories and `QuickPass-electron` are cleaned as legacy host residue; new temp names use `Wipesnap-*`.
- `canQuitFromOmniLaunch` remains a persisted manifest/workspace field until a dedicated schema migration can safely rename it.
- `window.omnilaunch` remains a preload compatibility alias; renderer code uses `window.wipesnap`.

## App Support Classification

| Tier | Meaning | Examples |
| --- | --- | --- |
| Verified | Runtime and imported data behavior are proven for the app family or app. | Microsoft Edge, Cursor |
| Best-effort | Runtime isolation may work, but imported AppData is not claimed. | Generic Electron apps |
| Launch-only | App can launch, but data is unmanaged. | Unknown native Win32 apps |
| Needs adapter | App needs dedicated adapter work before support is claimed. | OBS Studio |
| Unsupported | Requested behavior is blocked. | Unsafe or unverified data import |

## Threat Boundary

Wipesnap helps reduce ordinary host residue on shared Windows PCs. It does not defend against a compromised host OS, administrator/EDR inspection, kernel malware, keyloggers, physical capture of an unlocked session, or memory forensics.

Chromium login sessions may require re-authentication on different PCs because services and browsers can bind credentials to host/device state.

Cloud/phone note: staging cloud code stores app-encrypted snapshots and patches, not launch capabilities. Phone/cloud cannot create, mutate, repair, migrate, or launch desktop capabilities. Do not present cloud sync or phone enrollment as production-ready without a later product gate.

## Getting Started

### Prerequisites

- Windows 10 or 11. Current support expectations are documented in the Phase 34 matrix; not every host combination has been manually validated yet.
- Node.js 18+

### Install

```bash
npm install
```

### Development

```bash
npm run dev
```

### Build

```bash
npm run build
```

### Package

```bash
npm run package
```

Produces a portable `.zip` in `dist/`.

## Validation

```bash
npm run check
npm run test
npm run build
```

If `npm run build` fails with `esbuild spawn EPERM` inside a sandbox, rerun with approval/outside the sandbox.

Do not run `scripts/e2e-ui-test.js` against a real working vault yet; it deletes root vault files to force a clean setup flow.

## Documentation

- [Architecture](docs/architecture.md)
- [Threat model](docs/threat-model.md)
- [Testing guide](docs/testing.md)
- [App adapter contract](docs/app-adapter-contract.md)
- [Codex workflow](docs/codex-workflow.md)

## License

Proprietary. All rights reserved.

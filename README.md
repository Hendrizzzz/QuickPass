# Wipesnap

Portable workspace orchestration for Windows.

Wipesnap provisions a portable workspace from USB/NVMe-style storage. It launches saved browser tabs and desktop applications, runs managed profiles from host temp storage for performance, syncs supported data back to the portable drive, and performs guarded best-effort cleanup on exit.

## Current Architecture

- **Encrypted workspace config:** `vault.json` stores workspace configuration with AES-256-GCM and PBKDF2-SHA512 key derivation.
- **Drive detection:** Wipesnap queries `Win32_LogicalDisk` through PowerShell/CIM first and falls back to `vol <drive>` for a volume serial when CIM is unavailable.
- **Convenience unlock:** optional PIN and Fast Boot store encrypted helper material in `vault.meta.json` using the Windows volume serial reported by the host. This is convenience binding, not raw USB hardware identity.
- **Browser orchestration:** Playwright launches a persistent Chromium profile copied from `BrowserProfile/` to host temp and synced back on close.
- **Desktop app import:** imported app binaries are compressed as `Apps/<storage-id>.tar.zst`, extracted to host temp on launch, and described by Manifest V2 metadata.
- **App support tiers:** verified, best-effort, launch-only, needs-adapter, and unsupported tiers keep data-portability claims conservative.
- **Host cleanup:** temp browser profiles, runtime profiles, imported AppData copies, and app caches are wiped with ownership/path checks.
- **Diagnostics:** each run can write structured launch, readiness, sync, and cleanup diagnostics.

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

## Reset And Cleanup Scope

Factory reset is unauthenticated by design. The reset token is anti-misfire sequencing only, not authorization. Factory reset deletes exactly `vault.json`, `vault.meta.json`, and `vault.state.json`; it does not delete `Apps/`, `AppData/`, `BrowserProfile/`, imported archives, browser profiles, host caches, or diagnostics.

Normal shutdown cleanup closes the managed browser, closes only owned or safely identified desktop app processes, wipes Wipesnap Electron temp data, wipes local browser profile temp copies, wipes imported AppData temp copies, and wipes stale runtime-only app profiles. App binary cache cleanup is controlled by `clearCacheOnExit`; when disabled, extracted app binary caches may persist for faster relaunch. Cleanup is best-effort host-residue reduction, not a zero-residue guarantee.

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

## Getting Started

### Prerequisites

- Windows 10 or 11
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

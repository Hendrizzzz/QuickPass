# OmniLaunch

Portable workspace orchestration for Windows.

OmniLaunch provisions a portable workspace from USB/NVMe-style storage. It launches saved browser tabs and desktop applications, runs managed profiles from host temp storage for performance, syncs supported data back to the portable drive, and performs guarded best-effort cleanup on exit.

## Current Architecture

- **Encrypted workspace config:** `vault.json` stores workspace configuration with AES-256-GCM and PBKDF2-SHA512 key derivation.
- **Convenience unlock:** optional PIN and Fast Boot wrap the master password using the Windows volume serial reported by the host. This is convenience binding, not raw USB hardware identity.
- **Browser orchestration:** Playwright launches a persistent Chromium profile copied from `BrowserProfile/` to host temp and synced back on close.
- **Desktop app import:** imported app binaries are compressed as `Apps/<storage-id>.tar.zst`, extracted to host temp on launch, and described by Manifest V2 metadata.
- **App support tiers:** verified, best-effort, launch-only, needs-adapter, and unsupported tiers keep data-portability claims conservative.
- **Host cleanup:** temp browser profiles, runtime profiles, imported AppData copies, and app caches are wiped with ownership/path checks.
- **Diagnostics:** each run can write structured launch, readiness, sync, and cleanup diagnostics.

## Important Storage Notes

Encrypted by the vault layer:

- workspace config and saved tab URLs in `vault.json`
- PIN/FastBoot-wrapped master password in `vault.meta.json`

Stored beside the vault and potentially sensitive:

- browser profile in `BrowserProfile/`
- imported app archives and manifests in `Apps/`
- imported AppData payloads in `AppData/`
- run diagnostics such as `run-diagnostics.json`

## App Support Classification

| Tier | Meaning | Examples |
| --- | --- | --- |
| Verified | Runtime and imported data behavior are proven for the app family or app. | Microsoft Edge, Cursor |
| Best-effort | Runtime isolation may work, but imported AppData is not claimed. | Generic Electron apps |
| Launch-only | App can launch, but data is unmanaged. | Unknown native Win32 apps |
| Needs adapter | App needs dedicated adapter work before support is claimed. | OBS Studio |
| Unsupported | Requested behavior is blocked. | Unsafe or unverified data import |

## Threat Boundary

OmniLaunch helps reduce ordinary host residue on shared Windows PCs. It does not defend against a compromised host OS, administrator/EDR inspection, kernel malware, keyloggers, physical capture of an unlocked session, or memory forensics.

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

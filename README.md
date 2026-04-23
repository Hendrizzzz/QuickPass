<p align="center">
  <img src="build/appicon.png" alt="OmniLaunch" width="100" height="100" />
</p>

<h1 align="center">OmniLaunch</h1>

<p align="center">
  Portable workspace orchestration engine for Windows.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/platform-Windows%2010%2F11-0078D4?style=flat-square&logo=windows&logoColor=fff" alt="Windows" />
  <img src="https://img.shields.io/badge/runtime-Electron-47848F?style=flat-square&logo=electron&logoColor=fff" alt="Electron" />
  <img src="https://img.shields.io/badge/node-%3E%3D18-339933?style=flat-square&logo=nodedotjs&logoColor=fff" alt="Node ≥ 18" />
  <img src="https://img.shields.io/badge/status-active%20development-blue?style=flat-square" alt="Status" />
  <img src="https://img.shields.io/badge/license-proprietary-555?style=flat-square" alt="License" />
</p>

---

## Overview

OmniLaunch provisions authenticated, isolated workstation environments from portable storage (USB or NVMe) on any Windows machine. It orchestrates encrypted browser sessions and native desktop applications, manages per-app runtime isolation, and performs full host cleanup on exit — leaving zero forensic residue on the host operating system.

The workspace configuration, browser profile, and imported application archives are stored in an AES-256-GCM encrypted vault on the portable drive. On launch, data is extracted to the host's local temp storage for performance. On quit, all host-side state is wiped and changes are synced back to the vault.

## Features

- **Encrypted vault** — Workspace configuration encrypted with AES-256-GCM. Key derivation via PBKDF2-SHA512 (100,000 iterations). Optional PIN and Fast Boot convenience unlock bound to drive hardware serial.
- **Browser orchestration** — Isolated Chromium instance via Playwright with a portable profile. Concurrent tab loading with configurable retry, backoff, and URL classification.
- **Desktop app engine** — Import, extract, and launch portable desktop applications with per-app runtime profile isolation. Supports Chromium-family, VS Code-family, and generic Electron adapters.
- **App support tiers** — Each app is classified by verified data portability level. Imported AppData for unverified apps is blocked by default.
- **Process ownership safety** — PID-level tracking per app. Only owned processes are terminated on quit. Successor uncertainty fails closed.
- **Host cleanup** — Runtime profiles, temp caches, and stale data from interrupted sessions are wiped. Junction and symlink traversal is blocked during cleanup.
- **Run diagnostics** — Structured JSON diagnostics per session: timing, app readiness, browser sync, lifecycle events, and errors.

## App Support Classification

| Tier | Description | Examples |
|---|---|---|
| **Verified** | Runtime and data behavior proven via adapter testing. Full data portability supported. | Microsoft Edge, Cursor |
| **Best-effort** | Runtime isolation applied. Data portability unverified — imported AppData is blocked. | Generic Electron apps (Discord, Slack) |
| **Launch-only** | App launches without managed data. | Native Win32 apps without adapters |

## Portability Matrix

| Item | Portable | Notes |
|---|---|---|
| Workspace layout and saved tabs | ✅ | Stored in encrypted vault. |
| Browser bookmarks, history, and settings | ✅ | Carried via portable Chromium profile. |
| Browser login sessions | ⚠️ | Machine-bound encryption may require re-authentication. |
| Imported desktop app binaries | ✅ | Archives stored on drive, extracted per session. |
| Desktop app login sessions | ⚠️ | Electron/Chromium apps may require re-authentication per machine. |
| Host-specific absolute paths | ❌ | Not portable across machines. |

## Security

| Property | Implementation |
|---|---|
| Vault encryption | AES-256-GCM, PBKDF2-SHA512 (100k iterations) |
| Drive binding | PIN/Fast Boot keys derived from drive volume serial. Cloning invalidates convenience unlock. Master password remains universal. |
| Host isolation | All app and browser data runs from host temp, not directly from USB. Wiped on exit. |
| Process safety | Per-app PID tracking. Only owned processes are terminated. Uncertain ownership fails closed. |
| Stale cleanup | Leftover temp directories from interrupted sessions are detected and garbage-collected. |
| Threat boundary | Protects against forensic data residue on shared machines. Does not protect against kernel-level rootkits, hardware keyloggers, or elevated malware on the host. |

## Usage on Shared Machines

- Quit through OmniLaunch to ensure the full cleanup sequence runs.
- Keep "Clear App Cache on Exit" enabled on machines not owned by the operator.
- Expect re-authentication for some browser and app sessions on different hardware.
- If an imported app references absolute paths from another machine, update them manually after launch.

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

### Validation

```bash
npm run probe:lifecycle
node scripts/audit-engine.js
```

## Roadmap

Planned features under active development:

| Feature | Description | Status |
|---|---|---|
| **Support tier registry** | First-class app adapter registry with per-app capability resolution and Manifest V2 schema. | 🔜 Next |
| **Phone companion** | Local-network control plane. Pair a phone via QR to manage workspaces, edit tabs, launch, and quit remotely. | Planned |
| **Persistent browser mode** | Connect to a persistent browser instance on a trusted host for reliable signed-in account continuity. | Planned |
| **Account slots** | Per-provider account readiness tracking with assisted re-authentication guidance. | Planned |
| **Native app data adapters** | Exact directory-level data preservation for certified native apps (e.g., Notepad++, VLC). | Planned |
| **Host-write detection** | Scoped before/after snapshots to verify zero-footprint claims with evidence. | Planned |

## License

Proprietary. All rights reserved.

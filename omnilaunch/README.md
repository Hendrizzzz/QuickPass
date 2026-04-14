# OmniLaunch 🚀 (QuickPass Engine)

> A secure, hardware-bound workspace orchestration engine for ephemeral computing.

OmniLaunch provisions authenticated, trace-free workstation environments directly from portable storage. It orchestrates encrypted browser sessions and native portable applications without leaving forensic residue on the host operating system.

## 🏗️ Architecture Overview

OmniLaunch leverages an Electron-based micro-architecture, separating the cryptographic initialization from the presentation and browser orchestration layers.

* **Core Runtime:** Node.js + Electron
* **Presentation:** React 18, Vite, TailwindCSS
* **Browser Engine:** Playwright (Chromium) via CDP (Chrome DevTools Protocol)
* **Cryptography:** AES-256-GCM (Node `crypto`)
* **Hardware Interop:** WMI (`wmic`) for hardware UUID and process management; `vol` for filesystem volume serial; `usb` for detach detection

## ✨ Core Systems

### Ephemeral Segregation ("Ghost Browser")
Standard portable applications often leak state into `AppData` or the system registry. OmniLaunch mitigates this by wrapping an isolated Playwright Chromium instance. All session states, including TLS certificates, cookies, and local storage, are managed via a persistent Chrome profile stored in `BrowserProfile/`, synced between USB and local temp. The vault (`vault.json`) stores workspace configuration (tabs, app list) encrypted with AES-256-GCM. Upon session termination, the host machine retains zero state.

### Hardware-Bound Cryptography
The main vault is encrypted with the user's master password, deriving a 32-byte AES-256 key via PBKDF2-SHA512 (100,000 iterations). For convenience unlock methods (PIN, Fast Boot), the master password is separately encrypted using keys derived from the PIN or serial number, and stored in `vault.meta.json`.
* **Anti-Cloning:** Cloning to a different drive will break PIN and Fast Boot unlock (which depend on the filesystem volume serial), but the main vault can still be unlocked with the correct master password on any machine.
* **Local Fallback:** The codebase includes a fixed-drive encryption path using hardware UUID, but the current build forces removable-drive mode for simplicity. The local-drive path is architecturally supported but not active.

### Workspace Orchestration & Tear-down
Context switching is precise and immediate. 
* **Hydration:** Injects raw cookie states and navigates predefined tab structures via CDP in sub-second timeframes.
* **Process Spawning:** Concurrently boots external portable executables (e.g., VS Code, Telegram).
* **Sanitization:** Implements aggressive lifecycle hooks. On application `Quit`, the system terminates the Electron processes, halts the headless browser, issues `taskkill` equivalents to child executables, and actively scrubs temporary caching directories.

## 🚀 Development & Build

### Prerequisites
* Node.js v18+
* Windows OS (Required for WMI lookups and `.exe` process management)

### Setup

```bash
cd omnilaunch
npm install
```

### Commands

| Command | Description |
|---|---|
| `npm run dev` | Boots the application in development mode with HMR enabled. |
| `npm run build` | Compiles Vite and Electron assets into the `out/` directory. |
| `npm run package` | Builds and bundles a production-ready Windows executable inside a `.zip`. |

## 🔒 Security Posture

1. **Zero Knowledge Recovery:** The system is explicitly designed without administrative backdoors. Data contained within `vault.json` relies concurrently on user memory (PIN) and physical possession (USB Serial). Loss of either guarantees cryptographic data loss.
2. **Host Integrity:** OmniLaunch is designed to protect against data residue and downstream forensic analysis on shared/public machines. It does *not* protect against ring-0 rootkits or hardware-level keyloggers active on a compromised host machine.

## What Transfers Between PCs

| Item | Status | Notes |
|---|---|---|
| Saved tabs and workspace layout | Yes | URLs and app launch configuration roam with the vault. |
| Browser bookmarks, history, and settings | Usually | These live in the Chrome profile and are copied between machines. |
| Browser login sessions | Limited | Chrome may require re-login on a different Windows PC because encrypted secrets are machine-bound. |
| Imported desktop app binaries | Yes | Imported apps can launch from the USB workspace on another PC. |
| Desktop app login sessions | Limited | Electron and Chromium-based apps may require re-login on a different PC. |
| Host-specific workspace paths | No | Apps that store absolute `C:\Users\...` paths may partially break on another machine. |

## Lab/School PC Usage Guide

- Keep `Clear App Cache on Exit` enabled on shared or school machines.
- Expect some browser and desktop apps to ask you to sign in again on a different PC.
- Save your session before unplugging the USB drive.
- If OmniLaunch warns that an imported app contains paths from another PC, re-open that workspace inside the app and update the broken paths.
- If a desktop app opens the system browser for sign-in, that external browser window is outside OmniLaunch's shutdown control.

---
*OmniLaunch / QuickPass — Engineered for absolute workspace portability without compromise.*

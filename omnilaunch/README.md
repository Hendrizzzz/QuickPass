# 🚀 QuickPass: The Secure Workspace Orchestrator

QuickPass is a zero-friction, highly secure workspace initializer designed for public computers, shared workstations, or simply carrying your entire digital life in your pocket.

It solves a specific problem: **How do you instantly open all your required tabs and portable desktop apps, perfectly authenticated and arranged, without leaving a single trace of your cookies or passwords on a host machine?**

While standard portable apps leave you manually clicking menus and portable browsers store your sensitive cookies inside plain, easily-stolen folders, **QuickPass orchestrates your entire workflow instantly while encrypting your session state utilizing military-grade AES-256.** 

Plug it in, authenticate, and your exact desk is restored in 3 seconds.

---

## ✨ The QuickPass Difference

- **🔐 True Segregation (The "Ghost" Browser):** Most portable apps leave traces in the registry or local AppData. QuickPass uses an embedded Playwright engine. Every cookie, history, and login is trapped inside the secure, encrypted `vault.json` on your USB. When you remove the drive, zero trace exists on the host PC.
- **🛡️ Hardware-Bound Security:** 
  - **On a USB Drive:** You use a fast 4-digit PIN (or hardware FastBoot). Under the hood, QuickPass binds to the physical serial number of the flash drive and generates a 64-character master cryptographic key. If a thief clones your files to another USB, it will refuse to unlock.
  - **On a Local PC:** QuickPass adapts to ask for a traditional Master Password, ensuring maximum security for stationary deployments.
- **⚡ Instant Context Switching:** Launch your portable `.exe` applications (like VS Code, Telegram Portable, or specific tools) alongside your perfectly restored 20-tab browser setup with one click.
- **💾 Live Session Saving:** Discovered a great tutorial? Hit "Save Session" while you're working, and QuickPass captures all currently open tabs and cookies from all active windows.

---

## 🛠️ How It Works (The Tech Stack)

1. **Frontend:** React + Vite + TailwindCSS for a sleek, hardware-accelerated UI with modern glassmorphism aesthetics.
2. **Backend Engine:** Node.js + Electron handle the deep OS integrations, file system encryption, and native window management.
3. **Browser Automation:** Playwright (Chromium) is used as the automation engine. QuickPass uses Playwright's CDP (Chrome DevTools Protocol) to load and extract raw cookie states seamlessly.
4. **Cryptography:** Node's native `crypto` library handles AES-GCM encryption for the vault, tied directly to WMI (`wmic`) hardware serial number lookups.

---

## 📖 Walkthrough: The Daily Run

1. **Plug It In:** Insert your flash drive into any Windows PC and run `QuickPass.exe`.
2. **Unlock:** Enter your 4-digit PIN (or instantly bypass if you've enabled FastBoot for this specific hardware).
3. **Orchestrate:** QuickPass instantly decrypts the vault, fires up the browser, injects your cookies exactly as you left them, and launches your `.exe` apps. 
4. **Disappear:** When you're done, hit Quit. QuickPass gracefully tears down the browser, kills the desktop apps, and leaves the host machine exactly how you found it.

---

## ⚙️ Session Management

QuickPass isn't just a static launcher; it tracks your live workspace:
- **Save Session:** Captures all currently open tabs (including those in new Chrome windows via `Ctrl+N`) so you don't lose your place.
- **Desktop Apps:** Configure if you want QuickPass to forcefully kill your desktop apps when you quit, or restart them when you Relaunch.
- **Settings:** Access settings mid-session by quitting cleanly, re-entering your PIN at the unlock screen, and modifying your active apps or security toggles.

---

## 🚨 Security & Best Practices

- **Never forget your PIN or Password.** Your session cookies are encrypted with them. If you lose access, the `vault.json` is mathematically unrecoverable.
- Ensure your USB drive is completely wiped of old, unencrypted browser profiles if you previously used standard Portable browsers. QuickPass is only as secure as the files actively maintained inside its vault.

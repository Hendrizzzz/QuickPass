/**
 * OmniLaunch Automation Engine — Phase 16.2: Local-First Chrome + AppData
 * 
 * Architecture:
 * Chrome profile AND desktop app data are stored on USB but RUN from
 * local temp directories (the "PortableApps pattern"). This avoids
 * catastrophic random I/O on USB (1-5 MB/s → 500+ MB/s on SSD).
 * 
 * On launch:  robocopy USB → local temp (fast sequential read).
 * On app exit: robocopy local temp → USB (sync-on-exit via serialized queue).
 * On close:   wipe local traces (security).
 * 
 * Key Design Decisions (from 6-round architectural audit):
 * - Sync-On-Exit: Data syncs immediately when each app closes, not at workspace teardown
 * - Serialized Queue: Prevents USB bus saturation from parallel robocopy writes
 * - Timeout Escalation: Always waits for the real OS exit event; timeouts only escalate
 *   the kill method (graceful → force), avoiding macrotask/microtask ordering bugs
 * - Reentrancy Guard: Prevents double-close from concurrent callers
 * - abandonSync Flag: Prevents ghost writes during Node.js shutdown
 */
import { chromium } from 'playwright-core'
import { spawn, execSync, exec } from 'child_process'
import { join, parse as pathParse } from 'path'
import { mkdirSync, existsSync, rmSync, readdirSync, renameSync } from 'fs'
import os from 'os'
import crypto from 'crypto'
import { promisify } from 'util'
const execAsync = promisify(exec)

// Active browser/context references
let activeBrowser = null
let activeContext = null
let onDisconnectCallback = null
let activeVaultDir = null

// ─── Run Diagnostics Collector ──────────────────────────────────────────────
// Accumulates timing and status data throughout a run.
// Written to run-diagnostics.json on quit for post-test analysis.
export const runDiagnostics = {
    machineId: null,        // hashed hostname:user (privacy-safe)
    osVersion: null,
    startTime: null,
    phases: [],             // { name, startMs, endMs, durationMs, status, detail }
    appResults: [],         // { name, pid, realPid, exePath, isLauncher, closeMethod }
    browserSync: { copyInMs: null, copyOutMs: null, migrated: false },
    errors: []
}

export function diagPhaseStart(name) {
    runDiagnostics.phases.push({
        name, startMs: Date.now(), endMs: null, durationMs: null, status: 'running', detail: ''
    })
}

export function diagPhaseEnd(name, status = 'ok', detail = '') {
    const phase = runDiagnostics.phases.find(p => p.name === name && p.status === 'running')
    if (phase) {
        phase.endMs = Date.now()
        phase.durationMs = phase.endMs - phase.startMs
        phase.status = status
        phase.detail = detail
    }
}

export function diagError(context, message) {
    runDiagnostics.errors.push({ time: Date.now(), context, message })
}

function updateAppDiagnostic(appObj, patch) {
    if (!appObj?.diagRef) return
    Object.assign(appObj.diagRef, patch)
}

// ─── WQL Escape Helpers ─────────────────────────────────────────────────────
// WQL LIKE patterns treat %, _, [ as wildcards. Exact equality filters do not.

/**
 * Escape for WQL LIKE clauses (e.g., CommandLine like '%...%').
 * Bracket-escapes %, _, [, ] so they match literally.
 */
function escapeWqlLike(str) {
    return str
        .replace(/\[/g, '[[]')     // must be first to avoid double-escape
        .replace(/%/g, '[%]')
        .replace(/_/g, '[_]')
        .replace(/'/g, "''")
}

/**
 * Escape for exact WQL string literals (e.g., Name='...').
 * Only escapes single quotes — LIKE wildcards have no special meaning here.
 */
function escapeWqlLiteral(str) {
    return str.replace(/'/g, "''")
}

// ─── Process Query Abstraction ──────────────────────────────────────────────
// PowerShell Get-CimInstance preferred; falls back to wmic on failure.

/**
 * Query Win32_Process via PowerShell Get-CimInstance.
 * Falls back to wmic if PowerShell fails (access denied, timeout, missing cmdlet).
 * Returns raw stdout string.
 */
function queryProcesses(wqlFilter, selectFields = 'ProcessId') {
    // Try PowerShell first (modern, not deprecated)
    try {
        return execSync(
            `powershell -NoProfile -Command "Get-CimInstance Win32_Process -Filter \\"${wqlFilter}\\" | Select-Object -ExpandProperty ${selectFields}"`,
            { encoding: 'utf8', timeout: 8000, stdio: ['pipe', 'pipe', 'ignore'] }
        )
    } catch (psErr) {
        // Fallback to wmic (deprecated but may be available on older Windows)
        try {
            return execSync(
                `wmic process where "${wqlFilter}" get ${selectFields} /value`,
                { encoding: 'utf8', timeout: 5000, stdio: ['pipe', 'pipe', 'ignore'] }
            )
        } catch (_) { return '' }
    }
}

/**
 * Parse PIDs from either PowerShell (one per line) or WMIC (ProcessId=123) output.
 */
function parsePidsFromOutput(output) {
    const pids = []
    for (const line of output.split(/\r?\n/)) {
        const wmicMatch = line.match(/ProcessId=(\d+)/)
        if (wmicMatch) { pids.push(parseInt(wmicMatch[1])); continue }
        const num = parseInt(line.trim())
        if (!isNaN(num) && num > 0) pids.push(num)
    }
    return pids
}

// ─── Desktop App Tracking & Sync Queue ──────────────────────────────────────────

// Track launched desktop apps with full metadata for sync-on-exit
// Each entry: { pid, child, usbPath, localPath, exited, syncPromise, abandonSync,
//               isLauncherPattern, exePath, spawnTime }
let launchedApps = []

// Serialized sync queue — prevents USB bus saturation from parallel robocopy writes.
// Each sync is chained onto the previous one, guaranteeing sequential USB I/O.
let globalSyncQueue = Promise.resolve()

// Reentrancy guard — prevents double-close from concurrent callers
// (e.g., user clicks Close Workspace then immediately clicks Quit)
let closeInProgress = null

/**
 * Enqueue a sync operation (local → USB) onto the serialized queue.
 * Guarantees sequential writes even if multiple apps close simultaneously.
 * Always wipes local data after sync (security), even if sync fails.
 */
function enqueueSync(usbPath, localPath) {
    globalSyncQueue = globalSyncQueue.then(async () => {
        // Check if USB drive is still accessible before attempting sync
        const driveRoot = pathParse(usbPath).root
        if (!existsSync(driveRoot)) return

        try {
            await robocopyAsync(localPath, usbPath)
        } finally {
            // ALWAYS wipe local copy — security trumps data integrity
            try { rmSync(localPath, { recursive: true, force: true }) } catch (_) { }
        }
    }).catch(err => console.error('[QuickPass] Sync Queue error:', err))

    return globalSyncQueue
}

// ─── Local-First Profile Management ────────────────────────────────────────────

function patchProfileLocale(profileDir) {
    try {
        const fs = require('fs')

        // Patch Default/Preferences — create if missing (fresh profile)
        const defaultDir = join(profileDir, 'Default')
        if (!fs.existsSync(defaultDir)) fs.mkdirSync(defaultDir, { recursive: true })

        const prefsPath = join(defaultDir, 'Preferences')
        let prefs = {}
        try { prefs = JSON.parse(fs.readFileSync(prefsPath, 'utf8')) } catch (_) {}
        if (!prefs.intl) prefs.intl = {}
        prefs.intl.accept_languages = "en-US,en"
        prefs.intl.selected_languages = "en-US,en"
        // Phase 16: Also patch settings.language fields that Chrome uses for site locale
        if (!prefs.settings) prefs.settings = {}
        if (!prefs.settings.language) prefs.settings.language = {}
        prefs.settings.language.preferred_languages = "en-US,en"
        fs.writeFileSync(prefsPath, JSON.stringify(prefs), 'utf8')

        // Patch Local State — create if missing (fresh profile)
        const localStatePath = join(profileDir, 'Local State')
        let state = {}
        try { state = JSON.parse(fs.readFileSync(localStatePath, 'utf8')) } catch (_) {}
        if (!state.intl) state.intl = {}
        state.intl.app_locale = "en-US"
        state.intl.pref_locale = "en-US"
        fs.writeFileSync(localStatePath, JSON.stringify(state), 'utf8')

        // Phase 16: Delete TranslateRanker cache to prevent stale locale data
        const translateRankerPath = join(defaultDir, 'TranslateRankerModel')
        try { if (fs.existsSync(translateRankerPath)) fs.rmSync(translateRankerPath, { recursive: true, force: true }) } catch (_) {}
    } catch (_) {}
}

/**
 * Generates a unique local temp path for the Chrome profile.
 * Uses an MD5 hash of the vault dir to prevent collisions if
 * two different USBs are used on the same PC.
 */
function getLocalProfileDir(vaultDir) {
    const hash = crypto.createHash('md5').update(vaultDir).digest('hex').slice(0, 8)
    return join(os.tmpdir(), `QuickPass-Profile-${hash}`)
}

function warnOnEmbeddedHostPaths(localPath, appConfig, onStatus) {
    if (!localPath) return

    try {
        const fs = require('fs')
        const currentUser = os.userInfo().username
        const topFiles = fs.readdirSync(localPath)
            .filter(f => f.endsWith('.json') || f.endsWith('.code-workspace'))
            .slice(0, 10)

        for (const file of topFiles) {
            try {
                const content = fs.readFileSync(join(localPath, file), 'utf8')
                const foreignPathMatch = content.match(/[A-Z]:\\Users\\([^\\"]+)/i)
                if (foreignPathMatch && foreignPathMatch[1] !== currentUser) {
                    onStatus(`[WARN] ${appConfig.name} contains paths from a different PC (${foreignPathMatch[1]}). Some features may not work.`)
                    diagError('embedded-path', `${appConfig.name}/${file} references user ${foreignPathMatch[1]}`)
                    break
                }
            } catch (_) { }
        }
    } catch (_) { }
}

/**
 * Async robocopy wrapper — does NOT block the Node.js event loop.
 * Uses /MIR for exact replica in both directions.
 * Robocopy exit codes: 0-7 = success, 8+ = error.
 *
 * Phase 16.3 performance:
 * - Removed /IPG:2 (inter-packet gap) — was adding ~15s of artificial sleep per 500MB
 * - Added /MT:4 (multi-threaded) — significantly faster for directories with many small files
 */
function robocopyAsync(src, dest) {
    return new Promise((resolve, reject) => {
        const proc = spawn('robocopy',
            [src, dest, '/MIR', '/MT:4', '/NFL', '/NDL', '/NJH', '/NJS', '/NC', '/NS', '/NP', '/R:0', '/W:0',
             '/XD', 'Cache', 'Code Cache', 'GPUCache', 'ShaderCache', 'GrShaderCache',
             'DawnWebGPUCache', 'DawnGraphiteCache', 'Service Worker', 'ScriptCache',
             'BrowserMetrics', 'Crashpad', 'blob_storage', 'Session Storage', 'Temp', 'logs'],
            { stdio: 'ignore' })
        proc.on('close', (code) => {
            if (code >= 8) reject(new Error(`robocopy failed: exit ${code}`))
            else resolve()
        })
    })
}

/**
 * Securely wipes the local Chrome profile for a given vault.
 * EXPORTED for use by index.js (kill cord, exit handler).
 */
export function wipeLocalTraces(vaultDir) {
    try {
        const localProfile = getLocalProfileDir(vaultDir)
        rmSync(localProfile, { recursive: true, force: true })
    } catch (_) { }
}

/**
 * Wipes ALL QuickPass Chrome profile directories from temp.
 * Used as belt-and-suspenders fallback — no dependency on knowing vaultDir.
 */
export function wipeAllLocalProfiles() {
    try {
        const tempDir = os.tmpdir()
        for (const dir of readdirSync(tempDir)) {
            if (dir.startsWith('QuickPass-Profile-')) {
                try { rmSync(join(tempDir, dir), { recursive: true, force: true }) } catch (_) { }
            }
        }
    } catch (_) { }
}

/**
 * Wipes ALL QuickPass desktop app AUTH DATA directories from temp.
 * ALWAYS runs on exit — auth tokens must never persist on host PCs.
 * Belt-and-suspenders: called on process exit and kill cord.
 */
export function wipeAllLocalAppData() {
    try {
        const tempDir = os.tmpdir()
        for (const dir of readdirSync(tempDir)) {
            if (dir.startsWith('QuickPass-AppData-')) {
                try { rmSync(join(tempDir, dir), { recursive: true, force: true }) } catch (_) { }
            }
        }
    } catch (_) { }
}

/**
 * Wipes extracted app BINARIES (QuickPass-App-*) from temp.
 * Conditionally called based on clearCacheOnExit toggle.
 * When OFF: apps persist for instant <10s launches on home PC.
 * When ON:  zero-footprint mode for public/school PCs.
 */
export function wipeLocalAppCache() {
    try {
        const tempDir = os.tmpdir()
        for (const dir of readdirSync(tempDir)) {
            if (dir.startsWith('QuickPass-App-')) {
                try { rmSync(join(tempDir, dir), { recursive: true, force: true }) } catch (_) { }
            }
        }
    } catch (_) { }
}

// ─── Disconnect Detection ───────────────────────────────────────────────────────

export function onBrowserAllClosed(cb) {
    onDisconnectCallback = cb
}

function attachPageTracking(context) {
    let closeDebounce = null

    const checkAllClosed = () => {
        // Clear any pending debounce — a new page may have opened
        if (closeDebounce) { clearTimeout(closeDebounce); closeDebounce = null }

        try {
            const remaining = context?.pages() || []
            if (remaining.length === 0) {
                // Phase 16.3: Debounce 2s before closing — gives Google OAuth
                // redirects time to complete without falsely triggering disconnect.
                // Without this, logging into Google closes the browser because the
                // page count momentarily drops to 0 during the OAuth redirect.
                closeDebounce = setTimeout(() => {
                    try {
                        const recheck = context?.pages() || []
                        if (recheck.length === 0) {
                            if (onDisconnectCallback) onDisconnectCallback()
                            context?.close().catch(() => { })
                            activeBrowser = null
                            activeContext = null
                        }
                    } catch (_) {
                        if (onDisconnectCallback) onDisconnectCallback()
                        activeBrowser = null
                        activeContext = null
                    }
                }, 2000)
            }
        } catch (_) {
            if (onDisconnectCallback) onDisconnectCallback()
            activeBrowser = null
            activeContext = null
        }
    }
    const trackPage = (page) => page.on('close', checkAllClosed)
    for (const p of context.pages()) trackPage(p)
    context.on('page', (p) => trackPage(p))
}

// ─── Profile Lock Cleanup ───────────────────────────────────────────────────────

/**
 * Chrome creates a "SingletonLock" file inside the user-data-dir to prevent
 * multiple instances using the same profile. If Chrome crashes or the USB is
 * yanked, this lock file persists and blocks the next launch.
 * This function removes stale lock files before launching.
 */
function cleanProfileLocks(profileDir) {
    const lockFiles = ['SingletonLock', 'SingletonSocket', 'SingletonCookie']
    for (const lockFile of lockFiles) {
        const lockPath = join(profileDir, lockFile)
        try {
            if (existsSync(lockPath)) {
                rmSync(lockPath, { force: true })
            }
        } catch (_) { }
    }
}

// ─── Local-First Browser Launch ─────────────────────────────────────────────────

/**
 * Detects cross-machine profile migration and surgically removes
 * DPAPI-bound secrets so Chrome regenerates them cleanly.
 *
 * Design decisions (from 9-round peer review):
 * - Machine marker is SHA-256 hashed (privacy-safe, no raw hostnames on USB)
 * - DPAPI files are DELETED, not quarantined — quarantine files would be
 *   mirrored back to USB by robocopy /MIR on close, accumulating dead weight.
 *   The diagnostics log (run-diagnostics.json) serves as forensic record.
 * - Only os_crypt.encrypted_key is removed from Local State — locale patches,
 *   profile info, and all other settings are preserved.
 */
function handleProfileMigration(profileDir) {
    const fs = require('fs')
    // crypto is already imported at module scope (line 26)

    const rawId = `${os.hostname()}:${os.userInfo().username}`
    const machineHash = crypto.createHash('sha256').update(rawId).digest('hex').slice(0, 16)
    const markerPath = join(profileDir, '.quickpass-machine-id')
    const localStatePath = join(profileDir, 'Local State')

    let lastHash = null
    try { lastHash = fs.readFileSync(markerPath, 'utf8').trim() } catch (_) {}

    // Same machine or first run — no migration needed
    if (!lastHash || lastHash === machineHash) {
        try { fs.writeFileSync(markerPath, machineHash, 'utf8') } catch (_) {}
        return false
    }

    // ─── MIGRATION DETECTED ─────────────────────────────────────────
    console.log(`[QuickPass] Machine migration detected (${lastHash} → ${machineHash})`)
    diagPhaseStart('profile-migration-scrub')
    diagError('profile-migration', `Profile moved from machine ${lastHash} to ${machineHash}`)

    // Surgical scrub of Local State: remove ONLY os_crypt.encrypted_key
    // This preserves locale patches (intl.app_locale, intl.pref_locale) and all other state
    try {
        if (fs.existsSync(localStatePath)) {
            const state = JSON.parse(fs.readFileSync(localStatePath, 'utf8'))
            let modified = false
            if (state.os_crypt && state.os_crypt.encrypted_key) {
                delete state.os_crypt.encrypted_key
                modified = true
            }
            if (state.os_crypt && state.os_crypt.audit_enabled !== undefined) {
                delete state.os_crypt.audit_enabled
                modified = true
            }
            if (modified) {
                fs.writeFileSync(localStatePath, JSON.stringify(state), 'utf8')
                console.log('[QuickPass] Scrubbed DPAPI key from Local State')
            }
        }
    } catch (err) {
        diagError('profile-migration', `Local State scrub failed: ${err.message}`)
    }

    // Delete DPAPI-encrypted databases — Chrome will recreate them with new machine key
    // NOT quarantine — quarantined .bak files would be mirrored to USB by robocopy
    const filesToDelete = [
        join(profileDir, 'Default', 'Web Data'),       // token_service_table
        join(profileDir, 'Default', 'Login Data'),      // saved passwords
    ]
    for (const fp of filesToDelete) {
        if (existsSync(fp)) {
            try {
                require('fs').unlinkSync(fp)
                console.log(`[QuickPass] Deleted DPAPI-encrypted: ${fp}`)
            } catch (_) {}
        }
    }

    // Update marker to current machine
    try { fs.writeFileSync(markerPath, machineHash, 'utf8') } catch (_) {}

    diagPhaseEnd('profile-migration-scrub')
    return true
}

/**
 * Launch Chrome with a local copy of the USB-stored browser profile.
 *
 * Flow:
 * 1. Copy USB BrowserProfile → local temp dir (async robocopy, ~10-15s)
 * 2. Detect cross-machine migration & scrub DPAPI secrets
 * 3. Launch Chrome from local temp (SSD speed, no USB random I/O)
 * 4. On close, closeBrowser() syncs back and wipes local
 *
 * This is the "PortableApps pattern" — same approach used by
 * Portable Firefox, Tor Browser, etc.
 */
async function launchChrome(vaultDir, onStatus = () => {}) {
    activeVaultDir = vaultDir
    const usbProfile = join(vaultDir, 'BrowserProfile')
    const localProfile = getLocalProfileDir(vaultDir)
    mkdirSync(localProfile, { recursive: true })

    // Mirror USB profile → local temp (if profile exists on USB)
    diagPhaseStart('browser-copy-in')
    const copyInStart = Date.now()
    if (existsSync(usbProfile)) {
        try {
            await robocopyAsync(usbProfile, localProfile)
        } catch (err) {
            console.error('[QuickPass] Failed to sync profile from USB:', err)
            diagError('browser-copy-in', err.message)
        }
    }
    runDiagnostics.browserSync.copyInMs = Date.now() - copyInStart
    diagPhaseEnd('browser-copy-in')

    // Clean stale lock files from crashed sessions
    cleanProfileLocks(localProfile)

    // Detect cross-machine migration and scrub DPAPI secrets
    const migrated = handleProfileMigration(localProfile)
    if (migrated) {
        onStatus('[INFO] New PC detected - browser sessions will require re-login')
        runDiagnostics.browserSync.migrated = true
    }

    // Force English language by aggressively patching the embedded JSON preferences
    patchProfileLocale(localProfile)

    const launchOptions = {
        headless: false,
        channel: 'chrome',
        viewport: null,
        ignoreHTTPSErrors: true,
        locale: 'en-US',
        // Phase 16: Force Accept-Language header so sites serve English content
        extraHTTPHeaders: {
            'Accept-Language': 'en-US,en;q=0.9'
        },
        // Allow Chrome extensions + remove automation/sandbox banners
        ignoreDefaultArgs: ['--enable-automation', '--disable-extensions', '--no-sandbox'],
        args: [
            '--lang=en-US',
            '--no-first-run',
            '--no-default-browser-check',
            '--disable-infobars',
            '--disable-blink-features=AutomationControlled',
            '--start-maximized',
            '--disable-gpu-shader-disk-cache'
        ]
        // Phase 16: Removed hardcoded userAgent — let Chrome use its real, matching UA
        // to avoid version mismatch fingerprinting that triggers CAPTCHA
    }

    let context
    diagPhaseStart('browser-launch')
    try {
        context = await chromium.launchPersistentContext(localProfile, launchOptions)
    } catch (launchErr) {
        diagError('browser-launch', `Primary launch failed: ${launchErr.message}`)
        console.error('[QuickPass] Chrome launch failed, retrying with clean profile:', launchErr.message)

        // Nuclear fallback: nuke the corrupted local profile and start fresh
        try { rmSync(localProfile, { recursive: true, force: true }) } catch (_) {}
        mkdirSync(localProfile, { recursive: true })
        patchProfileLocale(localProfile)
        // Write machine marker so next run doesn't re-trigger migration
        const machineHash = crypto.createHash('sha256')
            .update(`${os.hostname()}:${os.userInfo().username}`)
            .digest('hex').slice(0, 16)
        try { require('fs').writeFileSync(join(localProfile, '.quickpass-machine-id'), machineHash) } catch (_) {}

        context = await chromium.launchPersistentContext(localProfile, launchOptions)
        onStatus('[WARN] Browser launched with fresh profile - all sessions reset')
    }
    diagPhaseEnd('browser-launch')

    const browser = context.browser()
    return { context, browser }
}

// ─── URL Extraction ─────────────────────────────────────────────────────────────â”€

/**
 * Collects URLs from the active browser context.
 * With persistent profiles, we no longer need to extract cookies/storageState
 * because all auth data lives in the profile directory on the USB.
 * We only extract URLs for workspace tracking.
 */
async function extractAllPages() {
    if (!activeContext) return { urls: [] }

    const allUrls = []

    // With launchPersistentContext there is only one context,
    // but we still iterate for robustness (Ctrl+N windows share the same context)
    const pages = activeContext.pages()
    for (const p of pages) {
        try {
            const url = p.url()
            if (url && url !== 'about:blank' && !url.startsWith('chrome://')) {
                allUrls.push(url)
            }
        } catch (_) { }
    }

    return { urls: allUrls }
}

// ─── Session Setup / Edit ───────────────────────────────────────────────────────

/**
 * Opens Chrome for session setup/editing.
 * With persistent profiles, savedState is no longer needed — the profile
 * on the USB already contains all cookies, GAIA tokens, and login sessions.
 * 
 * @param {Function} onStatus - Status callback
 * @param {string} vaultDir - USB vault directory (for profile storage)
 * @param {string[]} urls - URLs to open (empty = open google.com)
 */
export async function launchSessionSetup(onStatus, vaultDir, urls = []) {
    onStatus('Opening browser...')

    const { context, browser } = await launchChrome(vaultDir, onStatus)
    activeContext = context
    activeBrowser = browser

    // Phase 11+16: Bot Mitigation Script Injection
    await activeContext.addInitScript(() => {
        Object.defineProperty(navigator, 'webdriver', { get: () => undefined })
        // Phase 16: Don't overwrite window.chrome — it already exists in real Chrome
        // and replacing it with a stub is MORE detectable than leaving it alone
        if (!window.chrome) {
            window.chrome = { runtime: {} }
        }
    })

    attachPageTracking(activeContext)

    // Close the default blank page that launchPersistentContext opens
    const existingPages = activeContext.pages()
    const blankPages = existingPages.filter(p => p.url() === 'about:blank')

    if (urls.length > 0) {
        for (let i = 0; i < urls.length; i++) {
            const url = urls[i].startsWith('http') ? urls[i] : `https://${urls[i]}`
            const page = await activeContext.newPage()
            onStatus(`Loading tab ${i + 1}/${urls.length}...`)
            await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 }).catch(() => { })
        }
        // Close initial blank pages after new tabs are opened
        for (const bp of blankPages) {
            await bp.close().catch(() => { })
        }
        onStatus('All tabs loaded. Edit your workspace, then save.')
    } else {
        // Use the first existing page or create a new one
        const page = existingPages.length > 0 ? existingPages[0] : await activeContext.newPage()
        await page.goto('https://www.google.com', { waitUntil: 'domcontentloaded', timeout: 15000 }).catch(() => { })
        onStatus('Browser is ready. Navigate to your sites and log in.')
    }

    return { success: true }
}

// ─── Session Capture ────────────────────────────────────────────────────────────

/**
 * Captures URLs from the browser and CLOSES it (flushes profile to disk).
 * With persistent profiles, we only need to track URLs — auth data is
 * automatically persisted in the profile directory when the browser closes.
 */
export async function captureSession() {
    const result = await captureCurrentSession()

    // Close browser gracefully — this flushes all profile data to the USB
    await closeBrowser()

    if (!result.success && result.error === 'No tabs are open') {
        return { success: false, error: 'No tabs are open. Please open at least one website.' }
    }

    return result
}

/**
 * Captures URLs from the browser WITHOUT closing.
 */
export async function captureCurrentSession() {
    if (!activeContext) {
        return { success: false, error: 'No active browser session' }
    }

    try {
        const { urls } = await extractAllPages()

        if (urls.length === 0) {
            return { success: false, error: 'No tabs are open' }
        }

        // No longer returning 'state' (cookies) — profile handles auth persistence
        return { success: true, urls, tabCount: urls.length }
    } catch (err) {
        return { success: false, error: err.message }
    }
}

// ─── Browser & App Control ──────────────────────────────────────────────────────

/**
 * Gracefully closes the browser, syncs profile to USB, wipes local copy.
 * Uses try/finally to GUARANTEE local wipe even if sync fails.
 */
export async function closeBrowser() {
    onDisconnectCallback = null
    if (activeContext) {
        // Close context first — flushes all profile data to local temp dir
        await activeContext.close().catch(() => { })
        activeContext = null
        activeBrowser = null
    } else if (activeBrowser) {
        await activeBrowser.close().catch(() => { })
        activeBrowser = null
    }

    // Sync local profile → USB, then ALWAYS wipe local copy (security)
    if (activeVaultDir) {
        const usbProfile = join(activeVaultDir, 'BrowserProfile')
        const localProfile = getLocalProfileDir(activeVaultDir)
        diagPhaseStart('browser-copy-out')
        const copyOutStart = Date.now()
        try {
            mkdirSync(usbProfile, { recursive: true })
            await robocopyAsync(localProfile, usbProfile)
        } catch (err) {
            console.error('[QuickPass] Profile sync to USB failed:', err)
            diagError('browser-copy-out', err.message)
        } finally {
            runDiagnostics.browserSync.copyOutMs = Date.now() - copyOutStart
            diagPhaseEnd('browser-copy-out')
            // ALWAYS wipe local profile — even if sync failed
            try { rmSync(localProfile, { recursive: true, force: true }) } catch (_) { }
            activeVaultDir = null
        }
    }
}


/**
 * Find processes whose command line contains a specific path (SYNCHRONOUS).
 * Uses PowerShell Get-CimInstance with WMIC fallback via queryProcesses().
 * Used in closeDesktopApps() and emergencyKillDesktopAppsSync() where we
 * need synchronous results during teardown.
 */
function findRealPidsByCommandLine(searchString) {
    try {
        const escaped = escapeWqlLike(searchString)
        const output = queryProcesses(`CommandLine like '%${escaped}%'`)
        return parsePidsFromOutput(output)
    } catch (_) { return [] }
}

/**
 * Find processes whose command line contains a specific path (ASYNC).
 * Non-blocking — used for the polling monitor so we never freeze the event loop.
 * Returns a Promise that resolves to an array of PIDs.
 *
 * NOTE: Uses PowerShell only (no WMIC fallback). This is intentional —
 * async polling is non-critical. If PowerShell fails, the app falls through
 * to the authoritative closeDesktopApps() shutdown path which has full fallback.
 */
function findRealPidAsync(searchString) {
    return new Promise((resolve) => {
        try {
            const escaped = escapeWqlLike(searchString)
            const proc = spawn('powershell', [
                '-NoProfile', '-Command',
                `Get-CimInstance Win32_Process -Filter "CommandLine like '%${escaped}%'" | Select-Object -ExpandProperty ProcessId`
            ], { stdio: ['ignore', 'pipe', 'ignore'] })

            let output = ''
            proc.stdout.on('data', d => { output += d.toString() })
            proc.on('close', () => resolve(parsePidsFromOutput(output)))
            proc.on('error', () => resolve([]))
        } catch (_) { resolve([]) }
    })
}

/**
 * Find processes by name + creation-time window (SYNCHRONOUS).
 * Fallback for manually-added apps without localPath (e.g., CapCut).
 * Uses process Name (not full ExecutablePath) because ExecutablePath may
 * require SeDebugPrivilege. Creation-time window reduces false positives.
 * Has PowerShell→WMIC fallback (WMIC path loses creation-time precision).
 */
function findPidsByProcessName(exePath, spawnTime) {
    try {
        const exeName = require('path').basename(exePath)
        const escaped = escapeWqlLiteral(exeName)
        // Try PowerShell: emit CreatedMs as explicit Unix timestamp
        let output = ''
        try {
            output = execSync(
                `powershell -NoProfile -Command "Get-CimInstance Win32_Process -Filter \\"Name='${escaped}'\\" | ForEach-Object { [pscustomobject]@{ ProcessId = $_.ProcessId; CreatedMs = ([DateTimeOffset]$_.CreationDate).ToUnixTimeMilliseconds() } } | ConvertTo-Json -Compress"`,
                { encoding: 'utf8', timeout: 8000, stdio: ['pipe', 'pipe', 'ignore'] }
            )
        } catch (psErr) {
            // WMIC fallback: less precise (no creation-time filter), but functional
            const wmicOutput = queryProcesses(`Name='${escaped}'`)
            return parsePidsFromOutput(wmicOutput)
        }

        let entries = JSON.parse(output || '[]')
        if (!Array.isArray(entries)) entries = [entries]

        const validPids = []
        for (const entry of entries) {
            if (!entry || !entry.ProcessId) continue
            // Filter by creation time: only include processes started
            // within 60 seconds after our spawn (reduces false positives)
            if (spawnTime && entry.CreatedMs) {
                if (entry.CreatedMs < spawnTime || entry.CreatedMs > spawnTime + 60000) continue
            }
            validPids.push(entry.ProcessId)
        }
        return validPids
    } catch (_) { return [] }
}

/**
 * Gracefully close all tracked desktop apps, sync their data to USB,
 * and wipe local traces.
 *
 * Architecture (Timeout Escalation — NOT Promise.race):
 * 1. Send all graceful kill signals (taskkill /T) in parallel — O(1) block time
 * 2. Wait for all native OS exit events — the timeout only ESCALATES the kill
 *    method (graceful → force), never short-circuits the exit event wait.
 * 3. Handle launcher-pattern apps — find the real process by command-line
 *    fingerprint, kill it, and enqueue a deferred sync.
 * 4. Drain the serialized sync queue.
 *
 * Reentrancy guard: If called concurrently (e.g., user clicks Close Workspace
 * then immediately clicks Quit), subsequent calls piggyback on the active close.
 */
export async function closeDesktopApps() {
    // Reentrancy guard — piggyback on active close if one is already running
    if (closeInProgress) return closeInProgress

    closeInProgress = (async () => {
        // Phase 1: Send ALL graceful kill signals in parallel
        for (const app of launchedApps) {
            if (!app.exited && app.child.exitCode === null) {
                app.closeMethod = app.closeMethod || 'graceful'
                updateAppDiagnostic(app, { closeMethod: app.closeMethod })
                try {
                    execSync(`taskkill /pid ${app.pid} /T`, { stdio: 'ignore' })
                } catch (_) { }
            }
        }

        // Phase 2: Await exits with Timeout Escalation
        await Promise.all(launchedApps.map(app => {
            return new Promise(resolve => {
                // Already dead — just resolve (avoid hang on already-exited apps)
                if (app.exited || app.child.exitCode !== null) return resolve()

                let settled = false
                let escalateTimer, failsafeTimer

                app.child.once('exit', () => {
                    if (settled) return
                    settled = true
                    clearTimeout(escalateTimer)
                    clearTimeout(failsafeTimer)
                    resolve()
                })

                // Escalation: if graceful kill hasn't worked after 4s, force kill
                escalateTimer = setTimeout(() => {
                    if (!settled) {
                        app.closeMethod = 'force'
                        updateAppDiagnostic(app, { closeMethod: app.closeMethod })
                        try {
                            execSync(`taskkill /pid ${app.pid} /F`, { stdio: 'ignore' })
                        } catch (_) { }
                    }
                }, 4000)

                // Failsafe: if process is truly zombied after 7s, give up
                failsafeTimer = setTimeout(() => {
                    if (!settled) {
                        settled = true
                        app.abandonSync = true
                        app.closeMethod = 'failsafe'
                        updateAppDiagnostic(app, { closeMethod: app.closeMethod })
                        resolve()
                    }
                }, 7000)
            })
        }))

        // Phase 3: Handle launcher-pattern apps — the launcher exited early
        // but the real app is still running under a different PID.
        // Multi-signal approach: command-line fingerprint (primary), process-name (fallback)
        for (const app of launchedApps) {
            if (app.isLauncherPattern) {
                let realPids = []
                // Signal 1: command-line fingerprint (most precise for imported apps)
                if (app.localPath) {
                    realPids = findRealPidsByCommandLine(app.localPath)
                }
                // Signal 2: process name + creation-time window (for manually-added apps)
                if (realPids.length === 0 && app.exePath) {
                    realPids = findPidsByProcessName(app.exePath, app.spawnTime)
                    realPids = realPids.filter(p => p !== app.pid)
                }
                if (realPids.length > 0) {
                    app.closeMethod = 'launcher-kill'
                    updateAppDiagnostic(app, {
                        closeMethod: app.closeMethod,
                        isLauncher: true,
                        realPid: app.realPid || realPids[0] || null
                    })
                }
                for (const pid of realPids) {
                    try { execSync(`taskkill /pid ${pid} /F`, { stdio: 'ignore' }) } catch (_) { }
                }
                // Brief wait for the killed processes to fully exit
                if (realPids.length > 0) {
                    await new Promise(r => setTimeout(r, 500))
                }
                // Enqueue the deferred sync that was skipped during launcher exit
                if (app.usbPath && app.localPath && !app.syncPromise && !app.abandonSync) {
                    app.syncPromise = enqueueSync(app.usbPath, app.localPath)
                }
            }
        }

        // Phase 4: Drain all syncs (populated by exit events + deferred launcher syncs)
        await globalSyncQueue

        launchedApps = []
    })()

    try { await closeInProgress } finally { closeInProgress = null }
}

/**
 * Emergency synchronous kill for kill cord (USB yanked).
 * No syncs attempted — USB is gone. Just kill everything including
 * launcher-pattern orphans, and set abandonSync to prevent ghost writes.
 */
export function emergencyKillDesktopAppsSync() {
    for (const app of launchedApps) {
        app.abandonSync = true
        if (!app.exited && app.child.exitCode === null) {
            try {
                execSync(`taskkill /pid ${app.pid} /F`, { stdio: 'ignore' })
            } catch (_) { }
        }
        // Also kill launcher-pattern orphans using multi-signal approach
        if (app.isLauncherPattern) {
            let realPids = []
            if (app.localPath) {
                realPids = findRealPidsByCommandLine(app.localPath)
            }
            if (realPids.length === 0 && app.exePath) {
                realPids = findPidsByProcessName(app.exePath, app.spawnTime)
                realPids = realPids.filter(p => p !== app.pid)
            }
            for (const pid of realPids) {
                try { execSync(`taskkill /pid ${pid} /F`, { stdio: 'ignore' }) } catch (_) { }
            }
        }
    }
    launchedApps = []
}

// ─── Desktop App Launcher ───────────────────────────────────────────────────────

async function launchDesktopApp(appConfig, onStatus, vaultDir) {
    try {
        onStatus(`Launching ${appConfig.name}...`)
        let args = appConfig.args ? appConfig.args.split(' ').filter(Boolean) : []
        let appPath = appConfig.path

        // ─── Phase 17: Archive Extraction ─────────────────────────────
        // If the app was imported as a .tar.zst archive, extract it to local
        // temp on first launch. Subsequent launches skip extraction.
        // This makes apps run from fast SSD instead of slow USB.
        if (vaultDir && appPath.startsWith(vaultDir)) {
            const relPath = appPath.substring(vaultDir.length) // e.g. \Apps\Name\app.exe
            const parts = relPath.split(/[\\/]/).filter(Boolean) // ['Apps', 'Name', 'app.exe']
            if (parts[0] === 'Apps' && parts.length >= 3) {
                const appName = parts[1] // e.g. 'Antigravity'
                const exeRelative = parts.slice(2).join('\\') // e.g. 'app.exe' or 'bin\64bit\obs64.exe'
                const archivePath = join(vaultDir, 'Apps', `${appName}.tar.zst`)
                const dirPath = join(vaultDir, 'Apps', appName)

                if (existsSync(archivePath) && !existsSync(dirPath)) {
                    // Archive exists but not extracted — extract to local temp
                    const safeName = appName.replace(/[^a-zA-Z0-9_-]/g, '_')
                    const localAppDir = join(os.tmpdir(), `QuickPass-App-${safeName}`)
                    // Extract INTO a directory named after the app (not the source dir)
                    // --strip-components=1 removes the original source dir name (e.g. 'obs-studio')
                    // so contents go directly into localAppDir/appName/
                    const localAppRoot = join(localAppDir, appName)
                    const localExePath = join(localAppRoot, exeRelative)

                    if (!existsSync(localExePath)) {
                        onStatus(`Extracting ${appConfig.name}...`)
                        mkdirSync(localAppRoot, { recursive: true })
                        try {
                            // Fix 4: Use spawn array instead of execAsync template string
                            // to prevent command injection from paths with & | ; chars
                            await new Promise((resolve, reject) => {
                                const proc = spawn('tar', ['--zstd', '--strip-components=1', '-xf', archivePath, '-C', localAppRoot], { stdio: 'ignore' })
                                proc.on('close', (code) => code === 0 ? resolve() : reject(new Error(`tar exit ${code}`)))
                                proc.on('error', reject)
                            })
                        } catch (err) {
                            console.error(`[QuickPass] Failed to extract ${appName}:`, err)
                            // Fix 3: Wipe partial extraction to prevent corrupted state
                            // Without this, a half-extracted app (exe exists but DLLs don't)
                            // would permanently crash on every subsequent launch attempt
                            try { rmSync(localAppRoot, { recursive: true, force: true }) } catch (_) {}
                        }
                    }

                    // If extraction succeeded, redirect to local path
                    if (existsSync(localExePath)) {
                        appPath = localExePath
                        onStatus(`Launching ${appConfig.name} from local...`)
                    }
                } else if (existsSync(archivePath) && existsSync(dirPath)) {
                    // Legacy: both archive and directory exist — use directory (backward compat)
                } else if (!existsSync(dirPath) && !existsSync(archivePath)) {
                    // Check if already extracted to local temp
                    const safeName = appName.replace(/[^a-zA-Z0-9_-]/g, '_')
                    const localExePath = join(os.tmpdir(), `QuickPass-App-${safeName}`, appName, exeRelative)
                    if (existsSync(localExePath)) {
                        appPath = localExePath
                    }
                }
            }
        }

        // ─── Phase 16.2: Local-First AppData ────────────────────────────
        // For portable Electron/Chromium apps, copy AppData from USB → local temp
        // before launch, then run from local SSD speed instead of USB random I/O.
        let usbPath = null
        let localPath = null

        if (appConfig.portableData && vaultDir) {
            const safeName = appConfig.name.replace(/[^a-zA-Z0-9_-]/g, '_')
            const sanitizedPath = join(vaultDir, 'AppData', safeName)
            const rawPath = join(vaultDir, 'AppData', appConfig.name)

            // Phase 17.2: Backward compat for pre-17.2 imports that used raw names.
            // If raw folder exists, it has the originally imported data — prefer it.
            // If a buggy sanitized folder also exists, back it up (don't destroy it).
            if (safeName !== appConfig.name && existsSync(rawPath)) {
                usbPath = rawPath
                // Preserve any data the buggy launch-and-sync cycle put in the sanitized folder
                if (existsSync(sanitizedPath)) {
                    const bakPath = `${sanitizedPath}.bak-${Date.now()}`
                    try {
                        renameSync(sanitizedPath, bakPath)
                        console.log(`[QuickPass] Legacy conflict: backed up ${sanitizedPath} → ${bakPath}`)
                    } catch (e) {
                        console.warn(`[QuickPass] Failed to backup sanitized folder: ${e.message}`)
                    }
                }
            } else {
                usbPath = sanitizedPath
            }

            localPath = join(os.tmpdir(), `QuickPass-AppData-${safeName}`)

            mkdirSync(usbPath, { recursive: true })
            mkdirSync(localPath, { recursive: true })

            // Mirror USB AppData → local temp (fast sequential read)
            if (existsSync(usbPath)) {
                try {
                    onStatus(`Syncing ${appConfig.name} data to local...`)
                    await robocopyAsync(usbPath, localPath)
                } catch (err) {
                    console.error(`[QuickPass] Failed to sync AppData for ${appConfig.name}:`, err)
                }
            }

            // Point --user-data-dir to fast local temp, NOT slow USB
            args = [`--user-data-dir=${localPath}`, ...args]
        }

        warnOnEmbeddedHostPaths(localPath, appConfig, onStatus)

        let child

        // Phase 12: File Explorer Context Support
        const isExe = appPath.toLowerCase().endsWith('.exe') || appPath.toLowerCase().endsWith('.bat') || appPath.toLowerCase().endsWith('.cmd')

        // Phase 15: Set cwd to the directory containing the .exe
        let cwd = undefined
        if (isExe && appPath && existsSync(appPath)) {
            cwd = require('path').dirname(appPath)
        }

        if (isExe) {
            child = spawn(appPath, args, {
                detached: true,
                stdio: 'ignore',
                ...(cwd ? { cwd } : {})
            })
        } else {
            child = spawn('explorer.exe', [appPath, ...args], {
                detached: true,
                stdio: 'ignore',
                ...(cwd ? { cwd } : {})
            })
        }

        // Attach error listener BEFORE checking pid to prevent uncaught ENOENT crash
        const spawnError = new Promise((resolve) => {
            child.on('error', (err) => {
                onStatus(`[WARN] ${appConfig.name} — ${err.message}`)
                resolve({ success: false, name: appConfig.name, error: err.message })
            })
        })

        // Immediately fail if child process wasn't spawned
        if (!child.pid) {
            onStatus(`[WARN] ${appConfig.name} — Failed to spawn process`)
            return await spawnError
        }

        // ─── Track app with full metadata for sync-on-exit ──────────────
        const spawnTime = Date.now()
        const appObj = {
            pid: child.pid,
            child,
            usbPath,
            localPath,
            exited: false,
            syncPromise: null,
            abandonSync: false,
            isLauncherPattern: false,
            exePath: appConfig.path,
            spawnTime,
            closeMethod: null,
            diagRef: {
                name: appConfig.name,
                pid: child.pid,
                realPid: null,
                exePath: appPath,
                isLauncher: false,
                closeMethod: null
            }
        }
        runDiagnostics.appResults.push(appObj.diagRef)
        launchedApps.push(appObj)
        child.unref()

        // ─── Sync-On-Exit with Launcher Detection ────────────────────────
        // Some apps (Slack, Discord) use a launcher architecture: the spawned
        // process exits immediately after starting the real app under a new PID.
        // If exit fires within 15s of spawn, it's likely a launcher — DON'T sync
        // yet (the real app is still running and using the data directory).
        // The deferred sync happens in closeDesktopApps() via command-line fingerprint.
        child.once('exit', () => {
            appObj.exited = true
            if (appObj.abandonSync) return

            // Launcher detection: process exited very quickly after spawn
            const lifetime = Date.now() - spawnTime
            if (lifetime < 15000) {
                appObj.isLauncherPattern = true
                updateAppDiagnostic(appObj, { isLauncher: true })
                console.log(`[QuickPass] ${appConfig.name} exited in ${lifetime}ms — likely a launcher, deferring sync`)

                // Top-tier polling: find the real PID once (async, non-blocking),
                // then use process.kill(pid, 0) for zero-cost heartbeat checks.
                // Use localPath (most precise) or exePath (fallback) as search fingerprint
                const fingerprint = appObj.localPath
                const findFn = fingerprint
                    ? findRealPidAsync(fingerprint)
                    : Promise.resolve(findPidsByProcessName(appObj.exePath, appObj.spawnTime))

                findFn.then(pids => {
                    // Exclude our own original PID to avoid false self-match
                    pids = pids.filter(p => p !== appObj.pid)
                    if (pids.length === 0 || appObj.abandonSync || closeInProgress) return

                    const realPid = pids[0]
                    appObj.realPid = realPid  // Track for diagnostics
                    updateAppDiagnostic(appObj, { realPid })
                    const checkInterval = setInterval(() => {
                        if (appObj.abandonSync || closeInProgress) {
                            clearInterval(checkInterval)
                            return
                        }
                        try {
                            process.kill(realPid, 0) // Signal 0 = existence check only, no kill
                        } catch (e) {
                            // Process is dead — user manually closed it
                            clearInterval(checkInterval)
                            console.log(`[QuickPass] ${appConfig.name} manual close detected. Syncing to USB...`)
                            if (appObj.usbPath && appObj.localPath && !appObj.syncPromise && !appObj.abandonSync) {
                                appObj.syncPromise = enqueueSync(appObj.usbPath, appObj.localPath)
                            }
                        }
                    }, 5000)
                })

                return // Don't sync — real app is still running
            }

            if (appObj.usbPath && appObj.localPath && !appObj.syncPromise) {
                appObj.syncPromise = enqueueSync(appObj.usbPath, appObj.localPath)
            }
        })

        // Brief wait to detect immediate spawn failures
        const result = await new Promise((resolve) => {
            const errListener = (err) => {
                onStatus(`[WARN] ${appConfig.name} — ${err.message}`)
                resolve({ success: false, name: appConfig.name, error: err.message })
            }

            child.once('error', errListener)

            setTimeout(() => {
                child.removeListener('error', errListener)
                onStatus(`[OK] ${appConfig.name} - launched`)
                resolve({ success: true, name: appConfig.name })
            }, 100)
        })

        return result

    } catch (err) {
        onStatus(`[WARN] ${appConfig.name} — ${err.message}`)
        return { success: false, name: appConfig.name, error: err.message }
    }
}

// ─── Daily Workspace Launch ─────────────────────────────────────────────────────

/**
 * Launches the full workspace: browser tabs + desktop apps.
 * 
 * Phase 16.1: Desktop apps launch CONCURRENTLY with the browser — they no longer
 * wait for robocopy + Chrome + tab loading to finish first. A 1.5s stagger between
 * apps prevents CPU/disk saturation when multiple Electron apps initialize.
 */
export async function launchWorkspace(workspace, onStatus, vaultDir) {
    const savedUrls = (workspace.webTabs || []).filter(t => t.enabled).map(t => t.url)
    const enabledApps = (workspace.desktopApps || []).filter(a => a.enabled)
    const total = savedUrls.length + enabledApps.length

    if (total === 0) {
        onStatus('No items configured')
        return { webResults: [], appResults: [] }
    }

    onStatus(`Launching ${total} items...`)

    // ─── Track: Browser (async) ─────────────────────────────────────────
    // Runs robocopy → Chrome → tabs concurrently with desktop apps
    const browserTrack = async () => {
        if (savedUrls.length === 0) return []

        const { context, browser } = await launchChrome(vaultDir, onStatus)
        activeContext = context
        activeBrowser = browser

        // Phase 11+16: Bot Mitigation Script Injection
        await activeContext.addInitScript(() => {
            Object.defineProperty(navigator, 'webdriver', { get: () => undefined })
            if (!window.chrome) {
                window.chrome = { runtime: {} }
            }
        })

        // Close the default blank page that launchPersistentContext opens
        const blankPages = activeContext.pages().filter(p => p.url() === 'about:blank')

        // Phase 16.3: Close blank pages immediately (1s delay) instead of waiting
        // for all tabs to load. Previously about:blank sat visible for 35+ seconds.
        setTimeout(async () => {
            for (const bp of blankPages) {
                try { await bp.close() } catch (_) { }
            }
        }, 1000)

        const tabPromises = savedUrls.map((url, i) => {
            const fullUrl = url.startsWith('http') ? url : `https://${url}`
            return (async () => {
                const page = await activeContext.newPage()
                try {
                    onStatus(`[Tab ${i + 1}] Loading ${url}...`)
                    await page.goto(fullUrl, { waitUntil: 'domcontentloaded', timeout: 30000 })
                    onStatus(`[Tab ${i + 1}] [OK] ${url} - ready`)
                    return { type: 'web', url, success: true }
                } catch (err) {
                    onStatus(`[Tab ${i + 1}] [WARN] ${url} — ${err.message}`)
                    return { type: 'web', url, success: false }
                }
            })()
        })

        const results = await Promise.all(tabPromises)

        try {
            for (const p of activeContext.pages()) {
                if (p.url() !== 'about:blank') {
                    await p.bringToFront().catch(() => { })
                    break
                }
            }
        } catch (_) { }

        return results
    }

    // ─── Track: Desktop Apps (async, staggered) ─────────────────────────
    // Launches immediately (doesn't wait for browser), with 1.5s gaps so
    // multiple Electron apps don't overwhelm CPU/RAM during init
    // Phase 16.3: Removed artificial 1500ms stagger — robocopy already provides
    // natural spacing between app launches. The stagger was adding 6+ seconds
    // of pure waste to every workspace launch.
    const appsTrack = async () => {
        const appResults = []
        for (let i = 0; i < enabledApps.length; i++) {
            const appConfig = enabledApps[i]
            const result = await launchDesktopApp(appConfig, (msg) => onStatus(`[App ${i + 1}] ${msg}`), vaultDir)
            appResults.push({ type: 'app', ...result })
        }
        return appResults
    }

    // ─── Run both tracks concurrently ───────────────────────────────────
    const [webResults, appResults] = await Promise.all([
        browserTrack(),
        appsTrack()
    ])

    return { webResults, appResults }
}

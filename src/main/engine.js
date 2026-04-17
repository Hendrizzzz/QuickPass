/**
 * OmniLaunch Automation Engine - Phase 16.2: Local-First Chrome + AppData
 *
 * Architecture:
 * Chrome profile AND desktop app data are stored on USB but RUN from
 * local temp directories (the "PortableApps pattern"). This avoids
 * catastrophic random I/O on USB (1-5 MB/s -> 500+ MB/s on SSD).
 *
 * On launch: robocopy USB -> local temp (fast sequential read).
 * On app exit: robocopy local temp -> USB (sync-on-exit via serialized queue).
 * On close: wipe local traces (security).
 *
 * Key Design Decisions (from 6-round architectural audit):
 * - Sync-On-Exit: Data syncs immediately when each app closes, not at workspace teardown
 * - Serialized Queue: Prevents USB bus saturation from parallel robocopy writes
 * - Timeout Escalation: Always waits for the real OS exit event; timeouts only escalate
 *   the kill method (graceful -> force), avoiding macrotask/microtask ordering bugs
 * - Reentrancy Guard: Prevents double-close from concurrent callers
 * - abandonSync Flag: Prevents ghost writes during Node.js shutdown
 */
import { chromium } from 'playwright-core'
import { spawn, execSync } from 'child_process'
import { join, parse as pathParse, resolve as pathResolve, sep as pathSep } from 'path'
import { mkdirSync, existsSync, rmSync, readdirSync, renameSync, statSync } from 'fs'
import os from 'os'
import crypto from 'crypto'
import {
    isDangerousExecutablePath,
    parseVaultAppPath,
    readAppManifest,
    safeAppName,
    validateExtractedAppCache
} from './appManifest.js'

// Active browser/context references
let activeBrowser = null
let activeContext = null
let onDisconnectCallback = null
let activeVaultDir = null
let staleAppCacheCleanupScheduled = false

// --- Run Diagnostics Collector ---
// Accumulates timing and status data throughout a run.
// Written to run-diagnostics.json on quit for post-test analysis.
export const runDiagnostics = {
    machineId: null,  // hashed hostname:user (privacy-safe)
    osVersion: null,
    startTime: null,
    phases: [],  // { name, startMs, endMs, durationMs, status, detail }
    appResults: [],  // { name, pid, realPid, exePath, isLauncher, closeMethod, status, launchStage, error, ... }
    browserSync: { copyInMs: null, copyOutMs: null, migrated: false },
    runtimeChecks: {
        extractor: {
            checked: false,
            tarAvailable: null,
            zstdSupported: null,
            detail: ''
        }
    },
    webResults: [],
    errors: []
}

const TAB_LOAD_ATTEMPTS = 3
const TAB_LOAD_TIMEOUT_MS = 30000
const TAB_LOAD_BACKOFFS_MS = [500, 1500]
const TAB_LOAD_CONCURRENCY = 3

function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms))
}

function scheduleBackgroundTask(fn) {
    const timer = setTimeout(fn, 1000)
    if (typeof timer.unref === 'function') timer.unref()
    return timer
}

function scheduleStaleAppCacheCleanup(minAgeMs = 30000) {
    if (staleAppCacheCleanupScheduled) return
    staleAppCacheCleanupScheduled = true

    scheduleBackgroundTask(() => {
        try {
            const tempRoot = pathResolve(os.tmpdir())
            const appCacheDirs = readdirSync(tempRoot, { withFileTypes: true })
                .filter(entry => entry.isDirectory() && entry.name.startsWith('QuickPass-App-'))

            const cutoff = Date.now() - minAgeMs
            for (const appCacheDir of appCacheDirs) {
                const container = pathResolve(join(tempRoot, appCacheDir.name))
                if (!container.toLowerCase().startsWith(`${tempRoot.toLowerCase()}${pathSep}`)) continue

                const staleDirs = readdirSync(container, { withFileTypes: true })
                    .filter(entry => entry.isDirectory() && entry.name.includes('.stale-'))

                for (const staleDir of staleDirs) {
                    const stalePath = pathResolve(join(container, staleDir.name))
                    if (!stalePath.toLowerCase().startsWith(`${container.toLowerCase()}${pathSep}`)) continue

                    let stats = null
                    try { stats = statSync(stalePath) } catch (_) { }
                    if (stats && stats.mtimeMs > cutoff) continue

                    try {
                        rmSync(stalePath, {
                            recursive: true,
                            force: true,
                            maxRetries: 5,
                            retryDelay: 200
                        })
                    } catch (err) {
                        diagError('app-cache-stale-cleanup', `${stalePath}: ${err.message}`)
                    }
                }
            }
        } catch (err) {
            diagError('app-cache-stale-cleanup', err.message)
        } finally {
            staleAppCacheCleanupScheduled = false
        }
    })
}

function normalizeBrowserUrl(url) {
    const raw = String(url || '').trim()
    if (/^https?:\/\//i.test(raw)) return raw
    return `https://${raw}`
}

function getPageSnapshot(page) {
    return (async () => {
        const finalUrl = (() => {
            try { return page.url() } catch (_) { return null }
        })()
        let title = null
        try { title = await page.title() } catch (_) { }
        return { finalUrl, title }
    })()
}

async function loadTabWithRetry(page, originalUrl, tabIndex, onStatus, {
    attempts = TAB_LOAD_ATTEMPTS,
    timeoutMs = TAB_LOAD_TIMEOUT_MS,
    backoffsMs = TAB_LOAD_BACKOFFS_MS
} = {}) {
    const normalizedUrl = normalizeBrowserUrl(originalUrl)
    const errors = []
    let lastSnapshot = { finalUrl: null, title: null }

    for (let attempt = 1; attempt <= attempts; attempt++) {
        try {
            const retryLabel = attempt === 1 ? '' : ` (attempt ${attempt}/${attempts})`
            onStatus(`[Tab ${tabIndex}] Loading ${originalUrl}${retryLabel}...`)
            await page.goto(normalizedUrl, { waitUntil: 'domcontentloaded', timeout: timeoutMs })
            lastSnapshot = await getPageSnapshot(page)
            const readyLabel = attempt === 1 ? 'ready' : `ready after ${attempt} attempts`
            onStatus(`[Tab ${tabIndex}] [OK] ${originalUrl} - ${readyLabel}`)
            return {
                type: 'web',
                tabIndex,
                url: originalUrl,
                normalizedUrl,
                success: true,
                attempts: attempt,
                finalUrl: lastSnapshot.finalUrl,
                title: lastSnapshot.title,
                error: null,
                errors
            }
        } catch (err) {
            lastSnapshot = await getPageSnapshot(page)
            const message = err?.message || String(err)
            errors.push({ attempt, message, finalUrl: lastSnapshot.finalUrl, title: lastSnapshot.title })

            if (attempt < attempts) {
                const backoffMs = backoffsMs[Math.min(attempt - 1, backoffsMs.length - 1)] || 0
                onStatus(`[Tab ${tabIndex}] [WARN] ${originalUrl} failed (${message}); retrying...`)
                if (backoffMs > 0) await sleep(backoffMs)
                continue
            }

            onStatus(`[Tab ${tabIndex}] [WARN] ${originalUrl} - ${message}`)
            return {
                type: 'web',
                tabIndex,
                url: originalUrl,
                normalizedUrl,
                success: false,
                attempts,
                finalUrl: lastSnapshot.finalUrl,
                title: lastSnapshot.title,
                error: message,
                errors
            }
        }
    }
}

async function mapWithConcurrency(items, limit, worker) {
    const results = new Array(items.length)
    let nextIndex = 0
    const workerCount = Math.max(1, Math.min(limit, items.length))

    await Promise.all(Array.from({ length: workerCount }, async () => {
        while (nextIndex < items.length) {
            const currentIndex = nextIndex
            nextIndex += 1
            results[currentIndex] = await worker(items[currentIndex], currentIndex)
        }
    }))

    return results
}

async function openBrowserTabWithResult(context, url, tabIndex, onStatus, options = {}) {
    try {
        const page = await context.newPage()
        return await loadTabWithRetry(page, url, tabIndex, onStatus, options)
    } catch (err) {
        const message = err?.message || String(err)
        onStatus(`[Tab ${tabIndex}] [WARN] ${url} - ${message}`)
        return {
            type: 'web',
            tabIndex,
            url,
            normalizedUrl: normalizeBrowserUrl(url),
            success: false,
            attempts: 0,
            finalUrl: null,
            title: null,
            error: message,
            errors: [{ attempt: 0, message, finalUrl: null, title: null }]
        }
    }
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
    if (!appObj?.diagRef || !patch) return

    const nextPatch = { ...patch }
    const diagRef = appObj.diagRef
    const launchAlreadyFinal = diagRef.status === 'ok' || diagRef.status === 'failed'

    if (launchAlreadyFinal) {
        delete nextPatch.status
        delete nextPatch.launchStage
        delete nextPatch.error
        delete nextPatch.finalizedBy
    }

    Object.assign(diagRef, nextPatch)
}

function createAppDiagnostic(appConfig, attemptedPath) {
    return {
        name: appConfig.name,
        pid: null,
        realPid: null,
        exePath: null,
        isLauncher: false,
        closeMethod: null,
        status: 'starting',
        launchStage: 'resolving',
        attemptedPath: attemptedPath || null,
        resolvedPath: null,
        launchSource: 'raw-path',
        archivePath: null,
        archiveExists: false,
        directoryExists: false,
        localExeExists: false,
        error: null,
        launchVerifiedBy: null,
        launcherDetectionAttempts: 0,
        launcherDetectionMs: 0,
        handoffObserved: false,
        handoffSignal: null,
        handoffTimeoutMs: null,
        finalizedBy: null,
        manifestId: appConfig.manifestId || null,
        launchProfile: appConfig.launchProfile || null,
        dataProfile: appConfig.dataProfile || null,
        readinessProfile: appConfig.readinessProfile || null,
        binaryArchivePolicyVersion: appConfig.binaryArchivePolicyVersion ?? null,
        archivePolicyStatus: null,
        repairStatus: null,
        selectedExecutable: null,
        dangerousTarget: false,
        cacheValidation: null
    }
}

const DEFAULT_LAUNCHER_HANDOFF_TIMEOUT_MS = 8000
const LAUNCHER_HANDOFF_TIMEOUT_OVERRIDES_MS = {
    slack: 10000
}

function getLauncherHandoffTimeoutMs(appName) {
    const key = String(appName || '').trim().toLowerCase()
    return LAUNCHER_HANDOFF_TIMEOUT_OVERRIDES_MS[key] || DEFAULT_LAUNCHER_HANDOFF_TIMEOUT_MS
}

function setDiagnosticLaunchFinal(diagRef, patch) {
    if (!diagRef || !patch) return
    Object.assign(diagRef, patch)
}

function finalizeLaunchSuccess(appObj, {
    launchVerifiedBy,
    finalizedBy,
    extra = {}
} = {}) {
    if (!appObj?.diagRef) return

    setDiagnosticLaunchFinal(appObj.diagRef, {
        ...extra,
        status: 'ok',
        launchStage: 'ok',
        error: null,
        launchVerifiedBy: launchVerifiedBy || appObj.diagRef.launchVerifiedBy || null,
        finalizedBy: finalizedBy || launchVerifiedBy || appObj.diagRef.finalizedBy || null
    })
}

function finalizeLaunchFailure(appObj, {
    message,
    stage = 'failed',
    finalizedBy,
    extra = {}
} = {}) {
    if (!appObj?.diagRef) return

    setDiagnosticLaunchFinal(appObj.diagRef, {
        ...extra,
        status: 'failed',
        launchStage: stage,
        error: message || 'Launch failed',
        finalizedBy: finalizedBy || appObj.diagRef.finalizedBy || null
    })
}

function ensureExtractorPreflight() {
    const existing = runDiagnostics.runtimeChecks?.extractor
    if (existing?.checked) return existing

    const result = {
        checked: true,
        tarAvailable: false,
        zstdSupported: false,
        detail: ''
    }

    try {
        const versionOutput = execSync('tar --version', {
            encoding: 'utf8',
            timeout: 3000,
            stdio: ['ignore', 'pipe', 'ignore']
        })
        result.tarAvailable = true
        result.detail = versionOutput.split(/\r?\n/).find(Boolean) || 'tar available'
    } catch (err) {
        result.detail = err.message
        runDiagnostics.runtimeChecks.extractor = result
        diagError('extractor-preflight', `tar unavailable: ${err.message}`)
        return result
    }

    const probeDir = join(os.tmpdir(), `QuickPass-TarProbe-${Date.now()}-${Math.random().toString(16).slice(2)}`)
    try {
        const probeFile = join(probeDir, 'probe.txt')
        const probeArchive = join(probeDir, 'probe.tar.zst')
        mkdirSync(probeDir, { recursive: true })
        require('fs').writeFileSync(probeFile, 'probe', 'utf8')

        execSync(`tar --zstd -cf "${probeArchive}" -C "${probeDir}" probe.txt`, {
            encoding: 'utf8',
            timeout: 5000,
            stdio: ['ignore', 'ignore', 'ignore']
        })
        execSync(`tar --zstd -tf "${probeArchive}"`, {
            encoding: 'utf8',
            timeout: 5000,
            stdio: ['ignore', 'ignore', 'ignore']
        })
        result.zstdSupported = true
    } catch (err) {
        result.detail = `${result.detail}; zstd probe failed: ${err.message}`
        diagError('extractor-preflight', `tar zstd probe failed: ${err.message}`)
    } finally {
        try { rmSync(probeDir, { recursive: true, force: true }) } catch (_) { }
    }

    if (!result.zstdSupported) {
        diagError('extractor-preflight', 'tar available but --zstd probe failed')
    }

    runDiagnostics.runtimeChecks.extractor = result
    return result
}

// --- WQL Escape Helpers ---
// WQL LIKE patterns treat %, _, [ as wildcards. Exact equality filters do not.

/**
 * Escape for WQL LIKE clauses (e.g., CommandLine like '%...%').
 * Bracket-escapes %, _, [, ] so they match literally.
 */
function escapeWqlLike(str) {
    return str
        .replace(/\[/g, '[[]')  // must be first to avoid double-escape
        .replace(/%/g, '[%]')
        .replace(/_/g, '[_]')
        .replace(/'/g, "''")
}

/**
 * Escape for exact WQL string literals (e.g., Name='...').
 * Only escapes single quotes  LIKE wildcards have no special meaning here.
 */
function escapeWqlLiteral(str) {
    return str.replace(/'/g, "''")
}

// --- Process Query Abstraction ---
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

// --- Desktop App Tracking & Sync Queue ---
// Track launched desktop apps with full metadata for sync-on-exit
// Each entry: { pid, child, usbPath, localPath, exited, syncPromise, abandonSync,
//               isLauncherPattern, exePath, spawnTime }
let launchedApps = []

// Serialized sync queue - prevents USB bus saturation from parallel robocopy writes.
// Each sync is chained onto the previous one, guaranteeing sequential USB I/O.
let globalSyncQueue = Promise.resolve()

// Reentrancy guard - prevents double-close from concurrent callers
// (e.g., user clicks Close Workspace then immediately clicks Quit)
let closeInProgress = null

/**
 * Enqueue a sync operation (local  USB) onto the serialized queue.
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
            // ALWAYS wipe local copy  security trumps data integrity
            try { rmSync(localPath, { recursive: true, force: true }) } catch (_) { }
        }
    }).catch(err => console.error('[QuickPass] Sync Queue error:', err))

    return globalSyncQueue
}

// --- Local-First Profile Management ---
function patchProfileLocale(profileDir) {
    try {
        const fs = require('fs')

        // Patch Default/Preferences  create if missing (fresh profile)
        const defaultDir = join(profileDir, 'Default')
        if (!fs.existsSync(defaultDir)) fs.mkdirSync(defaultDir, { recursive: true })

        const prefsPath = join(defaultDir, 'Preferences')
        let prefs = {}
        try { prefs = JSON.parse(fs.readFileSync(prefsPath, 'utf8')) } catch (_) { }
        if (!prefs.intl) prefs.intl = {}
        prefs.intl.accept_languages = "en-US,en"
        prefs.intl.selected_languages = "en-US,en"
        // Phase 16: Also patch settings.language fields that Chrome uses for site locale
        if (!prefs.settings) prefs.settings = {}
        if (!prefs.settings.language) prefs.settings.language = {}
        prefs.settings.language.preferred_languages = "en-US,en"
        fs.writeFileSync(prefsPath, JSON.stringify(prefs), 'utf8')

        // Patch Local State  create if missing (fresh profile)
        const localStatePath = join(profileDir, 'Local State')
        let state = {}
        try { state = JSON.parse(fs.readFileSync(localStatePath, 'utf8')) } catch (_) { }
        if (!state.intl) state.intl = {}
        state.intl.app_locale = "en-US"
        state.intl.pref_locale = "en-US"
        fs.writeFileSync(localStatePath, JSON.stringify(state), 'utf8')

        // Phase 16: Delete TranslateRanker cache to prevent stale locale data
        const translateRankerPath = join(defaultDir, 'TranslateRankerModel')
        try { if (fs.existsSync(translateRankerPath)) fs.rmSync(translateRankerPath, { recursive: true, force: true }) } catch (_) { }
    } catch (_) { }
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
 * Async robocopy wrapper  does NOT block the Node.js event loop.
 * Uses /MIR for exact replica in both directions.
 * Robocopy exit codes: 0-7 = success, 8+ = error.
 *
 * Phase 16.3 performance:
 * - Removed /IPG:2 (inter-packet gap)  was adding ~15s of artificial sleep per 500MB
 * - Added /MT:4 (multi-threaded)  significantly faster for directories with many small files
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
 * Used as belt-and-suspenders fallback  no dependency on knowing vaultDir.
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
 * ALWAYS runs on exit  auth tokens must never persist on host PCs.
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

// --- Disconnect Detection ---
export function onBrowserAllClosed(cb) {
    onDisconnectCallback = cb
}

export function hasActiveBrowserSession() {
    if (!activeContext) return false

    try {
        const pages = activeContext.pages().filter((page) => !page.isClosed())
        return pages.length > 0
    } catch (_) {
        return false
    }
}

function attachPageTracking(context) {
    let closeDebounce = null

    const checkAllClosed = () => {
        // Clear any pending debounce  a new page may have opened
        if (closeDebounce) { clearTimeout(closeDebounce); closeDebounce = null }

        try {
            const remaining = context?.pages() || []
            if (remaining.length === 0) {
                // Phase 16.3: Debounce 2s before closing  gives Google OAuth
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

// --- Profile Lock Cleanup ---
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

// --- Local-First Browser Launch ---
/**
 * Detects cross-machine profile migration and surgically removes
 * DPAPI-bound secrets so Chrome regenerates them cleanly.
 *
 * Design decisions (from 9-round peer review):
 * - Machine marker is SHA-256 hashed (privacy-safe, no raw hostnames on USB)
 * - DPAPI files are DELETED, not quarantined  quarantine files would be
 *  mirrored back to USB by robocopy /MIR on close, accumulating dead weight.
 *  The diagnostics log (run-diagnostics.json) serves as forensic record.
 * - Only os_crypt.encrypted_key is removed from Local State  locale patches,
 *  profile info, and all other settings are preserved.
 */
function handleProfileMigration(profileDir) {
    const fs = require('fs')
    // crypto is already imported at module scope (line 26)

    const rawId = `${os.hostname()}:${os.userInfo().username}`
    const machineHash = crypto.createHash('sha256').update(rawId).digest('hex').slice(0, 16)
    const markerPath = join(profileDir, '.quickpass-machine-id')
    const localStatePath = join(profileDir, 'Local State')

    let lastHash = null
    try { lastHash = fs.readFileSync(markerPath, 'utf8').trim() } catch (_) { }

    // Same machine or first run  no migration needed
    if (!lastHash || lastHash === machineHash) {
        try { fs.writeFileSync(markerPath, machineHash, 'utf8') } catch (_) { }
        return false
    }

    // --- Migration Detected ---
    console.log(`[QuickPass] Machine migration detected (${lastHash} -> ${machineHash})`)
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

    // Delete DPAPI-encrypted databases  Chrome will recreate them with new machine key
    // NOT quarantine  quarantined .bak files would be mirrored to USB by robocopy
    const filesToDelete = [
        join(profileDir, 'Default', 'Web Data'),  // token_service_table
        join(profileDir, 'Default', 'Login Data'),  // saved passwords
    ]
    for (const fp of filesToDelete) {
        if (existsSync(fp)) {
            try {
                require('fs').unlinkSync(fp)
                console.log(`[QuickPass] Deleted DPAPI-encrypted: ${fp}`)
            } catch (_) { }
        }
    }

    // Update marker to current machine
    try { fs.writeFileSync(markerPath, machineHash, 'utf8') } catch (_) { }

    diagPhaseEnd('profile-migration-scrub')
    return true
}

/**
 * Launch Chrome with a local copy of the USB-stored browser profile.
 *
 * Flow:
 * 1. Copy USB BrowserProfile -> local temp dir (async robocopy, ~10-15s)
 * 2. Detect cross-machine migration & scrub DPAPI secrets
 * 3. Launch Chrome from local temp (SSD speed, no USB random I/O)
 * 4. On close, closeBrowser() syncs back and wipes local
 *
 * This is the "PortableApps pattern"  same approach used by
 * Portable Firefox, Tor Browser, etc.
 */
async function launchChrome(vaultDir, onStatus = () => { }) {
    activeVaultDir = vaultDir
    const usbProfile = join(vaultDir, 'BrowserProfile')
    const localProfile = getLocalProfileDir(vaultDir)
    mkdirSync(localProfile, { recursive: true })

    // Mirror USB profile -> local temp (if profile exists on USB)
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
        // Phase 16: Removed hardcoded userAgent  let Chrome use its real, matching UA
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
        try { rmSync(localProfile, { recursive: true, force: true }) } catch (_) { }
        mkdirSync(localProfile, { recursive: true })
        patchProfileLocale(localProfile)
        // Write machine marker so next run doesn't re-trigger migration
        const machineHash = crypto.createHash('sha256')
            .update(`${os.hostname()}:${os.userInfo().username}`)
            .digest('hex').slice(0, 16)
        try { require('fs').writeFileSync(join(localProfile, '.quickpass-machine-id'), machineHash) } catch (_) { }

        context = await chromium.launchPersistentContext(localProfile, launchOptions)
        onStatus('[WARN] Browser launched with fresh profile - all sessions reset')
    }
    diagPhaseEnd('browser-launch')

    const browser = context.browser()
    return { context, browser }
}

// --- URL Extraction ---
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

// --- Session Setup / Edit ---
/**
 * Opens Chrome for session setup/editing.
 * With persistent profiles, savedState is no longer needed - the profile
 * on the USB already contains all cookies, GAIA tokens, and login sessions.
 *
 * @param {Function} onStatus - Status callback
 * @param {string} vaultDir - USB vault directory (for profile storage)
 * @param {string[]} urls - URLs to open (empty = open google.com)
 */
export async function launchSessionSetup(onStatus, vaultDir, urls = []) {
    runDiagnostics.webResults = []
    onStatus('Opening browser...')

    const { context, browser } = await launchChrome(vaultDir, onStatus)
    activeContext = context
    activeBrowser = browser

    // Phase 11+16: Bot Mitigation Script Injection
    await activeContext.addInitScript(() => {
        Object.defineProperty(navigator, 'webdriver', { get: () => undefined })
        // Phase 16: Don't overwrite window.chrome - it already exists in real Chrome
        // and replacing it with a stub is MORE detectable than leaving it alone
        if (!window.chrome) {
            window.chrome = { runtime: {} }
        }
    })

    attachPageTracking(activeContext)

    // Close the default blank page that launchPersistentContext opens
    const existingPages = activeContext.pages()
    const blankPages = existingPages.filter(p => p.url() === 'about:blank')

    let tabsSuccessful = true
    if (urls.length > 0) {
        const setupResults = []
        for (let i = 0; i < urls.length; i++) {
            const result = await openBrowserTabWithResult(activeContext, urls[i], i + 1, (msg) => {
                onStatus(`${msg.replace(`[Tab ${i + 1}]`, `Loading tab ${i + 1}/${urls.length}:`)}`)
            })
            setupResults.push(result)
        }
        runDiagnostics.webResults = setupResults
        // Close initial blank pages after new tabs are opened
        for (const bp of blankPages) {
            await bp.close().catch(() => { })
        }
        const failedCount = setupResults.filter(result => !result.success).length
        tabsSuccessful = failedCount === 0
        if (failedCount > 0) {
            onStatus(`${failedCount} tab${failedCount === 1 ? '' : 's'} failed to load. Reload manually if needed, then save.`)
        } else {
            onStatus('All tabs loaded. Edit your workspace, then save.')
        }
    } else {
        // Use the first existing page or create a new one
        const page = existingPages.length > 0 ? existingPages[0] : null
        const result = page
            ? await loadTabWithRetry(page, 'https://www.google.com', 1, onStatus, { timeoutMs: 15000 })
            : await openBrowserTabWithResult(activeContext, 'https://www.google.com', 1, onStatus, { timeoutMs: 15000 })
        runDiagnostics.webResults = [result]
        tabsSuccessful = result.success
        if (result.success) {
            onStatus('Browser is ready. Navigate to your sites and log in.')
        } else {
            onStatus('Browser opened, but the start page failed to load. Reload manually if needed.')
        }
    }

    return { success: true, tabsSuccessful, webResults: runDiagnostics.webResults }
}

// --- Session Capture ---
/**
 * Captures URLs from the browser and CLOSES it (flushes profile to disk).
 * With persistent profiles, we only need to track URLs; auth data is
 * automatically persisted in the profile directory when the browser closes.
 */
export async function captureSession() {
    const result = await captureCurrentSession()

    // Close browser gracefully  this flushes all profile data to the USB
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

        // No longer returning 'state' (cookies)  profile handles auth persistence
        return { success: true, urls, tabCount: urls.length }
    } catch (err) {
        return { success: false, error: err.message }
    }
}

// --- Browser & App Control ---
/**
 * Gracefully closes the browser, syncs profile to USB, wipes local copy.
 * Uses try/finally to GUARANTEE local wipe even if sync fails.
 */
export async function closeBrowser() {
    onDisconnectCallback = null
    if (activeContext) {
        // Close context first  flushes all profile data to local temp dir
        await activeContext.close().catch(() => { })
        activeContext = null
        activeBrowser = null
    } else if (activeBrowser) {
        await activeBrowser.close().catch(() => { })
        activeBrowser = null
    }

    // Sync local profile  USB, then ALWAYS wipe local copy (security)
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
            // ALWAYS wipe local profile  even if sync failed
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
 * Non-blocking  used for the polling monitor so we never freeze the event loop.
 * Returns a Promise that resolves to an array of PIDs.
 *
 * NOTE: Uses PowerShell only (no WMIC fallback). This is intentional.
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
 * Has PowerShellWMIC fallback (WMIC path loses creation-time precision).
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

function getKnownSuccessorDetails(appObj) {
    if (appObj?.realPid && appObj.realPid !== appObj.pid) {
        return {
            pids: [appObj.realPid],
            signal: appObj.diagRef?.handoffSignal || 'known-real-pid'
        }
    }

    return null
}

async function findSuccessorDetails(appObj) {
    if (!appObj) {
        return { pids: [], signal: null }
    }

    const knownDetails = getKnownSuccessorDetails(appObj)
    if (knownDetails) return knownDetails

    if (appObj.localPath) {
        const commandLinePids = (await findRealPidAsync(appObj.localPath))
            .filter((pid) => pid !== appObj.pid)

        if (commandLinePids.length > 0) {
            return { pids: commandLinePids, signal: 'command-line' }
        }
    }

    if (appObj.exePath) {
        const processNamePids = findPidsByProcessName(appObj.exePath, appObj.spawnTime)
            .filter((pid) => pid !== appObj.pid)

        if (processNamePids.length > 0) {
            return { pids: processNamePids, signal: 'process-name' }
        }
    }

    return { pids: [], signal: null }
}

function findSuccessorDetailsSync(appObj) {
    if (!appObj) {
        return { pids: [], signal: null }
    }

    const knownDetails = getKnownSuccessorDetails(appObj)
    if (knownDetails) return knownDetails

    if (appObj.localPath) {
        const commandLinePids = findRealPidsByCommandLine(appObj.localPath)
            .filter((pid) => pid !== appObj.pid)

        if (commandLinePids.length > 0) {
            return { pids: commandLinePids, signal: 'command-line' }
        }
    }

    if (appObj.exePath) {
        const processNamePids = findPidsByProcessName(appObj.exePath, appObj.spawnTime)
            .filter((pid) => pid !== appObj.pid)

        if (processNamePids.length > 0) {
            return { pids: processNamePids, signal: 'process-name' }
        }
    }

    return { pids: [], signal: null }
}

function ensureLauncherHandoff(appObj, {
    timeoutMs = getLauncherHandoffTimeoutMs(appObj?.diagRef?.name),
    intervalMs = 500
} = {}) {
    if (!appObj) {
        return Promise.resolve({
            success: false,
            attempts: 0,
            durationMs: 0,
            pids: [],
            realPid: null,
            signal: null,
            timeoutMs
        })
    }

    if (appObj.launcherHandoffPromise) return appObj.launcherHandoffPromise

    updateAppDiagnostic(appObj, {
        isLauncher: true,
        handoffTimeoutMs: timeoutMs
    })

    appObj.launcherHandoffPromise = (async () => {
        const startedAt = Date.now()
        let attempts = 0

        while (Date.now() - startedAt <= timeoutMs) {
            attempts += 1
            const details = await findSuccessorDetails(appObj)
            if (details.pids.length > 0) {
                const realPid = details.pids[0]
                startLauncherMonitor(appObj, realPid)

                return {
                    success: true,
                    attempts,
                    durationMs: Date.now() - startedAt,
                    pids: details.pids,
                    realPid,
                    signal: details.signal,
                    timeoutMs
                }
            }

            if (Date.now() - startedAt + intervalMs > timeoutMs) break
            await new Promise((resolve) => setTimeout(resolve, intervalMs))
        }

        return {
            success: false,
            attempts,
            durationMs: Date.now() - startedAt,
            pids: [],
            realPid: null,
            signal: null,
            timeoutMs
        }
    })().then((result) => {
        updateAppDiagnostic(appObj, {
            handoffObserved: result.success,
            handoffSignal: result.signal,
            handoffTimeoutMs: result.timeoutMs,
            launcherDetectionAttempts: result.attempts,
            launcherDetectionMs: result.durationMs,
            ...(result.realPid ? { realPid: result.realPid } : {})
        })

        return result
    })

    return appObj.launcherHandoffPromise
}

function startLauncherMonitor(appObj, realPid) {
    if (!realPid || appObj.launcherMonitorStarted) return

    appObj.launcherMonitorStarted = true
    appObj.realPid = realPid
    updateAppDiagnostic(appObj, {
        isLauncher: true,
        realPid,
        launchVerifiedBy: 'launcher-handoff'
    })

    const checkInterval = setInterval(() => {
        if (appObj.abandonSync || closeInProgress) {
            clearInterval(checkInterval)
            return
        }
        try {
            process.kill(realPid, 0)
        } catch (_) {
            clearInterval(checkInterval)
            console.log(`[QuickPass] ${appObj.diagRef.name} manual close detected. Syncing to USB...`)
            if (appObj.usbPath && appObj.localPath && !appObj.syncPromise && !appObj.abandonSync) {
                appObj.syncPromise = enqueueSync(appObj.usbPath, appObj.localPath)
            }
        }
    }, 5000)
}

/**
 * Gracefully close all tracked desktop apps, sync their data to USB,
 * and wipe local traces.
 *
 * Architecture (Timeout Escalation - NOT Promise.race):
 * 1. Send all graceful kill signals (taskkill /T) in parallel  O(1) block time
 * 2. Wait for all native OS exit events  the timeout only ESCALATES the kill
 *  method (graceful -> force), never short-circuits the exit event wait.
 * 3. Handle launcher-pattern apps  find the real process by command-line
 *  fingerprint, kill it, and enqueue a deferred sync.
 * 4. Drain the serialized sync queue.
 *
 * Reentrancy guard: If called concurrently (e.g., user clicks Close Workspace
 * then immediately clicks Quit), subsequent calls piggyback on the active close.
 */
export async function closeDesktopApps() {
    // Reentrancy guard  piggyback on active close if one is already running
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
                // Already dead  just resolve (avoid hang on already-exited apps)
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

        // Phase 3: Handle launcher-pattern apps  the launcher exited early
        // but the real app is still running under a different PID.
        // Multi-signal approach: command-line fingerprint (primary), process-name (fallback)
        for (const app of launchedApps) {
            if (app.isLauncherPattern) {
                const successorDetails = findSuccessorDetailsSync(app)
                const realPids = successorDetails.pids
                if (realPids.length > 0) {
                    app.closeMethod = 'launcher-kill'
                    updateAppDiagnostic(app, {
                        closeMethod: app.closeMethod,
                        isLauncher: true,
                        ...(successorDetails.signal ? { handoffSignal: app.diagRef?.handoffSignal || successorDetails.signal } : {}),
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
 * No syncs attempted  USB is gone. Just kill everything including
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
            const successorDetails = findSuccessorDetailsSync(app)
            const realPids = successorDetails.pids
            for (const pid of realPids) {
                try { execSync(`taskkill /pid ${pid} /F`, { stdio: 'ignore' }) } catch (_) { }
            }
        }
    }
    launchedApps = []
}

// --- Desktop App Launcher ---
async function launchDesktopAppLegacy(appConfig, onStatus, vaultDir) {
    try {
        onStatus(`Launching ${appConfig.name}...`)
        let args = appConfig.args ? appConfig.args.split(' ').filter(Boolean) : []
        let appPath = appConfig.path

        // --- Phase 17: Archive Extraction ---
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
                    // Archive exists but not extracted  extract to local temp
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
                            try { rmSync(localAppRoot, { recursive: true, force: true }) } catch (_) { }
                        }
                    }

                    // If extraction succeeded, redirect to local path
                    if (existsSync(localExePath)) {
                        appPath = localExePath
                        onStatus(`Launching ${appConfig.name} from local...`)
                    }
                } else if (existsSync(archivePath) && existsSync(dirPath)) {
                    // Legacy: both archive and directory exist  use directory (backward compat)
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

        // --- Phase 16.2: Local-First AppData ---
        // For portable Electron/Chromium apps, copy AppData from USB -> local temp
        // before launch, then run from local SSD speed instead of USB random I/O.
        let usbPath = null
        let localPath = null

        if (appConfig.portableData && vaultDir) {
            const safeName = appConfig.name.replace(/[^a-zA-Z0-9_-]/g, '_')
            const sanitizedPath = join(vaultDir, 'AppData', safeName)
            const rawPath = join(vaultDir, 'AppData', appConfig.name)

            // Phase 17.2: Backward compat for pre-17.2 imports that used raw names.
            // If raw folder exists, it has the originally imported data  prefer it.
            // If a buggy sanitized folder also exists, back it up (don't destroy it).
            if (safeName !== appConfig.name && existsSync(rawPath)) {
                usbPath = rawPath
                // Preserve any data the buggy launch-and-sync cycle put in the sanitized folder
                if (existsSync(sanitizedPath)) {
                    const bakPath = `${sanitizedPath}.bak-${Date.now()}`
                    try {
                        renameSync(sanitizedPath, bakPath)
                        console.log(`[QuickPass] Legacy conflict: backed up ${sanitizedPath} -> ${bakPath}`)
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

            // Mirror USB AppData  local temp (fast sequential read)
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
                onStatus(`[WARN] ${appConfig.name}  ${err.message}`)
                resolve({ success: false, name: appConfig.name, error: err.message })
            })
        })

        // Immediately fail if child process wasn't spawned
        if (!child.pid) {
            onStatus(`[WARN] ${appConfig.name}  Failed to spawn process`)
            return await spawnError
        }

        // --- Track app with full metadata for sync-on-exit ---
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

        // --- Sync-On-Exit with Launcher Detection ---
        // Some apps (Slack, Discord) use a launcher architecture: the spawned
        // process exits immediately after starting the real app under a new PID.
        // If exit fires within 15s of spawn, it's likely a launcher. DON'T sync
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
                console.log(`[QuickPass] ${appConfig.name} exited in ${lifetime}ms  likely a launcher, deferring sync`)

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
                            // Process is dead  user manually closed it
                            clearInterval(checkInterval)
                            console.log(`[QuickPass] ${appConfig.name} manual close detected. Syncing to USB...`)
                            if (appObj.usbPath && appObj.localPath && !appObj.syncPromise && !appObj.abandonSync) {
                                appObj.syncPromise = enqueueSync(appObj.usbPath, appObj.localPath)
                            }
                        }
                    }, 5000)
                })

                return // Don't sync  real app is still running
            }

            if (appObj.usbPath && appObj.localPath && !appObj.syncPromise) {
                appObj.syncPromise = enqueueSync(appObj.usbPath, appObj.localPath)
            }
        })

        // Brief wait to detect immediate spawn failures
        const result = await new Promise((resolve) => {
            const errListener = (err) => {
                onStatus(`[WARN] ${appConfig.name}  ${err.message}`)
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
        onStatus(`[WARN] ${appConfig.name}  ${err.message}`)
        return { success: false, name: appConfig.name, error: err.message }
    }
}

// --- Daily Workspace Launch ---
/**
 * Launches the full workspace: browser tabs + desktop apps.
 *
 * Phase 16.1: Desktop apps launch CONCURRENTLY with the browser; they no longer
 * wait for robocopy + Chrome + tab loading to finish first. A 1.5s stagger between
 * apps prevents CPU/disk saturation when multiple Electron apps initialize.
 */
async function launchDesktopApp(appConfig, onStatus, vaultDir) {
    const diagRef = createAppDiagnostic(appConfig, appConfig.path)
    runDiagnostics.appResults.push(diagRef)
    let appObj = null

    const failLaunch = (context, message, stage = 'failed') => {
        if (appObj) {
            finalizeLaunchFailure(appObj, {
                message,
                stage,
                finalizedBy: context
            })
        } else {
            Object.assign(diagRef, {
                status: 'failed',
                launchStage: stage,
                error: message,
                finalizedBy: context
            })
        }
        diagError(context, `${appConfig.name}: ${message}`)
        onStatus(`[WARN] ${appConfig.name} - ${message}`)
        return { success: false, name: appConfig.name, error: message }
    }

    try {
        onStatus(`Launching ${appConfig.name}...`)
        let args = appConfig.args ? appConfig.args.split(' ').filter(Boolean) : []
        let appPath = appConfig.path
        let launchSource = 'raw-path'
        let usbPath = null
        let localPath = null
        const manifest = appConfig.manifest || (vaultDir ? readAppManifest(vaultDir, appConfig.manifestId || appConfig.name) : null)

        if (manifest) {
            Object.assign(diagRef, {
                manifestId: manifest.manifestId || appConfig.manifestId || null,
                launchProfile: manifest.launchProfile || appConfig.launchProfile || null,
                dataProfile: manifest.dataProfile || appConfig.dataProfile || null,
                readinessProfile: manifest.readinessProfile || appConfig.readinessProfile || null,
                binaryArchivePolicyVersion: manifest.binaryArchivePolicyVersion ?? appConfig.binaryArchivePolicyVersion ?? null,
                repairStatus: manifest.repairStatus || null,
                selectedExecutable: manifest.selectedExecutable?.relativePath || null
            })
        }

        if (vaultDir && appPath.startsWith(vaultDir)) {
            const parsedPath = parseVaultAppPath(appPath, vaultDir)
            if (parsedPath) {
                const appName = parsedPath.appName
                const safeName = safeAppName(appName)
                let exeRelative = parsedPath.exeRelative
                const manifestSelectedExe = manifest?.selectedExecutable?.relativePath
                if (manifestSelectedExe && !isDangerousExecutablePath(manifestSelectedExe)) {
                    exeRelative = manifestSelectedExe
                    appPath = join(vaultDir, 'Apps', appName, exeRelative)
                    diagRef.selectedExecutable = exeRelative
                }

                if (isDangerousExecutablePath(exeRelative)) {
                    diagRef.dangerousTarget = true
                    return failLaunch('dangerous-launch-target', `Refusing to launch unsafe executable target: ${exeRelative}`, 'resolving')
                }

                const archivePath = join(vaultDir, 'Apps', `${appName}.tar.zst`)
                const dirPath = join(vaultDir, 'Apps', appName)
                const archiveExists = existsSync(archivePath)
                const directoryExists = existsSync(dirPath)
                const localAppDir = join(os.tmpdir(), `QuickPass-App-${safeName}`)
                const localAppRoot = join(localAppDir, appName)
                const localExePath = join(localAppRoot, exeRelative)
                let validationRoot = null

                Object.assign(diagRef, {
                    archivePath,
                    archiveExists,
                    directoryExists,
                    selectedExecutable: exeRelative
                })

                const ensureLocalCachePath = (targetPath) => {
                    const resolvedTarget = pathResolve(targetPath)
                    const resolvedContainer = pathResolve(localAppDir)
                    if (!resolvedTarget.toLowerCase().startsWith(`${resolvedContainer.toLowerCase()}${pathSep}`)) {
                        throw new Error(`Refusing to touch unexpected app cache path: ${resolvedTarget}`)
                    }
                    return resolvedTarget
                }

                const removeLocalCachePath = (targetPath) => {
                    const resolvedTarget = ensureLocalCachePath(targetPath)
                    rmSync(resolvedTarget, {
                        recursive: true,
                        force: true,
                        maxRetries: 5,
                        retryDelay: 200
                    })
                    return resolvedTarget
                }

                const quarantineLocalAppRoot = async () => {
                    const resolvedRoot = ensureLocalCachePath(localAppRoot)
                    mkdirSync(localAppDir, { recursive: true })

                    if (!existsSync(resolvedRoot)) {
                        return { renamed: false, stalePath: null, attempts: 0 }
                    }

                    let lastError = null
                    for (let attempt = 0; attempt < 5; attempt++) {
                        const stalePath = join(localAppDir, `${appName}.stale-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`)
                        const resolvedStalePath = ensureLocalCachePath(stalePath)
                        if (existsSync(resolvedStalePath)) continue

                        try {
                            renameSync(resolvedRoot, resolvedStalePath)
                            return { renamed: true, stalePath: resolvedStalePath, attempts: attempt + 1 }
                        } catch (err) {
                            lastError = err
                            if (!existsSync(resolvedRoot)) {
                                return { renamed: false, stalePath: null, attempts: attempt + 1 }
                            }
                            if (attempt < 4) {
                                await sleep(150 * (attempt + 1))
                            }
                        }
                    }

                    throw lastError || new Error('Unable to quarantine stale app cache')
                }

                const cleanupQuarantinedCache = (stalePath) => {
                    if (!stalePath) return { attempted: false, succeeded: false, error: null }
                    try {
                        removeLocalCachePath(stalePath)
                        return { attempted: true, succeeded: true, error: null }
                    } catch (err) {
                        return { attempted: true, succeeded: false, error: err }
                    }
                }

                const extractArchiveToLocal = async (reason = 'initial') => {
                    const extractPhase = reason === 'refresh-cache'
                        ? `app-extract-refresh:${safeName}`
                        : `app-extract:${safeName}`
                    diagPhaseStart(extractPhase)
                    mkdirSync(localAppRoot, { recursive: true })
                    try {
                        await new Promise((resolve, reject) => {
                            const proc = spawn('tar', ['--zstd', '--strip-components=1', '-xf', archivePath, '-C', localAppRoot], { stdio: 'ignore' })
                            proc.on('close', (code) => code === 0 ? resolve() : reject(new Error(`tar exit ${code}`)))
                            proc.on('error', reject)
                        })
                        diagPhaseEnd(extractPhase)
                        return { success: true }
                    } catch (err) {
                        diagPhaseEnd(extractPhase, 'failed', err.message)
                        console.error(`[QuickPass] Failed to extract ${appName}:`, err)
                        try { removeLocalCachePath(localAppRoot) } catch (_) { }
                        return { success: false, error: err }
                    }
                }

                if (archiveExists && !directoryExists) {
                    const extractor = ensureExtractorPreflight()
                    launchSource = 'archive'
                    diagRef.launchStage = 'extracting'
                    onStatus(`Extracting ${appConfig.name}...`)

                    if (!extractor.tarAvailable || !extractor.zstdSupported) {
                        return failLaunch('app-extract', 'Extractor unavailable for .tar.zst payloads on this PC', 'extracting')
                    }

                    if (!existsSync(localExePath)) {
                        const extracted = await extractArchiveToLocal()
                        if (!extracted.success) {
                            return failLaunch('app-extract', `Extraction failed (${extracted.error.message})`, 'extracting')
                        }
                    }

                    diagRef.localExeExists = existsSync(localExePath)
                    if (!diagRef.localExeExists) {
                        return failLaunch('app-exe-missing', `Extracted executable not found at ${localExePath}`, 'extracting')
                    }

                    appPath = localExePath
                    validationRoot = localAppRoot
                    onStatus(`Launching ${appConfig.name} from local...`)
                } else if (!archiveExists && !directoryExists) {
                    launchSource = 'local-cache'
                    diagRef.localExeExists = existsSync(localExePath)
                    if (diagRef.localExeExists) {
                        appPath = localExePath
                        validationRoot = localAppRoot
                    } else {
                        return failLaunch('app-payload-missing', 'No app archive, directory, or local cache was found', 'resolving')
                    }
                } else {
                    launchSource = 'usb-directory'
                    validationRoot = dirPath
                    appPath = join(dirPath, exeRelative)
                }

                if (manifest && validationRoot) {
                    let cacheValidation = validateExtractedAppCache(validationRoot, manifest, exeRelative)
                    Object.assign(diagRef, {
                        cacheValidation,
                        archivePolicyStatus: cacheValidation.policyStatus,
                        binaryArchivePolicyVersion: cacheValidation.binaryArchivePolicyVersion
                    })

                    const canRefreshFromArchive = cacheValidation.status !== 'ok' &&
                        archiveExists &&
                        !directoryExists &&
                        cacheValidation.policyStatus === 'current' &&
                        !cacheValidation.unsafeExclusionPolicyDetected &&
                        manifest.repairStatus !== 'needs-reimport'

                    if (canRefreshFromArchive) {
                        onStatus(`Refreshing ${appConfig.name} local cache...`)
                        Object.assign(diagRef, {
                            cacheRefreshAttempted: true,
                            cacheRefreshReason: 'validation-failed',
                            cacheRefreshMethod: 'rename-and-reextract'
                        })

                        let staleCachePath = null
                        try {
                            const quarantine = await quarantineLocalAppRoot()
                            staleCachePath = quarantine.stalePath
                            Object.assign(diagRef, {
                                cacheRefreshRenameSucceeded: quarantine.renamed,
                                cacheRefreshRenameAttempts: quarantine.attempts,
                                staleCachePath: staleCachePath || null
                            })
                        } catch (err) {
                            Object.assign(diagRef, {
                                cacheRefreshRenameSucceeded: false,
                                cacheRefreshRenameError: err.message
                            })
                            return failLaunch('app-cache-refresh', `Failed to quarantine stale app cache: ${err.message}`, 'extracting')
                        }

                        const refreshed = await extractArchiveToLocal('refresh-cache')
                        diagRef.cacheRefreshExtractSucceeded = refreshed.success
                        if (!refreshed.success) {
                            return failLaunch('app-extract', `Cache refresh extraction failed (${refreshed.error.message})`, 'extracting')
                        }

                        diagRef.localExeExists = existsSync(localExePath)
                        if (!diagRef.localExeExists) {
                            return failLaunch('app-exe-missing', `Extracted executable not found at ${localExePath}`, 'extracting')
                        }

                        cacheValidation = validateExtractedAppCache(validationRoot, manifest, exeRelative)
                        Object.assign(diagRef, {
                            cacheValidation,
                            archivePolicyStatus: cacheValidation.policyStatus,
                            binaryArchivePolicyVersion: cacheValidation.binaryArchivePolicyVersion,
                            cacheRefreshSucceeded: cacheValidation.status === 'ok'
                        })

                        if (cacheValidation.status === 'ok' && staleCachePath) {
                            Object.assign(diagRef, {
                                staleCleanupAttempted: true,
                                staleCleanupScheduled: true,
                                staleCleanupSucceeded: null,
                                staleCleanupError: null
                            })
                            scheduleBackgroundTask(() => {
                                const cleanup = cleanupQuarantinedCache(staleCachePath)
                                Object.assign(diagRef, {
                                    staleCleanupAttempted: cleanup.attempted,
                                    staleCleanupScheduled: false,
                                    staleCleanupSucceeded: cleanup.succeeded,
                                    staleCleanupError: cleanup.error?.message || null
                                })
                                if (cleanup.error) {
                                    diagError('app-cache-cleanup', `${appConfig.name}: ${cleanup.error.message}`)
                                }
                            })
                        }
                    }

                    if (cacheValidation.status !== 'ok') {
                        const missing = cacheValidation.missingFiles?.length
                            ? ` Missing: ${cacheValidation.missingFiles.slice(0, 5).join(', ')}${cacheValidation.missingFiles.length > 5 ? ', ...' : ''}`
                            : ''
                        const policy = cacheValidation.unsafeExclusionPolicyDetected
                            ? ' The app archive was created under an unsafe legacy binary exclusion policy and should be reimported.'
                            : ''
                        return failLaunch('app-cache-invalid', `App cache validation failed.${missing}${policy}`, 'extracting')
                    }
                }
            }
        }

        if (isDangerousExecutablePath(appPath)) {
            diagRef.dangerousTarget = true
            return failLaunch('dangerous-launch-target', `Refusing to launch unsafe executable target: ${appPath}`, 'resolving')
        }

        if (appConfig.portableData && vaultDir) {
            const safeName = safeAppName(appConfig.name)
            const sanitizedPath = join(vaultDir, 'AppData', safeName)
            const rawPath = join(vaultDir, 'AppData', appConfig.name)

            if (safeName !== appConfig.name && existsSync(rawPath)) {
                usbPath = rawPath
                if (existsSync(sanitizedPath)) {
                    const bakPath = `${sanitizedPath}.bak-${Date.now()}`
                    try {
                        renameSync(sanitizedPath, bakPath)
                        console.log(`[QuickPass] Legacy conflict: backed up ${sanitizedPath} -> ${bakPath}`)
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

            try {
                diagRef.launchStage = 'syncing-data'
                onStatus(`Syncing ${appConfig.name} data to local...`)
                await robocopyAsync(usbPath, localPath)
            } catch (err) {
                console.error(`[QuickPass] Failed to sync AppData for ${appConfig.name}:`, err)
                diagError('app-data-sync', `${appConfig.name}: ${err.message}`)
            }

            args = [`--user-data-dir=${localPath}`, ...args]
        }

        warnOnEmbeddedHostPaths(localPath, appConfig, onStatus)

        const isExe = appPath.toLowerCase().endsWith('.exe') || appPath.toLowerCase().endsWith('.bat') || appPath.toLowerCase().endsWith('.cmd')
        const targetExists = appPath ? existsSync(appPath) : false

        Object.assign(diagRef, {
            exePath: appPath,
            resolvedPath: appPath,
            launchSource,
            launchStage: 'spawning'
        })

        if (!targetExists) {
            return failLaunch('app-path-missing', `Resolved path not found: ${appPath}`, 'resolving')
        }

        let cwd
        if (isExe) {
            cwd = require('path').dirname(appPath)
        }

        let child
        try {
            child = isExe
                ? spawn(appPath, args, {
                    detached: true,
                    stdio: 'ignore',
                    ...(cwd ? { cwd } : {})
                })
                : spawn('explorer.exe', [appPath, ...args], {
                    detached: true,
                    stdio: 'ignore',
                    ...(cwd ? { cwd } : {})
                })
        } catch (err) {
            return failLaunch('app-spawn', err.message, 'spawning')
        }

        if (!child.pid) {
            return failLaunch('app-spawn', 'Failed to spawn process', 'spawning')
        }

        const spawnTime = Date.now()
        appObj = {
            pid: child.pid,
            child,
            usbPath,
            localPath,
            exited: false,
            syncPromise: null,
            abandonSync: false,
            isLauncherPattern: false,
            launcherMonitorStarted: false,
            launcherHandoffPromise: null,
            exePath: appPath,
            spawnTime,
            closeMethod: null,
            diagRef
        }

        Object.assign(diagRef, {
            pid: child.pid,
            status: 'spawning'
        })

        launchedApps.push(appObj)
        child.unref()

        child.once('exit', () => {
            appObj.exited = true
            if (appObj.abandonSync) return

            const lifetime = Date.now() - spawnTime
            if (lifetime < 15000) {
                appObj.isLauncherPattern = true
                updateAppDiagnostic(appObj, {
                    isLauncher: true,
                    launchStage: 'handoff-pending'
                })
                console.log(`[QuickPass] ${appConfig.name} exited in ${lifetime}ms - likely a launcher, deferring sync`)

                ensureLauncherHandoff(appObj).catch(() => { })

                return
            }

            if (appObj.usbPath && appObj.localPath && !appObj.syncPromise) {
                appObj.syncPromise = enqueueSync(appObj.usbPath, appObj.localPath)
            }
        })

        const result = await new Promise((resolve) => {
            let settled = false
            const finish = (payload) => {
                if (settled) return
                settled = true
                resolve(payload)
            }

            child.once('error', (err) => {
                finish(failLaunch('app-spawn', err.message, 'spawning'))
            })

            setTimeout(async () => {
                if (settled) return

                if (appObj.exited) {
                    updateAppDiagnostic(appObj, {
                        status: 'launcher-detecting',
                        launchStage: 'launcher-detecting'
                    })
                    onStatus(`[INFO] ${appConfig.name} is handing off to its main process...`)

                    const handoff = await ensureLauncherHandoff(appObj)

                    if (!handoff.success) {
                        finish(failLaunch('app-spawn', 'Launcher process exited before handoff was observed', 'launcher-detecting'))
                        return
                    }

                    appObj.isLauncherPattern = true
                    finalizeLaunchSuccess(appObj, {
                        launchVerifiedBy: 'launcher-handoff',
                        finalizedBy: 'launcher-handoff',
                        extra: {
                            handoffObserved: true,
                            handoffSignal: handoff.signal,
                            handoffTimeoutMs: handoff.timeoutMs,
                            launcherDetectionAttempts: handoff.attempts,
                            launcherDetectionMs: handoff.durationMs,
                            ...(handoff.realPid ? { realPid: handoff.realPid } : {})
                        }
                    })
                    onStatus(`[OK] ${appConfig.name} - launched`)
                    finish({ success: true, name: appConfig.name })
                    return
                } else {
                    try {
                        process.kill(child.pid, 0)
                    } catch (_) {
                        finish(failLaunch('app-spawn', 'Process terminated immediately after launch', 'spawning'))
                        return
                    }

                    finalizeLaunchSuccess(appObj, {
                        launchVerifiedBy: 'initial-pid',
                        finalizedBy: 'initial-pid'
                    })
                    onStatus(`[OK] ${appConfig.name} - launched`)
                    finish({ success: true, name: appConfig.name })
                    return
                }
            }, 1000)
        })

        return result
    } catch (err) {
        return failLaunch('app-launch', err.message)
    }
}

export async function launchWorkspace(workspace, onStatus, vaultDir) {
    scheduleStaleAppCacheCleanup()
    const savedUrls = (workspace.webTabs || []).filter(t => t.enabled).map(t => t.url)
    const enabledApps = (workspace.desktopApps || []).filter(a => a.enabled)
    const total = savedUrls.length + enabledApps.length
    runDiagnostics.webResults = []

    if (total === 0) {
        onStatus('No items configured')
        return { webResults: [], appResults: [] }
    }

    onStatus(`Launching ${total} items...`)

    // --- Track: Browser (async) ---
    // Runs robocopy -> Chrome -> tabs concurrently with desktop apps
    const browserTrack = async () => {
        if (savedUrls.length === 0) {
            return []
        }

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

        const results = await mapWithConcurrency(savedUrls, TAB_LOAD_CONCURRENCY, async (url, i) => {
            return openBrowserTabWithResult(activeContext, url, i + 1, onStatus)
        })

        runDiagnostics.webResults = results

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

    // --- Track: Desktop Apps (async, staggered) ---
    // Launches immediately (doesn't wait for browser), with 1.5s gaps so
    // multiple Electron apps don't overwhelm CPU/RAM during init
    // Phase 16.3: Removed artificial 1500ms stagger; robocopy already provides
    // natural spacing between app launches. The stagger was adding 6+ seconds
    // of pure waste to every workspace launch.
    const appsTrack = async () => {
        const appResults = []
        if (enabledApps.length > 0) {
            ensureExtractorPreflight()
        }
        for (let i = 0; i < enabledApps.length; i++) {
            const appConfig = enabledApps[i]
            const result = await launchDesktopApp(appConfig, (msg) => onStatus(`[App ${i + 1}] ${msg}`), vaultDir)
            appResults.push({ type: 'app', ...result })
        }
        return appResults
    }

    // --- Run both tracks concurrently ---
    const [webResults, appResults] = await Promise.all([
        browserTrack(),
        appsTrack()
    ])

    return { webResults, appResults }
}

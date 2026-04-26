/**
 * Wipesnap Automation Engine - Phase 16.2: Local-First Chrome + AppData
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
import { spawn, execSync, execFileSync } from 'child_process'
import { join, parse as pathParse, resolve as pathResolve, sep as pathSep } from 'path'
import { mkdirSync, existsSync, rmSync, readdirSync, renameSync, statSync } from 'fs'
import os from 'os'
import crypto from 'crypto'
import {
    isDangerousExecutablePath,
    normalizeManifestProfiles,
    pickSupportFields,
    parseVaultAppPath,
    readAppManifest,
    resolveHostExeSupportFields,
    resolveHostFolderSupportFields,
    resolveImportedAppDataCapability,
    resolvePackagedAppSupportFields,
    resolveProtocolUriSupportFields,
    resolveShellExecuteSupportFields,
    safeAppName,
    validateExtractedAppCache
} from './appManifest.js'
import { parseLaunchArgs } from './launchArgs.js'

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
    cycleId: null,
    cycleType: null,
    cycleStartTime: null,
    cycles: [],
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

let diagnosticsCycleCounter = 0

function createBrowserSyncDiagnostics() {
    return { copyInMs: null, copyOutMs: null, migrated: false }
}

function createRuntimeChecksDiagnostics() {
    return {
        extractor: {
            checked: false,
            tarAvailable: null,
            zstdSupported: null,
            detail: ''
        }
    }
}

function hasDiagnosticsCycleData() {
    return runDiagnostics.phases.length > 0 ||
        runDiagnostics.appResults.length > 0 ||
        runDiagnostics.webResults.length > 0 ||
        runDiagnostics.errors.length > 0
}

function snapshotDiagnosticsCycle() {
    const snapshot = {
        cycleId: runDiagnostics.cycleId,
        cycleType: runDiagnostics.cycleType,
        cycleStartTime: runDiagnostics.cycleStartTime,
        phases: runDiagnostics.phases,
        appResults: runDiagnostics.appResults,
        browserSync: runDiagnostics.browserSync,
        runtimeChecks: runDiagnostics.runtimeChecks,
        webResults: runDiagnostics.webResults,
        errors: runDiagnostics.errors
    }

    try {
        return JSON.parse(JSON.stringify(snapshot))
    } catch (_) {
        return snapshot
    }
}

export function beginDiagnosticsCycle(cycleType) {
    if (hasDiagnosticsCycleData()) {
        runDiagnostics.cycles.push(snapshotDiagnosticsCycle())
        if (runDiagnostics.cycles.length > 20) {
            runDiagnostics.cycles = runDiagnostics.cycles.slice(-20)
        }
    }

    diagnosticsCycleCounter += 1
    runDiagnostics.cycleId = `${Date.now()}-${diagnosticsCycleCounter}`
    runDiagnostics.cycleType = cycleType
    runDiagnostics.cycleStartTime = Date.now()
    runDiagnostics.phases = []
    runDiagnostics.appResults = []
    runDiagnostics.browserSync = createBrowserSyncDiagnostics()
    runDiagnostics.runtimeChecks = createRuntimeChecksDiagnostics()
    runDiagnostics.webResults = []
    runDiagnostics.errors = []
}

const TAB_LOAD_ATTEMPTS = 3
const TAB_LOAD_TIMEOUT_MS = 30000
const TAB_LOAD_BACKOFFS_MS = [500, 1500]
const TAB_LOAD_CONCURRENCY = 3
const DESKTOP_APP_LAUNCH_CONCURRENCY = 3
const BROWSER_LAUNCH_PROFILES = new Set(['chromium-browser', 'edge-browser', 'chromium-singleton-browser'])
const BROWSER_PROCESS_NAMES_REQUIRING_STRONG_OWNERSHIP = new Set(['msedge.exe', 'chrome.exe', 'brave.exe', 'vivaldi.exe'])
const CAPTURABLE_BROWSER_SCHEMES = new Set(['http', 'https'])
const SKIPPED_BROWSER_URL_REASONS = {
    'about': 'browser-internal-page',
    'chrome': 'browser-internal-page',
    'chrome-error': 'browser-error-page',
    'edge': 'browser-internal-page',
    'devtools': 'browser-internal-page',
    'view-source': 'browser-internal-page',
    'file': 'local-file-url',
    'data': 'embedded-data-url',
    'blob': 'temporary-blob-url',
    'javascript': 'script-url',
    'mailto': 'external-protocol-url',
    'tel': 'external-protocol-url'
}

function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms))
}

function isBrowserLaunchProfile(profile) {
    return BROWSER_LAUNCH_PROFILES.has(String(profile || '').toLowerCase())
}

function isBrowserProcessName(exePath) {
    const exeName = pathParse(String(exePath || '')).base.toLowerCase()
    return BROWSER_PROCESS_NAMES_REQUIRING_STRONG_OWNERSHIP.has(exeName)
}

function looksLikeMicrosoftEdge(appConfig, manifest, appPath) {
    const values = [
        appConfig?.name,
        appConfig?.manifestId,
        manifest?.displayName,
        manifest?.safeName,
        manifest?.selectedExecutable?.relativePath,
        appPath,
        appConfig?.path
    ].map(value => String(value || '').toLowerCase())

    return values.some(value => value.includes('microsoft edge')) ||
        values.some(value => pathParse(value.replace(/\\/g, '/')).base === 'msedge.exe')
}

function resolveEffectiveLaunchProfile(appConfig, manifest, appPath) {
    if (looksLikeMicrosoftEdge(appConfig, manifest, appPath)) return 'chromium-browser'
    return manifest?.launchProfile || appConfig?.launchProfile || 'native-windowed'
}

function resolveEffectiveDataProfile(appConfig, manifest, launchProfile) {
    if (isBrowserLaunchProfile(launchProfile)) return { mode: 'chromium-user-data' }
    return manifest?.dataProfile || appConfig?.dataProfile || { mode: 'none' }
}

const RUNTIME_DATA_SUPPORT_LEVELS = Object.freeze({
    VERIFIED: 'verified',
    BEST_EFFORT: 'best-effort',
    UNSUPPORTED: 'unsupported'
})

// Runtime-data support is intentionally split into:
// - runtime-only isolation support
// - imported AppData redirection support
// - adapter identity / argument style
// This lets Wipesnap keep best-effort launch-only adapters without falsely
// advertising imported-data portability.
function resolveRuntimeDataPlan(appConfig, launchProfile, dataProfile) {
    const normalizedLaunchProfile = String(launchProfile || '').toLowerCase()
    const dataMode = String(dataProfile?.mode || '').toLowerCase()

    const basePlan = {
        launchProfile: normalizedLaunchProfile || 'native-windowed',
        dataMode,
        importedDataRequested: !!appConfig?.portableData,
        adapterId: 'none',
        runtimeProfileSupportLevel: RUNTIME_DATA_SUPPORT_LEVELS.UNSUPPORTED,
        importedDataSupportLevel: RUNTIME_DATA_SUPPORT_LEVELS.UNSUPPORTED,
        runtimeProfileSupported: false,
        importedDataSupported: false,
        argPrefix: null,
        addBrowserHardeningArgs: false,
        runtimeSupportReason: null,
        runtimeSupportWarning: null,
        unsupportedImportedDataReason: null
    }

    if (isBrowserLaunchProfile(normalizedLaunchProfile) || dataMode === 'chromium-user-data') {
        return {
            ...basePlan,
            adapterId: 'chromium-user-data-dir',
            runtimeProfileSupportLevel: RUNTIME_DATA_SUPPORT_LEVELS.VERIFIED,
            importedDataSupportLevel: RUNTIME_DATA_SUPPORT_LEVELS.VERIFIED,
            runtimeProfileSupported: true,
            importedDataSupported: true,
            argPrefix: '--user-data-dir=',
            addBrowserHardeningArgs: isBrowserLaunchProfile(normalizedLaunchProfile),
            runtimeSupportReason: 'Verified Chromium-style runtime profile adapter.'
        }
    }

    if (normalizedLaunchProfile === 'vscode-family' || dataMode === 'vscode-user-data') {
        return {
            ...basePlan,
            adapterId: 'vscode-user-data-dir',
            runtimeProfileSupportLevel: RUNTIME_DATA_SUPPORT_LEVELS.VERIFIED,
            importedDataSupportLevel: RUNTIME_DATA_SUPPORT_LEVELS.VERIFIED,
            runtimeProfileSupported: true,
            importedDataSupported: true,
            argPrefix: '--user-data-dir=',
            runtimeSupportReason: 'Verified VS Code-family runtime profile adapter.'
        }
    }

    if (normalizedLaunchProfile === 'electron-standard' || dataMode === 'electron-user-data') {
        return {
            ...basePlan,
            adapterId: 'electron-user-data-dir',
            runtimeProfileSupportLevel: RUNTIME_DATA_SUPPORT_LEVELS.BEST_EFFORT,
            importedDataSupportLevel: RUNTIME_DATA_SUPPORT_LEVELS.UNSUPPORTED,
            runtimeProfileSupported: true,
            importedDataSupported: false,
            argPrefix: '--user-data-dir=',
            runtimeSupportReason: 'Generic Electron runtime isolation is best-effort until Wipesnap has app-specific validation.',
            runtimeSupportWarning: 'Using best-effort Electron runtime isolation. Verify this app stays off host AppData on this PC before relying on zero-footprint guarantees.',
            unsupportedImportedDataReason: 'Wipesnap does not yet have a verified imported AppData adapter for generic Electron apps.'
        }
    }

    return basePlan
}

function supportsUserDataDirArg(launchProfile, dataProfile) {
    return resolveRuntimeDataPlan(null, launchProfile, dataProfile).runtimeProfileSupported
}

function needsRuntimeUserDataDir(appConfig, launchProfile, dataProfile) {
    return resolveRuntimeDataPlan(appConfig, launchProfile, dataProfile).runtimeProfileSupported
}

function supportsImportedAppDataRedirection(appConfig, launchProfile, dataProfile) {
    return resolveImportedAppDataCapability({
        appType: appConfig?.appType,
        appName: appConfig?.name,
        launchProfile,
        dataProfile
    }).importedDataSupported
}

function replaceArgWithPrefix(args, prefix, value) {
    return [value, ...(args || []).filter(arg => !String(arg || '').startsWith(prefix))]
}

function addArgIfMissing(args, arg) {
    return (args || []).some(existing => existing === arg) ? args : [arg, ...(args || [])]
}

function ensureOwnedPidSet(appObj) {
    if (!appObj) return new Set()
    if (!(appObj.ownedPids instanceof Set)) {
        appObj.ownedPids = new Set()
    }
    return appObj.ownedPids
}

function trackOwnedPid(appObj, pid, {
    signal = null,
    setRealPid = false,
    readyWindow = false
} = {}) {
    const numericPid = Number(pid)
    if (!appObj || !Number.isFinite(numericPid) || numericPid <= 0 || numericPid === process.pid) return false

    ensureOwnedPidSet(appObj).add(numericPid)

    if (readyWindow) {
        appObj.readyObserved = true
        appObj.readyWindowPid = numericPid
        updateAppDiagnostic(appObj, {
            readyObserved: true,
            readyWindowPid: numericPid
        })
    }

    if (setRealPid && numericPid !== appObj.pid) {
        appObj.realPid = numericPid
        if (signal) appObj.realPidSignal = signal
        updateAppDiagnostic(appObj, {
            realPid: numericPid
        })
    }

    return true
}

function trackOwnedPids(appObj, pids, options = {}) {
    for (const pid of pids || []) {
        trackOwnedPid(appObj, pid, options)
    }
}

function getTrackedOwnedPids(appObj, {
    includeRoot = true,
    excludeCurrentProcess = true
} = {}) {
    const tracked = new Set(ensureOwnedPidSet(appObj))
    if (includeRoot && appObj?.pid) tracked.add(appObj.pid)
    if (appObj?.realPid) tracked.add(appObj.realPid)
    if (appObj?.readyWindowPid) tracked.add(appObj.readyWindowPid)
    if (excludeCurrentProcess) tracked.delete(process.pid)
    return [...tracked].filter(pid => Number.isFinite(pid) && pid > 0)
}

function getLiveTrackedOwnedPids(appObj, options = {}) {
    return getTrackedOwnedPids(appObj, options).filter(pid => isPidAlive(pid))
}

function buildTaskkillCommand(pid, {
    tree = true,
    force = false
} = {}) {
    return `taskkill /pid ${pid}${tree ? ' /T' : ''}${force ? ' /F' : ''}`
}

function killPidSync(pid, options = {}) {
    try {
        execSync(buildTaskkillCommand(pid, options), { stdio: 'ignore' })
        return true
    } catch (_) {
        return false
    }
}

const READINESS_ERROR_WINDOW_PATTERNS = [
    { pattern: /\bcrash detected\b/i, reason: 'Crash dialog detected' },
    { pattern: /\bfatal(?: error)?\b/i, reason: 'Fatal error dialog detected' },
    { pattern: /\buncaught exception\b/i, reason: 'Uncaught exception dialog detected' },
    { pattern: /\bexception\b/i, reason: 'Exception dialog detected' },
    { pattern: /\berror\b/i, reason: 'Error dialog detected' }
]

const READINESS_ERROR_OUTPUT_PATTERNS = [
    { pattern: /\bmutex already exists\b/i, reason: 'Process reported a mutex-already-exists error' },
    { pattern: /\bcrash detected\b/i, reason: 'Process reported a crash-detected error' },
    { pattern: /\bfatal(?: error)?\b/i, reason: 'Process reported a fatal error' },
    { pattern: /\buncaught exception\b/i, reason: 'Process reported an uncaught exception' }
]

function detectReadinessErrorState(appObj, window) {
    const titleText = [window?.windowTitle, window?.className]
        .map(value => String(value || '').trim())
        .filter(Boolean)
        .join(' | ')

    for (const entry of READINESS_ERROR_WINDOW_PATTERNS) {
        if (entry.pattern.test(titleText)) {
            return {
                source: 'window',
                message: `${entry.reason}: ${titleText}`
            }
        }
    }

    const outputText = [
        appObj?.latestStdout,
        appObj?.latestStderr
    ].map(value => String(value || '').trim()).filter(Boolean).join('\n')

    for (const entry of READINESS_ERROR_OUTPUT_PATTERNS) {
        if (entry.pattern.test(outputText)) {
            return {
                source: 'process-output',
                message: entry.reason
            }
        }
    }

    return null
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
                .filter(entry => entry.isDirectory() && (
                    entry.name.startsWith(LOCAL_APP_CACHE_PREFIX) ||
                    entry.name.startsWith(LEGACY_LOCAL_APP_CACHE_PREFIX)
                ))

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

export function classifyBrowserUrl(url) {
    const raw = String(url || '').trim()
    if (!raw) {
        return {
            raw,
            normalizedUrl: null,
            scheme: null,
            launchable: false,
            capturable: false,
            reason: 'empty-url'
        }
    }

    if (/^[a-zA-Z]:[\\/]/.test(raw) || /^\\\\/.test(raw)) {
        return {
            raw,
            normalizedUrl: null,
            scheme: 'file',
            launchable: false,
            capturable: false,
            reason: 'local-file-url'
        }
    }

    const hostPortPattern = /^(?:localhost|(?:\d{1,3}\.){3}\d{1,3}|\[[0-9a-f:.]+\]|(?:[a-z0-9-]+\.)+[a-z0-9-]+):\d{1,5}(?:[/?#].*)?$/i
    if (hostPortPattern.test(raw)) {
        return {
            raw,
            normalizedUrl: `https://${raw}`,
            scheme: 'https',
            launchable: true,
            capturable: true,
            reason: null
        }
    }

    const explicitHttpMatch = raw.match(/^(https?):\/\//i)
    if (explicitHttpMatch) {
        const scheme = explicitHttpMatch[1].toLowerCase()
        if (CAPTURABLE_BROWSER_SCHEMES.has(scheme)) {
            return {
                raw,
                normalizedUrl: raw,
                scheme,
                launchable: true,
                capturable: true,
                reason: null
            }
        }
    }

    const schemeMatch = raw.match(/^([a-z][a-z0-9+.-]*):/i)
    if (schemeMatch) {
        const scheme = schemeMatch[1].toLowerCase()

        return {
            raw,
            normalizedUrl: null,
            scheme,
            launchable: false,
            capturable: false,
            reason: SKIPPED_BROWSER_URL_REASONS[scheme] || 'unsupported-browser-scheme'
        }
    }

    return {
        raw,
        normalizedUrl: `https://${raw}`,
        scheme: 'https',
        launchable: true,
        capturable: true,
        reason: null
    }
}

function normalizeBrowserUrl(url) {
    return classifyBrowserUrl(url).normalizedUrl
}

function createSkippedBrowserResult(originalUrl, tabIndex, classification = classifyBrowserUrl(originalUrl)) {
    const reason = classification.reason || 'unsupported-browser-url'
    const message = reason === 'browser-error-page'
        ? 'Skipped browser error page'
        : `Skipped unsupported browser URL (${reason})`

    return {
        type: 'web',
        tabIndex,
        url: originalUrl,
        normalizedUrl: classification.normalizedUrl,
        success: false,
        skipped: true,
        reason,
        attempts: 0,
        finalUrl: originalUrl || null,
        title: null,
        error: message,
        errors: []
    }
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
    const classification = classifyBrowserUrl(originalUrl)
    if (!classification.launchable) {
        const result = createSkippedBrowserResult(originalUrl, tabIndex, classification)
        onStatus(`[Tab ${tabIndex}] [WARN] ${originalUrl} - ${result.error}`)
        return result
    }

    const normalizedUrl = classification.normalizedUrl
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
    const classification = classifyBrowserUrl(url)
    if (!classification.launchable) {
        const result = createSkippedBrowserResult(url, tabIndex, classification)
        onStatus(`[Tab ${tabIndex}] [WARN] ${url} - ${result.error}`)
        return result
    }

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

function ensureAppDiagnosticInActiveCycle(appObj) {
    if (!appObj?.diagRef) return
    if (runDiagnostics.appResults.includes(appObj.diagRef)) return

    let cleanupRef = null
    try {
        cleanupRef = JSON.parse(JSON.stringify(appObj.diagRef))
    } catch (_) {
        cleanupRef = { ...appObj.diagRef }
    }

    cleanupRef.diagnosticRole = 'cleanup'
    appObj.diagRef = cleanupRef
    runDiagnostics.appResults.push(cleanupRef)
}

function createAppDiagnostic(appConfig, attemptedPath) {
    const supportFields = pickSupportFields(appConfig)
    return {
        name: appConfig.name,
        pid: null,
        realPid: null,
        readyObserved: false,
        readyWindowPid: null,
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
        supportTier: supportFields.supportTier || null,
        supportSummary: supportFields.supportSummary || null,
        adapterEvidence: supportFields.adapterEvidence || null,
        launchSourceType: supportFields.launchSourceType || null,
        launchMethod: supportFields.launchMethod || null,
        ownershipProofLevel: supportFields.ownershipProofLevel || null,
        closePolicy: supportFields.closePolicy || null,
        canQuitFromOmniLaunch: supportFields.canQuitFromOmniLaunch ?? null,
        availabilityStatus: supportFields.availabilityStatus || null,
        dataManagement: supportFields.dataManagement || null,
        requiresElevation: supportFields.requiresElevation ?? null,
        resolvedAt: supportFields.resolvedAt || null,
        resolvedHostId: supportFields.resolvedHostId || null,
        launchAdapter: supportFields.launchAdapter || null,
        runtimeAdapter: supportFields.runtimeAdapter || null,
        dataAdapters: supportFields.dataAdapters || [],
        registryAdapters: supportFields.registryAdapters || [],
        limitations: supportFields.limitations || [],
        certification: supportFields.certification || null,
        runtimeProfilePath: null,
        runtimeProfileIsolated: false,
        runtimeProfileSynced: false,
        runtimeProfileAdapterId: 'none',
        runtimeProfileArgStyle: 'none',
        runtimeProfileSupportLevel: RUNTIME_DATA_SUPPORT_LEVELS.UNSUPPORTED,
        runtimeProfileSupportReason: null,
        runtimeProfileSupportWarning: null,
        importedDataSupportLevel: RUNTIME_DATA_SUPPORT_LEVELS.UNSUPPORTED,
        importedDataSupported: false,
        runtimeProfileWiped: false,
        runtimeProfileWipeSkippedForSafety: false,
        runtimeProfileWipeSafetyReason: null,
        runtimeProfileWipeError: null,
        runtimeProfileInUsePids: [],
        cleanupRequiresStrongOwnership: false,
        cleanupSkippedForSafety: false,
        cleanupSafetyReason: null,
        spawnCwd: null,
        launchArgs: [],
        exitCode: null,
        exitSignal: null,
        lifetimeMs: null,
        boundedStdout: null,
        boundedStderr: null,
        readinessProfile: appConfig.readinessProfile || null,
        readiness: createReadinessDiagnostic(appConfig.readinessProfile),
        binaryArchivePolicyVersion: appConfig.binaryArchivePolicyVersion ?? null,
        archivePolicyStatus: null,
        repairStatus: null,
        selectedExecutable: null,
        dangerousTarget: false,
        cacheValidation: null
    }
}

function isHostExeLaunchConfig(appConfig) {
    return ['host-exe', 'registry-uninstall', 'app-paths', 'start-menu-shortcut'].includes(appConfig?.launchSourceType) &&
        appConfig?.launchMethod === 'spawn'
}

function isWeakShellHostLaunchConfig(appConfig) {
    return ['host-folder', 'shell-execute', 'protocol-uri', 'packaged-app'].includes(appConfig?.launchSourceType) &&
        ['shell-execute', 'protocol', 'packaged-app'].includes(appConfig?.launchMethod)
}

function applyHostExeDiagnostic(diagRef, appConfig, availabilityStatus = 'unknown') {
    Object.assign(diagRef, {
        ...resolveHostExeSupportFields({
            appName: appConfig?.name,
            availabilityStatus,
            launchSourceType: appConfig?.launchSourceType || 'host-exe',
            supportSummary: appConfig?.supportSummary,
            limitations: appConfig?.limitations
        }),
        launchSourceType: appConfig?.launchSourceType || 'host-exe'
    })
}

function applyWeakShellHostDiagnostic(diagRef, appConfig, availabilityStatus = appConfig?.availabilityStatus || 'unknown') {
    let supportFields
    if (appConfig?.launchSourceType === 'host-folder') {
        supportFields = resolveHostFolderSupportFields({ appName: appConfig?.name, availabilityStatus })
    } else if (appConfig?.launchSourceType === 'protocol-uri') {
        supportFields = resolveProtocolUriSupportFields({ appName: appConfig?.name, availabilityStatus })
    } else if (appConfig?.launchSourceType === 'packaged-app') {
        supportFields = resolvePackagedAppSupportFields({ appName: appConfig?.name, availabilityStatus })
    } else {
        supportFields = resolveShellExecuteSupportFields({
            appName: appConfig?.name,
            availabilityStatus,
            warning: appConfig?.shortcutClassification?.warning
        })
    }

    Object.assign(diagRef, {
        ...supportFields,
        path: appConfig?.path || null,
        availabilityStatus,
        dataManagement: 'unmanaged',
        ownershipProofLevel: supportFields.ownershipProofLevel || 'none',
        closePolicy: 'never',
        canQuitFromOmniLaunch: false,
        closeManagedAfterSpawn: false
    })
}

function canCloseLaunchedApp(appObj) {
    return appObj?.canQuitFromOmniLaunch !== false && appObj?.diagRef?.canQuitFromOmniLaunch !== false
}

const DEFAULT_LAUNCHER_HANDOFF_TIMEOUT_MS = 8000
const LAUNCHER_HANDOFF_TIMEOUT_OVERRIDES_MS = {
    slack: 10000
}
const DEFAULT_READINESS_TIMEOUT_MS = 15000
const READINESS_POLL_INTERVAL_MS = 750
const READINESS_PROCESS_TREE_DEPTH = 3
const READINESS_EMPTY_TREE_GRACE_MS = 3000
const RUNTIME_APP_PROFILE_PREFIX = 'Wipesnap-AppRuntime-'
const LEGACY_RUNTIME_APP_PROFILE_PREFIX = 'QuickPass-AppRuntime-'
const LOCAL_BROWSER_PROFILE_PREFIX = 'Wipesnap-Profile-'
const LEGACY_LOCAL_BROWSER_PROFILE_PREFIX = 'QuickPass-Profile-'
const LOCAL_APPDATA_PREFIX = 'Wipesnap-AppData-'
const LEGACY_LOCAL_APPDATA_PREFIX = 'QuickPass-AppData-'
const LOCAL_APP_CACHE_PREFIX = 'Wipesnap-App-'
const LEGACY_LOCAL_APP_CACHE_PREFIX = 'QuickPass-App-'
const MACHINE_MARKER_FILE = '.wipesnap-machine-id'
const LEGACY_MACHINE_MARKER_FILE = '.quickpass-machine-id'
const EARLY_EXIT_OUTPUT_LIMIT = 8192
const LAUNCHER_UPDATER_WINDOW_PATTERNS = [
    { pattern: /\b(updater?|updating|update available)\b/i, classification: 'updater-window' },
    { pattern: /\b(installer?|installing|setup)\b/i, classification: 'installer-window' },
    { pattern: /\b(uninstaller?|uninstalling|remove)\b/i, classification: 'uninstaller-window' },
    { pattern: /\b(helper|broker|crashpad|squirrel|stub)\b/i, classification: 'helper-window' },
    { pattern: /\blauncher\b/i, classification: 'launcher-window' }
]

function escapeRegExp(value) {
    return String(value || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

function compactLabel(value) {
    return String(value || '')
        .toLowerCase()
        .replace(/\.exe$/i, '')
        .replace(/[^a-z0-9]+/g, ' ')
        .trim()
}

function buildExpectedWindowPatterns(appObj) {
    const labels = new Set()
    const appName = compactLabel(appObj?.diagRef?.name)
    const exeName = compactLabel(pathParse(appObj?.exePath || '').name)
    if (appName && appName.length >= 3) labels.add(appName)
    if (exeName && exeName.length >= 3) labels.add(exeName)

    return [...labels].slice(0, 4).map((label) => ({
        label,
        pattern: new RegExp(escapeRegExp(label).replace(/\s+/g, '.*'), 'i')
    }))
}

function classifyReadinessWindow(appObj, window) {
    const titleText = [window?.windowTitle, window?.className, window?.processName]
        .map(value => String(value || '').trim())
        .filter(Boolean)
        .join(' | ')
    const expectedPatterns = buildExpectedWindowPatterns(appObj)
    const expectedMatch = expectedPatterns.find(entry => entry.pattern.test(titleText))
    const launcherMatch = LAUNCHER_UPDATER_WINDOW_PATTERNS.find(entry => entry.pattern.test(titleText))

    return {
        titleText,
        expected: !!expectedMatch,
        expectedPattern: expectedMatch?.label || null,
        classification: launcherMatch?.classification || (expectedMatch ? 'expected-window' : 'generic-window'),
        isLauncherOrUpdater: !!launcherMatch
    }
}

function resolveLaunchReadinessPolicy(appConfig = {}, diagRef = {}) {
    const launchSourceType = appConfig.launchSourceType || diagRef.launchSourceType || 'raw-path'
    const launchMethod = appConfig.launchMethod || diagRef.launchMethod || 'spawn'
    const noOwnership = ['host-folder', 'shell-execute', 'protocol-uri', 'packaged-app'].includes(launchSourceType) ||
        ['shell-execute', 'protocol', 'packaged-app'].includes(launchMethod)
    const closeManaged = appConfig.closeManagedAfterSpawn !== false &&
        appConfig.canQuitFromOmniLaunch !== false &&
        diagRef.canQuitFromOmniLaunch !== false

    if (noOwnership) {
        return {
            mode: 'activation-only',
            timeoutMs: 0,
            ownershipMode: 'none',
            closeManaged: false,
            allowLauncherWindowAsReady: false,
            partialReadyAllowed: true,
            readinessDescription: 'Windows shell activation was sent; Wipesnap cannot prove process ownership for this source.'
        }
    }

    const profile = diagRef.readinessProfile || appConfig.readinessProfile || {}
    return {
        mode: profile.mode || 'visible-window',
        timeoutMs: Number(profile.timeoutMs) || DEFAULT_READINESS_TIMEOUT_MS,
        ownershipMode: closeManaged ? 'owned-spawn' : 'weak-spawn',
        closeManaged,
        allowLauncherWindowAsReady: false,
        partialReadyAllowed: false,
        readinessDescription: closeManaged
            ? 'Readiness requires owned process/window evidence.'
            : 'Readiness can observe launch state, but Wipesnap will not close this app automatically.'
    }
}

function classifyLaunchTarget(appConfig = {}, appPath = '') {
    const sourceType = appConfig.launchSourceType || 'raw-path'
    const method = appConfig.launchMethod || 'spawn'
    const base = pathParse(appPath || '').base || String(appPath || '')

    if (sourceType === 'protocol-uri') {
        return { classification: 'protocol-activation', reason: 'Windows protocol handler launch; process ownership is not knowable.' }
    }
    if (sourceType === 'packaged-app') {
        return { classification: 'packaged-app-activation', reason: 'Windows packaged app activation; process ownership is not knowable.' }
    }
    if (sourceType === 'host-folder') {
        return { classification: 'folder-shell-activation', reason: 'Windows folder launch is delegated to Explorer; process ownership is not knowable.' }
    }
    if (sourceType === 'shell-execute' || method === 'shell-execute') {
        return { classification: 'shell-execute-activation', reason: 'ShellExecute may hand off to another process.' }
    }
    if (/\b(updater?|update|setup|install|uninstall|helper|broker|stub|launcher)\b/i.test(base)) {
        return { classification: 'launcher-updater-target', reason: `Launch target looks like a helper/launcher/updater: ${base}` }
    }
    return { classification: 'direct-launch-target', reason: 'Launch target is treated as a direct app process until readiness proves otherwise.' }
}

function createReadinessDiagnostic(readinessProfile) {
    return {
        mode: readinessProfile?.mode || null,
        timeoutMs: readinessProfile?.timeoutMs || null,
        policy: null,
        ownershipMode: null,
        expectedWindowPatterns: [],
        partialReady: false,
        partialReadyReason: null,
        windowClassification: null,
        launcherOrUpdaterWindowObserved: false,
        status: 'pending',
        durationMs: 0,
        checkedAt: null,
        rootPids: [],
        processTree: [],
        windowObserved: false,
        windowPid: null,
        windowHandle: null,
        windowTitle: null,
        windowClassName: null,
        windowBounds: null,
        windowDetectionSource: null,
        observedProcessName: null,
        observedVia: null,
        probeCount: 0,
        probeFailureCount: 0,
        probeTotalMs: 0,
        queryErrors: [],
        failureReason: null
    }
}

function updateReadinessDiagnostic(appObj, patch) {
    if (!appObj?.diagRef || !patch) return
    appObj.diagRef.readiness = {
        ...createReadinessDiagnostic(appObj.diagRef.readinessProfile),
        ...(appObj.diagRef.readiness || {}),
        ...patch
    }
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

    const probeDir = join(os.tmpdir(), `Wipesnap-TarProbe-${Date.now()}-${Math.random().toString(16).slice(2)}`)
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
 * WQL uses backslash as its escape character, so Windows paths must double
 * backslashes before being embedded in string literals. We also bracket-escape
 * LIKE wildcards that should be treated literally.
 */
function escapeWqlLike(str) {
    return str
        .replace(/\\/g, '\\\\')
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

function combineProcessQueryErrors(...errors) {
    const parts = []
    for (const error of errors) {
        const message = String(error || '').trim()
        if (!message) continue
        if (!parts.includes(message)) parts.push(message)
    }
    return parts.join(' | ') || 'process query failed'
}

function queryProcessIds(wqlFilter, timeoutMs = 8000) {
    try {
        const output = execFileSync(
            'powershell',
            ['-NoProfile', '-Command', `Get-CimInstance Win32_Process -Filter "${wqlFilter}" | Select-Object -ExpandProperty ProcessId`],
            { encoding: 'utf8', timeout: timeoutMs, stdio: ['pipe', 'pipe', 'pipe'] }
        )
        return { ok: true, pids: parsePidsFromOutput(output), error: null }
    } catch (psErr) {
        try {
            const output = execFileSync(
                'wmic',
                ['process', 'where', wqlFilter, 'get', 'ProcessId', '/value'],
                { encoding: 'utf8', timeout: Math.min(timeoutMs, 5000), stdio: ['pipe', 'pipe', 'pipe'] }
            )
            return { ok: true, pids: parsePidsFromOutput(output), error: null }
        } catch (wmicErr) {
            return {
                ok: false,
                pids: [],
                error: combineProcessQueryErrors(psErr?.message, wmicErr?.message),
                backendErrors: {
                    powershell: psErr?.message || null,
                    wmic: wmicErr?.message || null
                }
            }
        }
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

function parseJsonArrayOutput(output) {
    const trimmed = String(output || '').trim()
    if (!trimmed) return []

    try {
        const parsed = JSON.parse(trimmed)
        if (!parsed) return []
        return Array.isArray(parsed) ? parsed.filter(Boolean) : [parsed]
    } catch (_) {
        return []
    }
}

function escapePowerShellSingleQuoted(value) {
    return String(value || '').replace(/'/g, "''")
}

function runPowerShellJson(script, timeoutMs = 8000) {
    return new Promise((resolve) => {
        let settled = false
        let output = ''
        let errorOutput = ''
        let proc = null

        const finish = (payload) => {
            if (settled) return
            settled = true
            resolve(payload)
        }

        try {
            proc = spawn('powershell', ['-NoProfile', '-Command', script], {
                stdio: ['ignore', 'pipe', 'pipe']
            })
        } catch (err) {
            finish({ ok: false, entries: [], error: err.message })
            return
        }

        const timer = setTimeout(() => {
            try { proc.kill() } catch (_) { }
            finish({ ok: false, entries: [], error: `PowerShell probe timed out after ${timeoutMs}ms` })
        }, timeoutMs)
        if (typeof timer.unref === 'function') timer.unref()

        proc.stdout.on('data', chunk => { output += chunk.toString() })
        proc.stderr.on('data', chunk => { errorOutput += chunk.toString() })
        proc.on('error', (err) => {
            clearTimeout(timer)
            finish({ ok: false, entries: [], error: err.message })
        })
        proc.on('close', (code) => {
            clearTimeout(timer)
            if (settled) return
            if (code !== 0) {
                finish({ ok: false, entries: [], error: errorOutput.trim() || `PowerShell exited ${code}` })
                return
            }
            finish({ ok: true, entries: parseJsonArrayOutput(output), error: null })
        })
    })
}

function normalizeProcessEntry(entry) {
    const processId = Number(entry?.ProcessId)
    if (!Number.isFinite(processId) || processId <= 0) return null

    const parentProcessId = Number(entry?.ParentProcessId)
    const createdMs = Number(entry?.CreatedMs)
    return {
        pid: processId,
        parentPid: Number.isFinite(parentProcessId) && parentProcessId > 0 ? parentProcessId : null,
        name: entry?.Name || null,
        createdMs: Number.isFinite(createdMs) && createdMs > 0 ? createdMs : null
    }
}

function appendBoundedOutput(current, chunk, limit = EARLY_EXIT_OUTPUT_LIMIT) {
    const next = `${current || ''}${chunk?.toString?.() || ''}`
    if (next.length <= limit) return next
    return next.slice(0, limit)
}

async function getProcessesByFilterDetailed(wqlFilter) {
    const script = [
        `Get-CimInstance Win32_Process -Filter "${wqlFilter}"`,
        'ForEach-Object { [pscustomobject]@{ ProcessId = $_.ProcessId; ParentProcessId = $_.ParentProcessId; Name = $_.Name; CreatedMs = ([DateTimeOffset]$_.CreationDate).ToUnixTimeMilliseconds() } }',
        'ConvertTo-Json -Compress'
    ].join(' | ')

    const result = await runPowerShellJson(script)
    if (!result.ok) return { ok: false, entries: [], error: result.error }

    const detailedEntries = result.entries
        .map(normalizeProcessEntry)
        .filter(Boolean)
    return { ok: true, entries: detailedEntries, error: null }
}

async function getProcessesByIdsDetailed(pids) {
    const uniquePids = [...new Set((pids || []).map(pid => Number(pid)).filter(pid => Number.isFinite(pid) && pid > 0))]
    if (uniquePids.length === 0) return { ok: true, entries: [], error: null }

    const filter = uniquePids.map(pid => `ProcessId=${pid}`).join(' OR ')
    return getProcessesByFilterDetailed(filter)
}

async function getChildProcessesDetailed(parentPid) {
    const pid = Number(parentPid)
    if (!Number.isFinite(pid) || pid <= 0) return { ok: true, entries: [], error: null }
    return getProcessesByFilterDetailed(`ParentProcessId=${pid}`)
}

async function getProcessesByNameDetailed(exePath, spawnTime) {
    if (!exePath) return { ok: true, entries: [], error: null }
    const exeName = pathParse(exePath).base
    if (!exeName) return { ok: true, entries: [], error: null }

    const escaped = escapeWqlLiteral(exeName)
    const result = await getProcessesByFilterDetailed(`Name='${escaped}'`)
    if (!result.ok) return result

    const entries = result.entries.filter((entry) => {
        if (!spawnTime || !entry.createdMs) return true
        return entry.createdMs >= spawnTime && entry.createdMs <= spawnTime + 60000
    })
    return { ok: true, entries, error: null }
}

async function getWindowDetailsForPids(pids) {
    const uniquePids = [...new Set((pids || []).map(pid => Number(pid)).filter(pid => Number.isFinite(pid) && pid > 0))]
    if (uniquePids.length === 0) return []

    const script = `$ids = @(${uniquePids.join(',')}); Get-Process -Id $ids -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{ ProcessId = $_.Id; ProcessName = $_.ProcessName; MainWindowHandle = [int64]$_.MainWindowHandle; MainWindowTitle = $_.MainWindowTitle } } | ConvertTo-Json -Compress`

    const result = await runPowerShellJson(script)
    if (!result.ok) return []

    return result.entries
        .map((entry) => ({
            pid: Number(entry?.ProcessId),
            processName: entry?.ProcessName || null,
            windowHandle: Number(entry?.MainWindowHandle) || 0,
            windowTitle: entry?.MainWindowTitle || '',
            detectionSource: 'main-window-handle'
        }))
        .filter(entry => Number.isFinite(entry.pid) && entry.pid > 0)
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
    }).catch(err => console.error('[Wipesnap] Sync Queue error:', err))

    return globalSyncQueue
}

function isPathWithinDirectory(parentDir, candidatePath) {
    if (!parentDir || !candidatePath) return false

    const parent = pathResolve(parentDir)
    const candidate = pathResolve(candidatePath)
    const parentCmp = process.platform === 'win32' ? parent.toLowerCase() : parent
    const candidateCmp = process.platform === 'win32' ? candidate.toLowerCase() : candidate
    const parentWithSep = parentCmp.endsWith(pathSep) ? parentCmp : `${parentCmp}${pathSep}`

    return candidateCmp.startsWith(parentWithSep)
}

function isOwnedRuntimeProfilePath(profilePath) {
    if (!profilePath) return false

    try {
        const resolved = pathResolve(profilePath)
        const tempDir = pathResolve(os.tmpdir())
        const baseName = pathParse(resolved).base
        return (baseName.startsWith(RUNTIME_APP_PROFILE_PREFIX) ||
            baseName.startsWith(LEGACY_RUNTIME_APP_PROFILE_PREFIX)) &&
            pathParse(resolved).dir === tempDir &&
            isPathWithinDirectory(tempDir, resolved)
    } catch (_) {
        return false
    }
}

function findRuntimeProfileUsersSync(profilePath) {
    if (!isOwnedRuntimeProfilePath(profilePath)) {
        return { ok: false, pids: [], error: 'runtime profile path is not Wipesnap-owned' }
    }

    const escaped = escapeWqlLike(profilePath)
    const filter = [
        `CommandLine like '%${escaped}%'`,
        "Name <> 'powershell.exe'",
        "Name <> 'pwsh.exe'",
        "Name <> 'wmic.exe'"
    ].join(' AND ')
    const result = queryProcessIds(filter)

    return {
        ok: result.ok,
        pids: [...new Set(result.pids.filter(pid => pid > 0 && pid !== process.pid))],
        error: result.error
    }
}

function markRuntimeProfileWipeSkipped(appObj, reason, inUsePids = []) {
    updateAppDiagnostic(appObj, {
        runtimeProfileWiped: false,
        runtimeProfileWipeSkippedForSafety: true,
        runtimeProfileWipeSafetyReason: reason,
        runtimeProfileInUsePids: inUsePids
    })
}

function wipeRuntimeProfilePath(appObj, profilePath) {
    try {
        rmSync(profilePath, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 })
        updateAppDiagnostic(appObj, {
            runtimeProfileWiped: true,
            runtimeProfileWipeSkippedForSafety: false,
            runtimeProfileWipeSafetyReason: null,
            runtimeProfileWipeError: null,
            runtimeProfileInUsePids: []
        })
        return true
    } catch (err) {
        updateAppDiagnostic(appObj, {
            runtimeProfileWiped: false,
            runtimeProfileWipeError: err.message
        })
        diagError('app-runtime-profile-cleanup', `${appObj.diagRef?.name || appObj.pid}: ${err.message}`)
        return false
    }
}

function wipeRuntimeOnlyProfile(appObj) {
    if (!appObj?.localPath || appObj.usbPath) return false

    if (!isOwnedRuntimeProfilePath(appObj.localPath)) {
        updateAppDiagnostic(appObj, {
            runtimeProfileWiped: false,
            runtimeProfileWipeError: 'Refused to wipe non-owned runtime profile path'
        })
        diagError('app-runtime-profile-cleanup', `${appObj.diagRef?.name || appObj.pid}: refused non-owned runtime profile path`)
        return false
    }

    if (appObj.abandonSync) {
        markRuntimeProfileWipeSkipped(appObj, appObj.abandonSyncReason || 'App was abandoned during emergency shutdown; deferred to stale runtime profile cleanup.')
        return false
    }

    if (appObj.cleanupSkippedForSafety || appObj.diagRef?.cleanupSkippedForSafety) {
        markRuntimeProfileWipeSkipped(appObj, 'Process cleanup was skipped for safety; runtime profile deletion deferred.')
        return false
    }

    if (appObj.currentSessionRuntimeProfileSafeToDelete) {
        const liveOwnedPids = getLiveTrackedOwnedPids(appObj)
        if (liveOwnedPids.length === 0) {
            return wipeRuntimeProfilePath(appObj, appObj.localPath)
        }
        markRuntimeProfileWipeSkipped(appObj, 'Known owned processes are still alive after shutdown.', liveOwnedPids)
        return false
    }

    const users = findRuntimeProfileUsersSync(appObj.localPath)
    if (!users.ok) {
        markRuntimeProfileWipeSkipped(appObj, `Could not prove runtime profile was unused: ${users.error || 'process query failed'}`)
        return false
    }

    if (users.pids.length > 0) {
        markRuntimeProfileWipeSkipped(appObj, 'Runtime profile is still referenced by a live process.', users.pids)
        return false
    }

    return wipeRuntimeProfilePath(appObj, appObj.localPath)
}

export function wipeAllRuntimeAppProfiles({ staleOnly = true } = {}) {
    const summary = {
        checked: 0,
        wiped: 0,
        skipped: 0,
        errors: []
    }

    try {
        const tempDir = os.tmpdir()
        for (const dir of readdirSync(tempDir)) {
            if (!dir.startsWith(RUNTIME_APP_PROFILE_PREFIX) &&
                !dir.startsWith(LEGACY_RUNTIME_APP_PROFILE_PREFIX)) continue

            const profilePath = join(tempDir, dir)
            if (!isOwnedRuntimeProfilePath(profilePath)) {
                summary.skipped += 1
                summary.errors.push(`${dir}: refused non-owned path`)
                continue
            }

            try {
                if (!statSync(profilePath).isDirectory()) continue
            } catch (_) {
                continue
            }

            summary.checked += 1

            if (staleOnly) {
                const users = findRuntimeProfileUsersSync(profilePath)
                if (!users.ok) {
                    summary.skipped += 1
                    summary.errors.push(`${dir}: ${users.error || 'process query failed'}`)
                    continue
                }
                if (users.pids.length > 0) {
                    summary.skipped += 1
                    summary.errors.push(`${dir}: still in use by ${users.pids.join(', ')}`)
                    continue
                }
            }

            try {
                rmSync(profilePath, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 })
                summary.wiped += 1
            } catch (err) {
                summary.errors.push(`${dir}: ${err.message}`)
            }
        }
    } catch (err) {
        summary.errors.push(err.message)
    }

    if (summary.errors.length > 0) {
        const preview = summary.errors.slice(0, 5).join(' | ')
        const suffix = summary.errors.length > 5 ? ` | ... (${summary.errors.length - 5} more)` : ''
        diagError(
            'app-runtime-profile-cleanup',
            `checked=${summary.checked} wiped=${summary.wiped} skipped=${summary.skipped}: ${preview}${suffix}`
        )
    }

    return summary
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
    return join(os.tmpdir(), `${LOCAL_BROWSER_PROFILE_PREFIX}${hash}`)
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
 * Wipes all Wipesnap browser profile directories from temp.
 * Used as belt-and-suspenders fallback  no dependency on knowing vaultDir.
 * Legacy QuickPass temp names are also removed so old runs do not leave host residue.
 */
export function wipeAllLocalProfiles() {
    try {
        const tempDir = os.tmpdir()
        for (const dir of readdirSync(tempDir)) {
            if (dir.startsWith(LOCAL_BROWSER_PROFILE_PREFIX) ||
                dir.startsWith(LEGACY_LOCAL_BROWSER_PROFILE_PREFIX)) {
                try { rmSync(join(tempDir, dir), { recursive: true, force: true }) } catch (_) { }
            }
        }
    } catch (_) { }
}

/**
 * Wipes all Wipesnap desktop app auth-data directories from temp.
 * ALWAYS runs on exit  auth tokens must never persist on host PCs.
 * Belt-and-suspenders: called on process exit and kill cord.
 * Legacy QuickPass temp names are also removed so old runs do not leave host residue.
 */
export function wipeAllLocalAppData() {
    try {
        const tempDir = os.tmpdir()
        for (const dir of readdirSync(tempDir)) {
            if (dir.startsWith(LOCAL_APPDATA_PREFIX) ||
                dir.startsWith(LEGACY_LOCAL_APPDATA_PREFIX)) {
                try { rmSync(join(tempDir, dir), { recursive: true, force: true }) } catch (_) { }
            }
        }
    } catch (_) { }
}

/**
 * Wipes extracted app binaries from temp.
 * Conditionally called based on clearCacheOnExit toggle.
 * When OFF: apps persist for instant <10s launches on home PC.
 * When ON:  zero-footprint mode for public/school PCs.
 * Legacy QuickPass temp names are also removed when cache clearing is enabled.
 */
export function wipeLocalAppCache() {
    try {
        const tempDir = os.tmpdir()
        for (const dir of readdirSync(tempDir)) {
            if (dir.startsWith(LOCAL_APP_CACHE_PREFIX) ||
                dir.startsWith(LEGACY_LOCAL_APP_CACHE_PREFIX)) {
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
    const markerPath = join(profileDir, MACHINE_MARKER_FILE)
    const legacyMarkerPath = join(profileDir, LEGACY_MACHINE_MARKER_FILE)
    const localStatePath = join(profileDir, 'Local State')

    let lastHash = null
    try { lastHash = fs.readFileSync(markerPath, 'utf8').trim() } catch (_) { }
    if (!lastHash) {
        try { lastHash = fs.readFileSync(legacyMarkerPath, 'utf8').trim() } catch (_) { }
    }

    // Same machine or first run  no migration needed
    if (!lastHash || lastHash === machineHash) {
        try { fs.writeFileSync(markerPath, machineHash, 'utf8') } catch (_) { }
        return false
    }

    // --- Migration Detected ---
    console.log(`[Wipesnap] Machine migration detected (${lastHash} -> ${machineHash})`)
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
                console.log('[Wipesnap] Scrubbed DPAPI key from Local State')
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
                console.log(`[Wipesnap] Deleted DPAPI-encrypted: ${fp}`)
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
            console.error('[Wipesnap] Failed to sync profile from USB:', err)
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
        console.error('[Wipesnap] Chrome launch failed, retrying with clean profile:', launchErr.message)

        // Nuclear fallback: nuke the corrupted local profile and start fresh
        try { rmSync(localProfile, { recursive: true, force: true }) } catch (_) { }
        mkdirSync(localProfile, { recursive: true })
        patchProfileLocale(localProfile)
        // Write machine marker so next run doesn't re-trigger migration
        const machineHash = crypto.createHash('sha256')
            .update(`${os.hostname()}:${os.userInfo().username}`)
            .digest('hex').slice(0, 16)
            try { require('fs').writeFileSync(join(localProfile, MACHINE_MARKER_FILE), machineHash) } catch (_) { }

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
    if (!activeContext) return { urls: [], skippedUrls: [] }

    const allUrls = []
    const skippedUrls = []

    // With launchPersistentContext there is only one context,
    // but we still iterate for robustness (Ctrl+N windows share the same context)
    const pages = activeContext.pages()
    for (const [index, p] of pages.entries()) {
        try {
            const url = p.url()
            const classification = classifyBrowserUrl(url)

            if (classification.capturable) {
                allUrls.push(url)
            } else if (url && url !== 'about:blank') {
                skippedUrls.push({
                    url,
                    tabIndex: index + 1,
                    scheme: classification.scheme,
                    reason: classification.reason
                })
            }
        } catch (_) { }
    }

    return { urls: allUrls, skippedUrls }
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
export async function launchSessionSetup(onStatus, vaultDir, urls = [], options = {}) {
    if (!options.skipDiagnosticsCycle) {
        beginDiagnosticsCycle(urls.length > 0 ? 'edit' : 'setup')
    }
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
        const skippedCount = setupResults.filter(result => result.skipped).length
        const failedCount = setupResults.filter(result => !result.success && !result.skipped).length
        tabsSuccessful = failedCount === 0 && skippedCount === 0
        if (failedCount > 0) {
            onStatus(`${failedCount} tab${failedCount === 1 ? '' : 's'} failed to load. Reload manually if needed, then save.`)
        } else if (skippedCount > 0) {
            onStatus(`${skippedCount} browser-owned tab${skippedCount === 1 ? '' : 's'} skipped. Save to remove them from this workspace.`)
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
        const { urls, skippedUrls } = await extractAllPages()

        if (urls.length === 0) {
            if (skippedUrls.length > 0) {
                return {
                    success: false,
                    error: 'No website tabs are open. Browser internal/error pages were skipped.',
                    skippedUrls,
                    skippedCount: skippedUrls.length
                }
            }
            return { success: false, error: 'No tabs are open' }
        }

        // No longer returning 'state' (cookies)  profile handles auth persistence
        return {
            success: true,
            urls,
            tabCount: urls.length,
            skippedUrls,
            skippedCount: skippedUrls.length
        }
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
            console.error('[Wipesnap] Profile sync to USB failed:', err)
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
 * Uses PowerShell Get-CimInstance with WMIC fallback via queryProcessIds().
 * Used in closeDesktopApps() and emergencyKillDesktopAppsSync() where we
 * need synchronous results during teardown.
 */
function findRealPidsByCommandLine(searchString) {
    try {
        const escaped = escapeWqlLike(searchString)
        const filter = [
            `CommandLine like '%${escaped}%'`,
            "Name <> 'powershell.exe'",
            "Name <> 'pwsh.exe'",
            "Name <> 'wmic.exe'"
        ].join(' AND ')
        const result = queryProcessIds(filter)
        return {
            ok: result.ok,
            pids: result.ok ? result.pids : [],
            error: result.error
        }
    } catch (err) {
        return { ok: false, pids: [], error: err.message }
    }
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
                `Get-CimInstance Win32_Process -Filter "CommandLine like '%${escaped}%' AND Name <> 'powershell.exe' AND Name <> 'pwsh.exe' AND Name <> 'wmic.exe'" | Select-Object -ExpandProperty ProcessId`
            ], { stdio: ['ignore', 'pipe', 'ignore'] })

            let output = ''
            let settled = false
            const finish = (pids) => {
                if (settled) return
                settled = true
                resolve(pids)
            }
            const timer = setTimeout(() => {
                try { proc.kill() } catch (_) { }
                finish([])
            }, 8000)
            if (typeof timer.unref === 'function') timer.unref()

            proc.stdout.on('data', d => { output += d.toString() })
            proc.on('close', () => {
                clearTimeout(timer)
                finish(parsePidsFromOutput(output))
            })
            proc.on('error', () => {
                clearTimeout(timer)
                finish([])
            })
        } catch (_) { resolve([]) }
    })
}

async function findPidsByProcessName(exePath, spawnTime) {
    try {
        const result = await getProcessesByNameDetailed(exePath, spawnTime)
        if (result.ok) return result.entries.map(entry => entry.pid)

        return []
    } catch (_) { return [] }
}

function requiresStrongOwnershipForCleanup(appObj) {
    return !!appObj?.requiresStrongOwnership ||
        isBrowserLaunchProfile(appObj?.launchProfile || appObj?.diagRef?.launchProfile) ||
        isBrowserProcessName(appObj?.exePath)
}

function isStrongSuccessorSignal(signal) {
    return ['command-line', 'known-real-pid', 'visible-window', 'child-process', 'tracked-owned-pid'].includes(signal)
}

function getKnownSuccessorDetails(appObj, { requireStrongOwnership = false } = {}) {
    const trackedSuccessorPids = getTrackedOwnedPids(appObj)
        .filter(pid => pid !== appObj?.pid)

    if (trackedSuccessorPids.length > 0) {
        const signal = appObj?.realPidSignal || appObj?.diagRef?.handoffSignal || 'tracked-owned-pid'
        if (requireStrongOwnership && !isStrongSuccessorSignal(signal)) return null
        return {
            pids: trackedSuccessorPids,
            signal
        }
    }

    if (appObj?.realPid && appObj.realPid !== appObj.pid) {
        const signal = appObj.realPidSignal || appObj.diagRef?.handoffSignal || 'known-real-pid'
        if (requireStrongOwnership && !isStrongSuccessorSignal(signal)) return null
        return {
            pids: [appObj.realPid],
            signal
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

    if (!requiresStrongOwnershipForCleanup(appObj) && appObj.exePath) {
        const processNamePids = (await findPidsByProcessName(appObj.exePath, appObj.spawnTime))
            .filter((pid) => pid !== appObj.pid)

        if (processNamePids.length > 0) {
            return { pids: processNamePids, signal: 'process-name' }
        }
    }

    return { pids: [], signal: null }
}

function findSuccessorDetailsSync(appObj, { allowProcessNameFallback = !requiresStrongOwnershipForCleanup(appObj) } = {}) {
    if (!appObj) {
        return { pids: [], signal: null, error: null }
    }

    const knownDetails = getKnownSuccessorDetails(appObj, { requireStrongOwnership: !allowProcessNameFallback })
    if (knownDetails) return knownDetails

    let queryError = null
    if (appObj.localPath) {
        const commandLineResult = findRealPidsByCommandLine(appObj.localPath)
        const commandLinePids = commandLineResult.pids
            .filter((pid) => pid !== appObj.pid)

        if (commandLinePids.length > 0) {
            return { pids: commandLinePids, signal: 'command-line', error: null }
        }

        if (!commandLineResult.ok) {
            queryError = commandLineResult.error || queryError
        }
    }

    // Do not fall back to bare same-process-name matching in synchronous
    // teardown. It can over-own unrelated apps. If tracked PID and
    // command-line/runtime-profile proof fail, close must fail closed.
    if (allowProcessNameFallback && appObj.exePath && !appObj.localPath) {
        queryError = combineProcessQueryErrors(
            queryError,
            'No command-line ownership fingerprint is available; refused same-name teardown fallback.'
        )
    }

    return { pids: [], signal: null, error: queryError }
}

function isPidAlive(pid) {
    try {
        process.kill(pid, 0)
        return true
    } catch (_) {
        return false
    }
}

async function collectReadinessSnapshotFromPowerShell(appObj, {
    includeProcessNameFallback = true,
    maxDepth = READINESS_PROCESS_TREE_DEPTH
} = {}) {
    const startedAt = Date.now()
    const roots = new Set()
    if (appObj?.pid) roots.add(appObj.pid)
    if (appObj?.realPid) roots.add(appObj.realPid)

    const rootPids = [...roots].filter(Boolean)
    const exeName = includeProcessNameFallback && appObj?.exePath ? pathParse(appObj.exePath).base : ''
    const spawnStart = Number(appObj?.spawnTime) || 0
    const spawnEnd = spawnStart ? spawnStart + 60000 : 0
    const escapedExeName = escapePowerShellSingleQuoted(exeName)
    const ownershipFingerprint = appObj?.ownershipFingerprint || appObj?.localPath || ''
    const escapedOwnershipFingerprint = escapePowerShellSingleQuoted(escapeWqlLike(ownershipFingerprint))
    const rootArray = rootPids.length ? rootPids.join(',') : ''

    const script = `
$ErrorActionPreference = 'Stop'
$roots = @(${rootArray})
$exeName = '${escapedExeName}'
$ownershipFingerprint = '${escapedOwnershipFingerprint}'
$spawnStart = ${spawnStart}
$spawnEnd = ${spawnEnd}
$maxDepth = ${Number(maxDepth) || 0}
try {
    function Convert-QPProcess($process) {
        [pscustomobject]@{
            ProcessId = $process.ProcessId
            ParentProcessId = $process.ParentProcessId
            Name = $process.Name
            CreatedMs = ([DateTimeOffset]$process.CreationDate).ToUnixTimeMilliseconds()
        }
    }

    $selected = @{}

    if ($roots.Count -gt 0) {
        $rootFilter = ($roots | ForEach-Object { "ProcessId=$_" }) -join " OR "
        foreach ($raw in @(Get-CimInstance Win32_Process -Filter $rootFilter)) {
            $p = Convert-QPProcess $raw
            $selected[[string]$p.ProcessId] = $p
        }
    }

    if ($exeName -ne '') {
        $wqlExeName = $exeName -replace "'", "''"
        foreach ($raw in @(Get-CimInstance Win32_Process -Filter "Name='$wqlExeName'")) {
            $p = Convert-QPProcess $raw
            if ($spawnStart -eq 0 -or ($p.CreatedMs -ge $spawnStart -and $p.CreatedMs -le $spawnEnd)) {
                $selected[[string]$p.ProcessId] = $p
            }
        }
    }

    if ($ownershipFingerprint -ne '') {
        foreach ($raw in @(Get-CimInstance Win32_Process -Filter "CommandLine like '%$ownershipFingerprint%' AND Name <> 'powershell.exe' AND Name <> 'pwsh.exe' AND Name <> 'wmic.exe'")) {
            $p = Convert-QPProcess $raw
            $selected[[string]$p.ProcessId] = $p
        }
    }

    $frontier = @($selected.Values | ForEach-Object { $_.ProcessId })
    for ($depth = 0; $depth -lt $maxDepth -and $frontier.Count -gt 0; $depth++) {
        $next = @()
        $childFilter = ($frontier | ForEach-Object { "ParentProcessId=$_" }) -join " OR "
        foreach ($raw in @(Get-CimInstance Win32_Process -Filter $childFilter)) {
            $child = Convert-QPProcess $raw
            $key = [string]$child.ProcessId
            if (-not $selected.ContainsKey($key)) {
                $selected[$key] = $child
                $next += $child.ProcessId
            }
        }
        $frontier = @($next)
    }
    $processes = @($selected.Values | Sort-Object ProcessId)
    $ids = @($processes | ForEach-Object { $_.ProcessId })
    $windows = @()
    if ($ids.Count -gt 0) {
        $processNames = @{}
        foreach ($p in $processes) { $processNames[[int]$p.ProcessId] = $p.Name }
        $pidSet = @{}
        foreach ($id in $ids) { $pidSet[[int]$id] = $true }

        $windowSource = @"
using System;
using System.Text;
using System.Runtime.InteropServices;

public static class QPWindowProbe {
    public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    [DllImport("user32.dll")]
    public static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

    [DllImport("user32.dll")]
    public static extern bool IsWindowVisible(IntPtr hWnd);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    public static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int count);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    public static extern int GetClassName(IntPtr hWnd, StringBuilder text, int count);

    [DllImport("user32.dll")]
    public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId);

    [DllImport("user32.dll")]
    public static extern bool GetWindowRect(IntPtr hWnd, out RECT rect);

    [StructLayout(LayoutKind.Sequential)]
    public struct RECT {
        public int Left;
        public int Top;
        public int Right;
        public int Bottom;
    }
}
"@

        try {
            Add-Type -TypeDefinition $windowSource -ErrorAction Stop
            $foundWindows = New-Object System.Collections.Generic.List[object]
            $callback = [QPWindowProbe+EnumWindowsProc]{
            param([IntPtr]$hWnd, [IntPtr]$lParam)

            [uint32]$windowPid = 0
            [void][QPWindowProbe]::GetWindowThreadProcessId($hWnd, [ref]$windowPid)
            $pidInt = [int]$windowPid
            if ($pidSet.ContainsKey($pidInt)) {
                $title = New-Object System.Text.StringBuilder 512
                $className = New-Object System.Text.StringBuilder 256
                [void][QPWindowProbe]::GetWindowText($hWnd, $title, $title.Capacity)
                [void][QPWindowProbe]::GetClassName($hWnd, $className, $className.Capacity)
                $rect = New-Object QPWindowProbe+RECT
                $hasRect = [QPWindowProbe]::GetWindowRect($hWnd, [ref]$rect)
                $foundWindows.Add([pscustomobject]@{
                    ProcessId = $pidInt
                    ProcessName = $processNames[$pidInt]
                    WindowHandle = $hWnd.ToInt64()
                    WindowTitle = $title.ToString()
                    ClassName = $className.ToString()
                    Visible = [QPWindowProbe]::IsWindowVisible($hWnd)
                    Left = $(if ($hasRect) { $rect.Left } else { $null })
                    Top = $(if ($hasRect) { $rect.Top } else { $null })
                    Right = $(if ($hasRect) { $rect.Right } else { $null })
                    Bottom = $(if ($hasRect) { $rect.Bottom } else { $null })
                    DetectionSource = 'enum-windows'
                })
            }
            return $true
        }
            [void][QPWindowProbe]::EnumWindows($callback, [IntPtr]::Zero)
            $windows = @($foundWindows)
        } catch {
            $windows = @(Get-Process -Id $ids -ErrorAction SilentlyContinue | ForEach-Object {
                [pscustomobject]@{
                    ProcessId = $_.Id
                    ProcessName = $_.ProcessName
                    MainWindowHandle = [int64]$_.MainWindowHandle
                    MainWindowTitle = $_.MainWindowTitle
                    DetectionSource = 'main-window-handle'
                }
            })
        }
    }
    [pscustomobject]@{
        QueryOk = $true
        Processes = $processes
        Windows = $windows
        ProbeDurationMs = 0
        Error = $null
    } | ConvertTo-Json -Depth 6 -Compress
} catch {
    [pscustomobject]@{
        QueryOk = $false
        Processes = @()
        Windows = @()
        ProbeDurationMs = 0
        Error = $_.Exception.Message
    } | ConvertTo-Json -Depth 6 -Compress
}
`

    const result = await runPowerShellJson(script, 8000)
    if (!result.ok || result.entries.length === 0) {
        return {
            ok: false,
            processes: [],
            windows: [],
            durationMs: Date.now() - startedAt,
            error: result.error || 'readiness snapshot failed'
        }
    }

    const payload = result.entries[0]
    const rawProcesses = Array.isArray(payload?.Processes)
        ? payload.Processes
        : (payload?.Processes ? [payload.Processes] : [])
    const rawWindows = Array.isArray(payload?.Windows)
        ? payload.Windows
        : (payload?.Windows ? [payload.Windows] : [])

    return {
        ok: !!payload?.QueryOk,
        processes: rawProcesses.map(normalizeProcessEntry).filter(Boolean),
        windows: rawWindows.map((entry) => ({
            pid: Number(entry?.ProcessId),
            processName: entry?.ProcessName || null,
            windowHandle: Number(entry?.WindowHandle ?? entry?.MainWindowHandle) || 0,
            windowTitle: entry?.WindowTitle ?? entry?.MainWindowTitle ?? '',
            className: entry?.ClassName || null,
            visible: typeof entry?.Visible === 'boolean' ? entry.Visible : undefined,
            bounds: {
                left: Number(entry?.Left),
                top: Number(entry?.Top),
                right: Number(entry?.Right),
                bottom: Number(entry?.Bottom)
            },
            detectionSource: entry?.DetectionSource || (entry?.MainWindowHandle != null ? 'main-window-handle' : null)
        })).filter(entry => Number.isFinite(entry.pid) && entry.pid > 0),
        durationMs: Date.now() - startedAt,
        error: payload?.Error || null
    }
}

async function collectRelatedProcessSnapshot(appObj, {
    includeProcessNameFallback = true,
    maxDepth = READINESS_PROCESS_TREE_DEPTH
} = {}) {
    const roots = new Set()
    const collected = new Map()
    const queryErrors = []

    const addEntry = (entry) => {
        if (!entry?.pid || collected.has(entry.pid)) return false
        collected.set(entry.pid, entry)
        return true
    }

    if (appObj?.pid) roots.add(appObj.pid)
    if (appObj?.realPid) roots.add(appObj.realPid)

    const snapshot = await collectReadinessSnapshotFromPowerShell(appObj, { includeProcessNameFallback, maxDepth })
    if (snapshot.ok) {
        for (const entry of snapshot.processes) {
            addEntry(entry)
        }
    } else if (snapshot.error) {
        queryErrors.push(snapshot.error)
    }

    for (const pid of roots) {
        if (!collected.has(pid) && isPidAlive(pid)) {
            addEntry({ pid, parentPid: null, name: null, createdMs: null })
        }
    }

    const processTree = [...collected.values()]
        .sort((a, b) => a.pid - b.pid)
        .map(entry => ({
            pid: entry.pid,
            parentPid: entry.parentPid,
            name: entry.name,
            createdMs: entry.createdMs
        }))
    let windows = snapshot.windows || []
    if (!snapshot.ok) {
        windows = await getWindowDetailsForPids(processTree.map(entry => entry.pid))
    }

    return {
        rootPids: [...roots].filter(Boolean).sort((a, b) => a - b),
        processTree,
        windows,
        queryOk: snapshot.ok,
        probeDurationMs: snapshot.durationMs || 0,
        queryErrors
    }
}

function pickVisibleWindow(windows, appObj = null) {
    const visible = (windows || []).filter(window =>
        Number(window.windowHandle) !== 0 &&
        window.visible !== false
    )
    if (visible.length === 0) return null

    return visible.sort((a, b) => {
        if (appObj) {
            const aClass = classifyReadinessWindow(appObj, a)
            const bClass = classifyReadinessWindow(appObj, b)
            if (aClass.expected !== bClass.expected) return aClass.expected ? -1 : 1
            if (aClass.isLauncherOrUpdater !== bClass.isLauncherOrUpdater) return aClass.isLauncherOrUpdater ? 1 : -1
        }
        const aHasTitle = String(a.windowTitle || '').trim() ? 1 : 0
        const bHasTitle = String(b.windowTitle || '').trim() ? 1 : 0
        return bHasTitle - aHasTitle
    })[0]
}

function getReadinessProfileForApp(appObj) {
    return resolveLaunchReadinessPolicy(appObj?.appConfig || {}, appObj?.diagRef || {})
}

function applyReadinessSnapshot(appObj, snapshot, patch = {}) {
    const { window: providedWindow, ...readinessPatch } = patch
    const window = providedWindow || pickVisibleWindow(snapshot.windows, appObj)
    const windowClassification = window ? classifyReadinessWindow(appObj, window) : null
    updateReadinessDiagnostic(appObj, {
        rootPids: snapshot.rootPids,
        processTree: snapshot.processTree,
        windowObserved: !!window,
        windowPid: window?.pid || null,
        windowHandle: window?.windowHandle || null,
        windowTitle: window?.windowTitle || null,
        windowClassName: window?.className || null,
        windowBounds: window?.bounds || null,
        windowDetectionSource: window?.detectionSource || null,
        windowClassification: windowClassification?.classification || null,
        expectedWindowMatched: windowClassification?.expected || false,
        expectedWindowPattern: windowClassification?.expectedPattern || null,
        launcherOrUpdaterWindowObserved: windowClassification?.isLauncherOrUpdater || false,
        observedProcessName: window?.processName || null,
        ...readinessPatch
    })
}

async function ensureAppReadiness(appObj, {
    onStatus,
    includeProcessNameFallback = true
} = {}) {
    const policy = getReadinessProfileForApp(appObj)
    const { mode, timeoutMs } = policy
    const startedAt = Date.now()
    const expectedWindowPatterns = buildExpectedWindowPatterns(appObj).map(entry => entry.label)

    updateReadinessDiagnostic(appObj, {
        mode,
        timeoutMs,
        policy: policy.readinessDescription,
        ownershipMode: policy.ownershipMode,
        expectedWindowPatterns,
        status: 'checking',
        checkedAt: startedAt,
        durationMs: 0,
        failureReason: null
    })

    if (mode === 'activation-only') {
        updateReadinessDiagnostic(appObj, {
            status: 'partial-ready',
            checkedAt: startedAt,
            durationMs: 0,
            partialReady: true,
            partialReadyReason: policy.readinessDescription,
            failureReason: null
        })
        return {
            success: true,
            status: 'partial-ready',
            launchVerifiedBy: 'shell-activation-sent',
            finalizedBy: 'activation-only',
            observedPid: appObj?.pid || null,
            partialReady: true
        }
    }

    if (mode === 'visible-window') {
        onStatus?.(`[INFO] ${appObj.diagRef.name} waiting for a visible window...`)
    }

    let lastSnapshot = null
    let emptyTreeSince = null
    let readinessProbeCount = 0
    let readinessProbeFailureCount = 0
    let readinessProbeTotalMs = 0

    while (Date.now() - startedAt <= timeoutMs) {
        const snapshot = await collectRelatedProcessSnapshot(appObj, {
            includeProcessNameFallback: includeProcessNameFallback && !requiresStrongOwnershipForCleanup(appObj)
        })
        const window = pickVisibleWindow(snapshot.windows, appObj)
        if (requiresStrongOwnershipForCleanup(appObj) && snapshot.queryOk) {
            trackOwnedPids(appObj, snapshot.processTree.map(entry => entry.pid))
        }
        const durationMs = Date.now() - startedAt
        lastSnapshot = snapshot
        readinessProbeCount += 1
        readinessProbeTotalMs += snapshot.probeDurationMs || 0
        if (!snapshot.queryOk) readinessProbeFailureCount += 1

        if (mode === 'process') {
            if (snapshot.processTree.length > 0) {
                applyReadinessSnapshot(appObj, snapshot, {
                    status: 'background-ready',
                    durationMs,
                    checkedAt: Date.now(),
                    observedVia: 'process-tree',
                    probeCount: readinessProbeCount,
                    probeFailureCount: readinessProbeFailureCount,
                    probeTotalMs: readinessProbeTotalMs,
                    failureReason: null
                })
                return {
                    success: true,
                    status: 'background-ready',
                    launchVerifiedBy: 'process-ready',
                    finalizedBy: 'process-ready',
                    observedPid: snapshot.processTree[0]?.pid || null
                }
            }
        } else if (window) {
            const errorState = detectReadinessErrorState(appObj, window)
            const observedVia = window?.detectionSource || 'main-window'
            const windowClassification = classifyReadinessWindow(appObj, window)

            trackOwnedPid(appObj, window.pid, {
                signal: 'visible-window',
                setRealPid: window.pid && window.pid !== appObj.pid && !appObj.realPid,
                readyWindow: true
            })

            if (errorState) {
                applyReadinessSnapshot(appObj, snapshot, {
                    window,
                    status: 'error-window',
                    durationMs,
                    checkedAt: Date.now(),
                    observedVia,
                    probeCount: readinessProbeCount,
                    probeFailureCount: readinessProbeFailureCount,
                    probeTotalMs: readinessProbeTotalMs,
                    failureReason: errorState.message
                })
                return {
                    success: false,
                    status: 'error-window',
                    stage: 'readiness-checking',
                    message: errorState.message
                }
            }

            if (windowClassification.isLauncherOrUpdater && !policy.allowLauncherWindowAsReady) {
                applyReadinessSnapshot(appObj, snapshot, {
                    window,
                    status: 'partial-ready',
                    durationMs,
                    checkedAt: Date.now(),
                    observedVia,
                    probeCount: readinessProbeCount,
                    probeFailureCount: readinessProbeFailureCount,
                    probeTotalMs: readinessProbeTotalMs,
                    partialReady: true,
                    partialReadyReason: `Observed ${windowClassification.classification}, waiting for main app window.`,
                    failureReason: null
                })
            } else {
                applyReadinessSnapshot(appObj, snapshot, {
                    window,
                    status: appObj.isLauncherPattern || appObj.realPid ? 'handoff-ready' : 'ready',
                    durationMs,
                    checkedAt: Date.now(),
                    observedVia,
                    probeCount: readinessProbeCount,
                    probeFailureCount: readinessProbeFailureCount,
                    probeTotalMs: readinessProbeTotalMs,
                    failureReason: null
                })
                return {
                    success: true,
                    status: appObj.isLauncherPattern || appObj.realPid ? 'handoff-ready' : 'ready',
                    launchVerifiedBy: 'visible-window',
                    finalizedBy: 'visible-window',
                    observedPid: window.pid || null
                }
            }
        }

        if (snapshot.queryErrors?.length) {
            updateReadinessDiagnostic(appObj, {
                queryErrors: snapshot.queryErrors,
                probeFailureCount: readinessProbeFailureCount
            })
        }

        applyReadinessSnapshot(appObj, snapshot, {
            status: snapshot.processTree.length > 0 ? 'running-no-window' : 'exited-early',
            durationMs,
            probeCount: readinessProbeCount,
            probeFailureCount: readinessProbeFailureCount,
            probeTotalMs: readinessProbeTotalMs,
            checkedAt: Date.now()
        })

        if (snapshot.processTree.length === 0) {
            if (emptyTreeSince == null) emptyTreeSince = Date.now()
            if (Date.now() - emptyTreeSince >= READINESS_EMPTY_TREE_GRACE_MS) break
        } else {
            emptyTreeSince = null
        }
        if (Date.now() - startedAt + READINESS_POLL_INTERVAL_MS > timeoutMs) break
        await sleep(READINESS_POLL_INTERVAL_MS)
    }

    const durationMs = Date.now() - startedAt
    const allReadinessProbesFailed = readinessProbeCount > 0 && readinessProbeFailureCount === readinessProbeCount
    const status = allReadinessProbesFailed
        ? 'readiness-probe-failed'
        : (lastSnapshot?.processTree?.length ? 'running-no-window' : 'exited-early')
    const failureReason = allReadinessProbesFailed
        ? `Readiness probe failed: ${lastSnapshot?.queryErrors?.[0] || 'unable to query process/window state'}`
        : status === 'running-no-window'
            ? `No visible window was observed within ${Math.round(timeoutMs / 1000)}s`
            : 'Process exited before a visible window appeared'

    applyReadinessSnapshot(appObj, lastSnapshot || { rootPids: [], processTree: [], windows: [] }, {
        status,
        durationMs,
        checkedAt: Date.now(),
        probeCount: readinessProbeCount,
        probeFailureCount: readinessProbeFailureCount,
        probeTotalMs: readinessProbeTotalMs,
        failureReason
    })

    return {
        success: false,
        status,
        stage: 'readiness-checking',
        message: failureReason
    }
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
                startLauncherMonitor(appObj, realPid, details.signal)

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

function startLauncherMonitor(appObj, realPid, signal = 'known-real-pid') {
    if (!realPid || appObj.launcherMonitorStarted) return

    appObj.launcherMonitorStarted = true
    trackOwnedPid(appObj, realPid, { signal, setRealPid: true })
    updateAppDiagnostic(appObj, {
        isLauncher: true,
        realPid,
        handoffSignal: signal,
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
            console.log(`[Wipesnap] ${appObj.diagRef.name} manual close detected. Syncing to USB...`)
            if (appObj.usbPath && appObj.localPath && !appObj.syncPromise && !appObj.abandonSync) {
                appObj.syncPromise = enqueueSync(appObj.usbPath, appObj.localPath)
            } else {
                wipeRuntimeOnlyProfile(appObj)
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
        for (const app of launchedApps) {
            ensureAppDiagnosticInActiveCycle(app)
        }

        // Phase 1: Send ALL graceful kill signals in parallel
        for (const app of launchedApps) {
            if (!canCloseLaunchedApp(app)) {
                updateAppDiagnostic(app, {
                    closeMethod: 'not-owned',
                    cleanupSkippedForSafety: true,
                cleanupSafetyReason: 'Wipesnap did not have ownership proof for this app; quit was skipped.'
                })
                continue
            }
            if (!app.exited && app.child.exitCode === null) {
                app.closeMethod = app.closeMethod || 'graceful'
                updateAppDiagnostic(app, { closeMethod: app.closeMethod })
                killPidSync(app.pid, { tree: true, force: false })
            }
        }

        // Phase 2: Await exits with Timeout Escalation
        await Promise.all(launchedApps.map(app => {
            return new Promise(resolve => {
                if (!canCloseLaunchedApp(app)) return resolve()
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
                        killPidSync(app.pid, { tree: true, force: true })
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

        // Phase 3: Handle successor-owned and strong-ownership apps.
        // Chromium/launcher-style apps can outlive the original root PID, so we
        // first kill any owned successor PIDs we already tracked in-session and
        // only then fall back to command-line rediscovery.
        for (const app of launchedApps) {
            if (!canCloseLaunchedApp(app)) continue
            const strongOwnershipRequired = requiresStrongOwnershipForCleanup(app)
            const shouldEvaluateSuccessors =
                app.isLauncherPattern ||
                strongOwnershipRequired ||
                getTrackedOwnedPids(app, { includeRoot: false }).length > 0

            let killedOwnedProcesses = false
            const killOwnedSuccessorPids = (pids, signal = null) => {
                const uniquePids = [...new Set((pids || [])
                    .map(pid => Number(pid))
                    .filter(pid => Number.isFinite(pid) && pid > 0 && pid !== app.pid))]

                if (uniquePids.length === 0) return false

                trackOwnedPids(app, uniquePids, { signal })
                if (!app.realPid && uniquePids[0]) {
                    trackOwnedPid(app, uniquePids[0], { signal, setRealPid: true })
                }

                app.closeMethod = app.isLauncherPattern ? 'launcher-kill' : 'owned-tree-kill'
                updateAppDiagnostic(app, {
                    closeMethod: app.closeMethod,
                    isLauncher: !!app.isLauncherPattern,
                    ...(signal ? { handoffSignal: app.diagRef?.handoffSignal || signal } : {}),
                    realPid: app.realPid || uniquePids[0] || null
                })

                for (const pid of uniquePids) {
                    killPidSync(pid, { tree: true, force: true })
                }
                return true
            }

            const trackedSuccessorPids = getLiveTrackedOwnedPids(app, { includeRoot: false })
            if (killOwnedSuccessorPids(trackedSuccessorPids, app.realPidSignal || app.diagRef?.handoffSignal || 'tracked-owned-pid')) {
                killedOwnedProcesses = true
            }

            let successorDetails = { pids: [], signal: null, error: null }
            if (shouldEvaluateSuccessors) {
                successorDetails = findSuccessorDetailsSync(app, {
                    allowProcessNameFallback: !strongOwnershipRequired
                })
                if (killOwnedSuccessorPids(successorDetails.pids, successorDetails.signal)) {
                    killedOwnedProcesses = true
                }
            }

            if (killedOwnedProcesses) {
                await new Promise(r => setTimeout(r, 500))
            }

            const rootAlive = isPidAlive(app.pid)
            const liveOwnedSuccessorPids = getLiveTrackedOwnedPids(app, { includeRoot: false })
            const readyBasedOwnershipConfirmed = !!app.readyObserved || !!app.realPid || !!app.diagRef?.handoffObserved
            const successorDiscoveryFailed = shouldEvaluateSuccessors &&
                !!successorDetails.error &&
                successorDetails.pids.length === 0 &&
                liveOwnedSuccessorPids.length === 0
            const successorDiscoveryUncertain = shouldEvaluateSuccessors &&
                !successorDiscoveryFailed &&
                !rootAlive &&
                successorDetails.pids.length === 0 &&
                liveOwnedSuccessorPids.length === 0 &&
                (app.isLauncherPattern || strongOwnershipRequired) &&
                !readyBasedOwnershipConfirmed
            const successorDiscoveryUncertaintyReason = app.isLauncherPattern
                ? 'No successor ownership proof was available after launcher exit; skipped sync and cleanup for safety.'
                : 'No strong ownership proof was available after teardown; skipped sync and cleanup for safety.'
            const successorSafetyBlocked = successorDiscoveryFailed || successorDiscoveryUncertain
            const sessionProcessesClosed = !rootAlive &&
                liveOwnedSuccessorPids.length === 0 &&
                !successorSafetyBlocked

            app.currentSessionRuntimeProfileSafeToDelete = sessionProcessesClosed &&
                (!strongOwnershipRequired || readyBasedOwnershipConfirmed)

            if (successorDiscoveryFailed) {
                app.cleanupSkippedForSafety = true
                updateAppDiagnostic(app, {
                    cleanupSkippedForSafety: true,
                    successorDiscoveryFailed: true,
                    cleanupSafetyReason: `Could not confirm successor shutdown: ${successorDetails.error}`
                })
            } else if (successorDiscoveryUncertain) {
                app.cleanupSkippedForSafety = true
                updateAppDiagnostic(app, {
                    cleanupSkippedForSafety: true,
                    successorDiscoveryUncertain: true,
                    cleanupSafetyReason: successorDiscoveryUncertaintyReason
                })
            } else if (strongOwnershipRequired && (rootAlive || liveOwnedSuccessorPids.length > 0)) {
                app.cleanupSkippedForSafety = true
                const reason = rootAlive
                    ? 'Owned root process remained alive after teardown; skipped cleanup for safety.'
                    : `Owned successor process remained alive after teardown: ${liveOwnedSuccessorPids.join(', ')}`
                updateAppDiagnostic(app, {
                    cleanupSkippedForSafety: true,
                    cleanupSafetyReason: reason
                })
            } else if (strongOwnershipRequired && app.isLauncherPattern && successorDetails.pids.length === 0 && !app.currentSessionRuntimeProfileSafeToDelete) {
                app.cleanupSkippedForSafety = true
                updateAppDiagnostic(app, {
                    cleanupSkippedForSafety: true,
                    cleanupSafetyReason: successorDetails.error
                        ? `Could not confirm owned successor process after launcher exit: ${successorDetails.error}`
                        : 'No strongly owned successor process was found after launcher exit; deferred cleanup for safety.'
                })
            }

            if (app.usbPath && app.localPath && !app.syncPromise && !app.abandonSync) {
                if (sessionProcessesClosed) {
                    app.syncPromise = enqueueSync(app.usbPath, app.localPath)
                } else {
                    app.abandonSync = true
                    app.abandonSyncReason = rootAlive
                        ? 'Process remained alive after teardown; skipped sync for safety.'
                        : successorDiscoveryFailed
                            ? `Could not confirm successor shutdown before sync: ${successorDetails.error}`
                            : successorDiscoveryUncertain
                                ? successorDiscoveryUncertaintyReason
                                : 'Owned successor process remained alive after teardown; skipped sync for safety.'
                    updateAppDiagnostic(app, {
                        cleanupSkippedForSafety: true,
                        cleanupSafetyReason: app.abandonSyncReason
                    })
                }
            }
        }

        // Phase 4: Drain all syncs (populated by exit events + deferred launcher syncs)
        await globalSyncQueue

        // Phase 5: Wipe runtime-only isolated profiles that were never synced
        // because they were created only to prevent host profile attachment.
        for (const app of launchedApps) {
            wipeRuntimeOnlyProfile(app)
        }

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
        if (!canCloseLaunchedApp(app)) {
            updateAppDiagnostic(app, {
                closeMethod: 'not-owned',
                cleanupSkippedForSafety: true,
                cleanupSafetyReason: 'Wipesnap did not have ownership proof for this app; emergency quit was skipped.'
            })
            continue
        }
        app.abandonSync = true
        app.abandonSyncReason = 'App was abandoned during emergency shutdown; deferred to stale runtime profile cleanup.'
        if (!app.exited && app.child.exitCode === null) {
            killPidSync(app.pid, { tree: true, force: true })
        }
        // Also kill launcher-pattern orphans using multi-signal approach
        if (app.isLauncherPattern || requiresStrongOwnershipForCleanup(app)) {
            const strongOwnershipRequired = requiresStrongOwnershipForCleanup(app)
            const successorDetails = findSuccessorDetailsSync(app, {
                allowProcessNameFallback: !strongOwnershipRequired
            })
            const realPids = successorDetails.pids
            for (const pid of realPids) {
                killPidSync(pid, { tree: true, force: true })
            }
        }
    }
    wipeAllRuntimeAppProfiles({ staleOnly: true })
    launchedApps = []
}

function resolveImportedDataUsbPath(appConfig, vaultDir) {
    const safeName = safeAppName(appConfig?.name || '')
    const sanitizedPath = join(vaultDir, 'AppData', safeName)
    const rawPath = join(vaultDir, 'AppData', appConfig?.name || safeName)
    let usbPath = sanitizedPath

    if (safeName !== appConfig?.name && existsSync(rawPath)) {
        usbPath = rawPath
        if (existsSync(sanitizedPath)) {
            const bakPath = `${sanitizedPath}.bak-${Date.now()}`
            try {
                renameSync(sanitizedPath, bakPath)
                console.log(`[Wipesnap] Legacy conflict: backed up ${sanitizedPath} -> ${bakPath}`)
            } catch (err) {
                console.warn(`[Wipesnap] Failed to backup sanitized folder: ${err.message}`)
            }
        }
    }

    return { safeName, usbPath }
}

function getUnsupportedImportedDataMessage(appConfig, effectiveLaunchProfile, runtimeDataPlan = null) {
    const reason = runtimeDataPlan?.unsupportedImportedDataReason ||
        'Wipesnap currently supports imported AppData only for Chromium/Edge and VS Code-family launch profiles.'
    const runtimeLevel = runtimeDataPlan?.runtimeProfileSupportLevel || RUNTIME_DATA_SUPPORT_LEVELS.UNSUPPORTED
    const levelDetail = runtimeLevel === RUNTIME_DATA_SUPPORT_LEVELS.BEST_EFFORT
        ? ' Wipesnap may still attempt best-effort runtime isolation for launch-only use, but imported AppData requires a verified adapter.'
        : ''
    return `${appConfig.name} was imported with AppData, but launch profile '${effectiveLaunchProfile}' does not have a verified imported AppData redirection strategy in Wipesnap. ${reason}${levelDetail} Reimport without AppData or add an app-specific runtime data adapter before launching it in Wipesnap.`
}

// --- Desktop App Launcher ---
async function launchDesktopAppLegacy(appConfig, onStatus, vaultDir) {
    return launchDesktopApp(appConfig, onStatus, vaultDir)
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
        let args = parseLaunchArgs(appConfig.args)
        let appPath = appConfig.path
        let launchSource = 'raw-path'
        let usbPath = null
        let localPath = null
        const isHostExeLaunch = isHostExeLaunchConfig(appConfig)
        const isWeakShellHostLaunch = isWeakShellHostLaunchConfig(appConfig)
        if (isHostExeLaunch) {
            applyHostExeDiagnostic(diagRef, appConfig)
        } else if (isWeakShellHostLaunch) {
            applyWeakShellHostDiagnostic(diagRef, appConfig)
        }
        let manifest = appConfig.manifest || (vaultDir ? readAppManifest(vaultDir, appConfig.manifestId || appConfig.name) : null)
        if (manifest) {
            manifest = normalizeManifestProfiles(manifest).manifest
        }

        if (manifest) {
            Object.assign(diagRef, {
                manifestId: manifest.manifestId || appConfig.manifestId || null,
                launchProfile: manifest.launchProfile || appConfig.launchProfile || null,
                dataProfile: manifest.dataProfile || appConfig.dataProfile || null,
                ...pickSupportFields(manifest),
                readinessProfile: manifest.readinessProfile || appConfig.readinessProfile || null,
                readiness: createReadinessDiagnostic(manifest.readinessProfile || appConfig.readinessProfile),
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
                const localAppDir = join(os.tmpdir(), `${LOCAL_APP_CACHE_PREFIX}${safeName}`)
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
                        console.error(`[Wipesnap] Failed to extract ${appName}:`, err)
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

        if (!isWeakShellHostLaunch && isDangerousExecutablePath(appPath)) {
            diagRef.dangerousTarget = true
            return failLaunch('dangerous-launch-target', `Refusing to launch unsafe executable target: ${appPath}`, 'resolving')
        }

        if ((isHostExeLaunch || isWeakShellHostLaunch) && [
            'missing-on-this-PC',
            'stale-registry-reference',
            'stale-app-path-reference',
            'stale-shortcut-reference',
            'stale-shell-execute-reference',
            'stale-protocol-reference',
            'stale-packaged-app-reference'
        ].includes(diagRef.availabilityStatus)) {
            const reason = appConfig.registryResolution?.reason ||
                appConfig.appPathsResolution?.reason ||
                appConfig.shortcutClassification?.warning ||
                appConfig.shellExecuteResolution?.reason ||
                appConfig.protocolResolution?.reason ||
                appConfig.packagedAppResolution?.reason ||
                appConfig.hostResolution?.reason ||
                'Host app could not be resolved on this PC.'
            return failLaunch('host-app-unavailable', `${appConfig.name} is unavailable on this PC. ${reason}`, 'resolving')
        }

        const effectiveLaunchProfile = isHostExeLaunch || isWeakShellHostLaunch
            ? 'native-windowed'
            : resolveEffectiveLaunchProfile(appConfig, manifest, appPath)
        const effectiveDataProfile = isHostExeLaunch || isWeakShellHostLaunch
            ? { mode: 'none' }
            : resolveEffectiveDataProfile(appConfig, manifest, effectiveLaunchProfile)
        const importedDataRequested = isHostExeLaunch || isWeakShellHostLaunch ? false : !!appConfig.portableData
        const runtimeDataPlan = resolveRuntimeDataPlan(appConfig, effectiveLaunchProfile, effectiveDataProfile)
        const supportsRuntimeUserDataDir = runtimeDataPlan.runtimeProfileSupported
        const supportsImportedDataRedirection = supportsImportedAppDataRedirection(appConfig, effectiveLaunchProfile, effectiveDataProfile)
        const useRuntimeProfile = supportsRuntimeUserDataDir
        const syncImportedData = importedDataRequested && !!vaultDir && supportsImportedDataRedirection
        const cleanupRequiresStrongOwnership = isBrowserLaunchProfile(effectiveLaunchProfile) || isBrowserProcessName(appPath)

        Object.assign(diagRef, {
            launchProfile: effectiveLaunchProfile,
            dataProfile: effectiveDataProfile,
            runtimeProfileIsolated: useRuntimeProfile,
            runtimeProfileSynced: syncImportedData,
            runtimeProfileAdapterId: runtimeDataPlan.adapterId,
            runtimeProfileArgStyle: runtimeDataPlan.argPrefix ? 'user-data-dir' : 'none',
            runtimeProfileSupportLevel: runtimeDataPlan.runtimeProfileSupportLevel,
            runtimeProfileSupportReason: runtimeDataPlan.runtimeSupportReason,
            runtimeProfileSupportWarning: runtimeDataPlan.runtimeSupportWarning,
            importedDataSupportLevel: runtimeDataPlan.importedDataSupportLevel,
            importedDataSupported: supportsImportedDataRedirection,
            cleanupRequiresStrongOwnership
        })

        if (importedDataRequested && !vaultDir) {
            return failLaunch(
                'imported-data-misconfigured',
                `${appConfig.name} is configured with imported AppData, but no active vault is available to load it.`,
                'resolving'
            )
        }

        if (importedDataRequested && !supportsImportedDataRedirection) {
            return failLaunch(
                'imported-data-unsupported',
                getUnsupportedImportedDataMessage(appConfig, effectiveLaunchProfile, runtimeDataPlan),
                'resolving'
            )
        }

        if (useRuntimeProfile) {
            const safeName = safeAppName(appConfig.name)

            if (runtimeDataPlan.runtimeSupportWarning) {
                onStatus(`[WARN] ${appConfig.name} - ${runtimeDataPlan.runtimeSupportWarning}`)
            }

            if (syncImportedData) {
                const importedDataPaths = resolveImportedDataUsbPath(appConfig, vaultDir)
                usbPath = importedDataPaths.usbPath
                localPath = join(os.tmpdir(), `${LOCAL_APPDATA_PREFIX}${importedDataPaths.safeName}`)
                mkdirSync(usbPath, { recursive: true })
                mkdirSync(localPath, { recursive: true })

                try {
                    diagRef.launchStage = 'syncing-data'
                    onStatus(`Syncing ${appConfig.name} data to local...`)
                    await robocopyAsync(usbPath, localPath)
                } catch (err) {
                    console.error(`[Wipesnap] Failed to sync AppData for ${appConfig.name}:`, err)
                    diagError('app-data-sync', `${appConfig.name}: ${err.message}`)
                }
            } else {
                localPath = join(os.tmpdir(), `${RUNTIME_APP_PROFILE_PREFIX}${safeName}-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`)
                mkdirSync(localPath, { recursive: true })
            }

            if (runtimeDataPlan.argPrefix) {
                args = replaceArgWithPrefix(args, runtimeDataPlan.argPrefix, `${runtimeDataPlan.argPrefix}${localPath}`)
            }
            if (runtimeDataPlan.addBrowserHardeningArgs) {
                args = addArgIfMissing(args, '--no-default-browser-check')
                args = addArgIfMissing(args, '--no-first-run')
            }

            Object.assign(diagRef, {
                runtimeProfilePath: localPath,
                runtimeProfileIsolated: true,
                runtimeProfileSynced: syncImportedData
            })
        }

        warnOnEmbeddedHostPaths(localPath, appConfig, onStatus)

        const isExe = appPath.toLowerCase().endsWith('.exe') || appPath.toLowerCase().endsWith('.bat') || appPath.toLowerCase().endsWith('.cmd')
        const targetExists = appPath ? existsSync(appPath) : false
        const readinessPolicy = resolveLaunchReadinessPolicy(appConfig, diagRef)
        const launchTargetClassification = classifyLaunchTarget(appConfig, appPath)

        Object.assign(diagRef, {
            exePath: appPath,
            resolvedPath: appPath,
            launchSource: (isHostExeLaunch || isWeakShellHostLaunch) ? appConfig.launchSourceType : launchSource,
            readinessPolicy: readinessPolicy.readinessDescription,
            readinessOwnershipMode: readinessPolicy.ownershipMode,
            launchTargetClassification: launchTargetClassification.classification,
            launchTargetClassificationReason: launchTargetClassification.reason,
            launchStage: 'spawning'
        })

        const canLaunchWithoutFilesystemTarget = ['protocol-uri', 'packaged-app'].includes(appConfig?.launchSourceType)
        if (!targetExists && !canLaunchWithoutFilesystemTarget) {
            if (isHostExeLaunch) {
                Object.assign(diagRef, {
                    availabilityStatus: 'missing-on-this-PC',
                    launchStage: 'resolving'
                })
            }
            return failLaunch('app-path-missing', `Resolved path not found: ${appPath}`, 'resolving')
        }

        let cwd
        if (isExe) {
            cwd = require('path').dirname(appPath)
        }

        let child
        let stdoutCapture = ''
        let stderrCapture = ''
        const launchArgsSnapshot = [...args]
        try {
            child = isExe
                ? spawn(appPath, args, {
                    detached: true,
                    stdio: ['ignore', 'pipe', 'pipe'],
                    ...(cwd ? { cwd } : {})
                })
                : spawn('explorer.exe', [appPath, ...args], {
                    detached: true,
                    stdio: ['ignore', 'pipe', 'pipe'],
                    ...(cwd ? { cwd } : {})
                })
        } catch (err) {
            return failLaunch('app-spawn', err.message, 'spawning')
        }

        if (!child.pid) {
            return failLaunch('app-spawn', 'Failed to spawn process', 'spawning')
        }

        if (isHostExeLaunch && appConfig.closeManagedAfterSpawn !== false) {
            Object.assign(diagRef, {
                availabilityStatus: 'available',
                ownershipProofLevel: 'strong',
                closePolicy: 'owned-tree',
                canQuitFromOmniLaunch: true,
                dataManagement: 'unmanaged'
            })
        } else if (isHostExeLaunch) {
            Object.assign(diagRef, {
                availabilityStatus: 'available',
                dataManagement: 'unmanaged'
            })
        } else if (isWeakShellHostLaunch) {
            Object.assign(diagRef, {
                availabilityStatus: 'available',
                ownershipProofLevel: diagRef.ownershipProofLevel || (appConfig.launchSourceType === 'shell-execute' ? 'weak' : 'none'),
                closePolicy: 'never',
                canQuitFromOmniLaunch: false,
                closeManagedAfterSpawn: false,
                dataManagement: 'unmanaged'
            })
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
            abandonSyncReason: null,
            isLauncherPattern: false,
            launcherMonitorStarted: false,
            launcherHandoffPromise: null,
            exePath: appPath,
            spawnTime,
            closeMethod: null,
            launchProfile: effectiveLaunchProfile,
            dataProfile: effectiveDataProfile,
            requiresStrongOwnership: cleanupRequiresStrongOwnership,
            canQuitFromOmniLaunch: diagRef.canQuitFromOmniLaunch !== false,
            ownershipProofLevel: diagRef.ownershipProofLevel || null,
            closePolicy: diagRef.closePolicy || null,
            ownershipFingerprint: localPath || null,
            appConfig,
            realPidSignal: null,
            readyObserved: false,
            readyWindowPid: null,
            ownedPids: new Set([child.pid]),
            currentSessionRuntimeProfileSafeToDelete: false,
            latestStdout: '',
            latestStderr: '',
            diagRef
        }

        Object.assign(diagRef, {
            pid: child.pid,
            status: 'spawning',
            spawnCwd: cwd || null,
            launchArgs: launchArgsSnapshot
        })

        launchedApps.push(appObj)
        child.stdout?.on?.('data', chunk => {
            stdoutCapture = appendBoundedOutput(stdoutCapture, chunk)
            appObj.latestStdout = stdoutCapture
        })
        child.stderr?.on?.('data', chunk => {
            stderrCapture = appendBoundedOutput(stderrCapture, chunk)
            appObj.latestStderr = stderrCapture
        })
        child.stdout?.unref?.()
        child.stderr?.unref?.()
        child.unref()

        child.once('exit', (code, signal) => {
            appObj.exited = true

            const lifetime = Date.now() - spawnTime
            updateAppDiagnostic(appObj, {
                exitCode: code,
                exitSignal: signal,
                lifetimeMs: lifetime,
                spawnCwd: cwd || null,
                launchArgs: launchArgsSnapshot,
                ...(stdoutCapture ? { boundedStdout: stdoutCapture } : {}),
                ...(stderrCapture ? { boundedStderr: stderrCapture } : {})
            })

            if (appObj.abandonSync) return

            if (lifetime < 15000 && appObj.canQuitFromOmniLaunch !== false && !appObj.readyObserved && !closeInProgress && !appObj.closeMethod) {
                appObj.isLauncherPattern = true
                updateAppDiagnostic(appObj, {
                    isLauncher: true,
                    launchStage: 'handoff-pending'
                })
                console.log(`[Wipesnap] ${appConfig.name} exited in ${lifetime}ms - likely a launcher, deferring sync`)

                ensureLauncherHandoff(appObj).catch(() => { })

                return
            }

            if (closeInProgress) return

            if (appObj.usbPath && appObj.localPath && !appObj.syncPromise) {
                appObj.syncPromise = enqueueSync(appObj.usbPath, appObj.localPath)
            } else if (appObj.localPath && !appObj.usbPath) {
                wipeRuntimeOnlyProfile(appObj)
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

                const finishWithReadiness = async ({
                    handoff = null,
                    fallbackFromMissedHandoff = false
                } = {}) => {
                    const readiness = await ensureAppReadiness(appObj, { onStatus })
                    const handoffExtra = handoff ? {
                        handoffObserved: !!handoff.success,
                        handoffSignal: handoff.signal,
                        handoffTimeoutMs: handoff.timeoutMs,
                        launcherDetectionAttempts: handoff.attempts,
                        launcherDetectionMs: handoff.durationMs
                    } : {}

                    if (readiness.success) {
                        if (readiness.observedPid) {
                            trackOwnedPid(appObj, readiness.observedPid, {
                                signal: readiness.launchVerifiedBy === 'visible-window' ? 'visible-window' : 'process-tree',
                                setRealPid: readiness.observedPid !== appObj.pid && !appObj.realPid,
                                readyWindow: readiness.launchVerifiedBy === 'visible-window'
                            })
                        }
                        finalizeLaunchSuccess(appObj, {
                            launchVerifiedBy: readiness.launchVerifiedBy,
                            finalizedBy: readiness.finalizedBy,
                            extra: {
                                ...handoffExtra,
                                ...(readiness.observedPid && readiness.observedPid !== appObj.pid ? { realPid: readiness.observedPid } : {}),
                                ...(fallbackFromMissedHandoff ? { handoffFallbackReady: true } : {})
                            }
                        })
                        onStatus(`[OK] ${appConfig.name} - ready`)
                        finish({ success: true, name: appConfig.name })
                        return true
                    }

                    const message = fallbackFromMissedHandoff
                        ? `Launcher exited before handoff was observed. ${readiness.message}`
                        : readiness.message
                    finish(failLaunch('app-readiness', message, readiness.stage || 'readiness-checking'))
                    return false
                }

                const launchPolicy = getReadinessProfileForApp(appObj)
                if (launchPolicy.mode === 'activation-only') {
                    await finishWithReadiness()
                    return
                }

                if (appObj.exited) {
                    updateAppDiagnostic(appObj, {
                        status: 'launcher-detecting',
                        launchStage: 'launcher-detecting'
                    })
                    onStatus(`[INFO] ${appConfig.name} is handing off to its main process...`)

                    const handoff = await ensureLauncherHandoff(appObj)

                    if (!handoff.success) {
                        await finishWithReadiness({ handoff, fallbackFromMissedHandoff: true })
                        return
                    }

                    appObj.isLauncherPattern = true
                    updateAppDiagnostic(appObj, {
                        isLauncher: true,
                        handoffObserved: true,
                        handoffSignal: handoff.signal,
                        handoffTimeoutMs: handoff.timeoutMs,
                        launcherDetectionAttempts: handoff.attempts,
                        launcherDetectionMs: handoff.durationMs,
                        ...(handoff.realPid ? { realPid: handoff.realPid } : {})
                    })
                    await finishWithReadiness({ handoff })
                    return
                } else {
                    try {
                        process.kill(child.pid, 0)
                    } catch (_) {
                        finish(failLaunch('app-spawn', 'Process terminated immediately after launch', 'spawning'))
                        return
                    }

                    await finishWithReadiness()
                    return
                }
            }, 1000)
        })

        return result
    } catch (err) {
        return failLaunch('app-launch', err.message)
    }
}

export async function launchWorkspace(workspace, onStatus, vaultDir, options = {}) {
    if (!options.skipDiagnosticsCycle) {
        beginDiagnosticsCycle('launch')
    }
    scheduleStaleAppCacheCleanup()
    const savedUrls = (workspace.webTabs || []).filter(t => t.enabled).map(t => t.url)
    const enabledApps = (workspace.desktopApps || []).filter(a => a.enabled)
    const total = savedUrls.length + enabledApps.length

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
        if (enabledApps.length > 0) {
            ensureExtractorPreflight()
        }

        const appResults = await mapWithConcurrency(enabledApps, DESKTOP_APP_LAUNCH_CONCURRENCY, async (appConfig, i) => {
            const result = await launchDesktopApp(appConfig, (msg) => onStatus(`[App ${i + 1}] ${msg}`), vaultDir)
            return { type: 'app', ...result }
        })
        return appResults
    }

    // --- Run both tracks concurrently ---
    const [webResults, appResults] = await Promise.all([
        browserTrack(),
        appsTrack()
    ])

    return { webResults, appResults }
}

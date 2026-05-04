import { existsSync, readFileSync, readdirSync, statSync } from 'fs'
import { basename, isAbsolute, join, win32 } from 'path'
import { createCapabilityStore, validateCapabilityUserArgs } from './capabilityStore.js'
import {
    APP_MANIFEST_SUFFIX,
    LEGACY_APP_MANIFEST_SUFFIX,
    safeAppName
} from './appManifest.js'
import { DEFAULT_IMPORT_RESERVATION_STALE_MS } from './importReservations.js'
import { loadDiagnosticsSummary } from './diagnosticsView.js'
import { WORKSPACE_CAPABILITY_VAULT_KEY } from './workspaceCapabilityMigration.js'

export const WORKSPACE_HEALTH_STATUSES = Object.freeze({
    READY: 'ready',
    NEEDS_ATTENTION: 'needs-attention',
    BROKEN: 'broken'
})

const MAX_LABEL_LENGTH = 96
const MAX_MESSAGE_LENGTH = 180
const MAX_REASONS = 24
const MAX_APPS = 80
const MANIFEST_SUFFIXES = [APP_MANIFEST_SUFFIX, LEGACY_APP_MANIFEST_SUFFIX]
const ARCHIVE_SUFFIX = '.tar.zst'
const IMPORTED_CAPABILITY_TYPES = new Set(['vault-archive', 'vault-directory', 'imported-app'])
const HOST_EXE_CAPABILITY_TYPES = new Set([
    'host-exe',
    'registry-uninstall',
    'app-paths',
    'start-menu-shortcut',
    'shortcut'
])
const HOST_FOLDER_CAPABILITY_TYPES = new Set(['host-folder'])
const SHELL_TARGET_CAPABILITY_TYPES = new Set(['shell-execute'])

function isPlainObject(value) {
    return !!value && typeof value === 'object' && !Array.isArray(value)
}

function limitString(value, maxLength = MAX_MESSAGE_LENGTH) {
    const text = String(value ?? '').replace(/[\r\n\t]+/g, ' ').replace(/\s{2,}/g, ' ').trim()
    if (text.length <= maxLength) return text
    return `${text.slice(0, Math.max(0, maxLength - 1)).trim()}...`
}

function redactSensitiveText(value, maxLength = MAX_MESSAGE_LENGTH) {
    let text = limitString(value, maxLength * 2)
    if (!text) return ''

    text = text
        .replace(/file:\/\/\/[^\s"')]+/gi, '[redacted-path]')
        .replace(/\\\\[^\s"')]+/g, '[redacted-path]')
        .replace(/[a-zA-Z]:\\[^\r\n"']+/g, '[redacted-path]')
        .replace(/\b(https?:\/\/[^\s?#]+)[^\s]*/gi, '$1[redacted-url-detail]')
        .replace(/\b(password|pin|token|secret|cookie|credential|auth|key|fastboot)([\w.-]{0,24})\s*[:=]\s*[^,;\s]+/gi, '$1$2=[redacted]')
        .replace(/\b[A-Fa-f0-9]{32,}\b/g, '[redacted-token]')
        .replace(/\b[A-Za-z0-9+/]{40,}={0,2}\b/g, '[redacted-token]')

    return limitString(text, maxLength)
}

function sanitizeLabel(value, fallback = 'Workspace item') {
    const text = redactSensitiveText(value, MAX_LABEL_LENGTH)
    return text || fallback
}

function createBaseSummary(overrides = {}) {
    return {
        success: true,
        available: true,
        state: 'ready',
        status: WORKSPACE_HEALTH_STATUSES.READY,
        statusLabel: 'Ready',
        message: 'Workspace looks ready to launch.',
        counts: {
            apps: 0,
            enabledApps: 0,
            browserTabs: 0,
            checks: 0,
            broken: 0,
            warnings: 0,
            info: 0,
            pendingImportReservations: 0,
            staleImportReservations: 0
        },
        browserProfile: {
            configured: false,
            present: false,
            status: 'not-configured'
        },
        diagnostics: {
            available: false,
            status: 'missing',
            failures: 0,
            warnings: 0
        },
        importReservations: {
            present: false,
            pending: 0,
            stale: 0
        },
        apps: [],
        reasons: [],
        ...overrides
    }
}

function createFailureSummary(state, message, overrides = {}) {
    return createBaseSummary({
        success: false,
        available: false,
        state,
        status: WORKSPACE_HEALTH_STATUSES.BROKEN,
        statusLabel: 'Broken',
        message,
        ...overrides
    })
}

function statusLabel(status) {
    if (status === WORKSPACE_HEALTH_STATUSES.BROKEN) return 'Broken'
    if (status === WORKSPACE_HEALTH_STATUSES.NEEDS_ATTENTION) return 'Needs attention'
    return 'Ready'
}

function addReason(summary, severity, scope, name, message, code) {
    const normalizedSeverity = severity === 'broken'
        ? 'broken'
        : severity === 'warning'
            ? 'warning'
            : 'info'

    if (summary.reasons.length < MAX_REASONS) {
        summary.reasons.push({
            severity: normalizedSeverity,
            scope: sanitizeLabel(scope, 'workspace').toLowerCase(),
            name: sanitizeLabel(name, 'Workspace item'),
            message: redactSensitiveText(message || 'Workspace item needs attention.'),
            code: sanitizeLabel(code || 'workspace-health', 'workspace-health').toLowerCase()
        })
    }
}

function finalizeSummary(summary) {
    summary.counts.broken = summary.reasons.filter(reason => reason.severity === 'broken').length
    summary.counts.warnings = summary.reasons.filter(reason => reason.severity === 'warning').length
    summary.counts.info = summary.reasons.filter(reason => reason.severity === 'info').length
    summary.counts.checks = summary.apps.length + 1 + (summary.diagnostics.available ? 1 : 0)

    if (summary.counts.broken > 0) {
        summary.status = WORKSPACE_HEALTH_STATUSES.BROKEN
        summary.message = 'Workspace has broken launch references.'
    } else if (summary.counts.warnings > 0) {
        summary.status = WORKSPACE_HEALTH_STATUSES.NEEDS_ATTENTION
        summary.message = 'Workspace can launch, but some items need attention.'
    } else {
        summary.status = WORKSPACE_HEALTH_STATUSES.READY
        summary.message = 'Workspace looks ready to launch.'
    }
    summary.statusLabel = statusLabel(summary.status)
    return summary
}

function createFs(fsApi) {
    return fsApi || { existsSync, statSync, readFileSync, readdirSync }
}

function statPath(fs, pathValue) {
    try {
        if (!pathValue || !fs.existsSync(pathValue)) return { exists: false, isFile: false, isDirectory: false }
        const stat = fs.statSync(pathValue)
        return {
            exists: true,
            isFile: !!stat?.isFile?.(),
            isDirectory: !!stat?.isDirectory?.()
        }
    } catch (_) {
        return { exists: false, isFile: false, isDirectory: false, inaccessible: true }
    }
}

function normalizeWorkspace(workspace) {
    if (!isPlainObject(workspace)) throw new Error('Workspace data is malformed.')
    return {
        ...workspace,
        webTabs: Array.isArray(workspace.webTabs) ? workspace.webTabs : [],
        desktopApps: Array.isArray(workspace.desktopApps) ? workspace.desktopApps : []
    }
}

function enabledTabs(workspace) {
    return workspace.webTabs.filter(tab => tab?.enabled !== false && typeof tab?.url === 'string' && tab.url.trim())
}

function appDisplayName(entry, index) {
    return sanitizeLabel(entry?.displayName || entry?.name || `App ${index + 1}`)
}

function addAppIssue(appHealth, summary, severity, message, code) {
    appHealth.issues.push({
        severity,
        message: redactSensitiveText(message),
        code
    })
    addReason(summary, severity, 'app', appHealth.name, message, code)
}

function validateSavedArgs(entry, record, appHealth, summary) {
    try {
        validateCapabilityUserArgs(entry.userArgs || [], record, {
            fieldName: 'workspace entry userArgs'
        })
    } catch (_) {
        addAppIssue(
            appHealth,
            summary,
            'broken',
            'Saved launch arguments are outside this app capability policy.',
            'invalid-launch-arguments'
        )
    }
}

function checkHostExecutable(record, appHealth, summary, fs) {
    const target = statPath(fs, record.launch.path)
    if (target.inaccessible) {
        addAppIssue(
            appHealth,
            summary,
            'broken',
            'Saved host executable could not be inspected on this PC.',
            'inaccessible-host-executable'
        )
    } else if (!target.exists) {
        addAppIssue(
            appHealth,
            summary,
            'broken',
            'Saved host executable is not present on this PC.',
            'missing-host-executable'
        )
    } else if (!target.isFile) {
        addAppIssue(
            appHealth,
            summary,
            'broken',
            'Saved host executable target is not a readable file.',
            'invalid-host-executable'
        )
    }
}

function checkHostFolder(record, appHealth, summary, fs) {
    const target = statPath(fs, record.launch.path)
    if (target.inaccessible) {
        addAppIssue(
            appHealth,
            summary,
            'broken',
            'Saved host folder could not be inspected on this PC.',
            'inaccessible-host-folder'
        )
    } else if (!target.exists) {
        addAppIssue(
            appHealth,
            summary,
            'broken',
            'Saved host folder is not present on this PC.',
            'missing-host-folder'
        )
    } else if (!target.isDirectory) {
        addAppIssue(
            appHealth,
            summary,
            'broken',
            'Saved host folder target is not a readable folder.',
            'invalid-host-folder'
        )
    }
}

function checkShellTarget(record, appHealth, summary, fs) {
    const target = statPath(fs, record.launch.path)
    if (target.inaccessible) {
        addAppIssue(
            appHealth,
            summary,
            'broken',
            'Saved shell target could not be inspected on this PC.',
            'inaccessible-shell-target'
        )
    } else if (!target.exists) {
        addAppIssue(
            appHealth,
            summary,
            'broken',
            'Saved shell target is not present on this PC.',
            'missing-shell-target'
        )
    }
}

function manifestCandidatePaths(vaultDir, manifestId, storageId) {
    const ids = [...new Set([manifestId, storageId].filter(Boolean).map(value => safeAppName(value)))]
    const candidates = []
    for (const id of ids) {
        for (const suffix of MANIFEST_SUFFIXES) {
            candidates.push(join(vaultDir, 'Apps', `${id}${suffix}`))
        }
    }
    return candidates
}

function readImportedManifest(vaultDir, manifestId, storageId, fs) {
    for (const pathValue of manifestCandidatePaths(vaultDir, manifestId, storageId)) {
        const stat = statPath(fs, pathValue)
        if (!stat.exists) continue
        if (!stat.isFile) return { exists: true, malformed: true, manifest: null }
        try {
            const manifest = JSON.parse(fs.readFileSync(pathValue, 'utf8'))
            if (!isPlainObject(manifest)) return { exists: true, malformed: true, manifest: null }
            return { exists: true, malformed: false, manifest }
        } catch (_) {
            return { exists: true, malformed: true, manifest: null }
        }
    }
    return { exists: false, malformed: false, manifest: null }
}

function safeArchiveName(manifest, storageId) {
    const archiveName = String(manifest?.archiveName || `${storageId}${ARCHIVE_SUFFIX}`).trim()
    if (!archiveName || basename(archiveName) !== archiveName || !archiveName.toLowerCase().endsWith(ARCHIVE_SUFFIX)) {
        return ''
    }
    return archiveName
}

function isSafeRelativePath(value) {
    const text = String(value || '').replace(/\//g, '\\').trim()
    if (!text || text.includes('\0')) return false
    if (isAbsolute(text) || win32.isAbsolute(text)) return false
    return !text.split(/[\\/]+/).some(part => part === '..')
}

function checkSelectedExecutableForDirectory(vaultDir, storageId, manifest, appHealth, summary, fs) {
    const selected = String(manifest?.selectedExecutable?.relativePath || '').replace(/\//g, '\\').trim()
    if (!selected) {
        addAppIssue(
            appHealth,
            summary,
            'broken',
            'Imported app manifest is missing a selected executable.',
            'missing-imported-selected-executable'
        )
        return
    }
    if (!isSafeRelativePath(selected)) {
        addAppIssue(
            appHealth,
            summary,
            'broken',
            'Imported app manifest selected executable is unsafe.',
            'unsafe-imported-selected-executable'
        )
        return
    }

    const exeStat = statPath(fs, join(vaultDir, 'Apps', storageId, selected))
    if (!exeStat.exists || !exeStat.isFile) {
        addAppIssue(
            appHealth,
            summary,
            'broken',
            'Imported app executable is missing from the saved app folder.',
            'missing-imported-executable'
        )
    }
}

function checkImportedApp(record, appHealth, summary, vaultDir, fs) {
    const storageId = record.launch.storageId
    const manifestId = record.launch.manifestId || storageId
    const manifestResult = readImportedManifest(vaultDir, manifestId, storageId, fs)

    if (!manifestResult.exists) {
        addAppIssue(
            appHealth,
            summary,
            'broken',
            'Imported app manifest is missing.',
            'missing-imported-manifest'
        )
        return
    }
    if (manifestResult.malformed) {
        addAppIssue(
            appHealth,
            summary,
            'broken',
            'Imported app manifest could not be read safely.',
            'malformed-imported-manifest'
        )
        return
    }

    const manifest = manifestResult.manifest
    if (manifest.safeName && manifest.safeName !== storageId) {
        addAppIssue(
            appHealth,
            summary,
            'broken',
            'Imported app manifest does not match the saved capability.',
            'imported-manifest-storage-mismatch'
        )
    }
    if (manifest.manifestId && manifestId && manifest.manifestId !== manifestId) {
        addAppIssue(
            appHealth,
            summary,
            'broken',
            'Imported app manifest ID does not match the saved capability.',
            'imported-manifest-id-mismatch'
        )
    }

    if (record.type === 'vault-directory') {
        const directoryStat = statPath(fs, join(vaultDir, 'Apps', storageId))
        if (!directoryStat.exists) {
            addAppIssue(
                appHealth,
                summary,
                'broken',
                'Imported app folder is missing.',
                'missing-imported-folder'
            )
            return
        }
        if (!directoryStat.isDirectory) {
            addAppIssue(
                appHealth,
                summary,
                'broken',
                'Imported app folder is not readable.',
                'invalid-imported-folder'
            )
            return
        }
        checkSelectedExecutableForDirectory(vaultDir, storageId, manifest, appHealth, summary, fs)
        return
    }

    const archiveName = safeArchiveName(manifest, storageId)
    if (!archiveName) {
        addAppIssue(
            appHealth,
            summary,
            'broken',
            'Imported app archive reference is malformed.',
            'malformed-imported-archive-reference'
        )
        return
    }
    const archiveStat = statPath(fs, join(vaultDir, 'Apps', archiveName))
    if (!archiveStat.exists) {
        addAppIssue(
            appHealth,
            summary,
            'broken',
            'Imported app archive is missing.',
            'missing-imported-archive'
        )
    } else if (!archiveStat.isFile) {
        addAppIssue(
            appHealth,
            summary,
            'broken',
            'Imported app archive is not a readable file.',
            'invalid-imported-archive'
        )
    }
}

function checkAppEntry(entry, index, store, summary, { vaultDir, fs }) {
    const name = appDisplayName(entry, index)
    const appHealth = {
        name,
        enabled: !!(entry?.enabled !== false && entry?.quarantined !== true),
        status: 'ready',
        type: 'unknown',
        issues: []
    }

    if (!isPlainObject(entry)) {
        appHealth.status = WORKSPACE_HEALTH_STATUSES.BROKEN
        addAppIssue(appHealth, summary, 'broken', 'Saved app entry is malformed.', 'malformed-app-entry')
        return appHealth
    }

    if (entry.quarantined === true) {
        appHealth.enabled = false
        appHealth.status = WORKSPACE_HEALTH_STATUSES.NEEDS_ATTENTION
        addAppIssue(
            appHealth,
            summary,
            'warning',
            entry.quarantineReason || 'App entry is quarantined and will not launch.',
            entry.quarantineCode || 'quarantined-app-entry'
        )
        return appHealth
    }

    if (entry.enabled === false) {
        appHealth.status = 'disabled'
        return appHealth
    }

    let record = null
    try {
        record = store.require(entry.capabilityId)
        appHealth.type = record.type
    } catch (_) {
        appHealth.status = WORKSPACE_HEALTH_STATUSES.BROKEN
        addAppIssue(
            appHealth,
            summary,
            'broken',
            'Saved launch capability is missing or stale.',
            'missing-capability'
        )
        return appHealth
    }

    validateSavedArgs(entry, record, appHealth, summary)

    if (HOST_EXE_CAPABILITY_TYPES.has(record.type)) {
        checkHostExecutable(record, appHealth, summary, fs)
    } else if (HOST_FOLDER_CAPABILITY_TYPES.has(record.type)) {
        checkHostFolder(record, appHealth, summary, fs)
    } else if (SHELL_TARGET_CAPABILITY_TYPES.has(record.type)) {
        checkShellTarget(record, appHealth, summary, fs)
    } else if (IMPORTED_CAPABILITY_TYPES.has(record.type)) {
        checkImportedApp(record, appHealth, summary, vaultDir, fs)
    }

    if (appHealth.issues.some(issue => issue.severity === 'broken')) {
        appHealth.status = WORKSPACE_HEALTH_STATUSES.BROKEN
    } else if (appHealth.issues.some(issue => issue.severity === 'warning')) {
        appHealth.status = WORKSPACE_HEALTH_STATUSES.NEEDS_ATTENTION
    }
    return appHealth
}

function checkBrowserProfile(workspace, summary, vaultDir, fs) {
    const tabs = enabledTabs(workspace)
    summary.counts.browserTabs = tabs.length
    summary.browserProfile.configured = tabs.length > 0

    const profileStat = statPath(fs, join(vaultDir, 'BrowserProfile'))
    summary.browserProfile.present = profileStat.exists && profileStat.isDirectory
    summary.browserProfile.status = tabs.length === 0
        ? 'not-configured'
        : summary.browserProfile.present
            ? 'present'
            : 'missing'

    if (tabs.length > 0 && !summary.browserProfile.present) {
        addReason(
            summary,
            'warning',
            'browser',
            'Browser profile',
            'Saved tabs are configured, but no browser profile is saved yet.',
            'missing-browser-profile'
        )
    }
}

function readReservationJson(fs, lockPath) {
    try {
        const parsed = JSON.parse(fs.readFileSync(lockPath, 'utf8'))
        return isPlainObject(parsed) ? parsed : null
    } catch (_) {
        return null
    }
}

function reservationCreatedAtMs(fs, lockPath, reservation, now) {
    if (Number.isFinite(Number(reservation?.createdAtMs))) return Number(reservation.createdAtMs)
    if (reservation?.createdAt) {
        const parsed = Date.parse(reservation.createdAt)
        if (Number.isFinite(parsed)) return parsed
    }
    try {
        return Number(fs.statSync(lockPath).mtimeMs)
    } catch (_) {
        return now
    }
}

function scanImportReservations(vaultDir, fs, { now = Date.now, staleMs = DEFAULT_IMPORT_RESERVATION_STALE_MS } = {}) {
    const appsReservationDir = join(vaultDir, 'Apps', '.reservations')
    const currentTime = typeof now === 'function' ? Number(now()) : Number(now)
    const resolvedNow = Number.isFinite(currentTime) ? currentTime : Date.now()
    const resolvedStaleMs = Number.isFinite(Number(staleMs)) && Number(staleMs) > 0
        ? Number(staleMs)
        : DEFAULT_IMPORT_RESERVATION_STALE_MS
    const result = { present: false, pending: 0, stale: 0 }
    const dirStat = statPath(fs, appsReservationDir)
    if (!dirStat.exists || !dirStat.isDirectory) return result

    let entries = []
    try {
        entries = fs.readdirSync(appsReservationDir, { withFileTypes: true })
    } catch (_) {
        return result
    }

    for (const entry of entries) {
        if (!entry.isFile?.() || !entry.name.endsWith('.lock')) continue
        const lockPath = join(appsReservationDir, entry.name)
        const reservation = readReservationJson(fs, lockPath)
        const createdAt = reservationCreatedAtMs(fs, lockPath, reservation, resolvedNow)
        const stale = Math.max(0, resolvedNow - createdAt) >= resolvedStaleMs
        result.present = true
        if (stale) result.stale += 1
        else result.pending += 1
    }

    return result
}

function checkImportReservations(summary, vaultDir, fs, options = {}) {
    const reservations = scanImportReservations(vaultDir, fs, options)
    summary.importReservations = reservations
    summary.counts.pendingImportReservations = reservations.pending
    summary.counts.staleImportReservations = reservations.stale

    if (reservations.stale > 0) {
        addReason(
            summary,
            'warning',
            'import',
            'Import reservations',
            `${reservations.stale} stale import reservation${reservations.stale === 1 ? '' : 's'} found.`,
            'stale-import-reservations'
        )
    }
    if (reservations.pending > 0) {
        addReason(
            summary,
            'info',
            'import',
            'Import reservations',
            `${reservations.pending} import reservation${reservations.pending === 1 ? '' : 's'} still pending.`,
            'pending-import-reservations'
        )
    }
}

function checkDiagnostics(summary, vaultDir, fs, diagnosticsSummary = null) {
    const diagnostics = diagnosticsSummary || loadDiagnosticsSummary({ vaultDir, fsApi: fs })
    summary.diagnostics = {
        available: !!diagnostics?.available,
        status: diagnostics?.status || diagnostics?.state || 'missing',
        failures: Number(diagnostics?.counts?.failures || 0),
        warnings: Number(diagnostics?.counts?.warnings || 0)
    }

    if (diagnostics?.success && diagnostics?.state === 'ready') {
        if (diagnostics.status === 'failed') {
            addReason(
                summary,
                'warning',
                'diagnostics',
                'Last diagnostics',
                `Last diagnostics include ${summary.diagnostics.failures || 1} failure${summary.diagnostics.failures === 1 ? '' : 's'}.`,
                'recent-diagnostics-failures'
            )
        } else if (diagnostics.status === 'warning') {
            addReason(
                summary,
                'warning',
                'diagnostics',
                'Last diagnostics',
                `Last diagnostics include ${summary.diagnostics.warnings || 1} warning${summary.diagnostics.warnings === 1 ? '' : 's'}.`,
                'recent-diagnostics-warnings'
            )
        }
        return
    }

    if (diagnostics?.success === false && diagnostics?.state !== 'missing') {
        addReason(
            summary,
            'warning',
            'diagnostics',
            'Diagnostics',
            diagnostics.message || 'Diagnostics could not be read safely.',
            'diagnostics-unavailable'
        )
    }
}

export function loadWorkspaceHealthSummary({
    workspace,
    vaultDir,
    fsApi = null,
    now = Date.now,
    staleMs = DEFAULT_IMPORT_RESERVATION_STALE_MS,
    diagnosticsSummary = null
} = {}) {
    const fs = createFs(fsApi)
    if (!vaultDir || typeof vaultDir !== 'string') {
        return createFailureSummary('unavailable', 'Workspace health location is unavailable.')
    }

    let normalizedWorkspace = null
    let store = null
    try {
        normalizedWorkspace = normalizeWorkspace(workspace || {})
        store = createCapabilityStore({
            vaultValue: normalizedWorkspace[WORKSPACE_CAPABILITY_VAULT_KEY] || null
        })
    } catch (err) {
        return createFailureSummary('malformed', err?.message || 'Workspace health could not be computed safely.')
    }

    const summary = createBaseSummary()
    summary.counts.apps = normalizedWorkspace.desktopApps.length
    summary.counts.enabledApps = normalizedWorkspace.desktopApps.filter(app => app?.enabled !== false && app?.quarantined !== true).length

    for (const [index, appEntry] of normalizedWorkspace.desktopApps.entries()) {
        if (summary.apps.length >= MAX_APPS) break
        summary.apps.push(checkAppEntry(appEntry, index, store, summary, { vaultDir, fs }))
    }

    checkBrowserProfile(normalizedWorkspace, summary, vaultDir, fs)
    checkImportReservations(summary, vaultDir, fs, { now, staleMs })
    checkDiagnostics(summary, vaultDir, fs, diagnosticsSummary)

    return finalizeSummary(summary)
}

export function loadWorkspaceHealthSummaryHandlerCore({ input, deps }) {
    try {
        deps.requireActiveSession()
        if (input !== undefined) {
            return createFailureSummary('invalid-request', 'Workspace health does not accept renderer input.')
        }
        const workspace = deps.loadActiveVaultWorkspace()
        return loadWorkspaceHealthSummary({
            workspace,
            vaultDir: deps.getVaultDir(),
            fsApi: deps.fsApi || null,
            now: deps.now || Date.now,
            staleMs: deps.staleMs,
            diagnosticsSummary: deps.diagnosticsSummary || null
        })
    } catch (err) {
        const message = err?.message || 'Session is locked.'
        const state = /locked/i.test(message) ? 'locked' : 'unavailable'
        return createFailureSummary(state, state === 'locked' ? 'Session is locked.' : 'Workspace health is unavailable.')
    }
}

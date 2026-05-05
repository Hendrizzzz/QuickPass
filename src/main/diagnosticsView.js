import { existsSync, readFileSync, statSync } from 'fs'
import { join } from 'path'

export const DIAGNOSTICS_FILE_NAME = 'run-diagnostics.json'
export const MAX_DIAGNOSTICS_BYTES = 1024 * 1024

const MAX_PHASES = 24
const MAX_APPS = 50
const MAX_BROWSER_TABS = 24
const MAX_WARNINGS = 24
const MAX_FAILURES = 24
const MAX_MESSAGE_LENGTH = 240
const MAX_LABEL_LENGTH = 96

const CYCLE_TYPE_VALUES = new Set(['run', 'launch', 'setup', 'edit'])
const PHASE_STATUS_VALUES = new Set(['running', 'ok', 'failed', 'warning', 'warn', 'error', 'crashed', 'blocked', 'skipped', 'unknown'])
const APP_ROLE_VALUES = new Set(['launch', 'cleanup'])
const APP_STATUS_VALUES = new Set(['starting', 'spawning', 'launcher-detecting', 'ok', 'failed', 'error', 'crashed', 'blocked', 'skipped', 'unknown'])
const APP_STAGE_VALUES = new Set(['resolving', 'extracting', 'spawning', 'handoff-pending', 'launcher-detecting', 'readiness-checking', 'ok', 'failed', 'unknown'])
const READINESS_STATUS_VALUES = new Set(['pending', 'checking', 'partial-ready', 'background-ready', 'error-window', 'ready', 'ok', 'failed', 'unknown'])
const SUPPORT_TIER_VALUES = new Set(['verified', 'best-effort', 'launch-only', 'needs-adapter', 'unsupported', 'unknown'])
const LAUNCH_SOURCE_TYPE_VALUES = new Set(['vault-archive', 'vault-directory', 'host-exe', 'host-folder', 'registry-uninstall', 'app-paths', 'start-menu-shortcut', 'shell-execute', 'protocol-uri', 'packaged-app', 'raw-path', 'unknown'])
const LAUNCH_METHOD_VALUES = new Set(['spawn', 'shell-execute', 'protocol', 'packaged-app', 'unknown'])
const AVAILABILITY_STATUS_VALUES = new Set(['available', 'missing-on-this-pc', 'stale-registry-reference', 'stale-app-path-reference', 'stale-shortcut-reference', 'stale-shell-execute-reference', 'stale-protocol-reference', 'stale-packaged-app-reference', 'unsupported', 'unknown'])
const CLOSE_METHOD_VALUES = new Set(['none', 'not-owned', 'graceful', 'force', 'failsafe', 'launcher-kill', 'owned-tree-kill'])
const LAUNCH_VERIFIED_BY_VALUES = new Set(['unknown', 'shell-activation-sent', 'process-ready', 'visible-window', 'launcher-handoff', 'process-spawn'])
const IMPORTED_DATA_SUPPORT_LEVEL_VALUES = new Set(['verified', 'best-effort', 'unsupported', 'unknown'])
const ARCHIVE_POLICY_STATUS_VALUES = new Set(['current', 'legacy', 'unknown', 'ok', 'failed'])
const SYNC_BACK_STATUS_VALUES = new Set(['not-run', 'running', 'completed', 'failed', 'deferred', 'blocked', 'unknown'])
const CLEANUP_LIFECYCLE_STATUS_VALUES = new Set(['not-run', 'started', 'completed', 'deferred', 'blocked', 'failed', 'unknown'])
const FINAL_STATE_VALUES = new Set(['synced', 'cleanup-completed', 'cleanup-deferred', 'cleanup-failed', 'action-needed', 'unknown'])
const BROWSER_REASON_VALUES = new Set(['', 'empty-url', 'local-file-url', 'browser-error-page', 'browser-internal-page', 'unsupported-browser-scheme', 'unsupported-browser-url'])
const STATUS_CLASSIFICATION_VALUES = new Set([
    ...PHASE_STATUS_VALUES,
    ...APP_STATUS_VALUES,
    ...READINESS_STATUS_VALUES,
    ...SUPPORT_TIER_VALUES,
    ...AVAILABILITY_STATUS_VALUES,
    ...ARCHIVE_POLICY_STATUS_VALUES
])
const FAILURE_STATUS_VALUES = new Set(['failed', 'error', 'crashed', 'blocked', 'missing-on-this-pc', 'stale-registry-reference', 'stale-app-path-reference', 'stale-shortcut-reference', 'stale-shell-execute-reference', 'stale-protocol-reference', 'stale-packaged-app-reference'])
const WARNING_STATUS_VALUES = new Set(['warning', 'warn', 'unsupported', 'missing-on-this-pc', 'stale-registry-reference', 'stale-app-path-reference', 'stale-shortcut-reference', 'stale-shell-execute-reference', 'stale-protocol-reference', 'stale-packaged-app-reference'])

const EMPTY_COUNTS = Object.freeze({
    apps: 0,
    appFailures: 0,
    warnings: 0,
    failures: 0,
    browserTabs: 0,
    browserFailures: 0
})

function createEmptySummary(state = 'missing', overrides = {}) {
    return {
        success: state === 'missing' || state === 'empty',
        available: false,
        state,
        status: state === 'empty' ? 'empty' : 'missing',
        message: state === 'missing'
            ? 'No diagnostics have been recorded yet.'
            : 'Diagnostics did not contain a recorded run.',
        counts: { ...EMPTY_COUNTS },
        lastRun: null,
        lastLaunch: null,
        browser: {
            present: false,
            status: 'empty',
            tabCount: 0,
            succeeded: 0,
            failed: 0,
            skipped: 0,
            copyInMs: null,
            copyOutMs: null,
            migrated: false,
            tabs: []
        },
        cleanup: {
            present: false,
            copyOutMs: null,
            appsObserved: 0,
            skippedForSafety: 0,
            runtimeProfilesWiped: 0,
            runtimeProfilesDeferred: 0
        },
        lifecycle: {
            metadataOnly: true,
            launchStarted: false,
            workspaceRunning: false,
            quitRequested: false,
            browserSyncBack: { status: 'not-run', copyOutMs: null },
            appSessionSyncBack: { status: 'not-run', completed: 0, failed: 0, deferred: 0, blocked: 0 },
            cleanup: { status: 'not-run', completed: false, deferred: 0, blocked: 0, failed: 0 },
            finalState: 'unknown',
            finalStateLabel: 'Unknown',
            recoveryGuidance: 'No final lifecycle status has been recorded yet.'
        },
        imports: {
            present: false,
            importedDataApps: 0,
            unsupportedImportedData: 0,
            archiveWarnings: 0,
            extractor: null
        },
        phases: [],
        apps: [],
        warnings: [],
        failures: [],
        ...overrides
    }
}

function createFailureSummary(state, message, overrides = {}) {
    return createEmptySummary(state, {
        success: false,
        available: false,
        status: 'failed',
        message,
        ...overrides
    })
}

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

function sanitizeLabel(value, fallback = 'Unknown') {
    const text = redactSensitiveText(value, MAX_LABEL_LENGTH)
    return text || fallback
}

function normalizeStatusToken(value) {
    const redacted = redactSensitiveText(value, 128)
    if (!redacted || redacted.includes('[redacted')) return ''
    const text = redacted.toLowerCase()
    return text.replace(/[^a-z0-9_.:-]/g, '-').slice(0, 64)
}

function sanitizeStatus(value, fallback = 'unknown', allowedValues = STATUS_CLASSIFICATION_VALUES) {
    const text = normalizeStatusToken(value)
    if (!text) return fallback
    if (allowedValues && !allowedValues.has(text)) return fallback
    return text
}

function normalizeBoolean(value) {
    return value === true
}

function normalizeNumber(value) {
    if (value == null) return null
    const number = Number(value)
    return Number.isFinite(number) && number >= 0 ? number : null
}

function normalizeTimestamp(value) {
    const number = Number(value)
    return Number.isFinite(number) && number > 0 ? number : null
}

function validateCycleShape(cycle) {
    if (!isPlainObject(cycle)) return false
    for (const key of ['phases', 'appResults', 'webResults', 'errors']) {
        if (cycle[key] != null && !Array.isArray(cycle[key])) return false
    }
    if (cycle.browserSync != null && !isPlainObject(cycle.browserSync)) return false
    if (cycle.runtimeChecks != null && !isPlainObject(cycle.runtimeChecks)) return false
    return true
}

function validateDiagnosticsShape(raw) {
    if (!isPlainObject(raw)) return false
    if (raw.cycles != null && !Array.isArray(raw.cycles)) return false
    if (!validateCycleShape(raw)) return false
    if (Array.isArray(raw.cycles) && raw.cycles.some(cycle => !validateCycleShape(cycle))) return false
    return true
}

function hasCycleContent(cycle) {
    return !!cycle?.cycleStartTime ||
        !!cycle?.cycleType ||
        (Array.isArray(cycle?.phases) && cycle.phases.length > 0) ||
        (Array.isArray(cycle?.appResults) && cycle.appResults.length > 0) ||
        (Array.isArray(cycle?.webResults) && cycle.webResults.length > 0) ||
        (Array.isArray(cycle?.errors) && cycle.errors.length > 0)
}

function collectCycles(raw) {
    const cycles = []
    if (Array.isArray(raw.cycles)) {
        raw.cycles.forEach((cycle, index) => {
            if (hasCycleContent(cycle)) cycles.push({ ...cycle, __index: index })
        })
    }
    if (hasCycleContent(raw)) {
        cycles.push({ ...raw, __index: cycles.length })
    }

    return cycles
        .map((cycle, index) => ({ ...cycle, __sort: normalizeTimestamp(cycle.cycleStartTime) ?? index }))
        .sort((a, b) => a.__sort - b.__sort)
}

function summarizeCycleMeta(cycle) {
    if (!cycle) return null
    return {
        type: sanitizeStatus(cycle.cycleType || 'run', 'run', CYCLE_TYPE_VALUES),
        startedAt: normalizeTimestamp(cycle.cycleStartTime),
        durationMs: summarizeDuration(cycle.phases || []),
        status: summarizeCycleStatus(cycle),
        phaseCount: Array.isArray(cycle.phases) ? cycle.phases.length : 0,
        appCount: Array.isArray(cycle.appResults) ? cycle.appResults.length : 0,
        browserTabCount: Array.isArray(cycle.webResults) ? cycle.webResults.length : 0,
        errorCount: Array.isArray(cycle.errors) ? cycle.errors.length : 0
    }
}

function summarizeDuration(phases) {
    const durations = (Array.isArray(phases) ? phases : [])
        .map(phase => normalizeNumber(phase?.durationMs))
        .filter(value => value != null)
    if (durations.length === 0) return null
    return durations.reduce((sum, value) => sum + value, 0)
}

function isFailureStatus(status) {
    const value = sanitizeStatus(status, 'unknown', STATUS_CLASSIFICATION_VALUES)
    return FAILURE_STATUS_VALUES.has(value)
}

function isWarningStatus(status) {
    const value = sanitizeStatus(status, 'unknown', STATUS_CLASSIFICATION_VALUES)
    return WARNING_STATUS_VALUES.has(value)
}

function summarizeCycleStatus(cycle) {
    const phases = Array.isArray(cycle?.phases) ? cycle.phases : []
    const apps = Array.isArray(cycle?.appResults) ? cycle.appResults : []
    const webResults = Array.isArray(cycle?.webResults) ? cycle.webResults : []
    const errors = Array.isArray(cycle?.errors) ? cycle.errors : []

    if (errors.length > 0) return 'failed'
    if (phases.some(phase => isFailureStatus(phase?.status))) return 'failed'
    if (apps.some(app => isFailureStatus(app?.status))) return 'failed'
    if (webResults.some(tab => tab?.success === false && !tab?.skipped)) return 'failed'
    if (phases.some(phase => isWarningStatus(phase?.status))) return 'warning'
    if (apps.some(app => hasAppWarning(app))) return 'warning'
    if (webResults.some(tab => tab?.skipped)) return 'warning'
    if (phases.length || apps.length || webResults.length) return 'ok'
    return 'empty'
}

function summarizePhases(phases = []) {
    return phases.slice(0, MAX_PHASES).map(phase => ({
        name: sanitizeLabel(phase?.name, 'Phase'),
        status: sanitizeStatus(phase?.status || 'unknown', 'unknown', PHASE_STATUS_VALUES),
        durationMs: normalizeNumber(phase?.durationMs),
        detail: redactSensitiveText(phase?.detail || '', 160)
    }))
}

function getReadinessStatus(app) {
    return sanitizeStatus(app?.readiness?.status || (app?.readyObserved ? 'ok' : 'unknown'), 'unknown', READINESS_STATUS_VALUES)
}

function getAppError(app) {
    return redactSensitiveText(
        app?.error ||
        app?.readiness?.failureReason ||
        app?.runtimeProfileWipeError ||
        app?.cleanupSafetyReason ||
        '',
        180
    )
}

function hasAppWarning(app) {
    return !!app?.cleanupSkippedForSafety ||
        !!app?.runtimeProfileWipeSkippedForSafety ||
        ['failed', 'deferred', 'blocked'].includes(sanitizeStatus(app?.appSessionSyncBackStatus || 'not-run', 'not-run', SYNC_BACK_STATUS_VALUES)) ||
        isWarningStatus(app?.availabilityStatus) ||
        isWarningStatus(app?.supportTier) ||
        isWarningStatus(app?.archivePolicyStatus) ||
        isWarningStatus(app?.readiness?.status)
}

function summarizeApps(appResults = []) {
    return appResults.slice(0, MAX_APPS).map(app => {
        const cleanupSkippedForSafety = normalizeBoolean(app?.cleanupSkippedForSafety)
        const runtimeProfileWipeSkippedForSafety = normalizeBoolean(app?.runtimeProfileWipeSkippedForSafety)
        const error = getAppError(app)
        const warning = cleanupSkippedForSafety
            ? redactSensitiveText(app?.cleanupSafetyReason || 'Cleanup skipped for safety.', 180)
            : runtimeProfileWipeSkippedForSafety
                ? redactSensitiveText(app?.runtimeProfileWipeSafetyReason || 'Runtime profile cleanup was deferred for safety.', 180)
                : ''

        return {
            name: sanitizeLabel(app?.name, 'Unnamed app'),
            role: sanitizeStatus(app?.diagnosticRole || 'launch', 'launch', APP_ROLE_VALUES),
            status: sanitizeStatus(app?.status || 'unknown', 'unknown', APP_STATUS_VALUES),
            stage: sanitizeStatus(app?.launchStage || 'unknown', 'unknown', APP_STAGE_VALUES),
            readinessStatus: getReadinessStatus(app),
            supportTier: sanitizeStatus(app?.supportTier || 'unknown', 'unknown', SUPPORT_TIER_VALUES),
            launchSourceType: sanitizeStatus(app?.launchSourceType || app?.launchSource || 'unknown', 'unknown', LAUNCH_SOURCE_TYPE_VALUES),
            launchMethod: sanitizeStatus(app?.launchMethod || 'unknown', 'unknown', LAUNCH_METHOD_VALUES),
            availabilityStatus: sanitizeStatus(app?.availabilityStatus || 'unknown', 'unknown', AVAILABILITY_STATUS_VALUES),
            closeMethod: sanitizeStatus(app?.closeMethod || 'none', 'none', CLOSE_METHOD_VALUES),
            launchVerifiedBy: sanitizeStatus(app?.launchVerifiedBy || 'unknown', 'unknown', LAUNCH_VERIFIED_BY_VALUES),
            runtimeProfileSynced: normalizeBoolean(app?.runtimeProfileSynced),
            runtimeProfileWiped: normalizeBoolean(app?.runtimeProfileWiped),
            runtimeProfileDeferred: runtimeProfileWipeSkippedForSafety,
            appSessionSyncBackStatus: sanitizeStatus(app?.appSessionSyncBackStatus || 'not-run', 'not-run', SYNC_BACK_STATUS_VALUES),
            appSessionSyncBackError: redactSensitiveText(app?.appSessionSyncBackError || '', 180),
            cleanupSkippedForSafety,
            cleanupSafetyReason: cleanupSkippedForSafety ? redactSensitiveText(app?.cleanupSafetyReason || 'Cleanup skipped for safety.', 180) : '',
            importedDataSupportLevel: sanitizeStatus(app?.importedDataSupportLevel || 'unknown', 'unknown', IMPORTED_DATA_SUPPORT_LEVEL_VALUES),
            importedDataSupported: normalizeBoolean(app?.importedDataSupported),
            archivePolicyStatus: sanitizeStatus(app?.archivePolicyStatus || 'unknown', 'unknown', ARCHIVE_POLICY_STATUS_VALUES),
            warning,
            error: isFailureStatus(app?.status) ? error : ''
        }
    })
}

function summarizeBrowser(browserSync = {}, webResults = []) {
    const tabs = webResults.slice(0, MAX_BROWSER_TABS).map((tab, index) => ({
        tabIndex: normalizeNumber(tab?.tabIndex) || index + 1,
        status: tab?.success ? 'ok' : tab?.skipped ? 'skipped' : 'failed',
        skipped: normalizeBoolean(tab?.skipped),
        attempts: normalizeNumber(tab?.attempts),
        reason: sanitizeStatus(tab?.reason || '', '', BROWSER_REASON_VALUES),
        error: tab?.success ? '' : redactSensitiveText(tab?.error || tab?.reason || 'Tab did not load.', 160)
    }))

    const succeeded = webResults.filter(tab => tab?.success === true).length
    const skipped = webResults.filter(tab => tab?.skipped).length
    const failed = webResults.filter(tab => tab?.success === false && !tab?.skipped).length
    const hasSync = browserSync?.copyInMs != null || browserSync?.copyOutMs != null || browserSync?.migrated === true
    const present = webResults.length > 0 || hasSync

    return {
        present,
        status: failed > 0 ? 'failed' : skipped > 0 ? 'warning' : present ? 'ok' : 'empty',
        tabCount: webResults.length,
        succeeded,
        failed,
        skipped,
        copyInMs: normalizeNumber(browserSync?.copyInMs),
        copyOutMs: normalizeNumber(browserSync?.copyOutMs),
        migrated: normalizeBoolean(browserSync?.migrated),
        tabs
    }
}

function summarizeCleanup(apps, browser) {
    const cleanupApps = apps.filter(app => app.role === 'cleanup' || app.closeMethod !== 'none' || app.cleanupSkippedForSafety || app.runtimeProfileWiped || app.runtimeProfileDeferred)
    const skippedForSafety = cleanupApps.filter(app => app.cleanupSkippedForSafety).length
    const runtimeProfilesWiped = cleanupApps.filter(app => app.runtimeProfileWiped).length
    const runtimeProfilesDeferred = cleanupApps.filter(app => app.runtimeProfileDeferred).length
    const present = cleanupApps.length > 0 || browser.copyOutMs != null

    return {
        present,
        copyOutMs: browser.copyOutMs,
        appsObserved: cleanupApps.length,
        skippedForSafety,
        runtimeProfilesWiped,
        runtimeProfilesDeferred
    }
}

function summarizeImports(apps, runtimeChecks = {}) {
    const hasImportSignal = (app) => app.runtimeProfileSynced ||
        app.importedDataSupported ||
        ['verified', 'best-effort', 'partial'].includes(app.importedDataSupportLevel) ||
        (app.archivePolicyStatus !== 'unknown' && app.archivePolicyStatus !== 'ok')
    const importedDataApps = apps.filter(hasImportSignal).length
    const unsupportedImportedData = apps.filter(app => hasImportSignal(app) && app.importedDataSupportLevel === 'unsupported').length
    const archiveWarnings = apps.filter(app => app.archivePolicyStatus !== 'unknown' && app.archivePolicyStatus !== 'ok').length
    const extractor = isPlainObject(runtimeChecks?.extractor)
        ? {
            checked: normalizeBoolean(runtimeChecks.extractor.checked),
            tarAvailable: runtimeChecks.extractor.tarAvailable === true,
            zstdSupported: runtimeChecks.extractor.zstdSupported === true,
            detail: redactSensitiveText(runtimeChecks.extractor.detail || '', 160)
        }
        : null

    return {
        present: importedDataApps > 0 || archiveWarnings > 0 || !!extractor?.checked,
        importedDataApps,
        unsupportedImportedData,
        archiveWarnings,
        extractor
    }
}

function phaseNamed(phases, name) {
    return phases.some(phase => phase.name === name)
}

function phaseFailed(phases, name) {
    return phases.some(phase => phase.name === name && isFailureStatus(phase.status))
}

function errorsForContext(errors, pattern) {
    return errors.some(error => pattern.test(String(error?.context || '')))
}

function syncBackStatusLabel(status) {
    if (status === 'completed') return 'Completed'
    if (status === 'failed') return 'Failed'
    if (status === 'deferred') return 'Deferred'
    if (status === 'blocked') return 'Blocked'
    if (status === 'running') return 'Running'
    if (status === 'started') return 'Started'
    if (status === 'not-run') return 'Not run'
    return 'Unknown'
}

function finalStateLabel(state) {
    if (state === 'synced') return 'Synced'
    if (state === 'cleanup-completed') return 'Cleanup completed'
    if (state === 'cleanup-deferred') return 'Cleanup deferred'
    if (state === 'cleanup-failed') return 'Cleanup failed'
    if (state === 'action-needed') return 'Action needed'
    return 'Unknown'
}

function lifecycleGuidance(finalState, {
    browserCopyInFailed = false,
    browserLaunchFailed = false,
    browserCopyOutFailed = false
} = {}) {
    if (browserCopyInFailed) {
        return 'Browser profile copy-in failed, so browser launch was blocked to protect the portable profile. Keep the drive connected, review diagnostics, and resolve the profile access issue before launching again.'
    }
    if (browserLaunchFailed) {
        return 'Browser launch failed from the managed profile. Sync-back was blocked to protect the portable profile; review diagnostics before launching again.'
    }
    if (browserCopyOutFailed) {
        return 'Browser profile sync-back needs attention. Keep the drive connected, close remaining browser windows, reopen Wipesnap, and review diagnostics before unplugging.'
    }
    if (finalState === 'synced') {
        return 'Last diagnostics show sync-back and cleanup completed.'
    }
    if (finalState === 'cleanup-completed') {
        return 'Cleanup completed. Review sync-back rows if you expected browser or app data to save.'
    }
    if (finalState === 'cleanup-deferred') {
        return 'Cleanup was deferred for safety. Close remaining launched apps, reopen Wipesnap, and review diagnostics before unplugging.'
    }
    if (finalState === 'cleanup-failed') {
        return 'Cleanup failed. Keep the drive connected, close remaining launched apps, reopen Wipesnap, and review diagnostics before unplugging.'
    }
    if (finalState === 'action-needed') {
        return 'Sync-back or cleanup needs attention. Keep the drive connected, reopen Wipesnap, and review diagnostics before unplugging.'
    }
    return 'Final sync-back and cleanup state is unknown. Do not treat the workspace as fully synced until diagnostics are reviewed.'
}

function summarizeBrowserSyncBack({ browser, phases, errors, quitRequested }) {
    if (browser.copyOutMs != null) {
        const failed = phaseFailed(phases, 'browser-copy-out') || errorsForContext(errors, /browser-copy-out/i)
        return {
            status: failed ? 'failed' : 'completed',
            statusLabel: syncBackStatusLabel(failed ? 'failed' : 'completed'),
            copyOutMs: browser.copyOutMs
        }
    }
    if (quitRequested && browser.present) {
        return {
            status: 'unknown',
            statusLabel: 'Unknown',
            copyOutMs: null
        }
    }
    return {
        status: 'not-run',
        statusLabel: 'Not run',
        copyOutMs: null
    }
}

function summarizeAppSessionSyncBack(apps) {
    const syncApps = apps.filter(app => app.runtimeProfileSynced || app.appSessionSyncBackStatus !== 'not-run')
    const failed = syncApps.filter(app => app.appSessionSyncBackStatus === 'failed').length
    const blocked = syncApps.filter(app => app.appSessionSyncBackStatus === 'blocked').length
    const deferred = syncApps.filter(app => app.appSessionSyncBackStatus === 'deferred').length
    const completed = syncApps.filter(app => app.appSessionSyncBackStatus === 'completed').length
    const running = syncApps.filter(app => app.appSessionSyncBackStatus === 'running').length
    const status = failed > 0
        ? 'failed'
        : blocked > 0
            ? 'blocked'
            : deferred > 0
                ? 'deferred'
                : running > 0
                    ? 'running'
                    : completed > 0
                        ? 'completed'
                        : syncApps.length > 0
                            ? 'unknown'
                            : 'not-run'

    return {
        status,
        statusLabel: syncBackStatusLabel(status),
        completed,
        failed,
        deferred,
        blocked
    }
}

function phaseRunning(phases, name) {
    return phases.some(phase => phase.name === name && phase.status === 'running')
}

function summarizeCleanupLifecycle(cleanup, phases) {
    const blocked = Number(cleanup.skippedForSafety || 0)
    const deferred = Number(cleanup.runtimeProfilesDeferred || 0)
    const failed = phaseFailed(phases, 'workspace-cleanup')
    const completed = !!cleanup.present && blocked === 0 && deferred === 0 && !failed
    const status = blocked > 0
        ? 'blocked'
        : failed
            ? 'failed'
            : deferred > 0
                ? 'deferred'
                : completed
                    ? 'completed'
                    : phaseRunning(phases, 'workspace-cleanup')
                        ? 'started'
                        : phaseNamed(phases, 'workspace-cleanup')
                            ? 'unknown'
                            : 'not-run'
    return {
        status: sanitizeStatus(status, 'unknown', CLEANUP_LIFECYCLE_STATUS_VALUES),
        statusLabel: syncBackStatusLabel(status),
        completed,
        deferred,
        blocked,
        failed: failed ? 1 : 0
    }
}

function deriveFinalState({ browserSyncBack, appSessionSyncBack, cleanup, launchActionNeeded = false }) {
    const syncFailed = browserSyncBack.status === 'failed' || appSessionSyncBack.status === 'failed'
    const syncNeedsAttention = [browserSyncBack.status, appSessionSyncBack.status].some(status =>
        ['unknown', 'running', 'deferred', 'blocked'].includes(status)
    )
    if (cleanup.status === 'failed') return 'cleanup-failed'
    if (launchActionNeeded) return 'action-needed'
    if (syncFailed || syncNeedsAttention || ['blocked', 'started'].includes(cleanup.status)) return 'action-needed'
    if (cleanup.status === 'deferred') return 'cleanup-deferred'
    if (cleanup.status === 'completed') {
        if (browserSyncBack.status === 'completed' || appSessionSyncBack.status === 'completed') return 'synced'
        return 'cleanup-completed'
    }
    return 'unknown'
}

function summarizeLifecycle({ selectedCycle, phases, apps, browser, cleanup, errors }) {
    const quitRequested = phaseNamed(phases, 'quit-requested') ||
        phaseNamed(phases, 'workspace-cleanup') ||
        phaseNamed(phases, 'browser-copy-out') ||
        cleanup.present
    const browserCopyInFailed = phaseFailed(phases, 'browser-copy-in') || errorsForContext(errors, /browser-copy-in/i)
    const browserLaunchFailed = phaseFailed(phases, 'browser-launch') || errorsForContext(errors, /browser-launch/i)
    const browserCopyOutFailed = phaseFailed(phases, 'browser-copy-out') || errorsForContext(errors, /browser-copy-out/i)
    const browserSyncBack = summarizeBrowserSyncBack({ browser, phases, errors, quitRequested })
    const appSessionSyncBack = summarizeAppSessionSyncBack(apps)
    const cleanupLifecycle = summarizeCleanupLifecycle(cleanup, phases)
    const finalState = sanitizeStatus(
        deriveFinalState({
            browserSyncBack,
            appSessionSyncBack,
            cleanup: cleanupLifecycle,
            launchActionNeeded: browserCopyInFailed || browserLaunchFailed
        }),
        'unknown',
        FINAL_STATE_VALUES
    )

    return {
        metadataOnly: true,
        launchStarted: phaseNamed(phases, 'launch-started') || !!selectedCycle?.cycleStartTime,
        workspaceRunning: phaseNamed(phases, 'workspace-running') ||
            browser.succeeded > 0 ||
            apps.some(app => app.status === 'ok'),
        quitRequested,
        browserSyncBack,
        appSessionSyncBack,
        cleanup: cleanupLifecycle,
        finalState,
        finalStateLabel: finalStateLabel(finalState),
        recoveryGuidance: lifecycleGuidance(finalState, {
            browserCopyInFailed,
            browserLaunchFailed,
            browserCopyOutFailed
        })
    }
}

function addLimited(target, item, limit) {
    if (target.length < limit) target.push(item)
}

function collectWarnings({ phases, apps, browser, cleanup, imports }) {
    const warnings = []

    for (const phase of phases) {
        if (isWarningStatus(phase.status)) {
            addLimited(warnings, {
                scope: 'phase',
                name: phase.name,
                message: phase.detail || `Phase status: ${phase.status}`
            }, MAX_WARNINGS)
        }
    }

    for (const app of apps) {
        if (app.cleanupSkippedForSafety || app.runtimeProfileDeferred || hasSummarizedAppWarning(app)) {
            addLimited(warnings, {
                scope: 'app',
                name: app.name,
                message: app.appSessionSyncBackStatus === 'deferred'
                    ? 'App session sync-back was deferred for safety.'
                    : app.appSessionSyncBackStatus === 'blocked'
                        ? 'App session sync-back was blocked for safety.'
                        : app.warning || app.cleanupSafetyReason || `App status: ${app.availabilityStatus || app.status}`
            }, MAX_WARNINGS)
        }
    }

    if (browser.skipped > 0) {
        addLimited(warnings, {
            scope: 'browser',
            name: 'Browser tabs',
            message: `${browser.skipped} tab${browser.skipped === 1 ? '' : 's'} skipped.`
        }, MAX_WARNINGS)
    }

    if (cleanup.skippedForSafety > 0 || cleanup.runtimeProfilesDeferred > 0) {
        addLimited(warnings, {
            scope: 'cleanup',
            name: 'Cleanup',
            message: `${cleanup.skippedForSafety + cleanup.runtimeProfilesDeferred} cleanup item${cleanup.skippedForSafety + cleanup.runtimeProfilesDeferred === 1 ? '' : 's'} deferred for safety.`
        }, MAX_WARNINGS)
    }

    if (imports.unsupportedImportedData > 0 || imports.archiveWarnings > 0) {
        addLimited(warnings, {
            scope: 'import',
            name: 'Imported apps',
            message: `${imports.unsupportedImportedData + imports.archiveWarnings} imported app item${imports.unsupportedImportedData + imports.archiveWarnings === 1 ? '' : 's'} need attention.`
        }, MAX_WARNINGS)
    }

    return warnings
}

function hasSummarizedAppWarning(app) {
    return ['failed', 'deferred', 'blocked'].includes(app.appSessionSyncBackStatus) ||
        isWarningStatus(app.availabilityStatus) ||
        isWarningStatus(app.supportTier) ||
        isWarningStatus(app.archivePolicyStatus) ||
        isWarningStatus(app.readinessStatus)
}

function collectFailures({ phases, apps, browser, errors }) {
    const failures = []

    for (const phase of phases) {
        if (isFailureStatus(phase.status)) {
            addLimited(failures, {
                scope: 'phase',
                name: phase.name,
                message: phase.detail || `Phase failed with status ${phase.status}.`
            }, MAX_FAILURES)
        }
    }

    for (const app of apps) {
        if (isFailureStatus(app.status)) {
            addLimited(failures, {
                scope: 'app',
                name: app.name,
                message: app.error || `App failed during ${app.stage}.`
            }, MAX_FAILURES)
        }
        if (app.appSessionSyncBackStatus === 'failed') {
            addLimited(failures, {
                scope: 'sync-back',
                name: app.name,
                message: app.appSessionSyncBackError || 'App session sync-back failed.'
            }, MAX_FAILURES)
        }
    }

    if (browser.failed > 0) {
        addLimited(failures, {
            scope: 'browser',
            name: 'Browser tabs',
            message: `${browser.failed} tab${browser.failed === 1 ? '' : 's'} failed to load.`
        }, MAX_FAILURES)
    }

    for (const error of errors.slice(0, MAX_FAILURES)) {
        addLimited(failures, {
            scope: 'diagnostics',
            name: sanitizeLabel(error?.context || 'Runtime error'),
            message: redactSensitiveText(error?.message || 'Runtime diagnostic error.', 180)
        }, MAX_FAILURES)
    }

    return failures
}

function summarizeErrors(errors = []) {
    return errors.map(error => ({
        context: sanitizeLabel(error?.context || 'Runtime error'),
        message: redactSensitiveText(error?.message || 'Runtime diagnostic error.', 180)
    }))
}

function computeSummaryStatus({ browser, phases, apps, failures, warnings }) {
    if (failures.length > 0 || browser.status === 'failed') return 'failed'
    if (warnings.length > 0 || phases.some(phase => isWarningStatus(phase.status)) || apps.some(app => hasSummarizedAppWarning(app))) return 'warning'
    if (phases.length || apps.length || browser.present) return 'ok'
    return 'empty'
}

function buildSummary(raw, sizeBytes) {
    const cycles = collectCycles(raw)
    if (cycles.length === 0) return createEmptySummary('empty', { available: true, sizeBytes })

    const lastRunCycle = cycles[cycles.length - 1]
    const lastLaunchCycle = [...cycles].reverse().find(cycle => sanitizeStatus(cycle.cycleType, 'run', CYCLE_TYPE_VALUES) === 'launch') || null
    const selectedCycle = lastLaunchCycle || lastRunCycle

    const phases = summarizePhases(selectedCycle.phases || [])
    const apps = summarizeApps(selectedCycle.appResults || [])
    const browser = summarizeBrowser(selectedCycle.browserSync || {}, selectedCycle.webResults || [])
    const cleanup = summarizeCleanup(apps, browser)
    const imports = summarizeImports(apps, selectedCycle.runtimeChecks || {})
    const diagnosticErrors = summarizeErrors(selectedCycle.errors || [])
    const warnings = collectWarnings({ phases, apps, browser, cleanup, imports })
    const failures = collectFailures({ phases, apps, browser, errors: diagnosticErrors })
    const status = computeSummaryStatus({ browser, phases, apps, failures, warnings })
    const lifecycle = summarizeLifecycle({
        selectedCycle,
        phases,
        apps,
        browser,
        cleanup,
        errors: diagnosticErrors
    })

    return {
        success: true,
        available: true,
        state: 'ready',
        status,
        message: status === 'ok'
            ? 'Last diagnostics look healthy.'
            : status === 'warning'
                ? 'Last diagnostics include warnings.'
                : status === 'failed'
                    ? 'Last diagnostics include failures.'
                    : 'Diagnostics did not contain a recorded run.',
        sizeBytes,
        counts: {
            apps: apps.length,
            appFailures: apps.filter(app => isFailureStatus(app.status)).length,
            warnings: warnings.length,
            failures: failures.length,
            browserTabs: browser.tabCount,
            browserFailures: browser.failed
        },
        lastRun: summarizeCycleMeta(lastRunCycle),
        lastLaunch: lastLaunchCycle ? summarizeCycleMeta(lastLaunchCycle) : null,
        browser,
        cleanup,
        lifecycle,
        imports,
        phases,
        apps,
        warnings,
        failures
    }
}

export function loadDiagnosticsSummary({ vaultDir, maxBytes = MAX_DIAGNOSTICS_BYTES, fsApi = null } = {}) {
    const fs = fsApi || { existsSync, statSync, readFileSync }
    if (!vaultDir || typeof vaultDir !== 'string') {
        return createFailureSummary('unavailable', 'Diagnostics location is unavailable.')
    }

    const diagnosticsPath = join(vaultDir, DIAGNOSTICS_FILE_NAME)
    try {
        if (!fs.existsSync(diagnosticsPath)) return createEmptySummary('missing')

        const stat = fs.statSync(diagnosticsPath)
        if (!stat?.isFile?.()) {
            return createFailureSummary('malformed', 'Diagnostics are not readable.')
        }
        if (stat.size > maxBytes) {
            return createFailureSummary('oversized', 'Diagnostics are too large to display safely.', {
                sizeBytes: stat.size,
                maxBytes
            })
        }

        const rawText = fs.readFileSync(diagnosticsPath, 'utf-8')
        const parsed = JSON.parse(rawText)
        if (!validateDiagnosticsShape(parsed)) {
            return createFailureSummary('malformed', 'Diagnostics are malformed.')
        }

        return buildSummary(parsed, stat.size)
    } catch (_) {
        return createFailureSummary('malformed', 'Diagnostics could not be parsed safely.')
    }
}

export function loadDiagnosticsSummaryHandlerCore({ input, deps }) {
    try {
        deps.requireActiveSession()
        if (input !== undefined) {
            return createFailureSummary('invalid-request', 'Diagnostics summary does not accept renderer input.')
        }
        return loadDiagnosticsSummary({ vaultDir: deps.getVaultDir() })
    } catch (err) {
        return createFailureSummary('locked', err?.message || 'Session is locked.')
    }
}

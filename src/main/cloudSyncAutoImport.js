import { applyTrustedPatchesInvocationHandlerCore } from './cloudSyncInvocation.js'

export const CLOUD_SYNC_AUTO_IMPORT_OPERATION = 'auto-import-trusted-patches'

const FORBIDDEN_STATUS_TEXT = /deviceSessionToken|bearer\s+|syncRootKey|rootKeyMaterial|privateKey|vault\.json|vault\.meta\.json|vault\.state\.json|BrowserProfile|AppData[\\/]|cap_[A-Za-z0-9_-]{4,128}|[A-Za-z]:[\\/]|\\\\|HKEY_|HKLM|HKCU|powershell|taskkill|cmd\s|ciphertext|cloudEnvelope|encryptedEnvelope|importPlan|patchPayload|vaultData|devicePrivateKey|credential|browserSession|launchAuthority|firebase[-_\s]*(api[-_\s]*)?key|firebaseSecret|stack trace|\bat\s+.*:\d+:\d+/i
const SAFE_TOKEN_PATTERN = /^[a-z][a-z0-9-]{0,80}$/
const AUTO_IMPORT_STATUS_CATEGORIES = new Set([
    'idle',
    'scheduled',
    'running',
    'not-configured',
    'unavailable-runtime',
    'locked',
    'no-patches',
    'applied',
    'conflict',
    'skipped',
    'revoked-device',
    'invalid-signature',
    'invalid-key',
    'invalid-patch',
    'stale-base',
    'transaction-failure',
    'unknown-error'
])

const AUTO_IMPORT_DIAGNOSTIC_MESSAGES = {
    idle: 'Trusted auto-import has not run in this session.',
    scheduled: 'Trusted auto-import is scheduled after unlock.',
    running: 'Trusted auto-import is checking trusted patch metadata.',
    'not-configured': 'Cloud sync is not configured on this desktop.',
    'unavailable-runtime': 'Cloud sync runtime is unavailable on this desktop.',
    locked: 'Trusted auto-import requires an unlocked vault session.',
    'no-patches': 'No trusted patches were available to import.',
    applied: 'Trusted preset metadata patches were applied.',
    conflict: 'Trusted auto-import found a metadata conflict.',
    skipped: 'Trusted auto-import skipped one or more patches.',
    'revoked-device': 'A patch was skipped because its author device is revoked.',
    'invalid-signature': 'A patch was skipped because its signature was invalid.',
    'invalid-key': 'A patch was skipped because its key version or decryption check failed.',
    'invalid-patch': 'A patch was skipped because its schema or safe metadata was invalid.',
    'stale-base': 'A patch was not applied because it was based on stale desktop metadata.',
    'transaction-failure': 'Trusted auto-import could not finish the vault transaction.',
    'unknown-error': 'Trusted auto-import stopped with a sanitized error.'
}

const AUTO_IMPORT_RECOVERY_HINTS = {
    'not-configured': 'Configure cloud sync, then run manual cloud sync.',
    'unavailable-runtime': 'Run manual cloud sync after cloud sync is available.',
    locked: 'Unlock the vault, then run manual cloud sync.',
    'no-patches': 'Run manual cloud sync if you expected phone changes.',
    conflict: 'Review conflicts before applying phone changes.',
    skipped: 'Run manual cloud sync to review skipped patch status.',
    'revoked-device': 'Review trusted devices before syncing again.',
    'invalid-signature': 'Run manual cloud sync from a trusted device.',
    'invalid-key': 'Review device keys, then run manual cloud sync.',
    'invalid-patch': 'Review the phone changes, then run manual cloud sync.',
    'stale-base': 'Review conflicts before applying phone changes.',
    'transaction-failure': 'Check vault health, then run manual cloud sync.',
    'unknown-error': 'Run manual cloud sync to retry safely.'
}

const RECORD_CATEGORY_PRIORITY = [
    'transaction-failure',
    'revoked-device',
    'invalid-signature',
    'invalid-key',
    'invalid-patch',
    'stale-base',
    'conflict',
    'applied',
    'skipped'
]

function fail(message) {
    throw new Error(message)
}

function isPlainObject(value) {
    return !!value && typeof value === 'object' && !Array.isArray(value)
}

function clone(value) {
    return value == null ? value : JSON.parse(JSON.stringify(value))
}

function safeCount(value) {
    return Number.isSafeInteger(value) && value >= 0 ? value : 0
}

function safeToken(value, fallback = 'unknown') {
    if (typeof value !== 'string') return fallback
    const token = value.trim().toLowerCase()
    if (!token || token.length > 80 || FORBIDDEN_STATUS_TEXT.test(token)) return fallback
    return SAFE_TOKEN_PATTERN.test(token) ? token : fallback
}

function safeStatusCategory(value, fallback = 'unknown-error') {
    const category = safeToken(value, fallback)
    return AUTO_IMPORT_STATUS_CATEGORIES.has(category) ? category : fallback
}

function safeKnownText(value, fallback = '') {
    if (typeof value !== 'string') return fallback
    return FORBIDDEN_STATUS_TEXT.test(value) ? fallback : value
}

function isNotConfiguredErrorText(text) {
    return /not configured|not set up|not enrolled|configure cloud sync|runtime is not configured/i.test(text || '')
}

function sideEffectsNone(extra = {}) {
    return {
        writesVault: false,
        writesCapabilityVault: false,
        createsCapability: false,
        createsAccountSlots: false,
        createsBrowserProfiles: false,
        launches: false,
        writesCloudSnapshot: false,
        writesCloudPatchStatus: false,
        mergesPatch: false,
        ...extra
    }
}

function sanitizeSideEffects(sideEffects) {
    const value = isPlainObject(sideEffects) ? sideEffects : {}
    return sideEffectsNone({
        writesVault: value.writesVault === true,
        writesCapabilityVault: value.writesCapabilityVault === true,
        createsCapability: value.createsCapability === true,
        createsAccountSlots: value.createsAccountSlots === true,
        createsBrowserProfiles: value.createsBrowserProfiles === true,
        launches: value.launches === true,
        writesCloudSnapshot: value.writesCloudSnapshot === true,
        writesCloudPatchStatus: value.writesCloudPatchStatus === true,
        mergesPatch: value.mergesPatch === true
    })
}

function zeroSummary(extra = {}) {
    return {
        uploaded: 0,
        downloaded: 0,
        planned: 0,
        applied: 0,
        conflicts: 0,
        skipped: 0,
        ...extra
    }
}

function sanitizeSummary(summary) {
    const value = isPlainObject(summary) ? summary : {}
    return zeroSummary({
        uploaded: safeCount(value.uploaded),
        downloaded: safeCount(value.downloaded),
        planned: safeCount(value.planned),
        applied: safeCount(value.applied),
        conflicts: safeCount(value.conflicts),
        skipped: safeCount(value.skipped)
    })
}

function sanitizeCloudStatus(cloudStatus) {
    if (!isPlainObject(cloudStatus)) return null
    return {
        status: safeToken(cloudStatus.status),
        reason: safeToken(cloudStatus.reason || '', ''),
        metadataOnly: true
    }
}

function categorizeRecord(record) {
    const status = safeToken(record?.status, 'skipped')
    const reason = safeToken(record?.reason || record?.code || '', '')
    if (reason === 'revoked-device') return 'revoked-device'
    if (reason === 'invalid-signature') return 'invalid-signature'
    if (reason === 'invalid-key') return 'invalid-key'
    if (reason === 'stale-base') return 'stale-base'
    if (reason === 'transaction-failure') return 'transaction-failure'
    if (['schema-rejected', 'invalid-envelope', 'forbidden-material'].includes(reason)) return 'invalid-patch'
    if (status === 'conflict') return 'conflict'
    if (status === 'applied') return 'applied'
    if (status === 'skipped' || status === 'already-decided') return 'skipped'
    return 'skipped'
}

function sanitizeRecord(record) {
    const value = isPlainObject(record) ? record : {}
    const sanitized = {
        status: safeToken(value.status, 'skipped'),
        code: safeToken(value.code || '', ''),
        reason: safeToken(value.reason || value.code || '', ''),
        mergeStatus: safeToken(value.mergeStatus || '', ''),
        metadataOnly: true,
        cloudStatus: sanitizeCloudStatus(value.cloudStatus),
        sideEffects: sanitizeSideEffects(value.sideEffects)
    }
    return {
        ...sanitized,
        category: categorizeRecord(sanitized)
    }
}

function autoImportFlags({ scheduled = false, running = false, attempted = false } = {}) {
    return {
        scheduled: scheduled === true,
        running: running === true,
        attempted: attempted === true,
        metadataOnly: true
    }
}

function uniqueTokens(tokens) {
    return Array.from(new Set(tokens.map(token => safeToken(token, '')).filter(Boolean))).slice(0, 12)
}

function deriveStatusCategory(status) {
    const safeStatus = safeToken(status.status, 'idle')
    if (['idle', 'scheduled', 'running', 'locked'].includes(safeStatus)) return safeStatus
    if (safeStatus === 'unavailable') return status.categoryHint || 'unavailable-runtime'
    if (status.categoryHint) return status.categoryHint

    const recordCategories = uniqueTokens(status.records.map(record => record.category || categorizeRecord(record)))
    for (const category of RECORD_CATEGORY_PRIORITY) {
        if (recordCategories.includes(category)) return category
    }

    const totalRecords = safeCount(status.records.length)
    const totalDecisions = status.summary.applied + status.summary.conflicts + status.summary.skipped
    if (safeStatus === 'completed' && totalRecords === 0 && totalDecisions === 0) return 'no-patches'
    if (status.summary.applied > 0) return 'applied'
    if (status.summary.conflicts > 0) return 'conflict'
    if (status.summary.skipped > 0 || totalRecords > 0) return 'skipped'
    if (safeStatus === 'rejected') return 'unknown-error'
    return safeStatus === 'completed' ? 'no-patches' : 'unknown-error'
}

function createDiagnostics(status) {
    const category = safeStatusCategory(status.statusCategory)
    return {
        category,
        summary: safeKnownText(AUTO_IMPORT_DIAGNOSTIC_MESSAGES[category], AUTO_IMPORT_DIAGNOSTIC_MESSAGES['unknown-error']),
        recordCount: safeCount(status.records.length),
        recordCategories: uniqueTokens(status.records.map(record => record.category || categorizeRecord(record))),
        metadataOnly: true
    }
}

function createManualRecovery(statusCategory) {
    const category = safeStatusCategory(statusCategory)
    return {
        hint: safeKnownText(AUTO_IMPORT_RECOVERY_HINTS[category] || '', ''),
        automatic: false,
        metadataOnly: true
    }
}

function baseStatus({ success = false, status, summary, records, sideEffects, autoImport, statusCategory } = {}) {
    const sanitized = {
        success,
        operation: CLOUD_SYNC_AUTO_IMPORT_OPERATION,
        status: safeToken(status, 'idle'),
        metadataOnly: true,
        autoImport: autoImportFlags(autoImport),
        summary: sanitizeSummary(summary),
        records: Array.isArray(records) ? records.slice(0, 20).map(sanitizeRecord) : [],
        sideEffects: sanitizeSideEffects(sideEffects)
    }
    sanitized.statusCategory = safeStatusCategory(deriveStatusCategory({
        ...sanitized,
        categoryHint: statusCategory ? safeStatusCategory(statusCategory) : ''
    }))
    sanitized.diagnostics = createDiagnostics(sanitized)
    sanitized.manualRecovery = createManualRecovery(sanitized.statusCategory)
    return sanitized
}

function isLockedError(error) {
    return /session is locked|vault is locked|locked vault|unlock required|after vault unlock|active vault session|unlock/i
        .test(error?.message || '')
}

function isRuntimeUnavailableError(error) {
    return /cloud sync (invocation|transport).*requires|requires (unlocked desktop cloud sync storage|desktop cloud sync storage|a Functions client|a Firestore client|a current sanitized snapshot builder)|cannot (call|read|list) cloud sync|runtime is not configured/i
        .test(error?.message || '')
}

function categoryForError(error, status) {
    if (status === 'locked') return 'locked'
    if (status === 'unavailable') {
        return isNotConfiguredErrorText(error?.message || '') ? 'not-configured' : 'unavailable-runtime'
    }
    if (/transaction|commitvaultmeta|commit vault/i.test(error?.message || '')) return 'transaction-failure'
    return 'unknown-error'
}

function categoryForResult(value, status) {
    if (status === 'unavailable') {
        return isNotConfiguredErrorText(value.error || '') ? 'not-configured' : 'unavailable-runtime'
    }
    if (status === 'locked') return 'locked'
    if (status === 'rejected' && /transaction|commitvaultmeta|commit vault/i.test(value.error || '')) return 'transaction-failure'
    return ''
}

function safeLogCategory(error, status = '') {
    return safeKnownText(categoryForError(error, status || (isLockedError(error) ? 'locked' : isRuntimeUnavailableError(error) ? 'unavailable' : 'rejected')), 'unknown-error')
}

export function createTrustedAutoImportIdleStatus() {
    return baseStatus({
        status: 'idle',
        summary: zeroSummary(),
        records: [],
        sideEffects: sideEffectsNone(),
        autoImport: { scheduled: false, running: false, attempted: false }
    })
}

export function createTrustedAutoImportScheduledStatus({ running = false } = {}) {
    return baseStatus({
        status: running ? 'running' : 'scheduled',
        summary: zeroSummary(),
        records: [],
        sideEffects: sideEffectsNone(),
        autoImport: { scheduled: true, running, attempted: false }
    })
}

export function sanitizeTrustedAutoImportResult(result) {
    const value = isPlainObject(result) ? result : {}
    const status = safeToken(value.status, value.success === false ? 'rejected' : 'completed')
    return baseStatus({
        success: value.success === false ? false : status === 'completed',
        status,
        summary: sanitizeSummary(value.summary),
        records: value.records,
        sideEffects: value.sideEffects,
        autoImport: { scheduled: false, running: false, attempted: true },
        statusCategory: categoryForResult(value, status)
    })
}

export function sanitizeTrustedAutoImportError(error) {
    const status = isLockedError(error)
        ? 'locked'
        : isRuntimeUnavailableError(error)
            ? 'unavailable'
            : 'rejected'
    return baseStatus({
        success: false,
        status,
        summary: zeroSummary(),
        records: [],
        sideEffects: sideEffectsNone(),
        autoImport: { scheduled: false, running: false, attempted: true },
        statusCategory: categoryForError(error, status)
    })
}

export function cloudSyncAutoImportStatusContainsForbiddenMaterial(value) {
    const forbiddenKeys = new Set([
        'patchRevisionId',
        'patchId',
        'authorDeviceId',
        'baseSnapshotRevisionId',
        'currentSnapshotRevisionId',
        'ciphertext',
        'envelope',
        'payload',
        'cloudEnvelope',
        'encryptedEnvelope',
        'importPlan',
        'patchPayload',
        'stack',
        'vaultPath',
        'vaultData',
        'capabilityId',
        'capabilityRecord',
        'capabilityRecords',
        'token',
        'apiKey',
        'firebaseSecret',
        'syncRootKey',
        'rootKeyMaterial',
        'privateKey',
        'signingPrivateKey',
        'devicePrivateKey',
        'credential',
        'credentials',
        'bearer',
        'tokens',
        'browserSession',
        'launchAuthority'
    ])
    const scan = (candidate) => {
        if (Array.isArray(candidate)) return candidate.some(scan)
        if (isPlainObject(candidate)) {
            return Object.entries(candidate).some(([key, nested]) =>
                forbiddenKeys.has(key) || scan(nested)
            )
        }
        return typeof candidate === 'string' && FORBIDDEN_STATUS_TEXT.test(candidate)
    }
    return scan(value)
}

export function createTrustedAutoImportOrchestrator({
    resolveDeps,
    applyHandler = applyTrustedPatchesInvocationHandlerCore,
    schedule = (callback) => setTimeout(callback, 0),
    onStatus = () => {},
    logger = null
} = {}) {
    if (typeof resolveDeps !== 'function') fail('Trusted auto-import requires dependency resolver.')
    if (typeof applyHandler !== 'function') fail('Trusted auto-import requires an apply handler.')
    if (typeof schedule !== 'function') fail('Trusted auto-import requires a scheduler.')

    let sessionWindowId = 0
    let running = false
    let lastStatus = createTrustedAutoImportIdleStatus()
    const attemptedSessionIds = new Set()
    const queuedSessionIds = []

    const emit = (status) => {
        lastStatus = clone(status)
        try {
            onStatus(clone(lastStatus))
        } catch (error) {
            if (logger?.warn) logger.warn('[Wipesnap] trusted auto-import status emit failed.')
        }
        return clone(lastStatus)
    }

    const runQueued = () => {
        const nextSessionId = queuedSessionIds.find(id => !attemptedSessionIds.has(id))
        if (!nextSessionId) return
        const remaining = queuedSessionIds.filter(id => id !== nextSessionId)
        queuedSessionIds.length = 0
        queuedSessionIds.push(...remaining)
        scheduleRun(nextSessionId)
    }

    const runForSession = async (sessionId) => {
        if (!Number.isSafeInteger(sessionId) || sessionId < 1) {
            return emit(sanitizeTrustedAutoImportError(new Error('Session is locked')))
        }
        if (attemptedSessionIds.has(sessionId)) return clone(lastStatus)
        if (running) {
            if (!queuedSessionIds.includes(sessionId)) queuedSessionIds.push(sessionId)
            return clone(lastStatus)
        }

        attemptedSessionIds.add(sessionId)
        running = true
        emit(baseStatus({
            status: 'running',
            summary: zeroSummary(),
            records: [],
            sideEffects: sideEffectsNone(),
            autoImport: { scheduled: true, running: true, attempted: true }
        }))

        try {
            const result = await applyHandler({
                input: {},
                deps: resolveDeps()
            })
            return emit(sanitizeTrustedAutoImportResult(result))
        } catch (error) {
            if (logger?.warn) logger.warn('[Wipesnap] trusted auto-import failed:', safeLogCategory(error))
            return emit(sanitizeTrustedAutoImportError(error))
        } finally {
            running = false
            runQueued()
        }
    }

    function scheduleRun(sessionId) {
        try {
            schedule(() => {
                Promise.resolve(runForSession(sessionId)).catch(error => {
                    emit(sanitizeTrustedAutoImportError(error))
                })
            })
        } catch (error) {
            Promise.resolve(runForSession(sessionId)).catch(runError => {
                emit(sanitizeTrustedAutoImportError(runError))
            })
        }
    }

    function beginUnlockSession() {
        sessionWindowId += 1
        return sessionWindowId
    }

    return {
        scheduleAfterUnlock() {
            const sessionId = beginUnlockSession()
            emit(createTrustedAutoImportScheduledStatus({ running }))
            scheduleRun(sessionId)
            return clone(lastStatus)
        },
        runAfterUnlock() {
            const sessionId = beginUnlockSession()
            emit(createTrustedAutoImportScheduledStatus({ running }))
            return runForSession(sessionId)
        },
        markLocked() {
            queuedSessionIds.length = 0
            return emit(baseStatus({
                success: false,
                status: 'locked',
                summary: zeroSummary(),
                records: [],
                sideEffects: sideEffectsNone(),
                autoImport: { scheduled: false, running, attempted: false }
            }))
        },
        getStatus() {
            return clone(lastStatus)
        }
    }
}

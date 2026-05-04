import crypto from 'crypto'
import { lstatSync, existsSync, readdirSync, realpathSync, statSync } from 'fs'
import { readdir, stat } from 'fs/promises'
import { basename, join, resolve, sep } from 'path'
import {
    repairLegacyAppConfig,
    resolveImportedAppDataCapability,
    safeAppName
} from './appManifest.js'

const IMPORTED_DATA_ACTIVE_MODES = new Set([
    'chromium-user-data',
    'vscode-user-data',
    'electron-user-data'
])
const MAX_RENDERER_TEXT_LENGTH = 160
const CLEANUP_RESULT_STATUS_VALUES = new Set(['removed', 'failed', 'blocked'])
const CLEANUP_RESULT_REASON_CODE_VALUES = new Set([
    'removed',
    'cleanup-blocked',
    'cleanup-failed',
    'cleanup-request-invalid'
])

async function getDirSizeAsync(dirPath, skipDirs = new Set()) {
    let total = 0
    try {
        const entries = await readdir(dirPath, { withFileTypes: true })
        const tasks = entries.map(async (entry) => {
            if (entry.isDirectory()) {
                if (skipDirs.has(entry.name)) return 0
                return getDirSizeAsync(join(dirPath, entry.name), skipDirs)
            }
            try { return (await stat(join(dirPath, entry.name))).size } catch (_) { return 0 }
        })
        const sizes = await Promise.all(tasks)
        total = sizes.reduce((acc, value) => acc + value, 0)
    } catch (_) { }
    return total
}

export function isPathInside(parentPath, childPath) {
    const parent = resolve(parentPath).toLowerCase()
    const child = resolve(childPath).toLowerCase()
    const parentWithSep = parent.endsWith(sep) ? parent : `${parent}${sep}`
    return child === parent || child.startsWith(parentWithSep)
}

function safeRealpath(targetPath) {
    try {
        return realpathSync.native(targetPath)
    } catch (_) {
        try { return realpathSync(targetPath) } catch (_) { return null }
    }
}

function isPlainObject(value) {
    return !!value && typeof value === 'object' && !Array.isArray(value)
}

function limitRendererText(value, maxLength = MAX_RENDERER_TEXT_LENGTH) {
    const text = String(value ?? '').replace(/[\r\n\t]+/g, ' ').replace(/\s{2,}/g, ' ').trim()
    if (text.length <= maxLength) return text
    return `${text.slice(0, Math.max(0, maxLength - 1)).trim()}...`
}

function redactRendererText(value, maxLength = MAX_RENDERER_TEXT_LENGTH) {
    let text = limitRendererText(value, maxLength * 2)
    if (!text) return ''

    text = text
        .replace(/file:\/\/\/[^\s"')]+/gi, '[redacted-path]')
        .replace(/\\\\[^\s"')]+/g, '[redacted-path]')
        .replace(/[a-zA-Z]:\\[^\r\n"']+/g, '[redacted-path]')
        .replace(/\b(password|pin|token|secret|cookie|credential|auth|key|fastboot)([\w.-]{0,24})\s*[:=]\s*[^,;\s]+/gi, '$1$2=[redacted]')
        .replace(/\b[A-Fa-f0-9]{32,}\b/g, '[redacted-token]')
        .replace(/\b[A-Za-z0-9+/]{40,}={0,2}\b/g, '[redacted-token]')

    return limitRendererText(text, maxLength)
}

function normalizeCleanupResultStatus(value, fallback = 'failed') {
    const status = String(value || '').toLowerCase()
    return CLEANUP_RESULT_STATUS_VALUES.has(status) ? status : fallback
}

function normalizeCleanupReasonCode(value, fallback = 'cleanup-failed') {
    const reasonCode = String(value || '').toLowerCase()
    return CLEANUP_RESULT_REASON_CODE_VALUES.has(reasonCode) ? reasonCode : fallback
}

export function isSafePayloadDirectory(appDataRoot, payloadPath) {
    if (!isPathInside(appDataRoot, payloadPath)) {
        return { safe: false, reason: 'Path is outside the vault AppData directory.' }
    }

    let linkStats = null
    try {
        linkStats = lstatSync(payloadPath)
    } catch (err) {
        return { safe: false, reason: `Could not inspect payload path: ${err.message}` }
    }

    if (linkStats.isSymbolicLink()) {
        return { safe: false, reason: 'Refused to remove symbolic-link or junction AppData payload.' }
    }

    if (!linkStats.isDirectory()) {
        return { safe: false, reason: 'Refused to remove a non-directory AppData payload.' }
    }

    const realRoot = safeRealpath(appDataRoot)
    const realPayload = safeRealpath(payloadPath)
    if (!realRoot || !realPayload) {
        return { safe: false, reason: 'Could not resolve real filesystem path before cleanup.' }
    }

    if (!isPathInside(realRoot, realPayload)) {
        return { safe: false, reason: 'Resolved payload path escapes the vault AppData directory.' }
    }

    return { safe: true, realRoot, realPayload }
}

export function getAppDataPayloadCandidates(appName, vaultDir) {
    const name = String(appName || '').trim()
    const safeName = safeAppName(name)
    if (!safeName) return []

    const appDataRoot = join(vaultDir, 'AppData')
    const candidates = [join(appDataRoot, safeName)]
    if (name && name !== safeName) {
        candidates.push(join(appDataRoot, name))
    }

    return [...new Set(candidates)].filter(candidate => isPathInside(appDataRoot, candidate))
}

function hasActiveImportedAppData(appConfig, manifest) {
    if (appConfig?.portableData === true) return true
    if (appConfig?.portableData === false) return false

    const dataMode = String(appConfig?.dataProfile?.mode || manifest?.dataProfile?.mode || 'none').toLowerCase()
    return IMPORTED_DATA_ACTIVE_MODES.has(dataMode)
}

function getPayloadId(payloadPath) {
    return crypto.createHash('sha256').update(resolve(payloadPath).toLowerCase()).digest('hex').slice(0, 16)
}

export async function findStaleUnsupportedAppDataPayloads(workspace, vaultDir, options = {}) {
    const {
        persistLegacyRepairs = false,
        onError = null
    } = options
    const appDataRoot = join(vaultDir, 'AppData')
    if (!existsSync(appDataRoot)) return []

    const desktopApps = Array.isArray(workspace?.desktopApps) ? workspace.desktopApps : []
    const payloads = []
    const seen = new Set()
    const referencedPayloadPaths = new Set()

    for (const desktopApp of desktopApps) {
        let repaired = null
        try {
            repaired = repairLegacyAppConfig(desktopApp, vaultDir, { persist: persistLegacyRepairs })
        } catch (err) {
            if (typeof onError === 'function') {
                onError(desktopApp, err)
            }
            continue
        }

        const appConfig = repaired?.appConfig || desktopApp || {}
        const manifest = repaired?.manifest || appConfig.manifest || {}
        const capability = resolveImportedAppDataCapability({
            appType: manifest.appType,
            appName: appConfig.name || manifest.displayName || manifest.safeName,
            launchProfile: appConfig.launchProfile || manifest.launchProfile,
            dataProfile: appConfig.dataProfile || manifest.dataProfile
        })

        const displayName = appConfig.name || manifest.displayName || manifest.safeName
        const candidatePaths = getAppDataPayloadCandidates(displayName, vaultDir)
        if (hasActiveImportedAppData(appConfig, manifest)) {
            for (const candidatePath of candidatePaths) {
                referencedPayloadPaths.add(resolve(candidatePath).toLowerCase())
            }
        }

        if (capability.importedDataSupported) continue

        for (const payloadPath of candidatePaths) {
            if (!existsSync(payloadPath)) continue
            if (!isPathInside(appDataRoot, payloadPath)) continue

            let stats = null
            try { stats = statSync(payloadPath) } catch (_) { }
            if (!stats?.isDirectory?.()) continue

            const id = getPayloadId(payloadPath)
            if (seen.has(id)) continue
            seen.add(id)

            const safety = isSafePayloadDirectory(appDataRoot, payloadPath)
            const sizeBytes = safety.safe ? await getDirSizeAsync(payloadPath) : 0
            payloads.push({
                id,
                name: displayName || basename(payloadPath),
                safeName: safeAppName(displayName),
                path: payloadPath,
                sizeBytes,
                sizeMB: sizeBytes > 0 ? Math.max(1, Math.round(sizeBytes / (1024 * 1024))) : 0,
                cleanupBlocked: !safety.safe,
                cleanupBlockedReason: safety.safe ? null : safety.reason,
                reason: capability.importedDataSupportReason || 'This app profile does not have a verified imported AppData adapter.'
            })
        }
    }

    try {
        const entries = readdirSync(appDataRoot, { withFileTypes: true })
        for (const entry of entries) {
            if (!entry.isDirectory() && !entry.isSymbolicLink()) continue

            const payloadPath = join(appDataRoot, entry.name)
            if (!isPathInside(appDataRoot, payloadPath)) continue
            if (referencedPayloadPaths.has(resolve(payloadPath).toLowerCase())) continue

            const id = getPayloadId(payloadPath)
            if (seen.has(id)) continue
            seen.add(id)

            const safety = isSafePayloadDirectory(appDataRoot, payloadPath)
            const sizeBytes = safety.safe ? await getDirSizeAsync(payloadPath) : 0
            payloads.push({
                id,
                name: entry.name,
                safeName: entry.name,
                path: payloadPath,
                sizeBytes,
                sizeMB: sizeBytes > 0 ? Math.max(1, Math.round(sizeBytes / (1024 * 1024))) : 0,
                orphaned: true,
                cleanupBlocked: !safety.safe,
                cleanupBlockedReason: safety.safe ? null : safety.reason,
                reason: 'No saved desktop app currently references this imported AppData payload.'
            })
        }
    } catch (err) {
        if (typeof onError === 'function') {
            onError({ name: 'orphan scan' }, err)
        }
    }

    return payloads
}

export function selectStaleAppDataPayloads(payloadIds, payloads) {
    if (!Array.isArray(payloadIds) || payloadIds.length === 0) {
        throw new Error('Select at least one AppData payload to remove.')
    }

    const allowedIds = new Set(payloadIds.map(id => String(id || '').trim()).filter(Boolean))
    if (allowedIds.size === 0) {
        throw new Error('Select at least one valid AppData payload to remove.')
    }

    const selectedPayloads = payloads.filter(payload => allowedIds.has(payload.id))
    if (selectedPayloads.length === 0) {
        throw new Error('Selected AppData payloads are no longer stale in the saved workspace.')
    }
    if (selectedPayloads.length !== allowedIds.size) {
        throw new Error('One or more selected AppData payloads are no longer stale in the saved workspace.')
    }

    return selectedPayloads
}

export function sanitizeStaleAppDataPayloadForRenderer(payload) {
    return {
        id: String(payload?.id || ''),
        name: redactRendererText(payload?.name || 'Imported AppData', 96) || 'Imported AppData',
        safeName: redactRendererText(payload?.safeName || '', 96),
        sizeBytes: Number.isFinite(Number(payload?.sizeBytes)) && Number(payload.sizeBytes) >= 0 ? Number(payload.sizeBytes) : 0,
        sizeMB: Number.isFinite(Number(payload?.sizeMB)) && Number(payload.sizeMB) >= 0 ? Number(payload.sizeMB) : 0,
        cleanupBlocked: payload?.cleanupBlocked === true,
        cleanupBlockedReason: payload?.cleanupBlocked ? 'Cleanup blocked for safety.' : null,
        orphaned: payload?.orphaned === true,
        reason: redactRendererText(payload?.reason || 'This imported AppData payload is no longer used by the saved workspace.')
    }
}

export function sanitizeStaleAppDataPayloadsForRenderer(payloads) {
    return (Array.isArray(payloads) ? payloads : []).map(sanitizeStaleAppDataPayloadForRenderer)
}

function getCleanupRecordPayload(record) {
    if (isPlainObject(record?.payload)) return record.payload
    return record
}

function getCleanupRecordStatus(record, fallback) {
    return normalizeCleanupResultStatus(record?.status || fallback, fallback)
}

function getCleanupRecordReasonCode(record, status) {
    const fallback = status === 'removed'
        ? 'removed'
        : status === 'blocked'
            ? 'cleanup-blocked'
            : 'cleanup-failed'
    return normalizeCleanupReasonCode(record?.reasonCode, fallback)
}

export function sanitizeStaleAppDataCleanupRecordForRenderer(record, fallbackStatus = 'failed') {
    const payload = getCleanupRecordPayload(record)
    const item = sanitizeStaleAppDataPayloadForRenderer(payload)
    const status = getCleanupRecordStatus(record, fallbackStatus)
    return {
        id: item.id,
        name: item.name,
        safeName: item.safeName,
        sizeMB: item.sizeMB,
        orphaned: item.orphaned,
        status,
        reasonCode: getCleanupRecordReasonCode(record, status),
        metadataOnly: true
    }
}

export function sanitizeStaleAppDataCleanupResultForRenderer(result = {}) {
    const removed = (Array.isArray(result.removed) ? result.removed : [])
        .map(record => sanitizeStaleAppDataCleanupRecordForRenderer(record, 'removed'))
    const failed = (Array.isArray(result.failed) ? result.failed : [])
        .map(record => sanitizeStaleAppDataCleanupRecordForRenderer(record, 'failed'))
    const explicitFailure = result.success === false || !!result.error
    const success = result.success === true
        ? failed.length === 0 && !explicitFailure
        : failed.length === 0 && !explicitFailure
    const errorCode = success
        ? null
        : normalizeCleanupReasonCode(result.errorCode, failed.length > 0 ? 'cleanup-failed' : 'cleanup-request-invalid')

    return {
        success,
        removed,
        failed,
        removedCount: removed.length,
        failedCount: failed.length,
        remainingPayloads: sanitizeStaleAppDataPayloadsForRenderer(result.remainingPayloads),
        error: success
            ? null
            : errorCode === 'cleanup-request-invalid'
                ? 'Stale AppData cleanup could not start safely.'
                : 'Some stale AppData payloads could not be removed.',
        errorCode,
        metadataOnly: true
    }
}

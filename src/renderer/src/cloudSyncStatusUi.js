const OPERATION_LABELS = {
    'upload-sanitized-snapshot': 'Snapshot upload',
    'download-encrypted-patch-summaries': 'Patch download',
    'plan-safe-preset-patches': 'Patch planning',
    'apply-trusted-patches': 'Trusted apply',
    'auto-import-trusted-patches': 'Trusted auto-import',
    'list-pending-device-enrollments': 'Phone enrollment',
    'approve-phone-planner-enrollment': 'Phone approval'
}

const STATUS_LABELS = {
    accepted: 'Uploaded',
    downloaded: 'Downloaded',
    planned: 'Planned',
    listed: 'Listed',
    approved: 'Approved',
    completed: 'Completed',
    'not-configured': 'Not configured',
    'unavailable-runtime': 'Runtime unavailable',
    locked: 'Locked',
    unavailable: 'Unavailable',
    rejected: 'Rejected',
    idle: 'Idle',
    scheduled: 'Scheduled',
    running: 'Running',
    'no-patches': 'No patches',
    conflict: 'Conflict',
    skipped: 'Skipped',
    applied: 'Applied',
    'already-decided': 'Already decided',
    'revoked-device': 'Revoked device',
    'invalid-signature': 'Invalid signature',
    'invalid-key': 'Invalid key',
    'invalid-patch': 'Invalid patch',
    'invalid-envelope': 'Invalid patch',
    'schema-rejected': 'Invalid patch',
    'forbidden-material': 'Invalid patch',
    'stale-base': 'Stale base',
    'transaction-failure': 'Transaction failure',
    'unknown-error': 'Sanitized error',
    'duplicate-patch': 'Duplicate patch',
    'merge-rejected': 'Merge rejected',
    merged: 'Merged',
    'unknown-safe-id': 'Unknown item',
    'unknown-safe-preset': 'Unknown preset',
    'cloud-conflict': 'Cloud conflict'
}

const FORBIDDEN_STATUS_TEXT = /deviceSessionToken|bearer\s+|syncRootKey|rootKeyMaterial|privateKey|vault\.json|vault\.meta\.json|vault\.state\.json|BrowserProfile|AppData[\\/]|cap_[A-Za-z0-9_-]{4,128}|[A-Za-z]:[\\/]|\\\\|HKEY_|HKLM|HKCU|powershell|taskkill|cmd\s|ciphertext|cloudEnvelope|encryptedEnvelope|importPlan|patchPayload|vaultData|devicePrivateKey|credential|browserSession|launchAuthority|firebase[-_\s]*(api[-_\s]*)?key|firebaseSecret|stack trace|\bat\s+.*:\d+:\d+/i

function safeToken(value, fallback = 'unknown') {
    if (typeof value !== 'string') return fallback
    const text = value.trim()
    if (!text || text.length > 80 || FORBIDDEN_STATUS_TEXT.test(text)) return fallback
    if (!/^[A-Za-z0-9 _:-]+$/.test(text)) return fallback
    return text
}

function safeMessage(value, fallback) {
    if (typeof value !== 'string') return fallback
    const text = value.replace(/[\u0000-\u001F\u007F]/g, ' ').trim()
    if (!text || FORBIDDEN_STATUS_TEXT.test(text)) return fallback
    return text.length > 140 ? `${text.slice(0, 137).trim()}...` : text
}

function safeCount(value) {
    return Number.isSafeInteger(value) && value >= 0 ? value : 0
}

function statusLabel(status) {
    return STATUS_LABELS[status] || safeToken(status, 'Unknown')
}

function operationLabel(operation) {
    return OPERATION_LABELS[operation] || 'Cloud sync'
}

function displayStatusFor(result, status) {
    if (result?.operation === 'auto-import-trusted-patches' && result?.statusCategory) {
        return safeToken(result.statusCategory, status)
    }
    return status
}

function defaultMessage(result, status) {
    if (result?.success === false) {
        if (status === 'not-configured') return 'Cloud sync is not configured on this desktop.'
        if (status === 'unavailable-runtime') return 'Cloud sync runtime is unavailable on this desktop.'
        if (status === 'locked') return 'Unlock the vault before using cloud sync.'
        if (status === 'unavailable') return 'Cloud sync is not configured on this desktop.'
        return 'Cloud sync did not complete.'
    }
    if (result?.operation === 'upload-sanitized-snapshot') return 'Sanitized snapshot uploaded.'
    if (result?.operation === 'download-encrypted-patch-summaries') return 'Encrypted patch summaries checked.'
    if (result?.operation === 'plan-safe-preset-patches') return 'Validate-only patch planning complete.'
    if (result?.operation === 'apply-trusted-patches') return 'Trusted patch apply complete.'
    if (result?.operation === 'list-pending-device-enrollments') return 'Pending phone enrollment metadata refreshed.'
    if (result?.operation === 'approve-phone-planner-enrollment') return 'Phone enrollment approved and key grant staged.'
    if (result?.operation === 'auto-import-trusted-patches') {
        if (status === 'scheduled') return 'Trusted auto-import scheduled.'
        if (status === 'running') return 'Trusted auto-import running.'
        if (status === 'no-patches') return 'No trusted patches were available.'
        if (status === 'applied') return 'Trusted preset metadata patches were applied.'
        if (status === 'conflict') return 'Trusted auto-import found a metadata conflict.'
        if (status === 'stale-base') return 'Phone changes were based on stale desktop metadata.'
        if (status === 'revoked-device') return 'A patch was skipped because its author device is revoked.'
        if (status === 'invalid-signature') return 'A patch was skipped because its signature was invalid.'
        if (status === 'invalid-key') return 'A patch was skipped because its key check failed.'
        if (status === 'invalid-patch') return 'A patch was skipped because its safe metadata was invalid.'
        if (status === 'transaction-failure') return 'Trusted auto-import could not finish the vault transaction.'
        if (status === 'unknown-error') return 'Trusted auto-import stopped with a sanitized error.'
        if (status === 'skipped') return 'Trusted auto-import skipped one or more patches.'
        return 'Trusted auto-import status updated.'
    }
    return 'Cloud sync action complete.'
}

function summarizeRecord(record) {
    const status = safeToken(record?.status, 'unknown')
    const reason = safeToken(record?.reason || record?.code || '', '')
    const category = safeToken(record?.category || '', '')
    return {
        status,
        statusLabel: statusLabel(status),
        reason,
        category,
        categoryLabel: category ? statusLabel(category) : '',
        reasonLabel: reason ? statusLabel(reason) : '',
        encrypted: record?.encrypted === true,
        metadataOnly: true
    }
}

export function createCloudSyncStatusView(result) {
    if (!result || typeof result !== 'object' || Array.isArray(result)) {
        return {
            title: 'Cloud sync',
            status: 'idle',
            statusLabel: 'Idle',
            message: 'No cloud sync action has run.',
            diagnostics: {
                category: 'idle',
                summary: 'No cloud sync action has run.',
                recordCount: 0,
                recordCategories: [],
                metadataOnly: true
            },
            recoveryHint: '',
            counts: { uploaded: 0, downloaded: 0, planned: 0, applied: 0, conflicts: 0, skipped: 0 },
            records: [],
            metadataOnly: true
        }
    }

    const status = safeToken(result.status, result.success === false ? 'rejected' : 'completed')
    const displayStatus = displayStatusFor(result, status)
    const summary = result.summary && typeof result.summary === 'object' ? result.summary : {}
    const diagnostics = result.diagnostics && typeof result.diagnostics === 'object' && !Array.isArray(result.diagnostics)
        ? result.diagnostics
        : null
    const recoveryHint = result.manualRecovery && typeof result.manualRecovery === 'object' && !Array.isArray(result.manualRecovery)
        ? safeMessage(result.manualRecovery.hint, '')
        : ''
    return {
        title: operationLabel(result.operation),
        status: displayStatus,
        rawStatus: status,
        statusLabel: statusLabel(displayStatus),
        message: safeMessage(diagnostics?.summary, safeMessage(result.error, defaultMessage(result, displayStatus))),
        diagnostics: {
            category: safeToken(diagnostics?.category, displayStatus),
            summary: safeMessage(diagnostics?.summary, defaultMessage(result, displayStatus)),
            recordCount: safeCount(diagnostics?.recordCount),
            recordCategories: Array.isArray(diagnostics?.recordCategories)
                ? diagnostics.recordCategories.slice(0, 12).map(item => safeToken(item, '')).filter(Boolean)
                : [],
            metadataOnly: true
        },
        recoveryHint,
        counts: {
            uploaded: safeCount(summary.uploaded),
            downloaded: safeCount(summary.downloaded),
            planned: safeCount(summary.planned),
            applied: safeCount(summary.applied),
            conflicts: safeCount(summary.conflicts),
            skipped: safeCount(summary.skipped)
        },
        records: Array.isArray(result.records)
            ? result.records.slice(0, 5).map(summarizeRecord)
            : [],
        metadataOnly: true
    }
}

export function cloudSyncStatusViewContainsForbiddenMaterial(value) {
    const text = JSON.stringify(value || {})
    return FORBIDDEN_STATUS_TEXT.test(text) ||
        /ciphertext|cloudEnvelope|encryptedEnvelope|importPlan|patchPayload|vaultData|devicePrivateKey|credential|browserSession|launchAuthority|firebaseSecret|apiKey|firebase[-_\s]*(api[-_\s]*)?key|\bat\s+.*:\d+:\d+/i.test(text)
}

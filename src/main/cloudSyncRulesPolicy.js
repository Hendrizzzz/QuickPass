export const CLOUD_SYNC_FIRESTORE_RULES_VERSION = 2

const READ_OPERATIONS = new Set(['get', 'list', 'read'])
const WRITE_OPERATIONS = new Set(['create', 'update', 'delete', 'write'])
const OWNER_READ_COLLECTIONS = new Set(['devices', 'keyGrants', 'snapshots', 'patches'])
const OWNER_READ_SINGLETONS = new Set(['state'])
const DEVICE_ROLES = new Set(['desktop', 'phone', 'web-planner'])

function isPlainObject(value) {
    return !!value && typeof value === 'object' && !Array.isArray(value)
}

function normalizePath(path) {
    return String(path || '')
        .replace(/^\/+|\/+$/g, '')
        .split('/')
        .filter(Boolean)
}

function normalizeOperation(operation) {
    return String(operation || '').trim().toLowerCase()
}

function isOwnerPath(parts, authUid) {
    return parts.length >= 2 && parts[0] === 'users' && parts[1] === authUid
}

function matchesReadableCloudSyncPath(parts) {
    if (parts.length !== 4) return false
    if (OWNER_READ_COLLECTIONS.has(parts[2])) return true
    return OWNER_READ_SINGLETONS.has(parts[2])
}

function normalizePositiveInteger(value) {
    return Number.isSafeInteger(value) && value > 0 ? value : null
}

function validateDeviceClaims(authClaims) {
    if (!isPlainObject(authClaims)) return { valid: false, reason: 'device-claims-required' }
    const deviceId = typeof authClaims.wipesnapDeviceId === 'string'
        ? authClaims.wipesnapDeviceId.trim()
        : ''
    const role = typeof authClaims.wipesnapDeviceRole === 'string'
        ? authClaims.wipesnapDeviceRole.trim()
        : ''
    const enrollmentEpoch = normalizePositiveInteger(authClaims.wipesnapEnrollmentEpoch)
    const keyVersion = normalizePositiveInteger(authClaims.wipesnapKeyVersion)

    if (!/^dev_[A-Za-z0-9_-]+$/.test(deviceId)) return { valid: false, reason: 'device-claims-required' }
    if (!DEVICE_ROLES.has(role)) return { valid: false, reason: 'device-claims-required' }
    if (enrollmentEpoch == null || keyVersion == null) return { valid: false, reason: 'device-claims-required' }
    return {
        valid: true,
        claims: { deviceId, role, enrollmentEpoch, keyVersion }
    }
}

function validateActiveDeviceRecord({ authUid, claims, deviceRecord }) {
    if (!isPlainObject(deviceRecord)) return { valid: false, reason: 'device-not-enrolled' }
    if (deviceRecord.ownerUid !== authUid) return { valid: false, reason: 'mismatched-device-denied' }
    if (deviceRecord.deviceId !== claims.deviceId) return { valid: false, reason: 'mismatched-device-denied' }
    if (deviceRecord.status !== 'active' || deviceRecord.revokedAt != null) {
        return { valid: false, reason: 'revoked-device-denied' }
    }
    if (deviceRecord.enrollmentEpoch !== claims.enrollmentEpoch) {
        return { valid: false, reason: 'mismatched-enrollment-denied' }
    }
    if (deviceRecord.keyVersion !== claims.keyVersion) return { valid: false, reason: 'mismatched-key-version-denied' }
    if (deviceRecord.role !== claims.role) return { valid: false, reason: 'mismatched-role-denied' }
    if (!Array.isArray(deviceRecord.syncScopes) || !deviceRecord.syncScopes.includes('read')) {
        return { valid: false, reason: 'read-scope-required' }
    }
    return { valid: true }
}

function validateResourceMetadata({ authUid, claims, resourceData }) {
    if (!isPlainObject(resourceData)) return { valid: false, reason: 'resource-metadata-required' }
    if (resourceData.ownerUid !== authUid) return { valid: false, reason: 'resource-owner-denied' }
    if (resourceData.keyVersion !== claims.keyVersion) return { valid: false, reason: 'resource-key-version-denied' }
    return { valid: true }
}

export function evaluateCloudSyncFirestoreAccess({
    path,
    operation,
    authUid,
    authClaims,
    deviceRecord,
    resourceData
} = {}) {
    const op = normalizeOperation(operation)
    const parts = normalizePath(path)
    if (!authUid) return { allowed: false, reason: 'auth-required' }
    if (WRITE_OPERATIONS.has(op)) return { allowed: false, reason: 'direct-client-writes-denied' }
    if (!READ_OPERATIONS.has(op)) return { allowed: false, reason: 'unsupported-operation' }
    if (!isOwnerPath(parts, authUid)) return { allowed: false, reason: 'cross-user-or-unknown-path-denied' }
    if (!matchesReadableCloudSyncPath(parts)) return { allowed: false, reason: 'default-deny' }

    const claimCheck = validateDeviceClaims(authClaims)
    if (!claimCheck.valid) return { allowed: false, reason: claimCheck.reason }
    const { claims } = claimCheck
    const activeDeviceCheck = validateActiveDeviceRecord({ authUid, claims, deviceRecord })
    if (!activeDeviceCheck.valid) return { allowed: false, reason: activeDeviceCheck.reason }

    const collection = parts[2]
    const documentId = parts[3]
    if (collection === 'devices') {
        if (documentId !== claims.deviceId) return { allowed: false, reason: 'mismatched-device-denied' }
        return { allowed: true, reason: 'device-bound-read' }
    }

    const resourceCheck = validateResourceMetadata({ authUid, claims, resourceData })
    if (!resourceCheck.valid) return { allowed: false, reason: resourceCheck.reason }

    if (collection === 'keyGrants' &&
        resourceData.recipientDeviceId !== claims.deviceId &&
        claims.role !== 'desktop') {
        return { allowed: false, reason: 'key-grant-recipient-denied' }
    }

    return { allowed: true, reason: 'device-bound-read' }
}

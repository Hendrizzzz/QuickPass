import { constants, createHash, createPublicKey, publicEncrypt } from 'crypto'
import {
    CLOUD_SYNC_DEVICE_RECORD_TYPE,
    CLOUD_SYNC_KEY_GRANT_RECORD_TYPE,
    CLOUD_SYNC_SCHEMA_VERSION,
    CLOUD_SYNC_SIGNING_ALGORITHM,
    assertNoForbiddenCloudSyncBackendPlaintext,
    signCloudSyncCanonicalMetadata,
    validateCloudSyncDeviceRecord,
    validateCloudSyncKeyGrant
} from './cloudSyncEnvelope.js'
import {
    CLOUD_SYNC_ADMIN_OPERATIONS,
    CLOUD_SYNC_INGESTION_OPERATIONS,
    CLOUD_SYNC_INGESTION_SCHEMA_VERSION,
    createCloudSyncAdminSignatureMetadata,
    createCloudSyncIngestionSignatureMetadata
} from './cloudSyncIngestion.js'

export const CLOUD_SYNC_ENROLLMENT_APPROVAL_OPERATION = 'approve-phone-planner-enrollment'

const REQUEST_ID_PATTERN = /^dev_[A-Za-z0-9_-]{1,92}$/
const SAFE_STATUS_TEXT = /^[a-z][a-z0-9-]{0,80}$/

function fail(message) {
    throw new Error(message)
}

function isPlainObject(value) {
    return !!value && typeof value === 'object' && !Array.isArray(value)
}

function clone(value) {
    return value == null ? value : JSON.parse(JSON.stringify(value))
}

function normalizeRequestId(value, fieldName = 'requestId') {
    if (typeof value !== 'string') fail(`${fieldName} must be a string.`)
    const text = value.trim()
    if (!REQUEST_ID_PATTERN.test(text)) fail(`${fieldName} must be a safe device enrollment request id.`)
    return text
}

function normalizeInput(input = {}) {
    if (!isPlainObject(input)) fail('Cloud sync enrollment approval input must be an object.')
    for (const key of Object.keys(input)) {
        if (key !== 'requestId') fail(`Cloud sync enrollment approval input.${key} is not accepted.`)
    }
    return { requestId: normalizeRequestId(input.requestId) }
}

function sideEffectsNone(extra = {}) {
    return {
        writesVault: false,
        writesCapabilityVault: false,
        createsCapability: false,
        createsAccountSlots: false,
        createsBrowserProfiles: false,
        launches: false,
        writesCloudDeviceEnrollment: false,
        writesCloudKeyGrant: false,
        ...extra
    }
}

function safeStatus(value, fallback = 'unknown') {
    if (typeof value !== 'string') return fallback
    const text = value.trim().toLowerCase()
    return SAFE_STATUS_TEXT.test(text) ? text : fallback
}

function sha256Base64Url(bytes) {
    return createHash('sha256').update(bytes).digest('base64url')
}

function syncRootKeyBytes(value) {
    if (Buffer.isBuffer(value)) return Buffer.from(value)
    if (ArrayBuffer.isView(value)) return Buffer.from(value.buffer, value.byteOffset, value.byteLength)
    if (value instanceof ArrayBuffer) return Buffer.from(value)
    if (typeof value === 'string') {
        const text = value.trim()
        if (/^[A-Za-z0-9_-]{32,}={0,2}$/.test(text)) {
            try {
                const decoded = Buffer.from(text, 'base64url')
                if (decoded.length === 32) return decoded
            } catch (_) { }
        }
        return Buffer.from(text, 'utf8')
    }
    if (value && typeof value.export === 'function') {
        const exported = value.export()
        return Buffer.isBuffer(exported) ? Buffer.from(exported) : Buffer.from(exported)
    }
    fail('Desktop sync root key material is not available for key grant wrapping.')
}

function normalizeDesktopState(state) {
    const device = validateCloudSyncDeviceRecord(state?.device)
    if (device.role !== 'desktop') fail('Enrollment approval requires a desktop cloud sync device.')
    if (state.ownerUid !== device.ownerUid) fail('Desktop cloud sync owner must match device owner.')
    if (!state.signingPrivateKey) fail('Desktop signing key is required for enrollment approval.')
    const keyBytes = syncRootKeyBytes(state.syncRootKey)
    if (keyBytes.length !== 32) fail('Desktop sync root key must be exactly 32 bytes.')
    return { ...state, device, syncRootKeyBytes: keyBytes }
}

async function callCloudFunction(functionsClient, name, data) {
    if (!functionsClient) fail('Cloud sync enrollment approval requires a Functions client.')
    if (typeof functionsClient.callCloudSyncFunction === 'function') return functionsClient.callCloudSyncFunction(name, data)
    if (typeof functionsClient.call === 'function') return functionsClient.call(name, data)
    if (typeof functionsClient[name] === 'function') return functionsClient[name](data)
    fail(`Functions client cannot call ${name}.`)
}

async function updateLocalSequence(storage, deviceSequence) {
    if (typeof storage.updateDeviceSequence === 'function') {
        await storage.updateDeviceSequence(deviceSequence)
    }
}

function pendingRecordFromFunctionRecord(record) {
    const request = isPlainObject(record) ? record : fail('Pending enrollment record is invalid.')
    const device = validateCloudSyncDeviceRecord(request.device)
    if (!['phone', 'web-planner'].includes(device.role)) fail('Pending enrollment must be a phone or web planner device.')
    if (device.status !== 'pending') fail('Pending enrollment device must still be pending.')
    return {
        requestId: normalizeRequestId(request.requestId || device.deviceId),
        status: safeStatus(request.status, 'pending'),
        device,
        requestedAt: Number.isSafeInteger(request.requestedAt) ? request.requestedAt : 0,
        updatedAt: Number.isSafeInteger(request.updatedAt) ? request.updatedAt : 0,
        pairingChallengeHash: typeof request.pairingChallengeHash === 'string' ? request.pairingChallengeHash : ''
    }
}

export function createCloudSyncKeyGrantIdForDevice({ deviceId, keyVersion }) {
    const safeDeviceId = normalizeRequestId(deviceId, 'deviceId')
    if (!Number.isSafeInteger(keyVersion) || keyVersion <= 0) fail('keyVersion must be a positive safe integer.')
    return `grant_${safeDeviceId.slice(4)}_v${keyVersion}`.slice(0, 96)
}

function sanitizePendingEnrollment(record) {
    const pending = pendingRecordFromFunctionRecord(record)
    return {
        requestId: pending.requestId,
        status: pending.status,
        deviceId: pending.device.deviceId,
        role: pending.device.role,
        platform: pending.device.platform,
        enrollmentEpoch: pending.device.enrollmentEpoch,
        keyVersion: pending.device.keyVersion,
        requestedAt: pending.requestedAt,
        updatedAt: pending.updatedAt,
        signingPublicKeyFingerprint: pending.device.signingPublicKey.fingerprint,
        wrapPublicKeyFingerprint: pending.device.wrapPublicKey.fingerprint,
        metadataOnly: true
    }
}

function publicKeyFromWrapRecord(device) {
    return createPublicKey({
        key: Buffer.from(device.wrapPublicKey.spki, 'base64url'),
        format: 'der',
        type: 'spki'
    })
}

function wrapSyncRootKeyForDevice(syncRootKey, device) {
    const wrapped = publicEncrypt({
        key: publicKeyFromWrapRecord(device),
        oaepHash: 'sha256',
        padding: constants.RSA_PKCS1_OAEP_PADDING
    }, syncRootKey)
    return {
        ciphertext: wrapped.toString('base64url'),
        hash: sha256Base64Url(wrapped)
    }
}

function createKeyGrant({ ownerUid, desktopDevice, recipientDevice, syncRootKey, now }) {
    const wrapped = wrapSyncRootKeyForDevice(syncRootKey, recipientDevice)
    return validateCloudSyncKeyGrant({
        product: 'wipesnap',
        recordType: CLOUD_SYNC_KEY_GRANT_RECORD_TYPE,
        schemaVersion: CLOUD_SYNC_SCHEMA_VERSION,
        ownerUid,
        grantId: createCloudSyncKeyGrantIdForDevice({
            deviceId: recipientDevice.deviceId,
            keyVersion: recipientDevice.keyVersion
        }),
        recipientDeviceId: recipientDevice.deviceId,
        createdByDeviceId: desktopDevice.deviceId,
        keyVersion: desktopDevice.keyVersion,
        wrapAlg: 'RSA-OAEP-256',
        wrappedKeyCiphertext: wrapped.ciphertext,
        wrappedKeyHash: wrapped.hash,
        createdAt: now,
        revokedAt: null,
        revokedByDeviceId: null
    })
}

function signAdminApproval({ state, pending, deviceSequence, requestedAt }) {
    return {
        alg: CLOUD_SYNC_SIGNING_ALGORITHM,
        keyId: state.device.deviceId,
        value: signCloudSyncCanonicalMetadata({
            canonicalMetadata: createCloudSyncAdminSignatureMetadata({
                operation: CLOUD_SYNC_ADMIN_OPERATIONS.approveDeviceEnrollment,
                ownerUid: state.ownerUid,
                actorDeviceId: state.device.deviceId,
                targetDeviceId: pending.device.deviceId,
                deviceSequence,
                enrollmentEpoch: state.device.enrollmentEpoch,
                keyVersion: state.device.keyVersion,
                documentId: pending.requestId,
                document: pending.device,
                requestedAt
            }),
            privateKey: state.signingPrivateKey
        })
    }
}

function signKeyGrant({ state, keyGrant, deviceSequence, requestedAt }) {
    return {
        alg: CLOUD_SYNC_SIGNING_ALGORITHM,
        keyId: state.device.deviceId,
        value: signCloudSyncCanonicalMetadata({
            canonicalMetadata: createCloudSyncIngestionSignatureMetadata({
                operation: CLOUD_SYNC_INGESTION_OPERATIONS.keyGrant,
                ownerUid: state.ownerUid,
                deviceId: state.device.deviceId,
                deviceSequence,
                enrollmentEpoch: state.device.enrollmentEpoch,
                keyVersion: state.device.keyVersion,
                documentId: keyGrant.grantId,
                document: keyGrant,
                requestedAt
            }),
            privateKey: state.signingPrivateKey
        })
    }
}

function errorResult(operation, error) {
    const locked = /unlock|locked|active vault session/i.test(error?.message || '')
    return {
        success: false,
        operation,
        status: locked ? 'locked' : 'rejected',
        error: locked
            ? 'Cloud sync enrollment approval requires an unlocked vault session.'
            : 'Cloud sync enrollment approval failed.',
        records: [],
        summary: { pending: 0, approved: 0, granted: 0, skipped: 1 },
        metadataOnly: true,
        sideEffects: sideEffectsNone()
    }
}

export async function listPendingCloudSyncDeviceEnrollmentsAfterUnlock({
    storage,
    functionsClient
} = {}) {
    const operation = 'list-pending-device-enrollments'
    try {
        if (!storage || typeof storage.loadAfterUnlock !== 'function') fail('Enrollment listing requires unlocked desktop cloud sync storage.')
        const state = normalizeDesktopState(await storage.loadAfterUnlock())
        const result = await callCloudFunction(functionsClient, 'listPendingCloudSyncDeviceEnrollments', {})
        const records = Array.isArray(result?.records)
            ? result.records.map(sanitizePendingEnrollment)
            : []
        return {
            success: true,
            operation,
            status: 'listed',
            records,
            summary: { pending: records.length, approved: 0, granted: 0, skipped: 0 },
            desktopDeviceId: state.device.deviceId,
            metadataOnly: true,
            sideEffects: sideEffectsNone()
        }
    } catch (error) {
        return errorResult(operation, error)
    }
}

export async function approveCloudSyncDeviceEnrollmentAndGrantAfterUnlock({
    input = {},
    storage,
    functionsClient,
    now = Date.now
} = {}) {
    const operation = CLOUD_SYNC_ENROLLMENT_APPROVAL_OPERATION
    let desktopState = null
    try {
        const request = normalizeInput(input)
        if (!storage || typeof storage.loadAfterUnlock !== 'function') fail('Enrollment approval requires unlocked desktop cloud sync storage.')
        desktopState = normalizeDesktopState(await storage.loadAfterUnlock())
        const timestamp = typeof now === 'function' ? now() : now
        const pendingList = await callCloudFunction(functionsClient, 'listPendingCloudSyncDeviceEnrollments', {})
        const pending = (Array.isArray(pendingList?.records) ? pendingList.records : [])
            .map(pendingRecordFromFunctionRecord)
            .find(record => record.requestId === request.requestId)
        if (!pending) fail('Pending phone planner enrollment request was not found.')
        if (pending.device.ownerUid !== desktopState.ownerUid) fail('Pending phone planner enrollment owner does not match desktop.')
        if (pending.device.keyVersion !== desktopState.device.keyVersion) fail('Pending phone planner device key version does not match desktop.')
        assertNoForbiddenCloudSyncBackendPlaintext(pending.device)

        const approvalSequence = desktopState.device.deviceSequence + 1
        const approvalSignature = signAdminApproval({
            state: desktopState,
            pending,
            deviceSequence: approvalSequence,
            requestedAt: timestamp
        })
        const approval = await callCloudFunction(functionsClient, 'approveCloudSyncDeviceEnrollment', {
            requestId: pending.requestId,
            documentId: pending.requestId,
            signature: approvalSignature,
            deviceSequence: approvalSequence,
            requestedAt: timestamp
        })
        const activeDevice = validateCloudSyncDeviceRecord(approval.device)
        if (activeDevice.status !== 'active') fail('Approved phone planner device did not become active.')

        const grantSequence = approvalSequence + 1
        const keyGrant = createKeyGrant({
            ownerUid: desktopState.ownerUid,
            desktopDevice: desktopState.device,
            recipientDevice: activeDevice,
            syncRootKey: desktopState.syncRootKeyBytes,
            now: timestamp
        })
        const keyGrantSignature = signKeyGrant({
            state: desktopState,
            keyGrant,
            deviceSequence: grantSequence,
            requestedAt: timestamp
        })
        const grant = await callCloudFunction(functionsClient, 'approveCloudSyncKeyGrant', {
            documentId: keyGrant.grantId,
            document: keyGrant,
            signature: keyGrantSignature,
            deviceSequence: grantSequence,
            requestedAt: timestamp
        })
        await updateLocalSequence(storage, grantSequence)
        return {
            success: true,
            operation,
            status: 'approved',
            requestId: pending.requestId,
            deviceId: activeDevice.deviceId,
            role: activeDevice.role,
            keyGrantId: keyGrant.grantId,
            deviceSequence: grantSequence,
            cloudStatus: {
                enrollment: safeStatus(approval.status, 'approved'),
                keyGrant: safeStatus(grant.status, 'accepted'),
                metadataOnly: true
            },
            summary: { pending: 0, approved: 1, granted: 1, skipped: 0 },
            metadataOnly: true,
            sideEffects: sideEffectsNone({
                writesCloudDeviceEnrollment: true,
                writesCloudKeyGrant: true
            })
        }
    } catch (error) {
        return errorResult(operation, error)
    } finally {
        if (desktopState?.syncRootKeyBytes) desktopState.syncRootKeyBytes.fill(0)
    }
}

export function cloudSyncEnrollmentApprovalResultContainsForbiddenMaterial(value) {
    const text = JSON.stringify(value || {})
    return /wrappedKeyCiphertext|syncRootKey|rootKeyMaterial|privateKey|deviceSessionToken|customToken|idToken|refreshToken|accessToken|vault\.json|vault\.meta\.json|vault\.state\.json|BrowserProfile[\\/]|AppData[\\/]|cap_[A-Za-z0-9_-]{4,128}|[A-Za-z]:[\\/]|\\\\|HKEY_|HKLM|HKCU|powershell|taskkill|cmd\s|ciphertext|cloudEnvelope|encryptedEnvelope|importPlan|patchPayload|vaultData|credential|browserSession|launchAuthority/i.test(text)
}

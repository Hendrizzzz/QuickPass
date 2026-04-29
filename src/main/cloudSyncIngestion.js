import { createHash, createPublicKey } from 'crypto'
import {
    CLOUD_SYNC_PATCH_DOC_TYPE,
    CLOUD_SYNC_SIGNING_ALGORITHM,
    CLOUD_SYNC_SNAPSHOT_DOC_TYPE,
    assertNoForbiddenCloudSyncBackendPlaintext,
    serializeCanonicalCloudSyncMetadata,
    validateCloudSyncDeviceRecord,
    validateCloudSyncEnvelope,
    validateCloudSyncKeyGrant,
    verifyCloudSyncCanonicalMetadata,
    verifyCloudSyncEnvelopeSignature
} from './cloudSyncEnvelope.js'

export const CLOUD_SYNC_INGESTION_SCHEMA_VERSION = 1
export const CLOUD_SYNC_INGESTION_RATE_LIMIT = Object.freeze({
    windowMs: 60_000,
    maxWritesPerWindow: 20
})
export const CLOUD_SYNC_INGESTION_OPERATIONS = Object.freeze({
    deviceRecord: 'device-record',
    keyGrant: 'key-grant',
    snapshotEnvelope: 'snapshot-envelope',
    patchEnvelope: 'patch-envelope'
})

const DEVICE_ROLES = new Set(['desktop', 'phone', 'web-planner'])
const DEVICE_ID_PATTERN = /^dev_[A-Za-z0-9_-]{1,92}$/
const OWNER_UID_PATTERN = /^[A-Za-z0-9:_-]{1,128}$/
const MAX_TIMESTAMP = 8_640_000_000_000_000

export class CloudSyncIngestionError extends Error {
    constructor(code, message) {
        super(message)
        this.name = 'CloudSyncIngestionError'
        this.code = code
    }
}

function fail(code, message) {
    throw new CloudSyncIngestionError(code, message)
}

function isPlainObject(value) {
    return !!value && typeof value === 'object' && !Array.isArray(value)
}

function clone(value) {
    return value == null ? value : JSON.parse(JSON.stringify(value))
}

function normalizeString(value, fieldName, { required = true, max = 256 } = {}) {
    if (value == null || value === '') {
        if (required) fail('invalid-argument', `${fieldName} is required.`)
        return ''
    }
    if (typeof value !== 'string') fail('invalid-argument', `${fieldName} must be a string.`)
    if (value.includes('\0') || /[\u0000-\u001F\u007F]/.test(value)) {
        fail('invalid-argument', `${fieldName} contains unsupported control characters.`)
    }
    const text = value.trim()
    if (required && !text) fail('invalid-argument', `${fieldName} is required.`)
    if (text.length > max) fail('invalid-argument', `${fieldName} is too long.`)
    return text
}

function normalizeOwnerUid(value, fieldName = 'ownerUid') {
    const text = normalizeString(value, fieldName, { max: 128 })
    if (!OWNER_UID_PATTERN.test(text)) fail('invalid-argument', `${fieldName} must be a safe Firebase uid.`)
    return text
}

function normalizeDeviceId(value, fieldName = 'deviceId') {
    const text = normalizeString(value, fieldName, { max: 96 })
    if (!DEVICE_ID_PATTERN.test(text)) fail('invalid-argument', `${fieldName} must be a safe device id.`)
    return text
}

function normalizePositiveInteger(value, fieldName) {
    if (!Number.isSafeInteger(value) || value <= 0) {
        fail('invalid-argument', `${fieldName} must be a positive safe integer.`)
    }
    return value
}

function normalizeNonNegativeInteger(value, fieldName) {
    if (!Number.isSafeInteger(value) || value < 0) {
        fail('invalid-argument', `${fieldName} must be a non-negative safe integer.`)
    }
    return value
}

function normalizeTimestamp(value, fieldName, fallback) {
    const candidate = value == null ? fallback : value
    if (!Number.isSafeInteger(candidate) || candidate < 0 || candidate > MAX_TIMESTAMP) {
        fail('invalid-argument', `${fieldName} must be a non-negative timestamp.`)
    }
    return candidate
}

function normalizeAuth(auth) {
    if (!isPlainObject(auth) || !auth.uid) fail('unauthenticated', 'Cloud sync ingestion requires authentication.')
    const uid = normalizeOwnerUid(auth.uid, 'auth.uid')
    const token = isPlainObject(auth.token) ? auth.token : isPlainObject(auth.claims) ? auth.claims : {}
    const deviceId = normalizeDeviceId(token.wipesnapDeviceId, 'auth.token.wipesnapDeviceId')
    const role = normalizeString(token.wipesnapDeviceRole, 'auth.token.wipesnapDeviceRole', { max: 40 })
    if (!DEVICE_ROLES.has(role)) fail('permission-denied', 'Cloud sync ingestion requires a supported device role claim.')
    return {
        uid,
        deviceId,
        role,
        enrollmentEpoch: normalizePositiveInteger(token.wipesnapEnrollmentEpoch, 'auth.token.wipesnapEnrollmentEpoch'),
        keyVersion: normalizePositiveInteger(token.wipesnapKeyVersion, 'auth.token.wipesnapKeyVersion')
    }
}

function sha256Base64Url(value) {
    return createHash('sha256').update(value).digest('base64url')
}

function documentHash(document) {
    return sha256Base64Url(Buffer.from(serializeCanonicalCloudSyncMetadata(document), 'utf8'))
}

export function createCloudSyncIngestionSignatureMetadata({
    operation,
    ownerUid,
    deviceId,
    deviceSequence,
    enrollmentEpoch,
    keyVersion,
    documentId,
    document,
    requestedAt
}) {
    return serializeCanonicalCloudSyncMetadata({
        product: 'wipesnap',
        schemaVersion: CLOUD_SYNC_INGESTION_SCHEMA_VERSION,
        operation,
        ownerUid,
        deviceId,
        deviceSequence,
        enrollmentEpoch,
        keyVersion,
        documentId,
        documentHash: documentHash(document),
        requestedAt
    })
}

function publicKeyFromDeviceRecord(device) {
    try {
        return createPublicKey({
            key: Buffer.from(device.signingPublicKey.spki, 'base64url'),
            format: 'der',
            type: 'spki'
        })
    } catch (_) {
        fail('failed-precondition', 'Enrolled device signing public key is not usable.')
    }
}

function invalidArgumentFrom(error) {
    if (error instanceof CloudSyncIngestionError) throw error
    fail('invalid-argument', error.message || 'Cloud sync ingestion input is invalid.')
}

function permissionDeniedFrom(error) {
    if (error instanceof CloudSyncIngestionError) throw error
    fail('permission-denied', error.message || 'Cloud sync ingestion signature is not valid.')
}

function verifyDetachedIngestionSignature({
    authContext,
    device,
    operation,
    documentId,
    document,
    deviceSequence,
    requestedAt,
    signature
}) {
    if (!isPlainObject(signature)) fail('permission-denied', 'Cloud sync ingestion request signature is required.')
    if (signature.alg !== CLOUD_SYNC_SIGNING_ALGORITHM) {
        fail('permission-denied', 'Cloud sync ingestion request signature algorithm is not supported.')
    }
    if (signature.keyId !== authContext.deviceId) {
        fail('permission-denied', 'Cloud sync ingestion request signature key does not match the caller device.')
    }
    const canonicalMetadata = createCloudSyncIngestionSignatureMetadata({
        operation,
        ownerUid: authContext.uid,
        deviceId: authContext.deviceId,
        deviceSequence,
        enrollmentEpoch: authContext.enrollmentEpoch,
        keyVersion: authContext.keyVersion,
        documentId,
        document,
        requestedAt
    })
    let valid = false
    try {
        valid = verifyCloudSyncCanonicalMetadata({
            canonicalMetadata,
            signature: signature.value,
            publicKey: publicKeyFromDeviceRecord(device)
        })
    } catch (error) {
        permissionDeniedFrom(error)
    }
    if (!valid) fail('permission-denied', 'Cloud sync ingestion request signature is not valid.')
}

function requireScope(device, scope) {
    if (!Array.isArray(device.syncScopes) || !device.syncScopes.includes(scope)) {
        fail('permission-denied', `Cloud sync ingestion requires ${scope} scope.`)
    }
}

function requireRole(authContext, allowedRoles, message) {
    if (!allowedRoles.includes(authContext.role)) fail('permission-denied', message)
}

function assertClaimsMatchDevice(authContext, device) {
    if (device.ownerUid !== authContext.uid) fail('permission-denied', 'Device owner does not match caller.')
    if (device.deviceId !== authContext.deviceId) fail('permission-denied', 'Device id does not match caller.')
    if (device.role !== authContext.role) fail('permission-denied', 'Device role does not match caller.')
    if (device.enrollmentEpoch !== authContext.enrollmentEpoch) {
        fail('permission-denied', 'Device enrollment epoch does not match caller.')
    }
    if (device.keyVersion !== authContext.keyVersion) fail('permission-denied', 'Device key version does not match caller.')
}

function assertActiveDevice(authContext, device) {
    assertClaimsMatchDevice(authContext, device)
    if (device.status !== 'active' || device.revokedAt != null) {
        fail('permission-denied', 'Device is not active or has been revoked.')
    }
}

function assertMonotonicDeviceSequence(device, nextSequence) {
    if (nextSequence <= device.deviceSequence) {
        fail('already-exists', 'Cloud sync ingestion rejected a replayed or stale device sequence.')
    }
}

function userPath(uid, collection, id) {
    return `users/${uid}/${collection}/${id}`
}

function replayEventId(deviceId, sequence) {
    return `${deviceId}_${sequence}`
}

function rateBucketId(deviceId, now, windowMs) {
    return `${deviceId}_${Math.floor(now / windowMs) * windowMs}`
}

async function requireExistingActiveDevice(tx, authContext) {
    const path = userPath(authContext.uid, 'devices', authContext.deviceId)
    const raw = await tx.get(path)
    if (!raw) fail('permission-denied', 'Cloud sync device is not enrolled.')
    let device
    try {
        device = validateCloudSyncDeviceRecord(raw)
    } catch (error) {
        fail('failed-precondition', error.message || 'Cloud sync device record is invalid.')
    }
    assertActiveDevice(authContext, device)
    return { path, device }
}

async function assertCreateOnly(tx, path) {
    if (await tx.get(path)) fail('already-exists', 'Cloud sync ingestion target document already exists.')
}

async function enforceReplayAndRateLimit(tx, {
    authContext,
    deviceSequence,
    operation,
    documentId,
    now,
    rateLimit
}) {
    const eventPath = userPath(authContext.uid, 'ingestionEvents', replayEventId(authContext.deviceId, deviceSequence))
    if (await tx.get(eventPath)) fail('already-exists', 'Cloud sync ingestion rejected a replayed device sequence.')

    const bucketId = rateBucketId(authContext.deviceId, now, rateLimit.windowMs)
    const bucketPath = userPath(authContext.uid, 'rateLimits', bucketId)
    const bucket = await tx.get(bucketPath)
    const count = Number.isSafeInteger(bucket?.count) ? bucket.count : 0
    if (count >= rateLimit.maxWritesPerWindow) fail('resource-exhausted', 'Cloud sync ingestion rate limit exceeded.')
    await tx.set(bucketPath, {
        ownerUid: authContext.uid,
        deviceId: authContext.deviceId,
        bucketStart: Math.floor(now / rateLimit.windowMs) * rateLimit.windowMs,
        windowMs: rateLimit.windowMs,
        count: count + 1,
        updatedAt: now
    })
    await tx.create(eventPath, {
        ownerUid: authContext.uid,
        deviceId: authContext.deviceId,
        deviceSequence,
        operation,
        targetRef: documentId,
        createdAt: now
    })
}

async function updateDeviceSequence(tx, path, device, deviceSequence, now) {
    await tx.set(path, {
        ...device,
        deviceSequence,
        updatedAt: Math.max(device.updatedAt, now)
    })
}

function validateEnvelopeForIngestion({ envelopeInput, expectedDocType, authContext, documentId }) {
    let envelope
    try {
        envelope = validateCloudSyncEnvelope(envelopeInput, {
            expectedDocType,
            activeKeyVersion: authContext.keyVersion
        })
    } catch (error) {
        invalidArgumentFrom(error)
    }
    if (envelope.ownerUid !== authContext.uid) fail('permission-denied', 'Cloud sync envelope owner does not match caller.')
    if (envelope.deviceId !== authContext.deviceId) fail('permission-denied', 'Cloud sync envelope device does not match caller.')
    if (envelope.revisionId !== documentId) fail('invalid-argument', 'Cloud sync envelope revision id must match the target document id.')
    return envelope
}

function verifyEnvelopeSignatureForDevice(envelope, device) {
    try {
        verifyCloudSyncEnvelopeSignature({ envelope, publicKey: publicKeyFromDeviceRecord(device) })
    } catch (error) {
        permissionDeniedFrom(error)
    }
}

function acceptedEnvelopeDocument(envelope, authContext, now, extra = {}) {
    const stored = {
        ...envelope,
        ingestion: {
            status: 'accepted',
            ingestedAt: now,
            ingestedByDeviceId: authContext.deviceId,
            deviceRole: authContext.role,
            ...extra
        }
    }
    assertNoForbiddenCloudSyncBackendPlaintext(stored)
    return stored
}

async function ingestSnapshotEnvelope({
    tx,
    authContext,
    documentId,
    document,
    now,
    rateLimit
}) {
    requireRole(authContext, ['desktop'], 'Only desktop devices may ingest sanitized snapshot envelopes.')
    const { path: devicePath, device } = await requireExistingActiveDevice(tx, authContext)
    requireScope(device, 'snapshot-upload')
    const envelope = validateEnvelopeForIngestion({
        envelopeInput: document,
        expectedDocType: CLOUD_SYNC_SNAPSHOT_DOC_TYPE,
        authContext,
        documentId
    })
    assertMonotonicDeviceSequence(device, envelope.deviceSequence)
    verifyEnvelopeSignatureForDevice(envelope, device)

    const snapshotPath = userPath(authContext.uid, 'snapshots', envelope.revisionId)
    await assertCreateOnly(tx, snapshotPath)
    await enforceReplayAndRateLimit(tx, {
        authContext,
        deviceSequence: envelope.deviceSequence,
        operation: CLOUD_SYNC_INGESTION_OPERATIONS.snapshotEnvelope,
        documentId: envelope.revisionId,
        now,
        rateLimit
    })
    await tx.create(snapshotPath, acceptedEnvelopeDocument(envelope, authContext, now))
    await tx.set(userPath(authContext.uid, 'state', 'sync'), {
        ownerUid: authContext.uid,
        keyVersion: authContext.keyVersion,
        latestSnapshotRevisionId: envelope.revisionId,
        latestSnapshotDeviceId: authContext.deviceId,
        latestSnapshotDeviceSequence: envelope.deviceSequence,
        updatedAt: now
    })
    await updateDeviceSequence(tx, devicePath, device, envelope.deviceSequence, now)
    return { status: 'accepted', path: snapshotPath, revisionId: envelope.revisionId }
}

function conflictForPatch(envelope, latestSnapshotRevisionId, now) {
    if (!latestSnapshotRevisionId || envelope.baseRevisionId === latestSnapshotRevisionId) return null
    return {
        status: 'conflict',
        reason: 'stale-base',
        detectedAt: now,
        detectedByDeviceId: envelope.deviceId,
        baseRevisionId: envelope.baseRevisionId,
        currentRevisionId: latestSnapshotRevisionId,
        conflictingRevisionId: envelope.revisionId
    }
}

async function ingestPatchEnvelope({
    tx,
    authContext,
    documentId,
    document,
    now,
    rateLimit
}) {
    requireRole(authContext, ['phone', 'web-planner'], 'Only phone or web planner devices may ingest safe patch envelopes.')
    const { path: devicePath, device } = await requireExistingActiveDevice(tx, authContext)
    requireScope(device, 'patch-upload')
    const envelope = validateEnvelopeForIngestion({
        envelopeInput: document,
        expectedDocType: CLOUD_SYNC_PATCH_DOC_TYPE,
        authContext,
        documentId
    })
    assertMonotonicDeviceSequence(device, envelope.deviceSequence)
    verifyEnvelopeSignatureForDevice(envelope, device)

    const patchPath = userPath(authContext.uid, 'patches', envelope.revisionId)
    await assertCreateOnly(tx, patchPath)
    const state = await tx.get(userPath(authContext.uid, 'state', 'sync'))
    const conflict = conflictForPatch(envelope, state?.latestSnapshotRevisionId || null, now)
    await enforceReplayAndRateLimit(tx, {
        authContext,
        deviceSequence: envelope.deviceSequence,
        operation: CLOUD_SYNC_INGESTION_OPERATIONS.patchEnvelope,
        documentId: envelope.revisionId,
        now,
        rateLimit
    })
    await tx.create(patchPath, acceptedEnvelopeDocument(envelope, authContext, now, {
        pending: true,
        ...(conflict ? { conflict } : {})
    }))
    await updateDeviceSequence(tx, devicePath, device, envelope.deviceSequence, now)
    return {
        status: conflict ? 'conflict' : 'accepted',
        path: patchPath,
        revisionId: envelope.revisionId,
        conflict
    }
}

async function ingestKeyGrant({
    tx,
    authContext,
    documentId,
    document,
    signature,
    requestedAt,
    deviceSequence,
    now,
    rateLimit
}) {
    requireRole(authContext, ['desktop'], 'Only desktop devices may ingest key grants.')
    const { path: devicePath, device } = await requireExistingActiveDevice(tx, authContext)
    requireScope(device, 'read')
    assertMonotonicDeviceSequence(device, deviceSequence)
    let keyGrant
    try {
        keyGrant = validateCloudSyncKeyGrant(document)
    } catch (error) {
        invalidArgumentFrom(error)
    }
    if (keyGrant.ownerUid !== authContext.uid) fail('permission-denied', 'Key grant owner does not match caller.')
    if (keyGrant.grantId !== documentId) fail('invalid-argument', 'Key grant id must match the target document id.')
    if (keyGrant.createdByDeviceId !== authContext.deviceId) {
        fail('permission-denied', 'Key grant creator must match the caller device.')
    }
    if (keyGrant.keyVersion !== authContext.keyVersion) fail('permission-denied', 'Key grant key version does not match caller.')
    const recipient = await tx.get(userPath(authContext.uid, 'devices', keyGrant.recipientDeviceId))
    if (!recipient) fail('failed-precondition', 'Key grant recipient device is not enrolled.')
    let recipientDevice
    try {
        recipientDevice = validateCloudSyncDeviceRecord(recipient)
    } catch (error) {
        fail('failed-precondition', error.message || 'Key grant recipient device record is invalid.')
    }
    if (recipientDevice.ownerUid !== authContext.uid || recipientDevice.status !== 'active' || recipientDevice.revokedAt != null) {
        fail('permission-denied', 'Key grant recipient device is not active.')
    }
    if (recipientDevice.keyVersion !== authContext.keyVersion) fail('permission-denied', 'Key grant recipient key version is stale.')
    verifyDetachedIngestionSignature({
        authContext,
        device,
        operation: CLOUD_SYNC_INGESTION_OPERATIONS.keyGrant,
        documentId,
        document: keyGrant,
        deviceSequence,
        requestedAt,
        signature
    })

    const grantPath = userPath(authContext.uid, 'keyGrants', keyGrant.grantId)
    await assertCreateOnly(tx, grantPath)
    await enforceReplayAndRateLimit(tx, {
        authContext,
        deviceSequence,
        operation: CLOUD_SYNC_INGESTION_OPERATIONS.keyGrant,
        documentId: keyGrant.grantId,
        now,
        rateLimit
    })
    assertNoForbiddenCloudSyncBackendPlaintext(keyGrant)
    await tx.create(grantPath, keyGrant)
    await updateDeviceSequence(tx, devicePath, device, deviceSequence, now)
    return { status: 'accepted', path: grantPath, grantId: keyGrant.grantId }
}

async function ingestDeviceRecord({
    tx,
    authContext,
    documentId,
    document,
    signature,
    requestedAt,
    now,
    rateLimit
}) {
    let deviceRecord
    try {
        deviceRecord = validateCloudSyncDeviceRecord(document)
    } catch (error) {
        invalidArgumentFrom(error)
    }
    if (deviceRecord.ownerUid !== authContext.uid) fail('permission-denied', 'Device record owner does not match caller.')
    if (deviceRecord.deviceId !== documentId) fail('invalid-argument', 'Device record id must match the target document id.')
    if (deviceRecord.status !== 'active' || deviceRecord.revokedAt != null) {
        fail('permission-denied', 'Only active non-revoked device records may be ingested in this slice.')
    }
    assertClaimsMatchDevice(authContext, deviceRecord)
    verifyDetachedIngestionSignature({
        authContext,
        device: deviceRecord,
        operation: CLOUD_SYNC_INGESTION_OPERATIONS.deviceRecord,
        documentId,
        document: deviceRecord,
        deviceSequence: deviceRecord.deviceSequence,
        requestedAt,
        signature
    })

    const devicePath = userPath(authContext.uid, 'devices', deviceRecord.deviceId)
    await assertCreateOnly(tx, devicePath)
    await enforceReplayAndRateLimit(tx, {
        authContext,
        deviceSequence: deviceRecord.deviceSequence,
        operation: CLOUD_SYNC_INGESTION_OPERATIONS.deviceRecord,
        documentId: deviceRecord.deviceId,
        now,
        rateLimit
    })
    assertNoForbiddenCloudSyncBackendPlaintext(deviceRecord)
    await tx.create(devicePath, deviceRecord)
    return { status: 'accepted', path: devicePath, deviceId: deviceRecord.deviceId }
}

function normalizeOperation(value) {
    const operation = normalizeString(value, 'operation', { max: 40 })
    if (!Object.values(CLOUD_SYNC_INGESTION_OPERATIONS).includes(operation)) {
        fail('invalid-argument', 'Cloud sync ingestion operation is not supported.')
    }
    return operation
}

export async function ingestCloudSyncDocument(input = {}) {
    if (!isPlainObject(input)) fail('invalid-argument', 'Cloud sync ingestion input must be an object.')
    if (!input.store || typeof input.store.runTransaction !== 'function') {
        fail('failed-precondition', 'Cloud sync ingestion requires a Firestore Admin store.')
    }
    const authContext = normalizeAuth(input.auth)
    const operation = normalizeOperation(input.operation)
    const documentId = normalizeString(input.documentId, 'documentId', { max: 128 })
    const document = clone(input.document)
    const now = normalizeTimestamp(input.now, 'now', Date.now())
    const requestedAt = normalizeTimestamp(input.requestedAt, 'requestedAt', now)
    const rateLimit = {
        windowMs: normalizePositiveInteger(
            input.rateLimit?.windowMs ?? CLOUD_SYNC_INGESTION_RATE_LIMIT.windowMs,
            'rateLimit.windowMs'
        ),
        maxWritesPerWindow: normalizePositiveInteger(
            input.rateLimit?.maxWritesPerWindow ?? CLOUD_SYNC_INGESTION_RATE_LIMIT.maxWritesPerWindow,
            'rateLimit.maxWritesPerWindow'
        )
    }
    const deviceSequence = input.deviceSequence == null
        ? null
        : normalizeNonNegativeInteger(input.deviceSequence, 'deviceSequence')

    try {
        return await input.store.runTransaction(async tx => {
            if (operation === CLOUD_SYNC_INGESTION_OPERATIONS.snapshotEnvelope) {
                return ingestSnapshotEnvelope({ tx, authContext, documentId, document, now, rateLimit })
            }
            if (operation === CLOUD_SYNC_INGESTION_OPERATIONS.patchEnvelope) {
                return ingestPatchEnvelope({ tx, authContext, documentId, document, now, rateLimit })
            }
            if (operation === CLOUD_SYNC_INGESTION_OPERATIONS.keyGrant) {
                if (deviceSequence == null) fail('invalid-argument', 'deviceSequence is required for key grant ingestion.')
                return ingestKeyGrant({
                    tx,
                    authContext,
                    documentId,
                    document,
                    signature: input.signature,
                    requestedAt,
                    deviceSequence,
                    now,
                    rateLimit
                })
            }
            if (operation === CLOUD_SYNC_INGESTION_OPERATIONS.deviceRecord) {
                return ingestDeviceRecord({
                    tx,
                    authContext,
                    documentId,
                    document,
                    signature: input.signature,
                    requestedAt,
                    now,
                    rateLimit
                })
            }
            fail('invalid-argument', 'Cloud sync ingestion operation is not supported.')
        })
    } catch (error) {
        if (error instanceof CloudSyncIngestionError) throw error
        fail('invalid-argument', error.message || 'Cloud sync ingestion failed closed.')
    }
}

export function createFirestoreAdminStore(db) {
    if (!db || typeof db.runTransaction !== 'function' || typeof db.doc !== 'function') {
        fail('failed-precondition', 'A Firestore Admin SDK database handle is required.')
    }
    return {
        runTransaction(callback) {
            return db.runTransaction(async transaction => callback({
                async get(path) {
                    const snapshot = await transaction.get(db.doc(path))
                    return snapshot.exists ? snapshot.data() : null
                },
                async create(path, data) {
                    transaction.create(db.doc(path), data)
                },
                async set(path, data) {
                    transaction.set(db.doc(path), data)
                },
                async update(path, data) {
                    transaction.update(db.doc(path), data)
                }
            }))
        }
    }
}

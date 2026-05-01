import {
    validateSafePresetPatchForPhone,
    validateSanitizedPresetSnapshotForPhone
} from './phonePlannerCore.js'

export const CLOUD_SYNC_SCHEMA_VERSION = 1
export const CLOUD_SYNC_ENVELOPE_VERSION = 1
export const CLOUD_SYNC_INGESTION_SCHEMA_VERSION = 1
export const CLOUD_SYNC_ENVELOPE_RECORD_TYPE = 'cloud-sync-envelope'
export const CLOUD_SYNC_DEVICE_RECORD_TYPE = 'cloud-sync-device'
export const CLOUD_SYNC_KEY_GRANT_RECORD_TYPE = 'cloud-sync-key-grant'
export const CLOUD_SYNC_SNAPSHOT_DOC_TYPE = 'sanitized-snapshot'
export const CLOUD_SYNC_PATCH_DOC_TYPE = 'safe-preset-patch'
export const CLOUD_SYNC_CONTENT_ENCRYPTION = 'AES-256-GCM'
export const CLOUD_SYNC_KEY_DERIVATION = 'HKDF-SHA256'
export const CLOUD_SYNC_SIGNING_ALGORITHM = 'ECDSA-P256-SHA256-P1363'

export const CLOUD_SYNC_ADMIN_OPERATIONS = Object.freeze({
    requestDeviceEnrollment: 'request-device-enrollment',
    claimDeviceSession: 'claim-device-session'
})

export const CLOUD_SYNC_INGESTION_OPERATIONS = Object.freeze({
    patchEnvelope: 'patch-envelope'
})

const AES_KEY_BYTES = 32
const AES_GCM_IV_BYTES = 12
const AES_GCM_TAG_BYTES = 16
const HKDF_SALT_BYTES = 32
const MAX_TIMESTAMP = 8_640_000_000_000_000
const MAX_CIPHERTEXT_BYTES = 512 * 1024
const MAX_ENVELOPE_JSON_BYTES = 768 * 1024
const SAFE_ID_PATTERN = /^[A-Za-z][A-Za-z0-9_-]+$/
const OWNER_UID_PATTERN = /^[A-Za-z0-9:_-]{1,128}$/
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/
const DOC_TYPES = new Set([CLOUD_SYNC_SNAPSHOT_DOC_TYPE, CLOUD_SYNC_PATCH_DOC_TYPE])
const ENVELOPE_KEYS = new Set([
    'product',
    'recordType',
    'schemaVersion',
    'envelopeVersion',
    'docType',
    'ownerUid',
    'snapshotId',
    'patchId',
    'revisionId',
    'baseRevisionId',
    'deviceId',
    'deviceSequence',
    'keyVersion',
    'createdAt',
    'updatedAt',
    'encryption',
    'ciphertext',
    'ciphertextHash',
    'signature',
    'tombstone',
    'conflict'
])
const ENCRYPTION_KEYS = new Set(['alg', 'kdf', 'salt', 'iv', 'tag'])
const SIGNATURE_KEYS = new Set(['alg', 'keyId', 'value'])
const DEVICE_RECORD_KEYS = new Set([
    'product',
    'recordType',
    'schemaVersion',
    'ownerUid',
    'deviceId',
    'role',
    'status',
    'platform',
    'syncScopes',
    'signingPublicKey',
    'wrapPublicKey',
    'enrollmentEpoch',
    'keyVersion',
    'deviceSequence',
    'createdAt',
    'updatedAt',
    'revokedAt',
    'revokedByDeviceId'
])
const KEY_GRANT_KEYS = new Set([
    'product',
    'recordType',
    'schemaVersion',
    'ownerUid',
    'grantId',
    'recipientDeviceId',
    'createdByDeviceId',
    'keyVersion',
    'wrapAlg',
    'wrappedKeyCiphertext',
    'wrappedKeyHash',
    'createdAt',
    'revokedAt',
    'revokedByDeviceId'
])
const PUBLIC_KEY_KEYS = new Set(['alg', 'spki', 'fingerprint'])
const DEVICE_ROLES = new Set(['phone', 'web-planner'])
const SYNC_SCOPES = new Set(['read', 'patch-upload'])
const DEVICE_STATUSES = new Set(['pending', 'active', 'revoked'])

const textEncoder = new TextEncoder()
const textDecoder = new TextDecoder()

function fail(message) {
    throw new Error(message)
}

function isPlainObject(value) {
    return !!value && typeof value === 'object' && !Array.isArray(value)
}

function clone(value) {
    return value == null ? value : JSON.parse(JSON.stringify(value))
}

function requireObject(value, fieldName) {
    if (!isPlainObject(value)) fail(`${fieldName} must be an object.`)
    return value
}

function jsonByteLength(value) {
    return textEncoder.encode(JSON.stringify(value)).length
}

function requireSubtle(cryptoApi = globalThis.crypto) {
    if (!cryptoApi?.subtle || typeof cryptoApi.getRandomValues !== 'function') {
        fail('Hosted phone planner requires WebCrypto.')
    }
    return cryptoApi.subtle
}

function randomBytes(length, cryptoApi = globalThis.crypto) {
    if (!cryptoApi?.getRandomValues) fail('Hosted phone planner requires WebCrypto randomness.')
    const bytes = new Uint8Array(length)
    cryptoApi.getRandomValues(bytes)
    return bytes
}

function bytesFrom(value, fieldName = 'bytes') {
    if (value instanceof Uint8Array) return new Uint8Array(value)
    if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength)
    if (value instanceof ArrayBuffer) return new Uint8Array(value)
    if (typeof value === 'string') return textEncoder.encode(value)
    fail(`${fieldName} must be bytes.`)
}

function base64Encode(bytes) {
    const input = bytesFrom(bytes)
    if (typeof Buffer !== 'undefined') return Buffer.from(input).toString('base64')
    let binary = ''
    for (let index = 0; index < input.length; index += 0x8000) {
        binary += String.fromCharCode(...input.slice(index, index + 0x8000))
    }
    return btoa(binary)
}

function base64Decode(value) {
    if (typeof Buffer !== 'undefined') return new Uint8Array(Buffer.from(value, 'base64'))
    const binary = atob(value)
    const bytes = new Uint8Array(binary.length)
    for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index)
    return bytes
}

export function encodeBase64Url(bytes) {
    return base64Encode(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}

export function decodeBase64Url(value, fieldName = 'base64url') {
    if (typeof value !== 'string' || !BASE64URL_PATTERN.test(value)) fail(`${fieldName} must be base64url data.`)
    const padded = value.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(value.length / 4) * 4, '=')
    return base64Decode(padded)
}

function normalizeString(value, fieldName, { required = true, max = 256 } = {}) {
    if (value == null || value === '') {
        if (required) fail(`${fieldName} is required.`)
        return ''
    }
    if (typeof value !== 'string') fail(`${fieldName} must be a string.`)
    if (value.includes('\0') || /[\u0000-\u001F\u007F]/.test(value)) fail(`${fieldName} contains unsupported control characters.`)
    const text = value.trim()
    if (required && !text) fail(`${fieldName} is required.`)
    if (text.length > max) fail(`${fieldName} is too long.`)
    return text
}

function normalizeTimestamp(value, fieldName, { allowNull = false } = {}) {
    if (value == null) {
        if (allowNull) return null
        fail(`${fieldName} is required.`)
    }
    if (typeof value !== 'number' || !Number.isFinite(value) || value < 0 || value > MAX_TIMESTAMP) {
        fail(`${fieldName} must be a non-negative timestamp.`)
    }
    return Math.floor(value)
}

function normalizeInteger(value, fieldName, { positive = false } = {}) {
    if (!Number.isSafeInteger(value) || value < (positive ? 1 : 0)) {
        fail(`${fieldName} must be a ${positive ? 'positive' : 'non-negative'} safe integer.`)
    }
    return value
}

function normalizeOwnerUid(value, fieldName = 'ownerUid') {
    const text = normalizeString(value, fieldName, { max: 128 })
    if (!OWNER_UID_PATTERN.test(text)) fail(`${fieldName} must be a safe Firebase uid.`)
    return text
}

function normalizeSafeId(value, fieldName, prefixes, { nullable = false } = {}) {
    if ((value == null || value === '') && nullable) return null
    const id = normalizeString(value, fieldName, { max: 96 })
    if (!SAFE_ID_PATTERN.test(id)) fail(`${fieldName} must be a safe id.`)
    if (prefixes && !prefixes.some(prefix => id.startsWith(prefix))) {
        fail(`${fieldName} must use an allowed safe id prefix.`)
    }
    return id
}

function rejectUnknownKeys(value, allowed, fieldName) {
    for (const key of Object.keys(value || {})) {
        if (!allowed.has(key)) fail(`${fieldName}.${key} is not supported.`)
    }
}

function normalizeDocType(value) {
    const docType = normalizeString(value, 'cloud sync envelope.docType', { max: 40 })
    if (!DOC_TYPES.has(docType)) fail('cloud sync envelope.docType is not supported.')
    return docType
}

export function canonicalizeCloudSyncValue(value) {
    if (Array.isArray(value)) return value.map(canonicalizeCloudSyncValue)
    if (isPlainObject(value)) {
        const next = {}
        for (const key of Object.keys(value).sort()) {
            const nested = value[key]
            next[key] = nested === undefined ? null : canonicalizeCloudSyncValue(nested)
        }
        return next
    }
    if (value === undefined) return null
    if (typeof value === 'number' && !Number.isFinite(value)) fail('Canonical cloud sync numbers must be finite.')
    return value
}

export function serializeCanonicalCloudSyncMetadata(value) {
    return JSON.stringify(canonicalizeCloudSyncValue(value))
}

export async function sha256Base64Url(value, cryptoApi = globalThis.crypto) {
    const subtle = requireSubtle(cryptoApi)
    const digest = await subtle.digest('SHA-256', bytesFrom(value))
    return encodeBase64Url(new Uint8Array(digest))
}

async function documentHash(document, cryptoApi) {
    return sha256Base64Url(serializeCanonicalCloudSyncMetadata(document), cryptoApi)
}

function emptyToNull(value) {
    return value == null || value === '' ? null : value
}

export async function createCloudSyncAdminSignatureMetadata({
    operation,
    ownerUid,
    actorDeviceId,
    targetDeviceId,
    deviceSequence,
    enrollmentEpoch,
    keyVersion,
    documentId,
    document,
    requestedAt
}, cryptoApi = globalThis.crypto) {
    return serializeCanonicalCloudSyncMetadata({
        product: 'wipesnap',
        schemaVersion: CLOUD_SYNC_INGESTION_SCHEMA_VERSION,
        operation,
        ownerUid,
        actorDeviceId: emptyToNull(actorDeviceId),
        targetDeviceId,
        deviceSequence,
        enrollmentEpoch,
        keyVersion,
        documentId,
        documentHash: await documentHash(document, cryptoApi),
        requestedAt
    })
}

export async function createCloudSyncIngestionSignatureMetadata({
    operation,
    ownerUid,
    deviceId,
    deviceSequence,
    enrollmentEpoch,
    keyVersion,
    documentId,
    document,
    requestedAt
}, cryptoApi = globalThis.crypto) {
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
        documentHash: await documentHash(document, cryptoApi),
        requestedAt
    })
}

export function createCloudSyncDeviceSessionClaimDocument({
    requestId,
    deviceId,
    keyGrantId,
    pairingChallengeHash
}) {
    return {
        product: 'wipesnap',
        schemaVersion: CLOUD_SYNC_INGESTION_SCHEMA_VERSION,
        purpose: 'device-session-claim',
        requestId: normalizeSafeId(requestId, 'requestId', ['dev_']),
        deviceId: normalizeSafeId(deviceId, 'deviceId', ['dev_']),
        keyGrantId: normalizeSafeId(keyGrantId, 'keyGrantId', ['grant_']),
        pairingChallengeHash: normalizeString(pairingChallengeHash, 'pairingChallengeHash', { max: 128 })
    }
}

export async function signCloudSyncCanonicalMetadataBrowser({
    canonicalMetadata,
    privateKey,
    cryptoApi = globalThis.crypto
}) {
    const subtle = requireSubtle(cryptoApi)
    if (!privateKey) fail('signing key is required.')
    const signature = await subtle.sign(
        { name: 'ECDSA', hash: 'SHA-256' },
        privateKey,
        textEncoder.encode(canonicalMetadata)
    )
    const bytes = new Uint8Array(signature)
    if (bytes.length !== 64) fail('WebCrypto ECDSA signature must be 64-byte P-1363 data.')
    return encodeBase64Url(bytes)
}

export async function verifyCloudSyncCanonicalMetadataBrowser({
    canonicalMetadata,
    signature,
    publicKey,
    cryptoApi = globalThis.crypto
}) {
    const subtle = requireSubtle(cryptoApi)
    return subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        publicKey,
        decodeBase64Url(signature, 'cloud sync signature.value'),
        textEncoder.encode(canonicalMetadata)
    )
}

export async function generatePhonePlannerCloudKeyPair(cryptoApi = globalThis.crypto) {
    const subtle = requireSubtle(cryptoApi)
    const signing = await subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['sign', 'verify']
    )
    const wrapping = await subtle.generateKey(
        {
            name: 'RSA-OAEP',
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: 'SHA-256'
        },
        false,
        ['decrypt']
    )
    if (signing.privateKey.extractable !== false || wrapping.privateKey.extractable !== false) {
        fail('Phone planner private device keys must be non-extractable.')
    }
    return { signing, wrapping }
}

export async function publicKeyRecord(publicKey, alg, cryptoApi = globalThis.crypto) {
    const subtle = requireSubtle(cryptoApi)
    const spki = new Uint8Array(await subtle.exportKey('spki', publicKey))
    return {
        alg,
        spki: encodeBase64Url(spki),
        fingerprint: await sha256Base64Url(spki, cryptoApi)
    }
}

export async function importSigningPublicKeyRecord(record, cryptoApi = globalThis.crypto) {
    const keyRecord = normalizePublicKeyRecord(record, 'signingPublicKey', CLOUD_SYNC_SIGNING_ALGORITHM)
    return requireSubtle(cryptoApi).importKey(
        'spki',
        decodeBase64Url(keyRecord.spki, 'signingPublicKey.spki'),
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['verify']
    )
}

function normalizePublicKeyRecord(input, fieldName, expectedAlg) {
    const record = requireObject(input, fieldName)
    rejectUnknownKeys(record, PUBLIC_KEY_KEYS, fieldName)
    if (record.alg !== expectedAlg) fail(`${fieldName}.alg is not supported.`)
    return {
        alg: expectedAlg,
        spki: normalizeString(record.spki, `${fieldName}.spki`, { max: 4096 }),
        fingerprint: normalizeString(record.fingerprint, `${fieldName}.fingerprint`, { max: 128 })
    }
}

export function validateCloudSyncDeviceRecordForPhone(input) {
    const device = requireObject(input, 'cloud sync device')
    rejectUnknownKeys(device, DEVICE_RECORD_KEYS, 'cloud sync device')
    if (device.product !== 'wipesnap') fail('cloud sync device.product is not supported.')
    if (device.recordType !== CLOUD_SYNC_DEVICE_RECORD_TYPE) fail('cloud sync device.recordType is not supported.')
    if (device.schemaVersion !== CLOUD_SYNC_SCHEMA_VERSION) fail('cloud sync device.schemaVersion is not supported.')
    const role = normalizeString(device.role, 'cloud sync device.role', { max: 40 })
    if (!['desktop', 'phone', 'web-planner'].includes(role)) fail('cloud sync device.role is not supported.')
    const status = normalizeString(device.status, 'cloud sync device.status', { max: 40 })
    if (!DEVICE_STATUSES.has(status)) fail('cloud sync device.status is not supported.')
    const syncScopes = Array.isArray(device.syncScopes) ? device.syncScopes : fail('cloud sync device.syncScopes must be an array.')
    return {
        product: 'wipesnap',
        recordType: CLOUD_SYNC_DEVICE_RECORD_TYPE,
        schemaVersion: CLOUD_SYNC_SCHEMA_VERSION,
        ownerUid: normalizeOwnerUid(device.ownerUid, 'cloud sync device.ownerUid'),
        deviceId: normalizeSafeId(device.deviceId, 'cloud sync device.deviceId', ['dev_']),
        role,
        status,
        platform: normalizeString(device.platform, 'cloud sync device.platform', { max: 40 }),
        syncScopes: syncScopes.map((scope, index) => {
            const text = normalizeString(scope, `cloud sync device.syncScopes[${index}]`, { max: 40 })
            if (!['read', 'snapshot-upload', 'patch-upload'].includes(text)) fail('cloud sync device.syncScopes contains an unsupported scope.')
            return text
        }),
        signingPublicKey: normalizePublicKeyRecord(device.signingPublicKey, 'cloud sync device.signingPublicKey', CLOUD_SYNC_SIGNING_ALGORITHM),
        wrapPublicKey: normalizePublicKeyRecord(device.wrapPublicKey, 'cloud sync device.wrapPublicKey', 'RSA-OAEP-256'),
        enrollmentEpoch: normalizeInteger(device.enrollmentEpoch, 'cloud sync device.enrollmentEpoch', { positive: true }),
        keyVersion: normalizeInteger(device.keyVersion, 'cloud sync device.keyVersion', { positive: true }),
        deviceSequence: normalizeInteger(device.deviceSequence, 'cloud sync device.deviceSequence'),
        createdAt: normalizeTimestamp(device.createdAt, 'cloud sync device.createdAt'),
        updatedAt: normalizeTimestamp(device.updatedAt, 'cloud sync device.updatedAt'),
        revokedAt: normalizeTimestamp(device.revokedAt, 'cloud sync device.revokedAt', { allowNull: true }),
        revokedByDeviceId: normalizeSafeId(device.revokedByDeviceId, 'cloud sync device.revokedByDeviceId', ['dev_'], { nullable: true })
    }
}

export function createCloudSyncKeyGrantIdForDevice({ deviceId, keyVersion }) {
    const safeDeviceId = normalizeSafeId(deviceId, 'deviceId', ['dev_'])
    const version = normalizeInteger(keyVersion, 'keyVersion', { positive: true })
    const grantId = `grant_${safeDeviceId.slice(4)}_v${version}`
    return normalizeSafeId(grantId.slice(0, 96), 'grantId', ['grant_'])
}

export async function createPendingWebPlannerDeviceRecord({
    ownerUid,
    deviceId,
    keyPair,
    keyVersion = 1,
    now = Date.now(),
    cryptoApi = globalThis.crypto
} = {}) {
    const timestamp = normalizeTimestamp(now, 'now')
    const keys = keyPair || await generatePhonePlannerCloudKeyPair(cryptoApi)
    const device = {
        product: 'wipesnap',
        recordType: CLOUD_SYNC_DEVICE_RECORD_TYPE,
        schemaVersion: CLOUD_SYNC_SCHEMA_VERSION,
        ownerUid: normalizeOwnerUid(ownerUid),
        deviceId: normalizeSafeId(deviceId, 'deviceId', ['dev_']),
        role: 'web-planner',
        status: 'pending',
        platform: 'web-pwa',
        syncScopes: ['read', 'patch-upload'],
        signingPublicKey: await publicKeyRecord(keys.signing.publicKey, CLOUD_SYNC_SIGNING_ALGORITHM, cryptoApi),
        wrapPublicKey: await publicKeyRecord(keys.wrapping.publicKey, 'RSA-OAEP-256', cryptoApi),
        enrollmentEpoch: 1,
        keyVersion: normalizeInteger(keyVersion, 'keyVersion', { positive: true }),
        deviceSequence: 1,
        createdAt: timestamp,
        updatedAt: timestamp,
        revokedAt: null,
        revokedByDeviceId: null
    }
    return { device: validateCloudSyncDeviceRecordForPhone(device), keyPair: keys }
}

export function createWebPlannerDeviceId(cryptoApi = globalThis.crypto) {
    return `dev_web_${encodeBase64Url(randomBytes(18, cryptoApi))}`
}

export function createPairingChallenge(cryptoApi = globalThis.crypto) {
    return encodeBase64Url(randomBytes(18, cryptoApi))
}

function createAadMetadata(envelope) {
    return {
        envelopeVersion: envelope.envelopeVersion,
        ownerUid: envelope.ownerUid,
        docType: envelope.docType,
        snapshotId: envelope.snapshotId,
        patchId: envelope.patchId,
        revisionId: envelope.revisionId,
        baseRevisionId: envelope.baseRevisionId,
        deviceId: envelope.deviceId,
        deviceSequence: envelope.deviceSequence,
        keyVersion: envelope.keyVersion
    }
}

function createSignatureMetadata(envelope) {
    return {
        ...createAadMetadata(envelope),
        product: envelope.product,
        recordType: envelope.recordType,
        schemaVersion: envelope.schemaVersion,
        createdAt: envelope.createdAt,
        updatedAt: envelope.updatedAt,
        encryption: envelope.encryption,
        ciphertextHash: envelope.ciphertextHash,
        tombstone: envelope.tombstone,
        conflict: envelope.conflict
    }
}

export function canonicalCloudSyncAad(envelope) {
    return serializeCanonicalCloudSyncMetadata(createAadMetadata(envelope))
}

export function canonicalCloudSyncSignatureMetadata(envelope) {
    return serializeCanonicalCloudSyncMetadata(createSignatureMetadata(envelope))
}

function payloadIdsForDocType(payload, docType) {
    if (docType === CLOUD_SYNC_SNAPSHOT_DOC_TYPE) {
        return {
            snapshotId: payload.snapshotId,
            patchId: null,
            revisionId: payload.revisionId,
            baseRevisionId: payload.baseRevisionId,
            deviceId: payload.sourceDeviceId
        }
    }
    if (docType === CLOUD_SYNC_PATCH_DOC_TYPE) {
        return {
            snapshotId: null,
            patchId: payload.patchId,
            revisionId: payload.patchRevisionId,
            baseRevisionId: payload.baseSnapshotRevisionId,
            deviceId: payload.authorDeviceId
        }
    }
    fail('cloud sync doc type is not supported.')
}

function validatePayloadForDocType(payload, docType, snapshotForPatch = null) {
    if (docType === CLOUD_SYNC_SNAPSHOT_DOC_TYPE) return validateSanitizedPresetSnapshotForPhone(payload)
    if (docType === CLOUD_SYNC_PATCH_DOC_TYPE) return validateSafePresetPatchForPhone(payload, snapshotForPatch || undefined)
    fail('cloud sync doc type is not supported.')
}

function validatePayloadMatchesEnvelope(payload, envelope) {
    const ids = payloadIdsForDocType(payload, envelope.docType)
    if (ids.snapshotId !== envelope.snapshotId) fail('cloud sync payload snapshot id does not match envelope.')
    if (ids.patchId !== envelope.patchId) fail('cloud sync payload patch id does not match envelope.')
    if (ids.revisionId !== envelope.revisionId) fail('cloud sync payload revision id does not match envelope.')
    if ((ids.baseRevisionId || null) !== (envelope.baseRevisionId || null)) fail('cloud sync payload base revision does not match envelope.')
    if (ids.deviceId !== envelope.deviceId) fail('cloud sync payload device id does not match envelope.')
}

async function importSyncRootKey(syncRootKey, cryptoApi = globalThis.crypto) {
    if (syncRootKey && typeof syncRootKey === 'object' && syncRootKey.type === 'secret' && syncRootKey.algorithm?.name === 'HKDF') {
        return syncRootKey
    }
    const bytes = bytesFrom(syncRootKey, 'syncRootKey')
    if (bytes.length !== AES_KEY_BYTES) fail('syncRootKey must be exactly 32 bytes.')
    return requireSubtle(cryptoApi).importKey('raw', bytes, 'HKDF', false, ['deriveKey', 'deriveBits'])
}

export async function deriveCloudSyncContentKeyBrowser({
    syncRootKey,
    docType,
    revisionId,
    keyVersion,
    salt,
    cryptoApi = globalThis.crypto
}) {
    const subtle = requireSubtle(cryptoApi)
    const rootKey = await importSyncRootKey(syncRootKey, cryptoApi)
    const info = textEncoder.encode(
        `wipesnap.cloud-sync.v1.${normalizeDocType(docType)}.${normalizeSafeId(revisionId, 'revisionId', ['srev_', 'patchrev_'])}.keyVersion.${normalizeInteger(keyVersion, 'keyVersion', { positive: true })}`
    )
    return subtle.deriveKey(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: bytesFrom(salt, 'salt'),
            info
        },
        rootKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    )
}

export async function createEncryptedCloudSyncEnvelopeBrowser({
    docType,
    payload,
    ownerUid,
    device,
    syncRootKey,
    signingPrivateKey,
    now = Date.now(),
    snapshotForPatch = null,
    cryptoApi = globalThis.crypto
} = {}) {
    const type = normalizeDocType(docType)
    const normalizedPayload = validatePayloadForDocType(payload, type, snapshotForPatch)
    const ids = payloadIdsForDocType(normalizedPayload, type)
    const normalizedDevice = validateCloudSyncDeviceRecordForPhone(device)
    if (!DEVICE_ROLES.has(normalizedDevice.role)) fail('Phone cloud sync envelopes require a phone or web planner device.')
    if (!normalizedDevice.syncScopes.includes('patch-upload') && type === CLOUD_SYNC_PATCH_DOC_TYPE) {
        fail('Phone cloud sync device cannot upload patches.')
    }
    if (normalizedDevice.ownerUid !== normalizeOwnerUid(ownerUid)) fail('Envelope owner must match the device owner.')
    if (ids.deviceId !== normalizedDevice.deviceId) fail('Envelope payload author must match the active phone device.')

    const salt = randomBytes(HKDF_SALT_BYTES, cryptoApi)
    const iv = randomBytes(AES_GCM_IV_BYTES, cryptoApi)
    const deviceSequence = normalizeInteger(normalizedDevice.deviceSequence + 1, 'deviceSequence')
    const envelopeBase = {
        product: 'wipesnap',
        recordType: CLOUD_SYNC_ENVELOPE_RECORD_TYPE,
        schemaVersion: CLOUD_SYNC_SCHEMA_VERSION,
        envelopeVersion: CLOUD_SYNC_ENVELOPE_VERSION,
        docType: type,
        ownerUid: normalizedDevice.ownerUid,
        snapshotId: ids.snapshotId,
        patchId: ids.patchId,
        revisionId: ids.revisionId,
        baseRevisionId: ids.baseRevisionId || null,
        deviceId: normalizedDevice.deviceId,
        deviceSequence,
        keyVersion: normalizedDevice.keyVersion,
        createdAt: normalizeTimestamp(now, 'now'),
        updatedAt: normalizeTimestamp(now, 'now'),
        tombstone: null,
        conflict: null
    }
    const aad = textEncoder.encode(canonicalCloudSyncAad(envelopeBase))
    const key = await deriveCloudSyncContentKeyBrowser({
        syncRootKey,
        docType: type,
        revisionId: envelopeBase.revisionId,
        keyVersion: envelopeBase.keyVersion,
        salt,
        cryptoApi
    })
    const plaintext = textEncoder.encode(serializeCanonicalCloudSyncMetadata(normalizedPayload))
    const encrypted = new Uint8Array(await requireSubtle(cryptoApi).encrypt(
        { name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 },
        key,
        plaintext
    ))
    const ciphertext = encrypted.slice(0, encrypted.length - AES_GCM_TAG_BYTES)
    const tag = encrypted.slice(encrypted.length - AES_GCM_TAG_BYTES)
    const envelope = {
        ...envelopeBase,
        encryption: {
            alg: CLOUD_SYNC_CONTENT_ENCRYPTION,
            kdf: CLOUD_SYNC_KEY_DERIVATION,
            salt: encodeBase64Url(salt),
            iv: encodeBase64Url(iv),
            tag: encodeBase64Url(tag)
        },
        ciphertext: encodeBase64Url(ciphertext),
        ciphertextHash: await sha256Base64Url(ciphertext, cryptoApi)
    }
    envelope.signature = {
        alg: CLOUD_SYNC_SIGNING_ALGORITHM,
        keyId: normalizedDevice.deviceId,
        value: await signCloudSyncCanonicalMetadataBrowser({
            canonicalMetadata: canonicalCloudSyncSignatureMetadata(envelope),
            privateKey: signingPrivateKey,
            cryptoApi
        })
    }
    return validateCloudSyncEnvelopeForPhone(envelope)
}

function normalizeEncryption(input) {
    const encryption = requireObject(input, 'cloud sync envelope.encryption')
    rejectUnknownKeys(encryption, ENCRYPTION_KEYS, 'cloud sync envelope.encryption')
    if (encryption.alg !== CLOUD_SYNC_CONTENT_ENCRYPTION) fail('cloud sync envelope.encryption.alg is not supported.')
    if (encryption.kdf !== CLOUD_SYNC_KEY_DERIVATION) fail('cloud sync envelope.encryption.kdf is not supported.')
    return {
        alg: CLOUD_SYNC_CONTENT_ENCRYPTION,
        kdf: CLOUD_SYNC_KEY_DERIVATION,
        salt: encodeBase64Url(decodeBase64Url(encryption.salt, 'cloud sync envelope.encryption.salt')),
        iv: encodeBase64Url(decodeBase64Url(encryption.iv, 'cloud sync envelope.encryption.iv')),
        tag: encodeBase64Url(decodeBase64Url(encryption.tag, 'cloud sync envelope.encryption.tag'))
    }
}

function normalizeSignature(input) {
    const signature = requireObject(input, 'cloud sync envelope.signature')
    rejectUnknownKeys(signature, SIGNATURE_KEYS, 'cloud sync envelope.signature')
    if (signature.alg !== CLOUD_SYNC_SIGNING_ALGORITHM) fail('cloud sync envelope.signature.alg is not supported.')
    const value = encodeBase64Url(decodeBase64Url(signature.value, 'cloud sync envelope.signature.value'))
    if (decodeBase64Url(value).length !== 64) fail('cloud sync envelope.signature.value must be a 64-byte signature.')
    return {
        alg: CLOUD_SYNC_SIGNING_ALGORITHM,
        keyId: normalizeSafeId(signature.keyId, 'cloud sync envelope.signature.keyId', ['dev_']),
        value
    }
}

export function validateCloudSyncEnvelopeForPhone(input, options = {}) {
    const envelope = requireObject(clone(input), 'cloud sync envelope')
    rejectUnknownKeys(envelope, ENVELOPE_KEYS, 'cloud sync envelope')
    if (jsonByteLength(envelope) > MAX_ENVELOPE_JSON_BYTES) fail('cloud sync envelope is too large.')
    if (envelope.product !== 'wipesnap') fail('cloud sync envelope.product is not supported.')
    if (envelope.recordType !== CLOUD_SYNC_ENVELOPE_RECORD_TYPE) fail('cloud sync envelope.recordType is not supported.')
    if (envelope.schemaVersion !== CLOUD_SYNC_SCHEMA_VERSION) fail('cloud sync envelope.schemaVersion is not supported.')
    if (envelope.envelopeVersion !== CLOUD_SYNC_ENVELOPE_VERSION) fail('cloud sync envelope.envelopeVersion is not supported.')
    const docType = normalizeDocType(envelope.docType)
    if (options.expectedDocType && docType !== options.expectedDocType) fail('cloud sync envelope doc type does not match.')
    const revisionId = normalizeSafeId(
        envelope.revisionId,
        'cloud sync envelope.revisionId',
        docType === CLOUD_SYNC_SNAPSHOT_DOC_TYPE ? ['srev_'] : ['patchrev_']
    )
    const keyVersion = normalizeInteger(envelope.keyVersion, 'cloud sync envelope.keyVersion', { positive: true })
    if (options.activeKeyVersion != null && keyVersion !== options.activeKeyVersion) fail('cloud sync envelope uses a stale key version.')
    const ciphertext = encodeBase64Url(decodeBase64Url(envelope.ciphertext, 'cloud sync envelope.ciphertext'))
    if (decodeBase64Url(ciphertext).length > MAX_CIPHERTEXT_BYTES) fail('cloud sync envelope.ciphertext is too large.')
    return {
        product: 'wipesnap',
        recordType: CLOUD_SYNC_ENVELOPE_RECORD_TYPE,
        schemaVersion: CLOUD_SYNC_SCHEMA_VERSION,
        envelopeVersion: CLOUD_SYNC_ENVELOPE_VERSION,
        docType,
        ownerUid: normalizeOwnerUid(envelope.ownerUid, 'cloud sync envelope.ownerUid'),
        snapshotId: normalizeSafeId(envelope.snapshotId, 'cloud sync envelope.snapshotId', ['snap_'], {
            nullable: docType !== CLOUD_SYNC_SNAPSHOT_DOC_TYPE
        }),
        patchId: normalizeSafeId(envelope.patchId, 'cloud sync envelope.patchId', ['patch_'], {
            nullable: docType !== CLOUD_SYNC_PATCH_DOC_TYPE
        }),
        revisionId,
        baseRevisionId: normalizeSafeId(envelope.baseRevisionId, 'cloud sync envelope.baseRevisionId', ['srev_', 'patchrev_'], { nullable: true }),
        deviceId: normalizeSafeId(envelope.deviceId, 'cloud sync envelope.deviceId', ['dev_']),
        deviceSequence: normalizeInteger(envelope.deviceSequence, 'cloud sync envelope.deviceSequence'),
        keyVersion,
        createdAt: normalizeTimestamp(envelope.createdAt, 'cloud sync envelope.createdAt'),
        updatedAt: normalizeTimestamp(envelope.updatedAt, 'cloud sync envelope.updatedAt'),
        encryption: normalizeEncryption(envelope.encryption),
        ciphertext,
        ciphertextHash: normalizeString(envelope.ciphertextHash, 'cloud sync envelope.ciphertextHash', { max: 128 }),
        signature: normalizeSignature(envelope.signature),
        tombstone: envelope.tombstone ?? null,
        conflict: envelope.conflict ?? null
    }
}

export async function decryptCloudSyncEnvelopeBrowser({
    envelope,
    syncRootKey,
    verifyPublicKeyRecord,
    expectedOwnerUid,
    expectedDocType,
    activeKeyVersion,
    snapshotForPatch = null,
    cryptoApi = globalThis.crypto
} = {}) {
    const normalized = validateCloudSyncEnvelopeForPhone(envelope, { expectedDocType, activeKeyVersion })
    if (expectedOwnerUid != null && normalized.ownerUid !== expectedOwnerUid) {
        fail('cloud sync envelope owner uid does not match.')
    }
    const ciphertext = decodeBase64Url(normalized.ciphertext, 'cloud sync envelope.ciphertext')
    if (await sha256Base64Url(ciphertext, cryptoApi) !== normalized.ciphertextHash) {
        fail('cloud sync envelope ciphertext hash does not match ciphertext.')
    }
    const verifyKey = await importSigningPublicKeyRecord(verifyPublicKeyRecord, cryptoApi)
    const signatureValid = await verifyCloudSyncCanonicalMetadataBrowser({
        canonicalMetadata: canonicalCloudSyncSignatureMetadata(normalized),
        signature: normalized.signature.value,
        publicKey: verifyKey,
        cryptoApi
    })
    if (!signatureValid) fail('cloud sync envelope signature is not valid.')

    const salt = decodeBase64Url(normalized.encryption.salt, 'cloud sync envelope.encryption.salt')
    const iv = decodeBase64Url(normalized.encryption.iv, 'cloud sync envelope.encryption.iv')
    const tag = decodeBase64Url(normalized.encryption.tag, 'cloud sync envelope.encryption.tag')
    const key = await deriveCloudSyncContentKeyBrowser({
        syncRootKey,
        docType: normalized.docType,
        revisionId: normalized.revisionId,
        keyVersion: normalized.keyVersion,
        salt,
        cryptoApi
    })
    let plaintext
    try {
        const sealed = new Uint8Array(ciphertext.length + tag.length)
        sealed.set(ciphertext, 0)
        sealed.set(tag, ciphertext.length)
        plaintext = await requireSubtle(cryptoApi).decrypt(
            {
                name: 'AES-GCM',
                iv,
                additionalData: textEncoder.encode(canonicalCloudSyncAad(normalized)),
                tagLength: 128
            },
            key,
            sealed
        )
    } catch (_) {
        fail('cloud sync envelope could not be decrypted or authenticated.')
    }
    let payload
    try {
        payload = JSON.parse(textDecoder.decode(plaintext))
    } catch (_) {
        fail('cloud sync envelope plaintext was not valid JSON.')
    }
    const normalizedPayload = validatePayloadForDocType(payload, normalized.docType, snapshotForPatch)
    validatePayloadMatchesEnvelope(normalizedPayload, normalized)
    return { envelope: normalized, payload: normalizedPayload }
}

export function validateCloudSyncKeyGrantForPhone(input) {
    const grant = requireObject(input, 'cloud sync key grant')
    rejectUnknownKeys(grant, KEY_GRANT_KEYS, 'cloud sync key grant')
    if (grant.product !== 'wipesnap') fail('cloud sync key grant.product is not supported.')
    if (grant.recordType !== CLOUD_SYNC_KEY_GRANT_RECORD_TYPE) fail('cloud sync key grant.recordType is not supported.')
    if (grant.schemaVersion !== CLOUD_SYNC_SCHEMA_VERSION) fail('cloud sync key grant.schemaVersion is not supported.')
    if (grant.wrapAlg !== 'RSA-OAEP-256') fail('cloud sync key grant.wrapAlg is not supported.')
    return {
        product: 'wipesnap',
        recordType: CLOUD_SYNC_KEY_GRANT_RECORD_TYPE,
        schemaVersion: CLOUD_SYNC_SCHEMA_VERSION,
        ownerUid: normalizeOwnerUid(grant.ownerUid, 'cloud sync key grant.ownerUid'),
        grantId: normalizeSafeId(grant.grantId, 'cloud sync key grant.grantId', ['grant_']),
        recipientDeviceId: normalizeSafeId(grant.recipientDeviceId, 'cloud sync key grant.recipientDeviceId', ['dev_']),
        createdByDeviceId: normalizeSafeId(grant.createdByDeviceId, 'cloud sync key grant.createdByDeviceId', ['dev_']),
        keyVersion: normalizeInteger(grant.keyVersion, 'cloud sync key grant.keyVersion', { positive: true }),
        wrapAlg: 'RSA-OAEP-256',
        wrappedKeyCiphertext: encodeBase64Url(decodeBase64Url(grant.wrappedKeyCiphertext, 'cloud sync key grant.wrappedKeyCiphertext')),
        wrappedKeyHash: normalizeString(grant.wrappedKeyHash, 'cloud sync key grant.wrappedKeyHash', { max: 128 }),
        createdAt: normalizeTimestamp(grant.createdAt, 'cloud sync key grant.createdAt'),
        revokedAt: normalizeTimestamp(grant.revokedAt, 'cloud sync key grant.revokedAt', { allowNull: true }),
        revokedByDeviceId: normalizeSafeId(grant.revokedByDeviceId, 'cloud sync key grant.revokedByDeviceId', ['dev_'], { nullable: true })
    }
}

export async function unwrapCloudSyncRootKeyGrant({
    keyGrant,
    wrappingPrivateKey,
    expectedOwnerUid,
    expectedDeviceId,
    expectedKeyVersion,
    cryptoApi = globalThis.crypto
} = {}) {
    const grant = validateCloudSyncKeyGrantForPhone(keyGrant)
    if (expectedOwnerUid != null && grant.ownerUid !== expectedOwnerUid) fail('key grant owner does not match.')
    if (expectedDeviceId != null && grant.recipientDeviceId !== expectedDeviceId) fail('key grant recipient does not match.')
    if (expectedKeyVersion != null && grant.keyVersion !== expectedKeyVersion) fail('key grant key version does not match.')
    if (grant.revokedAt != null) fail('key grant has been revoked.')
    const wrapped = decodeBase64Url(grant.wrappedKeyCiphertext, 'cloud sync key grant.wrappedKeyCiphertext')
    if (await sha256Base64Url(wrapped, cryptoApi) !== grant.wrappedKeyHash) fail('key grant wrapped key hash does not match.')
    let raw = null
    try {
        raw = new Uint8Array(await requireSubtle(cryptoApi).decrypt(
            { name: 'RSA-OAEP' },
            wrappingPrivateKey,
            wrapped
        ))
        if (raw.length !== AES_KEY_BYTES) fail('unwrapped sync root key has an invalid length.')
        const key = await importSyncRootKey(raw, cryptoApi)
        return {
            syncRootKey: key,
            keyVersion: grant.keyVersion,
            rawKeyBytesStored: false
        }
    } finally {
        if (raw) raw.fill(0)
    }
}

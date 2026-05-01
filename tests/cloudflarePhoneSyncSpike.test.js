import assert from 'assert/strict'
import { readFileSync } from 'fs'
import { webcrypto } from 'crypto'
import { test } from 'node:test'
import {
    CLOUD_SYNC_CONTENT_ENCRYPTION,
    CLOUD_SYNC_DEVICE_RECORD_TYPE,
    CLOUD_SYNC_ENVELOPE_RECORD_TYPE,
    CLOUD_SYNC_ENVELOPE_VERSION,
    CLOUD_SYNC_KEY_DERIVATION,
    CLOUD_SYNC_KEY_GRANT_RECORD_TYPE,
    CLOUD_SYNC_PATCH_DOC_TYPE,
    CLOUD_SYNC_SCHEMA_VERSION,
    CLOUD_SYNC_SIGNING_ALGORITHM,
    CLOUD_SYNC_SNAPSHOT_DOC_TYPE,
    createPendingWebPlannerDeviceRecord,
    generatePhonePlannerCloudKeyPair,
    publicKeyRecord,
    signCloudSyncCanonicalMetadataBrowser
} from '../src/phone-planner/phonePlannerCloudCrypto.js'
import {
    CLOUDFLARE_SYNC_LIMITS,
    CLOUDFLARE_SYNC_OPERATIONS,
    CLOUDFLARE_SYNC_PROVIDER_ID,
    CLOUDFLARE_SYNC_SIGNING_HEADERS,
    CLOUDFLARE_SYNC_STORAGE_DECISION
} from '../src/cloudflare-sync/cloudflareSyncConstants.js'
import {
    createCloudflareCanonicalRequestMetadata,
    sha256Base64Url,
    verifyCloudflareCanonicalRequest
} from '../src/cloudflare-sync/cloudflareCanonicalRequest.js'
import {
    CloudflareSyncError,
    cloudflareSyncBackendContainsForbiddenMaterial,
    createCloudflareSyncWorkerCore
} from '../src/cloudflare-sync/cloudflareSyncWorkerCore.js'
import {
    getCloudSyncProviderPlan,
    validateCloudSyncProviderId
} from '../src/main/cloudSyncProviderPlan.js'
import { validatePhonePlannerCloudProviderConfig } from '../src/phone-planner/phonePlannerCloudProvider.js'
import { validatePhonePlannerCloudflareConfig } from '../src/phone-planner/phonePlannerCloudflareConfig.js'

const OWNER = 'cf_owner_phase31_2'
const OTHER_OWNER = 'cf_owner_other'
const NOW = 1770000000000
const HOST = 'https://sync.example.test'

function clone(value) {
    return value == null ? value : JSON.parse(JSON.stringify(value))
}

function b64(bytes) {
    return Buffer.from(bytes).toString('base64url')
}

function forbiddenCloudMaterialPattern() {
    return /C:\\|AppData[\\/]|BrowserProfile|vault\.json|cap_[a-f0-9]{32,64}|syncRootKey|privateKey|launchAuthority|Bearer |refreshToken|accessToken|cookie|password/i
}

async function createDesktopDevice({ deviceId = 'dev_desktop_phase31_2', status = 'active', sequence = 1 } = {}) {
    const keyPair = await generatePhonePlannerCloudKeyPair(webcrypto)
    return {
        keyPair,
        device: {
            product: 'wipesnap',
            recordType: CLOUD_SYNC_DEVICE_RECORD_TYPE,
            schemaVersion: CLOUD_SYNC_SCHEMA_VERSION,
            ownerUid: OWNER,
            deviceId,
            role: 'desktop',
            status,
            platform: 'windows-electron',
            syncScopes: ['read', 'snapshot-upload', 'patch-upload'],
            signingPublicKey: await publicKeyRecord(keyPair.signing.publicKey, CLOUD_SYNC_SIGNING_ALGORITHM, webcrypto),
            wrapPublicKey: await publicKeyRecord(keyPair.wrapping.publicKey, 'RSA-OAEP-256', webcrypto),
            enrollmentEpoch: 1,
            keyVersion: 1,
            deviceSequence: sequence,
            createdAt: NOW,
            updatedAt: NOW,
            revokedAt: status === 'revoked' ? NOW + 1 : null,
            revokedByDeviceId: status === 'revoked' ? 'dev_desktop_admin' : null
        }
    }
}

async function createKeyGrant({ recipientDeviceId, createdByDeviceId }) {
    const wrapped = new Uint8Array(256).fill(0x42)
    return {
        product: 'wipesnap',
        recordType: CLOUD_SYNC_KEY_GRANT_RECORD_TYPE,
        schemaVersion: CLOUD_SYNC_SCHEMA_VERSION,
        ownerUid: OWNER,
        grantId: `grant_${recipientDeviceId.slice(4)}_v1`,
        recipientDeviceId,
        createdByDeviceId,
        keyVersion: 1,
        wrapAlg: 'RSA-OAEP-256',
        wrappedKeyCiphertext: b64(wrapped),
        wrappedKeyHash: await sha256Base64Url(wrapped, webcrypto),
        createdAt: NOW + 4,
        revokedAt: null,
        revokedByDeviceId: null
    }
}

async function envelopeFixture({
    docType = CLOUD_SYNC_SNAPSHOT_DOC_TYPE,
    deviceId = 'dev_desktop_phase31_2',
    deviceSequence = 2,
    revisionId = 'srev_phase31_2_snapshot_1',
    keyVersion = 1
} = {}) {
    const ciphertext = new Uint8Array(32).fill(docType === CLOUD_SYNC_SNAPSHOT_DOC_TYPE ? 0x51 : 0x52)
    return {
        product: 'wipesnap',
        recordType: CLOUD_SYNC_ENVELOPE_RECORD_TYPE,
        schemaVersion: CLOUD_SYNC_SCHEMA_VERSION,
        envelopeVersion: CLOUD_SYNC_ENVELOPE_VERSION,
        docType,
        ownerUid: OWNER,
        snapshotId: docType === CLOUD_SYNC_SNAPSHOT_DOC_TYPE ? 'snap_phase31_2' : null,
        patchId: docType === CLOUD_SYNC_PATCH_DOC_TYPE ? 'patch_phase31_2' : null,
        revisionId,
        baseRevisionId: docType === CLOUD_SYNC_PATCH_DOC_TYPE ? 'srev_phase31_2_snapshot_1' : null,
        deviceId,
        deviceSequence,
        keyVersion,
        createdAt: NOW + 10,
        updatedAt: NOW + 10,
        encryption: {
            alg: CLOUD_SYNC_CONTENT_ENCRYPTION,
            kdf: CLOUD_SYNC_KEY_DERIVATION,
            salt: b64(new Uint8Array(32).fill(0x61)),
            iv: b64(new Uint8Array(12).fill(0x62)),
            tag: b64(new Uint8Array(16).fill(0x63))
        },
        ciphertext: b64(ciphertext),
        ciphertextHash: await sha256Base64Url(ciphertext, webcrypto),
        signature: {
            alg: CLOUD_SYNC_SIGNING_ALGORITHM,
            keyId: deviceId,
            value: b64(new Uint8Array(64).fill(0x64))
        },
        tombstone: null,
        conflict: null
    }
}

function authHeaders(auth) {
    return {
        [CLOUDFLARE_SYNC_SIGNING_HEADERS.ownerUid]: auth.ownerUid,
        [CLOUDFLARE_SYNC_SIGNING_HEADERS.deviceId]: auth.deviceId,
        [CLOUDFLARE_SYNC_SIGNING_HEADERS.deviceRole]: auth.deviceRole,
        [CLOUDFLARE_SYNC_SIGNING_HEADERS.enrollmentEpoch]: String(auth.enrollmentEpoch),
        [CLOUDFLARE_SYNC_SIGNING_HEADERS.keyVersion]: String(auth.keyVersion),
        [CLOUDFLARE_SYNC_SIGNING_HEADERS.deviceSequence]: String(auth.deviceSequence),
        [CLOUDFLARE_SYNC_SIGNING_HEADERS.requestedAt]: String(auth.requestedAt),
        [CLOUDFLARE_SYNC_SIGNING_HEADERS.bodyHash]: auth.bodyHash,
        [CLOUDFLARE_SYNC_SIGNING_HEADERS.signatureAlg]: auth.signatureAlg,
        [CLOUDFLARE_SYNC_SIGNING_HEADERS.signatureKeyId]: auth.signatureKeyId,
        [CLOUDFLARE_SYNC_SIGNING_HEADERS.signature]: auth.signature
    }
}

async function signedRequest({
    method = 'GET',
    path,
    operation,
    body,
    device,
    privateKey,
    sequence,
    requestedAt = NOW + 100,
    authOverrides = {},
    headerMutator = null,
    bodyTextOverride = null
}) {
    const bodyText = method === 'GET' ? '' : JSON.stringify(body ?? {})
    const auth = {
        ownerUid: device.ownerUid,
        deviceId: device.deviceId,
        deviceRole: device.role,
        enrollmentEpoch: device.enrollmentEpoch,
        keyVersion: device.keyVersion,
        deviceSequence: sequence ?? device.deviceSequence + 1,
        requestedAt,
        bodyHash: await sha256Base64Url(bodyText, webcrypto),
        signatureAlg: 'ECDSA-P256-SHA256-P1363',
        signatureKeyId: device.deviceId,
        signature: '',
        ...authOverrides
    }
    auth.signature = await signCloudSyncCanonicalMetadataBrowser({
        canonicalMetadata: createCloudflareCanonicalRequestMetadata({
            ...auth,
            method,
            path,
            operation
        }),
        privateKey,
        cryptoApi: webcrypto
    })
    const headers = new Headers({
        'Content-Type': 'application/json; charset=utf-8',
        ...authHeaders(auth)
    })
    if (headerMutator) headerMutator(headers)
    return new Request(`${HOST}${path}`, {
        method,
        headers,
        body: method === 'GET' ? undefined : bodyTextOverride ?? bodyText
    })
}

class MemoryCloudflareSyncStore {
    constructor() {
        this.devices = new Map()
        this.enrollments = new Map()
        this.keyGrants = new Map()
        this.snapshots = new Map()
        this.patches = new Map()
        this.decisions = new Map()
        this.rateLimits = new Map()
        this.failedSignatures = new Map()
    }

    key(ownerUid, id) {
        return `${ownerUid}:${id}`
    }

    seedDevice(device) {
        this.devices.set(this.key(device.ownerUid, device.deviceId), clone(device))
    }

    getDevice(ownerUid, deviceId) {
        const device = this.devices.get(this.key(ownerUid, deviceId))
        if (!device) throw new CloudflareSyncError(403, 'wrong-device', 'Device is not enrolled.')
        return Promise.resolve(clone(device))
    }

    recordFailedSignature(auth) {
        const key = this.key(auth.ownerUid || 'unknown', auth.deviceId || 'unknown')
        this.failedSignatures.set(key, (this.failedSignatures.get(key) || 0) + 1)
        return Promise.resolve()
    }

    advanceDeviceSequence({ ownerUid, deviceId, deviceSequence }) {
        const key = this.key(ownerUid, deviceId)
        const device = this.devices.get(key)
        if (!device || device.status !== 'active') {
            throw new CloudflareSyncError(403, 'revoked-device', 'Device is not active.')
        }
        if (deviceSequence <= device.deviceSequence) {
            throw new CloudflareSyncError(403, 'duplicate-sequence', 'Device sequence was already used.')
        }
        device.deviceSequence = deviceSequence
        device.updatedAt = NOW + 100
        this.devices.set(key, clone(device))
        return Promise.resolve()
    }

    recordRateLimit({ ownerUid, deviceId, bucketMs, max }) {
        const key = `${ownerUid}:${deviceId}:${bucketMs}`
        const count = (this.rateLimits.get(key) || 0) + 1
        this.rateLimits.set(key, count)
        if (count > max) throw new CloudflareSyncError(429, 'rate-limited', 'Rate limit exceeded.')
        return Promise.resolve()
    }

    bootstrapDesktop({ ownerUid, device }) {
        this.seedDevice({ ...device, ownerUid })
        return Promise.resolve()
    }

    requestEnrollment({ ownerUid, requestId, device, pairingChallengeHash }) {
        this.seedDevice(device)
        this.enrollments.set(this.key(ownerUid, requestId), {
            ownerUid,
            requestId,
            deviceId: device.deviceId,
            status: 'pending',
            role: device.role,
            pairingChallengeHash,
            device: clone(device),
            requestedAt: NOW + 1,
            metadataOnly: true
        })
        return Promise.resolve()
    }

    listPendingEnrollments(ownerUid) {
        return Promise.resolve(Array.from(this.enrollments.values())
            .filter(record => record.ownerUid === ownerUid && record.status === 'pending')
            .map(clone))
    }

    approveEnrollment({ ownerUid, requestId, desktopDeviceId, keyGrant }) {
        const key = this.key(ownerUid, requestId)
        const request = this.enrollments.get(key)
        if (!request || request.status !== 'pending') throw new CloudflareSyncError(404, 'not-found', 'Enrollment not found.')
        if (keyGrant.recipientDeviceId !== request.deviceId) throw new CloudflareSyncError(403, 'wrong-device', 'Grant recipient mismatch.')
        request.status = 'approved'
        request.approvedByDeviceId = desktopDeviceId
        request.keyGrantId = keyGrant.grantId
        const device = { ...request.device, status: 'active', updatedAt: NOW + 4 }
        this.seedDevice(device)
        this.enrollments.set(key, clone(request))
        this.keyGrants.set(this.key(ownerUid, keyGrant.grantId), clone(keyGrant))
        return Promise.resolve({ device, keyGrant: clone(keyGrant) })
    }

    claimEnrollment({ ownerUid, requestId, deviceId, keyGrantId, pairingChallengeHash }) {
        const key = this.key(ownerUid, requestId)
        const request = this.enrollments.get(key)
        if (!request || request.status !== 'approved') throw new CloudflareSyncError(404, 'not-found', 'Approved enrollment not found.')
        if (request.deviceId !== deviceId || request.keyGrantId !== keyGrantId) throw new CloudflareSyncError(403, 'wrong-device', 'Claim device mismatch.')
        if (request.pairingChallengeHash !== pairingChallengeHash) throw new CloudflareSyncError(403, 'pairing-mismatch', 'Pairing mismatch.')
        request.status = 'claimed'
        this.enrollments.set(key, clone(request))
        return Promise.resolve({
            device: clone(this.devices.get(this.key(ownerUid, deviceId))),
            keyGrant: clone(this.keyGrants.get(this.key(ownerUid, keyGrantId)))
        })
    }

    insertSnapshot({ ownerUid, envelope }) {
        this.snapshots.set(this.key(ownerUid, envelope.revisionId), clone(envelope))
        this.latestSnapshotRevisionId = envelope.revisionId
        return Promise.resolve()
    }

    getLatestSnapshot(ownerUid) {
        return Promise.resolve(clone(this.snapshots.get(this.key(ownerUid, this.latestSnapshotRevisionId)) || null))
    }

    getSnapshot(ownerUid, revisionId) {
        return Promise.resolve(clone(this.snapshots.get(this.key(ownerUid, revisionId)) || null))
    }

    insertPatch({ ownerUid, envelope }) {
        this.patches.set(this.key(ownerUid, envelope.revisionId), {
            ownerUid,
            status: 'pending',
            envelope: clone(envelope),
            metadataOnly: true
        })
        return Promise.resolve()
    }

    listPatches(ownerUid, status = 'pending') {
        return Promise.resolve(Array.from(this.patches.values())
            .filter(record => record.ownerUid === ownerUid && record.status === status)
            .map(clone))
    }

    recordPatchDecision({ ownerUid, decision }) {
        const patch = this.patches.get(this.key(ownerUid, decision.patchRevisionId))
        if (patch) {
            patch.status = decision.status
            this.patches.set(this.key(ownerUid, decision.patchRevisionId), clone(patch))
        }
        this.decisions.set(this.key(ownerUid, decision.patchRevisionId), clone(decision))
        return Promise.resolve()
    }

    revokeDevice({ ownerUid, targetDeviceId, revokedByDeviceId, now }) {
        const key = this.key(ownerUid, targetDeviceId)
        const device = this.devices.get(key)
        if (!device) throw new CloudflareSyncError(404, 'not-found', 'Device not found.')
        device.status = 'revoked'
        device.revokedAt = now
        device.revokedByDeviceId = revokedByDeviceId
        this.devices.set(key, clone(device))
        return Promise.resolve()
    }

    serializedBackend() {
        return JSON.stringify({
            devices: Array.from(this.devices.values()),
            enrollments: Array.from(this.enrollments.values()),
            keyGrants: Array.from(this.keyGrants.values()),
            snapshots: Array.from(this.snapshots.values()),
            patches: Array.from(this.patches.values()),
            decisions: Array.from(this.decisions.values())
        })
    }
}

async function responseJson(response) {
    const json = await response.json()
    return { status: response.status, json }
}

test('Cloudflare plan uses D1 as authority and rejects KV for replay/revocation state', () => {
    assert.equal(CLOUDFLARE_SYNC_STORAGE_DECISION.authoritativeStore, 'd1')
    assert.equal(CLOUDFLARE_SYNC_STORAGE_DECISION.rejectKvAsAuthoritative, true)
    assert.equal(CLOUDFLARE_SYNC_STORAGE_DECISION.durableObjectsRequiredNow, false)
    assert.match(CLOUDFLARE_SYNC_STORAGE_DECISION.reason, /Replay|revocation|sequence|rate-limit|eventually consistent/i)

    const plan = getCloudSyncProviderPlan(validateCloudSyncProviderId(CLOUDFLARE_SYNC_PROVIDER_ID))
    assert.equal(plan.authoritativeStore, 'd1')
    assert.equal(plan.rejectKvAsAuthoritative, true)
    assert.equal(plan.canCoexist, true)
})

test('D1 migration declares authoritative constrained tables and indexed lookup paths', () => {
    const sql = readFileSync(new URL('../cloudflare/migrations/0001_wipesnap_phone_sync.sql', import.meta.url), 'utf8')
    for (const table of [
        'cloudflare_sync_owners',
        'cloudflare_sync_devices',
        'cloudflare_sync_enrollment_requests',
        'cloudflare_sync_key_grants',
        'cloudflare_sync_snapshots',
        'cloudflare_sync_patches',
        'cloudflare_sync_patch_apply_decisions',
        'cloudflare_sync_device_sequences',
        'cloudflare_sync_rate_limits',
        'cloudflare_sync_failed_signatures'
    ]) {
        assert.match(sql, new RegExp(`CREATE TABLE IF NOT EXISTS ${table}`))
    }
    assert.match(sql, /PRIMARY KEY \(owner_uid, device_id, device_sequence\)/)
    assert.match(sql, /CHECK \(role IN \('desktop', 'phone', 'web-planner'\)\)/)
    assert.match(sql, /CHECK \(status IN \('pending', 'approved', 'claimed', 'revoked', 'expired'\)\)/)
    assert.match(sql, /idx_cloudflare_sync_patches_pending/)
    assert.match(sql, /idx_cloudflare_sync_snapshots_latest/)
    assert.doesNotMatch(sql, /workers_kv|KVNamespace|eventual/i)
})

test('Cloudflare config loader is staging-only, secret-free, and coexists with Firebase provider config', () => {
    const cloudflare = validatePhonePlannerCloudflareConfig({
        environment: 'staging',
        provider: CLOUDFLARE_SYNC_PROVIDER_ID,
        apiBaseUrl: 'https://wipesnap-phone-sync-stage.workers.dev',
        useLocalDev: false
    })
    assert.equal(cloudflare.provider, CLOUDFLARE_SYNC_PROVIDER_ID)

    const provider = validatePhonePlannerCloudProviderConfig(cloudflare)
    assert.equal(provider.provider, CLOUDFLARE_SYNC_PROVIDER_ID)

    const firebase = validatePhonePlannerCloudProviderConfig({
        environment: 'staging',
        projectId: 'wipesnap-stage31',
        apiKey: 'AIzaSyStage31SafeWebKey',
        appId: '1:123456789012:web:stage31',
        authDomain: 'wipesnap-stage31.firebaseapp.com',
        functionsRegion: 'us-central1',
        allowAnonymousAuth: false
    })
    assert.equal(firebase.provider, 'firebase-staging')

    assert.throws(() => validatePhonePlannerCloudflareConfig({
        ...cloudflare,
        accountId: 'real-account-id'
    }), /forbidden|cannot be present/)
    assert.throws(() => validatePhonePlannerCloudflareConfig({
        ...cloudflare,
        apiBaseUrl: 'https://api.wipesnap.com'
    }), /production-looking/)
    assert.throws(() => validatePhonePlannerCloudflareConfig({
        ...cloudflare,
        deploymentToken: 'bearer token: nope'
    }), /forbidden|cannot be present/)
})

test('canonical request signing accepts valid signatures and rejects malformed signatures', async () => {
    const { device, keyPair } = await createDesktopDevice()
    const bodyText = ''
    const auth = {
        ownerUid: device.ownerUid,
        deviceId: device.deviceId,
        deviceRole: device.role,
        enrollmentEpoch: device.enrollmentEpoch,
        keyVersion: device.keyVersion,
        deviceSequence: 2,
        requestedAt: NOW + 10,
        bodyHash: await sha256Base64Url(bodyText, webcrypto),
        signatureAlg: 'ECDSA-P256-SHA256-P1363',
        signatureKeyId: device.deviceId,
        signature: ''
    }
    const canonicalMetadata = createCloudflareCanonicalRequestMetadata({
        ...auth,
        method: 'GET',
        path: '/v1/snapshots/latest',
        operation: CLOUDFLARE_SYNC_OPERATIONS.getLatestSnapshot
    })
    auth.signature = await signCloudSyncCanonicalMetadataBrowser({
        canonicalMetadata,
        privateKey: keyPair.signing.privateKey,
        cryptoApi: webcrypto
    })
    assert.equal(auth.signature.length > 80, true)
    assert.equal(await verifyCloudflareCanonicalRequest({
        canonicalMetadata,
        signature: auth.signature,
        publicKeyRecord: device.signingPublicKey,
        cryptoApi: webcrypto
    }), true)
    await assert.rejects(() => verifyCloudflareCanonicalRequest({
        canonicalMetadata,
        signature: 'abc',
        publicKeyRecord: device.signingPublicKey,
        cryptoApi: webcrypto
    }), /64-byte/)
})

test('Worker enrollment flow approves, claims, unwraps grant metadata, and downloads encrypted snapshot', async () => {
    const store = new MemoryCloudflareSyncStore()
    const { device: desktop, keyPair: desktopKeys } = await createDesktopDevice()
    const worker = createCloudflareSyncWorkerCore({ store, cryptoApi: webcrypto, now: () => NOW + 100 })

    let response = await worker.handle(await signedRequest({
        method: 'POST',
        path: '/v1/bootstrap/desktop',
        operation: CLOUDFLARE_SYNC_OPERATIONS.bootstrapDesktop,
        body: { document: desktop },
        device: desktop,
        privateKey: desktopKeys.signing.privateKey,
        sequence: 1
    }))
    assert.equal(response.status, 200, JSON.stringify(await response.clone().json()))

    const phoneKeys = await generatePhonePlannerCloudKeyPair(webcrypto)
    const pending = await createPendingWebPlannerDeviceRecord({
        ownerUid: OWNER,
        deviceId: 'dev_web_phase31_2',
        keyPair: phoneKeys,
        now: NOW + 1,
        cryptoApi: webcrypto
    })
    const pairingChallengeHash = await sha256Base64Url('phase31.2 pairing challenge', webcrypto)
    response = await worker.handle(await signedRequest({
        method: 'POST',
        path: '/v1/enrollments/request',
        operation: CLOUDFLARE_SYNC_OPERATIONS.requestEnrollment,
        body: { document: pending.device, pairingChallengeHash },
        device: pending.device,
        privateKey: phoneKeys.signing.privateKey,
        sequence: 1
    }))
    assert.equal(response.status, 200, JSON.stringify(await response.clone().json()))

    response = await worker.handle(await signedRequest({
        path: '/v1/enrollments/pending',
        operation: CLOUDFLARE_SYNC_OPERATIONS.listPendingEnrollments,
        device: desktop,
        privateKey: desktopKeys.signing.privateKey,
        sequence: 2
    }))
    const pendingList = await responseJson(response)
    assert.equal(pendingList.status, 200, JSON.stringify(pendingList))
    assert.equal(pendingList.json.records[0].device.role, 'web-planner')

    const keyGrant = await createKeyGrant({
        recipientDeviceId: pending.device.deviceId,
        createdByDeviceId: desktop.deviceId
    })
    response = await worker.handle(await signedRequest({
        method: 'POST',
        path: '/v1/enrollments/approve',
        operation: CLOUDFLARE_SYNC_OPERATIONS.approveEnrollment,
        body: { requestId: pending.device.deviceId, keyGrant },
        device: desktop,
        privateKey: desktopKeys.signing.privateKey,
        sequence: 3
    }))
    assert.equal(response.status, 200, JSON.stringify(await response.clone().json()))

    response = await worker.handle(await signedRequest({
        method: 'POST',
        path: '/v1/enrollments/claim',
        operation: CLOUDFLARE_SYNC_OPERATIONS.claimEnrollment,
        body: {
            requestId: pending.device.deviceId,
            keyGrantId: keyGrant.grantId,
            pairingChallengeHash
        },
        device: { ...pending.device, status: 'active' },
        privateKey: phoneKeys.signing.privateKey,
        sequence: 2
    }))
    const claim = await responseJson(response)
    assert.equal(claim.status, 200, JSON.stringify(claim))
    assert.equal(claim.json.device.deviceId, pending.device.deviceId)
    assert.equal(claim.json.keyGrant.wrappedKeyCiphertext, keyGrant.wrappedKeyCiphertext)
    assert.doesNotMatch(JSON.stringify(claim.json), /syncRootKey|rootKeyMaterial|privateKey|launchAuthority/i)

    const snapshotEnvelope = await envelopeFixture({
        deviceId: desktop.deviceId,
        deviceSequence: 4
    })
    response = await worker.handle(await signedRequest({
        method: 'POST',
        path: '/v1/snapshots',
        operation: CLOUDFLARE_SYNC_OPERATIONS.uploadSnapshot,
        body: { document: snapshotEnvelope },
        device: { ...desktop, deviceSequence: 3 },
        privateKey: desktopKeys.signing.privateKey,
        sequence: 4
    }))
    assert.equal(response.status, 200, JSON.stringify(await response.clone().json()))

    response = await worker.handle(await signedRequest({
        path: '/v1/snapshots/latest',
        operation: CLOUDFLARE_SYNC_OPERATIONS.getLatestSnapshot,
        device: { ...pending.device, status: 'active', deviceSequence: 2 },
        privateKey: phoneKeys.signing.privateKey,
        sequence: 3
    }))
    const downloaded = await responseJson(response)
    assert.equal(downloaded.status, 200, JSON.stringify(downloaded))
    assert.equal(downloaded.json.envelope.docType, CLOUD_SYNC_SNAPSHOT_DOC_TYPE)
    assert.match(downloaded.json.envelope.ciphertext, /^[A-Za-z0-9_-]+$/)
    assert.doesNotMatch(JSON.stringify(downloaded.json), forbiddenCloudMaterialPattern())
})

test('Worker rejects tampering, stale identity, duplicate/replayed sequence, revoked devices, and rate excess', async () => {
    const store = new MemoryCloudflareSyncStore()
    const { device: desktop, keyPair } = await createDesktopDevice()
    store.seedDevice(desktop)
    const worker = createCloudflareSyncWorkerCore({ store, cryptoApi: webcrypto, now: () => NOW + 100 })
    const baseBody = { document: await envelopeFixture({ deviceId: desktop.deviceId, deviceSequence: 2 }) }

    async function rejected(request, expectedStatus, expectedError) {
        const response = await worker.handle(request)
        const json = await response.json()
        assert.equal(response.status, expectedStatus, JSON.stringify(json))
        assert.equal(json.error, expectedError, JSON.stringify(json))
    }

    await rejected(await signedRequest({
        method: 'POST',
        path: '/v1/snapshots',
        operation: CLOUDFLARE_SYNC_OPERATIONS.uploadSnapshot,
        body: baseBody,
        device: desktop,
        privateKey: keyPair.signing.privateKey,
        sequence: 2,
        bodyTextOverride: JSON.stringify({ document: { ...baseBody.document, ciphertext: b64(new Uint8Array([1, 2, 3])) } })
    }), 403, 'tampered-body')

    await rejected(await signedRequest({
        method: 'POST',
        path: '/v1/bootstrap/desktop',
        operation: CLOUDFLARE_SYNC_OPERATIONS.bootstrapDesktop,
        body: { document: desktop },
        device: desktop,
        privateKey: keyPair.signing.privateKey,
        sequence: 1,
        authOverrides: { ownerUid: OTHER_OWNER }
    }), 403, 'wrong-owner')

    await rejected(await signedRequest({
        method: 'POST',
        path: '/v1/bootstrap/desktop',
        operation: CLOUDFLARE_SYNC_OPERATIONS.bootstrapDesktop,
        body: { document: desktop },
        device: desktop,
        privateKey: keyPair.signing.privateKey,
        sequence: 1,
        authOverrides: { deviceId: 'dev_wrong_phase31_2' }
    }), 403, 'wrong-device')

    await rejected(await signedRequest({
        method: 'POST',
        path: '/v1/bootstrap/desktop',
        operation: CLOUDFLARE_SYNC_OPERATIONS.bootstrapDesktop,
        body: { document: desktop },
        device: desktop,
        privateKey: keyPair.signing.privateKey,
        sequence: 1,
        authOverrides: { deviceRole: 'phone' }
    }), 403, 'wrong-role')

    await rejected(await signedRequest({
        method: 'POST',
        path: '/v1/bootstrap/desktop',
        operation: CLOUDFLARE_SYNC_OPERATIONS.bootstrapDesktop,
        body: { document: desktop },
        device: desktop,
        privateKey: keyPair.signing.privateKey,
        sequence: 1,
        authOverrides: { enrollmentEpoch: 2 }
    }), 403, 'stale-epoch')

    await rejected(await signedRequest({
        method: 'POST',
        path: '/v1/bootstrap/desktop',
        operation: CLOUDFLARE_SYNC_OPERATIONS.bootstrapDesktop,
        body: { document: desktop },
        device: desktop,
        privateKey: keyPair.signing.privateKey,
        sequence: 1,
        authOverrides: { keyVersion: 2 }
    }), 403, 'stale-key-version')

    await rejected(await signedRequest({
        path: '/v1/snapshots/latest',
        operation: CLOUDFLARE_SYNC_OPERATIONS.getLatestSnapshot,
        device: desktop,
        privateKey: keyPair.signing.privateKey,
        sequence: 2,
        headerMutator: headers => headers.set(CLOUDFLARE_SYNC_SIGNING_HEADERS.signature, 'abc')
    }), 403, 'malformed-signature')

    const accepted = await worker.handle(await signedRequest({
        path: '/v1/snapshots/latest',
        operation: CLOUDFLARE_SYNC_OPERATIONS.getLatestSnapshot,
        device: desktop,
        privateKey: keyPair.signing.privateKey,
        sequence: 2
    }))
    assert.equal(accepted.status, 200, JSON.stringify(await accepted.clone().json()))

    await rejected(await signedRequest({
        path: '/v1/snapshots/latest',
        operation: CLOUDFLARE_SYNC_OPERATIONS.getLatestSnapshot,
        device: { ...desktop, deviceSequence: 2 },
        privateKey: keyPair.signing.privateKey,
        sequence: 2
    }), 403, 'duplicate-sequence')

    store.seedDevice({ ...desktop, status: 'revoked', revokedAt: NOW + 1, revokedByDeviceId: 'dev_desktop_admin', deviceSequence: 10 })
    await rejected(await signedRequest({
        path: '/v1/snapshots/latest',
        operation: CLOUDFLARE_SYNC_OPERATIONS.getLatestSnapshot,
        device: { ...desktop, status: 'revoked', deviceSequence: 10, revokedAt: NOW + 1, revokedByDeviceId: 'dev_desktop_admin' },
        privateKey: keyPair.signing.privateKey,
        sequence: 11
    }), 403, 'revoked-device')

    const rateStore = new MemoryCloudflareSyncStore()
    rateStore.seedDevice(desktop)
    const rateWorker = createCloudflareSyncWorkerCore({ store: rateStore, cryptoApi: webcrypto, now: () => NOW + 100 })
    let lastResponse
    for (let sequence = 2; sequence <= CLOUDFLARE_SYNC_LIMITS.maxSignedRequestsPerWindow + 2; sequence += 1) {
        lastResponse = await rateWorker.handle(await signedRequest({
            path: '/v1/snapshots/latest',
            operation: CLOUDFLARE_SYNC_OPERATIONS.getLatestSnapshot,
            device: { ...desktop, deviceSequence: sequence - 1 },
            privateKey: keyPair.signing.privateKey,
            sequence
        }))
    }
    const limited = await responseJson(lastResponse)
    assert.equal(limited.status, 429, JSON.stringify(limited))
    assert.equal(limited.json.error, 'rate-limited')
})

test('snapshot and patch upload store encrypted envelopes plus safe metadata only', async () => {
    const store = new MemoryCloudflareSyncStore()
    const { device: desktop, keyPair: desktopKeys } = await createDesktopDevice()
    const phoneKeys = await generatePhonePlannerCloudKeyPair(webcrypto)
    const pending = await createPendingWebPlannerDeviceRecord({
        ownerUid: OWNER,
        deviceId: 'dev_web_phase31_2_upload',
        keyPair: phoneKeys,
        now: NOW + 1,
        cryptoApi: webcrypto
    })
    const phone = { ...pending.device, status: 'active' }
    store.seedDevice(desktop)
    store.seedDevice(phone)
    const worker = createCloudflareSyncWorkerCore({ store, cryptoApi: webcrypto, now: () => NOW + 100 })

    const snapshotEnvelope = await envelopeFixture({
        deviceId: desktop.deviceId,
        deviceSequence: 2,
        revisionId: 'srev_phase31_2_safe_only'
    })
    let response = await worker.handle(await signedRequest({
        method: 'POST',
        path: '/v1/snapshots',
        operation: CLOUDFLARE_SYNC_OPERATIONS.uploadSnapshot,
        body: { document: snapshotEnvelope },
        device: desktop,
        privateKey: desktopKeys.signing.privateKey,
        sequence: 2
    }))
    assert.equal(response.status, 200, JSON.stringify(await response.clone().json()))

    const patchEnvelope = await envelopeFixture({
        docType: CLOUD_SYNC_PATCH_DOC_TYPE,
        deviceId: phone.deviceId,
        deviceSequence: 2,
        revisionId: 'patchrev_phase31_2_safe_only'
    })
    response = await worker.handle(await signedRequest({
        method: 'POST',
        path: '/v1/patches',
        operation: CLOUDFLARE_SYNC_OPERATIONS.uploadPatch,
        body: { document: patchEnvelope },
        device: phone,
        privateKey: phoneKeys.signing.privateKey,
        sequence: 2
    }))
    assert.equal(response.status, 200, JSON.stringify(await response.clone().json()))

    const serialized = store.serializedBackend()
    assert.match(serialized, /ciphertext/)
    assert.match(serialized, /safe-preset-patch/)
    assert.doesNotMatch(serialized, forbiddenCloudMaterialPattern())
    assert.equal(cloudflareSyncBackendContainsForbiddenMaterial(snapshotEnvelope), false)
    assert.equal(cloudflareSyncBackendContainsForbiddenMaterial({ ...patchEnvelope, path: 'C:\\Users\\Alice\\AppData\\Local' }), true)

    response = await worker.handle(await signedRequest({
        method: 'POST',
        path: '/v1/patches',
        operation: CLOUDFLARE_SYNC_OPERATIONS.uploadPatch,
        body: { document: { ...patchEnvelope, path: 'C:\\Users\\Alice\\vault.json' } },
        device: { ...phone, deviceSequence: 2 },
        privateKey: phoneKeys.signing.privateKey,
        sequence: 3
    }))
    const rejected = await responseJson(response)
    assert.equal(rejected.status, 400, JSON.stringify(rejected))
    assert.equal(rejected.json.error, 'forbidden-material')
})

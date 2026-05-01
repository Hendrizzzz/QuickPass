import assert from 'assert/strict'
import {
    createHash,
    generateKeyPairSync,
    webcrypto
} from 'crypto'
import { test } from 'node:test'
import {
    CLOUD_SYNC_DEVICE_RECORD_TYPE,
    CLOUD_SYNC_SCHEMA_VERSION,
    CLOUD_SYNC_SIGNING_ALGORITHM
} from '../src/main/cloudSyncEnvelope.js'
import {
    approveCloudSyncDeviceEnrollment,
    approveCloudSyncKeyGrant,
    claimApprovedCloudSyncDeviceSession,
    ingestCloudSyncDocument,
    listPendingCloudSyncDeviceEnrollments,
    requestCloudSyncDeviceEnrollment
} from '../src/main/cloudSyncIngestion.js'
import { uploadDesktopSanitizedSnapshot } from '../src/main/cloudSyncClientTransport.js'
import {
    approveCloudSyncDeviceEnrollmentAndGrantAfterUnlock,
    cloudSyncEnrollmentApprovalResultContainsForbiddenMaterial,
    listPendingCloudSyncDeviceEnrollmentsAfterUnlock
} from '../src/main/cloudSyncEnrollmentApproval.js'
import {
    loadPhonePlannerFirebaseConfig,
    validatePhonePlannerFirebaseConfig
} from '../src/phone-planner/phonePlannerFirebaseConfig.js'
import {
    createIndexedDbAdapter,
    createPhonePlannerCloudStorage
} from '../src/phone-planner/phonePlannerCloudStorage.js'
import {
    claimHostedPlannerDeviceSession,
    downloadLatestHostedPlannerSnapshot,
    requestHostedPlannerEnrollment,
    uploadHostedPlannerSafePatch
} from '../src/phone-planner/phonePlannerCloudWorkflow.js'
import {
    createPhonePlannerState,
    importSnapshotIntoPlannerState,
    updateSnapshotPresetFields
} from '../src/phone-planner/phonePlannerCore.js'
import { SANITIZED_PRESET_SNAPSHOT_LIMITS } from '../src/main/sanitizedPresetSnapshot.js'

const UID = 'firebase_uid_phase31_1'
const NOW = 1770000000000
const SYNC_ROOT_KEY = Buffer.alloc(32, 0x31)

function clone(value) {
    return value == null ? value : JSON.parse(JSON.stringify(value))
}

function sha256Base64Url(bytes) {
    return createHash('sha256').update(bytes).digest('base64url')
}

function signingKeyPair() {
    return generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
}

function publicSigningKeyRecord(publicKey) {
    const spki = publicKey.export({ type: 'spki', format: 'der' })
    return {
        alg: CLOUD_SYNC_SIGNING_ALGORITHM,
        spki: spki.toString('base64url'),
        fingerprint: sha256Base64Url(spki)
    }
}

function wrapPublicKeyRecord(fill = 0x31) {
    const spki = Buffer.alloc(96, fill)
    return {
        alg: 'RSA-OAEP-256',
        spki: spki.toString('base64url'),
        fingerprint: sha256Base64Url(spki)
    }
}

function desktopDeviceRecord({ keys, sequence = 1 }) {
    return {
        product: 'wipesnap',
        recordType: CLOUD_SYNC_DEVICE_RECORD_TYPE,
        schemaVersion: CLOUD_SYNC_SCHEMA_VERSION,
        ownerUid: UID,
        deviceId: 'dev_desktop_phase31_1',
        role: 'desktop',
        status: 'active',
        platform: 'windows-electron',
        syncScopes: ['read', 'snapshot-upload', 'patch-upload'],
        signingPublicKey: publicSigningKeyRecord(keys.publicKey),
        wrapPublicKey: wrapPublicKeyRecord(),
        enrollmentEpoch: 1,
        keyVersion: 1,
        deviceSequence: sequence,
        createdAt: NOW,
        updatedAt: NOW,
        revokedAt: null,
        revokedByDeviceId: null
    }
}

function authForDevice(device) {
    return {
        uid: device.ownerUid,
        token: {
            wipesnapDeviceId: device.deviceId,
            wipesnapDeviceRole: device.role,
            wipesnapEnrollmentEpoch: device.enrollmentEpoch,
            wipesnapKeyVersion: device.keyVersion
        }
    }
}

function ownerAuth() {
    return { uid: UID, token: {} }
}

function snapshotFixture(sourceDeviceId) {
    return {
        product: 'wipesnap',
        kind: 'sanitized-preset-snapshot',
        schemaVersion: 1,
        snapshotId: 'snap_phase31_1',
        revisionId: 'srev_phase31_1_snapshot',
        baseRevisionId: null,
        sourceDeviceId,
        timestamp: NOW + 20,
        limits: { ...SANITIZED_PRESET_SNAPSHOT_LIMITS },
        selection: {
            defaultPresetId: 'preset_coding',
            nextPresetId: 'preset_coding',
            metadataOnly: true,
            selectionKind: 'metadata-only'
        },
        presets: [{
            id: 'preset_coding',
            name: 'Coding',
            order: 0,
            enabled: true,
            itemRefs: [{
                id: 'pref_ai_studio',
                itemId: 'item_ai_studio',
                order: 0,
                enabled: true,
                metadataOnly: true
            }, {
                id: 'pref_editor',
                itemId: 'item_editor',
                order: 1,
                enabled: true,
                metadataOnly: true
            }]
        }],
        availableItems: [{
            id: 'item_ai_studio',
            type: 'browser-tab',
            label: 'AI Studio',
            status: 'available',
            source: 'browser',
            url: 'https://aistudio.google.com/'
        }, {
            id: 'item_editor',
            type: 'desktop-app',
            label: 'Code Editor',
            status: 'available',
            source: 'desktop',
            metadataOnly: true
        }]
    }
}

class InMemoryFirestore {
    constructor() {
        this.docs = new Map()
    }

    normalize(path) {
        return String(path || '').replace(/^\/+|\/+$/g, '')
    }

    seed(path, data) {
        this.docs.set(this.normalize(path), clone(data))
    }

    get(path) {
        return clone(this.docs.get(this.normalize(path)) || null)
    }

    list(collectionPath) {
        const prefix = `${this.normalize(collectionPath)}/`
        return Array.from(this.docs.entries())
            .filter(([key]) => key.startsWith(prefix) && !key.slice(prefix.length).includes('/'))
            .map(([, value]) => clone(value))
    }

    listCollection(path) {
        return Promise.resolve(this.list(path))
    }

    runTransaction(callback) {
        const writes = []
        const pending = new Map()
        const read = path => {
            const key = this.normalize(path)
            if (pending.has(key)) return clone(pending.get(key))
            return clone(this.docs.get(key) || null)
        }
        const write = (type, path, data) => {
            const key = this.normalize(path)
            if (type === 'create' && (this.docs.has(key) || pending.has(key))) {
                throw new Error(`Document already exists: ${key}`)
            }
            const value = clone(data)
            pending.set(key, value)
            writes.push({ key, value })
        }
        return Promise.resolve(callback({
            get: path => Promise.resolve(read(path)),
            create: (path, data) => {
                write('create', path, data)
                return Promise.resolve()
            },
            set: (path, data) => {
                write('set', path, data)
                return Promise.resolve()
            },
            update: (path, data) => {
                const current = read(path)
                if (!current) throw new Error(`Document does not exist: ${this.normalize(path)}`)
                write('update', path, { ...current, ...data })
                return Promise.resolve()
            }
        })).then(result => {
            for (const { key, value } of writes) this.docs.set(key, clone(value))
            return result
        })
    }
}

class MemoryIndexedDbAdapter {
    constructor() {
        this.values = new Map()
    }

    key(storeName, key) {
        return `${storeName}:${key}`
    }

    put(storeName, key, value) {
        this.values.set(this.key(storeName, key), value)
        return Promise.resolve()
    }

    get(storeName, key) {
        return Promise.resolve(this.values.get(this.key(storeName, key)) || null)
    }

    serialized() {
        return JSON.stringify(Array.from(this.values.entries()), (_key, value) => {
            if (value && typeof value === 'object' && value.constructor?.name === 'CryptoKey') {
                return { cryptoKey: true, extractable: value.extractable, type: value.type }
            }
            return value
        })
    }
}

function createPhoneAuthClient() {
    let authState = { uid: UID, email: 'planner@example.test', signedIn: true, metadataOnly: true }
    let deviceClaims = null
    return {
        claims: () => deviceClaims,
        getSafeAuthState() {
            return authState
        },
        async signInWithCustomToken(token) {
            const parsed = JSON.parse(token)
            deviceClaims = parsed.claims
            authState = { uid: parsed.uid, email: '', signedIn: true, metadataOnly: true }
            return { user: authState }
        }
    }
}

function createAuthIssuer() {
    return {
        async createCustomToken(uid, claims) {
            return JSON.stringify({ uid, claims })
        }
    }
}

test('hosted phone Firebase config is staging-only and secret-free', async () => {
    const accepted = validatePhonePlannerFirebaseConfig({
        environment: 'staging',
        projectId: 'wipesnap-stage31',
        apiKey: 'AIzaSyStage31SafeWebKey',
        appId: '1:123456789012:web:stage31',
        authDomain: 'wipesnap-stage31.firebaseapp.com',
        functionsRegion: 'us-central1',
        allowAnonymousAuth: false
    })
    assert.equal(accepted.environment, 'staging')
    assert.equal(accepted.functionsRegion, 'us-central1')

    await assert.rejects(
        () => loadPhonePlannerFirebaseConfig({
            fetchImpl: async () => ({ ok: false })
        }),
        /missing|unavailable/
    )
    assert.throws(() => validatePhonePlannerFirebaseConfig({
        ...accepted,
        projectId: 'wipesnap-production'
    }), /production-looking/)
    assert.throws(() => validatePhonePlannerFirebaseConfig({
        ...accepted,
        privateKey: '-----BEGIN PRIVATE KEY-----\nnope\n-----END PRIVATE KEY-----'
    }), /privateKey|forbidden|cannot be present/)
})

test('phone cloud storage requires IndexedDB adapter and WebCrypto non-extractable keys', async () => {
    assert.throws(() => createIndexedDbAdapter({ indexedDb: null }), /IndexedDB/)
    assert.throws(() => createPhonePlannerCloudStorage({
        indexedDbAdapter: new MemoryIndexedDbAdapter(),
        cryptoApi: {}
    }), /WebCrypto/)

    const adapter = new MemoryIndexedDbAdapter()
    const storage = createPhonePlannerCloudStorage({
        indexedDbAdapter: adapter,
        cryptoApi: webcrypto,
        now: () => NOW
    })
    const pending = await storage.createPendingDevice({ ownerUid: UID })
    const pendingState = await storage.loadPendingDeviceState(pending.device.deviceId)
    assert.equal(pendingState.signingPrivateKey.extractable, false)
    assert.equal(pendingState.wrappingPrivateKey.extractable, false)
    assert.doesNotMatch(adapter.serialized(), /syncRootKey|rootKeyMaterial|privateKey":|deviceSessionToken|customToken/i)
})

test('hosted phone enrollment, key grant unwrap, snapshot download, and offline patch upload', async () => {
    const store = new InMemoryFirestore()
    const desktopKeys = signingKeyPair()
    let desktopDevice = desktopDeviceRecord({ keys: desktopKeys })
    store.seed(`users/${UID}/devices/${desktopDevice.deviceId}`, desktopDevice)
    const authClient = createPhoneAuthClient()
    const phoneStorageAdapter = new MemoryIndexedDbAdapter()
    const phoneStorage = createPhonePlannerCloudStorage({
        indexedDbAdapter: phoneStorageAdapter,
        cryptoApi: webcrypto,
        now: () => NOW
    })
    const firestoreClient = {
        getDocument: path => Promise.resolve(store.get(path))
    }
    const ownerFunctionsClient = {
        async callCloudSyncFunction(name, data) {
            if (name === 'requestCloudSyncDeviceEnrollment') {
                return requestCloudSyncDeviceEnrollment({
                    ...data,
                    auth: ownerAuth(),
                    store,
                    now: NOW + 1
                })
            }
            if (name === 'claimApprovedCloudSyncDeviceSession') {
                return claimApprovedCloudSyncDeviceSession({
                    ...data,
                    auth: ownerAuth(),
                    store,
                    authIssuer: createAuthIssuer(),
                    now: NOW + 6
                })
            }
            if (name === 'ingestCloudSyncDocument') {
                return ingestCloudSyncDocument({
                    ...data,
                    auth: { uid: UID, token: authClient.claims() || {} },
                    store,
                    now: NOW + 40
                })
            }
            throw new Error(`Unexpected phone function: ${name}`)
        }
    }

    const enrollment = await requestHostedPlannerEnrollment({
        authClient,
        functionsClient: ownerFunctionsClient,
        storage: phoneStorage,
        now: () => NOW + 1,
        cryptoApi: webcrypto
    })
    assert.equal(enrollment.status, 'pending')
    assert.match(enrollment.requestId, /^dev_web_/)
    assert.match(enrollment.keyGrantId, /^grant_/)
    assert.equal(store.list(`users/${UID}/deviceEnrollmentRequests`).length, 1)
    assert.equal(store.list(`users/${UID}/deviceEnrollmentRequests`)[0].status, 'pending')
    assert.equal(store.list(`users/${UID}/deviceEnrollmentRequests`)[0].device.role, 'web-planner')

    const desktopStorage = {
        async loadAfterUnlock() {
            return {
                ownerUid: UID,
                device: desktopDevice,
                signingPrivateKey: desktopKeys.privateKey,
                syncRootKey: Buffer.from(SYNC_ROOT_KEY)
            }
        },
        async updateDeviceSequence(deviceSequence) {
            desktopDevice = { ...desktopDevice, deviceSequence }
            store.seed(`users/${UID}/devices/${desktopDevice.deviceId}`, desktopDevice)
        }
    }
    const desktopFunctionsClient = {
        async callCloudSyncFunction(name, data) {
            const auth = authForDevice(desktopDevice)
            if (name === 'listPendingCloudSyncDeviceEnrollments') {
                return listPendingCloudSyncDeviceEnrollments({ auth, store })
            }
            if (name === 'approveCloudSyncDeviceEnrollment') {
                return approveCloudSyncDeviceEnrollment({
                    ...data,
                    auth,
                    store,
                    now: NOW + 2
                })
            }
            if (name === 'approveCloudSyncKeyGrant') {
                return approveCloudSyncKeyGrant({
                    ...data,
                    auth,
                    store,
                    now: NOW + 3
                })
            }
            if (name === 'ingestCloudSyncDocument') {
                return ingestCloudSyncDocument({
                    ...data,
                    auth,
                    store,
                    now: NOW + 20
                })
            }
            throw new Error(`Unexpected desktop function: ${name}`)
        }
    }
    const listedForApproval = await listPendingCloudSyncDeviceEnrollmentsAfterUnlock({
        storage: desktopStorage,
        functionsClient: desktopFunctionsClient
    })
    assert.equal(listedForApproval.success, true, JSON.stringify(listedForApproval))
    assert.equal(
        listedForApproval.records.some(record => record.requestId === enrollment.requestId),
        true,
        JSON.stringify(listedForApproval)
    )
    const approved = await approveCloudSyncDeviceEnrollmentAndGrantAfterUnlock({
        input: { requestId: enrollment.requestId },
        storage: desktopStorage,
        functionsClient: desktopFunctionsClient,
        now: () => NOW + 2
    })
    assert.equal(approved.success, true, JSON.stringify(approved))
    assert.equal(approved.status, 'approved')
    assert.equal(cloudSyncEnrollmentApprovalResultContainsForbiddenMaterial(approved), false, JSON.stringify(approved))
    assert.equal(store.get(`users/${UID}/keyGrants/${approved.keyGrantId}`).recipientDeviceId, approved.deviceId)

    const claim = await claimHostedPlannerDeviceSession({
        authClient,
        functionsClient: ownerFunctionsClient,
        firestoreClient,
        storage: phoneStorage,
        deviceId: enrollment.deviceId,
        now: () => NOW + 6,
        cryptoApi: webcrypto
    })
    assert.equal(claim.syncKeyActive, true)
    assert.equal(authClient.claims().wipesnapDeviceId, enrollment.deviceId)
    assert.doesNotMatch(phoneStorageAdapter.serialized(), /rootKeyMaterial|syncRootKeyBytes|deviceSessionToken|customToken/i)

    await uploadDesktopSanitizedSnapshot({
        storage: desktopStorage,
        functionsClient: desktopFunctionsClient,
        snapshotBuilder: async () => snapshotFixture(desktopDevice.deviceId),
        now: NOW + 20
    })
    const downloaded = await downloadLatestHostedPlannerSnapshot({
        firestoreClient,
        storage: phoneStorage
    })
    assert.equal(downloaded.status, 'downloaded')
    assert.equal(downloaded.snapshot.presets[0].name, 'Coding')
    assert.equal(downloaded.snapshot.availableItems.find(item => item.type === 'desktop-app').label, 'Code Editor')
    assert.doesNotMatch(JSON.stringify(downloaded.snapshot), /[A-Za-z]:\\|cap_[a-f0-9]{32,64}|BrowserProfile|AppData[\\/]/i)

    let plannerState = createPhonePlannerState({
        idFactory: prefix => `${prefix}_phase31_1`
    })
    plannerState = importSnapshotIntoPlannerState(plannerState, downloaded.snapshot, {
        authorDeviceId: enrollment.deviceId,
        idFactory: prefix => `${prefix}_phase31_1`
    })
    plannerState = updateSnapshotPresetFields(plannerState, 'preset_coding', { name: 'Coding Phone' })
    const uploadedPatch = await uploadHostedPlannerSafePatch({
        functionsClient: ownerFunctionsClient,
        storage: phoneStorage,
        editor: plannerState.snapshotEditor,
        now: () => NOW + 40,
        cryptoApi: webcrypto
    })
    assert.equal(uploadedPatch.status, 'accepted')
    const patchDoc = store.get(`users/${UID}/patches/${uploadedPatch.patchRevisionId}`)
    assert.equal(patchDoc.docType, 'safe-preset-patch')
    assert.equal(typeof patchDoc.ciphertext, 'string')
    assert.doesNotMatch(JSON.stringify(patchDoc), /Coding Phone|deviceSessionToken|syncRootKey|privateKey|[A-Za-z]:\\/i)
})

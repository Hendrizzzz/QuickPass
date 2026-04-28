import assert from 'assert/strict'
import { createHash, generateKeyPairSync } from 'crypto'
import { test } from 'node:test'
import {
    CLOUD_SYNC_CONTENT_ENCRYPTION,
    CLOUD_SYNC_DEVICE_RECORD_TYPE,
    CLOUD_SYNC_KEY_DERIVATION,
    CLOUD_SYNC_KEY_GRANT_RECORD_TYPE,
    CLOUD_SYNC_PATCH_DOC_TYPE,
    CLOUD_SYNC_SCHEMA_VERSION,
    CLOUD_SYNC_SIGNING_ALGORITHM,
    CLOUD_SYNC_SIGNING_ALGORITHM_DETAILS,
    CLOUD_SYNC_SNAPSHOT_DOC_TYPE,
    assertNoForbiddenCloudSyncBackendPlaintext,
    createEncryptedCloudSyncEnvelope,
    decryptCloudSyncEnvelope,
    validateCloudSyncConflictMetadata,
    validateCloudSyncDeviceRecord,
    validateCloudSyncEnvelope,
    validateCloudSyncKeyGrant,
    validateCloudSyncPayloadForDocType,
    validateCloudSyncTombstoneMetadata
} from '../src/main/cloudSyncEnvelope.js'
import { SANITIZED_PRESET_SNAPSHOT_LIMITS } from '../src/main/sanitizedPresetSnapshot.js'

const NOW = 1770000000000
const SYNC_ROOT_KEY = Buffer.alloc(32, 0x11)
const OTHER_SYNC_ROOT_KEY = Buffer.alloc(32, 0x99)
const SALT = Buffer.alloc(32, 0x22)
const IV = Buffer.alloc(12, 0x33)

function clone(value) {
    return JSON.parse(JSON.stringify(value))
}

function sha256Base64Url(bytes) {
    return createHash('sha256').update(bytes).digest('base64url')
}

function signingKeyPair() {
    return generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
}

function publicKeyRecord(alg, fill = 0x44) {
    const spkiBytes = Buffer.alloc(96, fill)
    return {
        alg,
        spki: spkiBytes.toString('base64url'),
        fingerprint: sha256Base64Url(spkiBytes)
    }
}

function snapshotFixture() {
    return {
        product: 'wipesnap',
        kind: 'sanitized-preset-snapshot',
        schemaVersion: 1,
        snapshotId: 'snap_phase21_foundation',
        revisionId: 'srev_phase21_foundation_1',
        baseRevisionId: null,
        sourceDeviceId: 'dev_desktop_phase21',
        timestamp: NOW,
        limits: { ...SANITIZED_PRESET_SNAPSHOT_LIMITS },
        selection: {
            defaultPresetId: 'preset_coding',
            nextPresetId: 'preset_coding',
            metadataOnly: true,
            selectionKind: 'metadata-only'
        },
        presets: [
            {
                id: 'preset_coding',
                name: 'Coding',
                order: 0,
                enabled: true,
                itemRefs: [
                    {
                        id: 'pref_ai_studio',
                        itemId: 'item_ai_studio',
                        order: 0,
                        enabled: true,
                        accountIntentionId: 'accti_personal_google',
                        profileIntentionId: 'profi_personal',
                        metadataOnly: true
                    }
                ]
            }
        ],
        availableItems: [
            {
                id: 'item_ai_studio',
                type: 'browser-tab',
                label: 'AI Studio',
                status: 'available',
                source: 'browser',
                url: 'https://aistudio.google.com/'
            },
            {
                id: 'item_cursor',
                type: 'desktop-app',
                label: 'Cursor',
                status: 'available',
                source: 'desktop'
            },
            {
                id: 'accti_personal_google',
                type: 'account-intention',
                label: 'Personal Google',
                status: 'available',
                source: 'account',
                provider: 'google',
                identifierHint: 'p***@gmail.com',
                state: 'needs-recheck',
                metadataOnly: true
            },
            {
                id: 'profi_personal',
                type: 'profile-intention',
                label: 'Personal',
                status: 'available',
                source: 'profile',
                provider: 'google',
                metadataOnly: true
            }
        ]
    }
}

function patchFixture(snapshot = snapshotFixture()) {
    return {
        product: 'wipesnap',
        kind: 'safe-preset-patch',
        schemaVersion: 1,
        patchId: 'patch_phase21_foundation',
        patchRevisionId: 'patchrev_phase21_foundation_1',
        baseSnapshotRevisionId: snapshot.revisionId,
        authorDeviceId: 'dev_phone_phase21',
        createdAt: NOW,
        updatedAt: NOW + 1,
        selection: {
            defaultPresetId: 'preset_coding',
            nextPresetId: 'preset_coding',
            metadataOnly: true,
            selectionKind: 'metadata-only'
        },
        presets: [
            {
                id: 'preset_coding',
                name: 'Coding Phone',
                order: 0,
                enabled: true,
                itemRefs: [
                    {
                        itemId: 'item_ai_studio',
                        order: 0,
                        enabled: false,
                        accountIntentionId: 'accti_personal_google',
                        profileIntentionId: 'profi_personal',
                        metadataOnly: true
                    },
                    {
                        itemId: 'patch_item_reference_notes',
                        order: 1,
                        enabled: true,
                        metadataOnly: true
                    }
                ],
                metadataOnly: true
            }
        ],
        newBrowserItems: [
            {
                id: 'patch_item_reference_notes',
                url: 'https://example.com/reference',
                label: 'Reference Notes',
                notes: 'Public web tab only.',
                enabled: true,
                metadataOnly: true
            }
        ]
    }
}

function createEnvelope({
    docType = CLOUD_SYNC_SNAPSHOT_DOC_TYPE,
    payload = snapshotFixture(),
    keyVersion = 1,
    deviceSequence = 7,
    keys = signingKeyPair()
} = {}) {
    return {
        keys,
        envelope: createEncryptedCloudSyncEnvelope({
            docType,
            payload,
            ownerUid: 'firebase_uid_1',
            deviceId: docType === CLOUD_SYNC_SNAPSHOT_DOC_TYPE ? 'dev_desktop_phase21' : 'dev_phone_phase21',
            deviceSequence,
            keyVersion,
            syncRootKey: SYNC_ROOT_KEY,
            signingPrivateKey: keys.privateKey,
            signingKeyId: 'dev_phase21_signing',
            salt: SALT,
            iv: IV,
            now: NOW
        })
    }
}

function tamperBase64Url(value) {
    const bytes = Buffer.from(value, 'base64url')
    const tampered = Buffer.from(bytes)
    tampered[0] ^= 0xff
    return tampered.toString('base64url')
}

test('snapshot and patch envelopes round trip with AES-256-GCM, HKDF-SHA256, and ECDSA P-256 signatures', () => {
    const keys = signingKeyPair()
    const snapshot = snapshotFixture()
    const patch = patchFixture(snapshot)
    const snapshotEnvelope = createEnvelope({ payload: snapshot, keys }).envelope
    const patchEnvelope = createEnvelope({
        docType: CLOUD_SYNC_PATCH_DOC_TYPE,
        payload: patch,
        keys,
        deviceSequence: 8
    }).envelope

    assert.equal(CLOUD_SYNC_SIGNING_ALGORITHM, 'ECDSA-P256-SHA256-P1363')
    assert.match(CLOUD_SYNC_SIGNING_ALGORITHM_DETAILS, /Node crypto/)
    assert.equal(snapshotEnvelope.encryption.alg, CLOUD_SYNC_CONTENT_ENCRYPTION)
    assert.equal(snapshotEnvelope.encryption.kdf, CLOUD_SYNC_KEY_DERIVATION)
    assert.equal(snapshotEnvelope.signature.alg, CLOUD_SYNC_SIGNING_ALGORITHM)

    const snapshotResult = decryptCloudSyncEnvelope({
        envelope: snapshotEnvelope,
        syncRootKey: SYNC_ROOT_KEY,
        verifyPublicKey: keys.publicKey,
        expectedOwnerUid: 'firebase_uid_1',
        expectedDocType: CLOUD_SYNC_SNAPSHOT_DOC_TYPE,
        activeKeyVersion: 1
    })
    const patchResult = decryptCloudSyncEnvelope({
        envelope: patchEnvelope,
        syncRootKey: SYNC_ROOT_KEY,
        verifyPublicKey: keys.publicKey,
        expectedOwnerUid: 'firebase_uid_1',
        expectedDocType: CLOUD_SYNC_PATCH_DOC_TYPE,
        activeKeyVersion: 1
    })

    assert.deepEqual(snapshotResult.payload, validateCloudSyncPayloadForDocType(snapshot, CLOUD_SYNC_SNAPSHOT_DOC_TYPE))
    assert.deepEqual(patchResult.payload, validateCloudSyncPayloadForDocType(patch, CLOUD_SYNC_PATCH_DOC_TYPE))
})

test('serialized snapshot and patch cloud docs contain ciphertext and safe metadata only', () => {
    const keys = signingKeyPair()
    const snapshot = snapshotFixture()
    const patch = patchFixture(snapshot)
    const docs = [
        createEnvelope({ payload: snapshot, keys }).envelope,
        createEnvelope({ docType: CLOUD_SYNC_PATCH_DOC_TYPE, payload: patch, keys, deviceSequence: 8 }).envelope
    ]

    for (const doc of docs) {
        assertNoForbiddenCloudSyncBackendPlaintext(doc)
        const serialized = JSON.stringify(doc)
        assert.match(serialized, /ciphertext/)
        assert.match(serialized, /AES-256-GCM/)
        assert.match(serialized, /HKDF-SHA256/)
        for (const forbidden of [
            'Coding',
            'Coding Phone',
            'AI Studio',
            'Cursor',
            'Reference Notes',
            'https://aistudio.google.com/',
            'https://example.com/reference',
            'p***@gmail.com',
            'Personal Google',
            'Public web tab only.'
        ]) {
            assert.equal(serialized.includes(forbidden), false, `cloud doc leaked ${forbidden}`)
        }
    }
})

test('snapshot payload URL validation mirrors the safe public browser URL boundary', () => {
    const safeSnapshot = snapshotFixture()
    safeSnapshot.availableItems[0].url = 'https://example.com/assets/app.js?next=%2Fapp.js#section'
    const normalized = validateCloudSyncPayloadForDocType(safeSnapshot, CLOUD_SYNC_SNAPSHOT_DOC_TYPE)
    assert.equal(normalized.availableItems[0].url, 'https://example.com/assets/app.js?next=%2Fapp.js#section')

    const keys = signingKeyPair()
    for (const url of [
        'http://localhost:3000/?token=do-not-store',
        'http://127.0.0.1:3000/callback',
        'http://192.168.1.2/',
        'https://example.com/callback?access_token=abc123',
        'https://example.com/?next=C:%255CUsers%255CAlice%255CAppData%255CLocal',
        'https://example.com/#C:%5CUsers%5CAlice%5CBrowserProfile',
        'https://example.com/vault.json',
        'https://example.com/C:%5CUsers%5CAlice%5Cvault.state.json',
        `https://example.com/?capability=cap_${'aa'.repeat(32)}`
    ]) {
        const snapshot = snapshotFixture()
        snapshot.availableItems[0].url = url
        assert.throws(
            () => validateCloudSyncPayloadForDocType(snapshot, CLOUD_SYNC_SNAPSHOT_DOC_TYPE),
            /url|filesystem|safe public web URL/
        )
        assert.throws(
            () => createEnvelope({ payload: snapshot, keys }),
            /url|filesystem|safe public web URL/
        )
    }
})

test('envelope decryption fails closed on wrong key, tampering, stale key version, and wrong doc type', () => {
    const { publicKey } = signingKeyPair()
    const { envelope, keys } = createEnvelope()

    assert.throws(() => decryptCloudSyncEnvelope({
        envelope,
        syncRootKey: OTHER_SYNC_ROOT_KEY,
        verifyPublicKey: keys.publicKey,
        expectedOwnerUid: 'firebase_uid_1',
        expectedDocType: CLOUD_SYNC_SNAPSHOT_DOC_TYPE,
        activeKeyVersion: 1
    }), /decrypted|authenticated/)

    assert.throws(() => decryptCloudSyncEnvelope({
        envelope: { ...envelope, ciphertext: tamperBase64Url(envelope.ciphertext) },
        syncRootKey: SYNC_ROOT_KEY,
        verifyPublicKey: keys.publicKey,
        expectedDocType: CLOUD_SYNC_SNAPSHOT_DOC_TYPE,
        activeKeyVersion: 1
    }), /ciphertext hash/)

    assert.throws(() => decryptCloudSyncEnvelope({
        envelope: { ...envelope, deviceSequence: envelope.deviceSequence + 1 },
        syncRootKey: SYNC_ROOT_KEY,
        verifyPublicKey: keys.publicKey,
        expectedDocType: CLOUD_SYNC_SNAPSHOT_DOC_TYPE,
        activeKeyVersion: 1
    }), /signature/)

    assert.throws(() => decryptCloudSyncEnvelope({
        envelope: {
            ...envelope,
            signature: { ...envelope.signature, value: tamperBase64Url(envelope.signature.value) }
        },
        syncRootKey: SYNC_ROOT_KEY,
        verifyPublicKey: keys.publicKey,
        expectedDocType: CLOUD_SYNC_SNAPSHOT_DOC_TYPE,
        activeKeyVersion: 1
    }), /signature/)

    assert.throws(() => decryptCloudSyncEnvelope({
        envelope,
        syncRootKey: SYNC_ROOT_KEY,
        verifyPublicKey: keys.publicKey,
        expectedDocType: CLOUD_SYNC_SNAPSHOT_DOC_TYPE,
        activeKeyVersion: 2
    }), /stale key version/)

    assert.throws(() => decryptCloudSyncEnvelope({
        envelope,
        syncRootKey: SYNC_ROOT_KEY,
        verifyPublicKey: keys.publicKey,
        expectedDocType: CLOUD_SYNC_PATCH_DOC_TYPE,
        activeKeyVersion: 1
    }), /doc type/)

    assert.throws(() => decryptCloudSyncEnvelope({
        envelope,
        syncRootKey: SYNC_ROOT_KEY,
        verifyPublicKey: publicKey,
        expectedDocType: CLOUD_SYNC_SNAPSHOT_DOC_TYPE,
        activeKeyVersion: 1
    }), /signature/)
})

test('cloud envelope validators reject backend-visible plaintext and forbidden material', () => {
    const { envelope } = createEnvelope()
    const cases = [
        doc => { doc.name = 'Coding' },
        doc => { doc.label = 'AI Studio' },
        doc => { doc.url = 'https://aistudio.google.com/' },
        doc => { doc.identifierHint = 'p***@gmail.com' },
        doc => { doc.presets = [{ id: 'preset_coding' }] },
        doc => { doc.availableItems = [{ label: 'Cursor' }] },
        doc => { doc.newBrowserItems = [{ url: 'https://example.com/' }] },
        doc => { doc.path = 'C:\\Users\\Alice\\Projects' },
        doc => { doc.capabilityId = `cap_${'aa'.repeat(32)}` },
        doc => { doc.vaultJson = { ciphertext: 'nope' } },
        doc => { doc.memo = 'Bearer abcdefghijklmnopqrstuvwxyz' },
        doc => { doc.memo = 'password=do-not-store' },
        doc => { doc.memo = 'BrowserProfile\\Default' },
        doc => { doc.memo = 'manifestId: unsafe' }
    ]

    for (const mutate of cases) {
        const doc = clone(envelope)
        mutate(doc)
        assert.throws(() => validateCloudSyncEnvelope(doc), /plaintext|forbidden|not accepted/)
    }
})

test('device, key grant, tombstone, and conflict schemas accept safe metadata only', () => {
    const device = validateCloudSyncDeviceRecord({
        product: 'wipesnap',
        recordType: CLOUD_SYNC_DEVICE_RECORD_TYPE,
        schemaVersion: CLOUD_SYNC_SCHEMA_VERSION,
        ownerUid: 'firebase_uid_1',
        deviceId: 'dev_phone_phase21',
        role: 'phone',
        status: 'active',
        platform: 'web-pwa',
        syncScopes: ['read', 'patch-upload'],
        signingPublicKey: publicKeyRecord(CLOUD_SYNC_SIGNING_ALGORITHM),
        wrapPublicKey: publicKeyRecord('RSA-OAEP-256', 0x45),
        enrollmentEpoch: 1,
        keyVersion: 1,
        deviceSequence: 3,
        createdAt: NOW,
        updatedAt: NOW,
        revokedAt: null,
        revokedByDeviceId: null
    })
    assert.equal(device.status, 'active')
    assert.deepEqual(device.syncScopes, ['read', 'patch-upload'])

    const wrapped = Buffer.alloc(96, 0x66)
    const keyGrant = validateCloudSyncKeyGrant({
        product: 'wipesnap',
        recordType: CLOUD_SYNC_KEY_GRANT_RECORD_TYPE,
        schemaVersion: CLOUD_SYNC_SCHEMA_VERSION,
        ownerUid: 'firebase_uid_1',
        grantId: 'grant_phone_phase21_k1',
        recipientDeviceId: 'dev_phone_phase21',
        createdByDeviceId: 'dev_desktop_phase21',
        keyVersion: 1,
        wrapAlg: 'RSA-OAEP-256',
        wrappedKeyCiphertext: wrapped.toString('base64url'),
        wrappedKeyHash: sha256Base64Url(wrapped),
        createdAt: NOW,
        revokedAt: null,
        revokedByDeviceId: null
    })
    assert.equal(keyGrant.keyVersion, 1)

    const tombstone = validateCloudSyncTombstoneMetadata({
        status: 'tombstoned',
        reason: 'superseded',
        tombstonedAt: NOW,
        tombstonedByDeviceId: 'dev_desktop_phase21',
        supersededByRevisionId: 'srev_phase21_foundation_2'
    })
    assert.equal(tombstone.reason, 'superseded')

    const conflict = validateCloudSyncConflictMetadata({
        status: 'conflict',
        reason: 'stale-base',
        detectedAt: NOW,
        detectedByDeviceId: 'dev_desktop_phase21',
        baseRevisionId: 'srev_phase21_foundation_1',
        currentRevisionId: 'srev_phase21_foundation_2',
        conflictingRevisionId: 'patchrev_phase21_foundation_1'
    })
    assert.equal(conflict.reason, 'stale-base')

    assert.throws(() => validateCloudSyncDeviceRecord({
        ...device,
        privateSigningKey: 'do-not-store'
    }), /forbidden|not accepted/)
    assert.throws(() => validateCloudSyncKeyGrant({
        ...keyGrant,
        syncRootKey: Buffer.alloc(32, 0x77).toString('base64url')
    }), /forbidden|not accepted/)
    assert.throws(() => validateCloudSyncTombstoneMetadata({
        ...tombstone,
        capabilityId: `cap_${'bb'.repeat(32)}`
    }), /forbidden|not accepted/)
    assert.throws(() => validateCloudSyncConflictMetadata({
        ...conflict,
        path: 'C:\\Users\\Alice\\vault.json'
    }), /forbidden|not accepted/)
})

import {
    CLOUD_SYNC_ADMIN_OPERATIONS,
    CLOUD_SYNC_INGESTION_OPERATIONS,
    CLOUD_SYNC_PATCH_DOC_TYPE,
    CLOUD_SYNC_SNAPSHOT_DOC_TYPE,
    CLOUD_SYNC_SIGNING_ALGORITHM,
    createCloudSyncAdminSignatureMetadata,
    createCloudSyncDeviceSessionClaimDocument,
    createCloudSyncIngestionSignatureMetadata,
    createCloudSyncKeyGrantIdForDevice,
    createEncryptedCloudSyncEnvelopeBrowser,
    createPairingChallenge,
    decryptCloudSyncEnvelopeBrowser,
    sha256Base64Url,
    signCloudSyncCanonicalMetadataBrowser,
    validateCloudSyncDeviceRecordForPhone,
    validateCloudSyncEnvelopeForPhone
} from './phonePlannerCloudCrypto.js'
import { exportSafePresetPatchJson } from './phonePlannerCore.js'

function fail(message) {
    throw new Error(message)
}

function clone(value) {
    return value == null ? value : JSON.parse(JSON.stringify(value))
}

function authStateOrFail(authClient) {
    if (!authClient || typeof authClient.getSafeAuthState !== 'function') fail('Firebase Auth is not initialized.')
    const state = authClient.getSafeAuthState()
    if (!state?.signedIn || !state.uid) fail('Sign in to Firebase staging first.')
    return state
}

async function callCloudFunction(functionsClient, name, data) {
    if (!functionsClient || typeof functionsClient.callCloudSyncFunction !== 'function') {
        fail('Cloud Functions client is not initialized.')
    }
    return functionsClient.callCloudSyncFunction(name, data)
}

async function getCloudDocument(firestoreClient, path) {
    if (!firestoreClient || typeof firestoreClient.getDocument !== 'function') {
        fail('Firestore client is not initialized.')
    }
    return firestoreClient.getDocument(path)
}

async function signAdminOperation({ operation, ownerUid, actorDevice, targetDeviceId, documentId, document, deviceSequence, requestedAt, signingPrivateKey, cryptoApi }) {
    return {
        alg: CLOUD_SYNC_SIGNING_ALGORITHM,
        keyId: actorDevice.deviceId,
        value: await signCloudSyncCanonicalMetadataBrowser({
            canonicalMetadata: await createCloudSyncAdminSignatureMetadata({
                operation,
                ownerUid,
                actorDeviceId: actorDevice.deviceId,
                targetDeviceId,
                deviceSequence,
                enrollmentEpoch: actorDevice.enrollmentEpoch,
                keyVersion: actorDevice.keyVersion,
                documentId,
                document,
                requestedAt
            }, cryptoApi),
            privateKey: signingPrivateKey,
            cryptoApi
        })
    }
}

async function signPatchIngestion({ ownerUid, device, documentId, document, deviceSequence, requestedAt, signingPrivateKey, cryptoApi }) {
    return {
        alg: CLOUD_SYNC_SIGNING_ALGORITHM,
        keyId: device.deviceId,
        value: await signCloudSyncCanonicalMetadataBrowser({
            canonicalMetadata: await createCloudSyncIngestionSignatureMetadata({
                operation: CLOUD_SYNC_INGESTION_OPERATIONS.patchEnvelope,
                ownerUid,
                deviceId: device.deviceId,
                deviceSequence,
                enrollmentEpoch: device.enrollmentEpoch,
                keyVersion: device.keyVersion,
                documentId,
                document,
                requestedAt
            }, cryptoApi),
            privateKey: signingPrivateKey,
            cryptoApi
        })
    }
}

function metadataResult(extra = {}) {
    return {
        metadataOnly: true,
        ...extra
    }
}

function envelopeWithoutBackendMetadata(rawEnvelope) {
    const envelope = clone(rawEnvelope)
    if (envelope && typeof envelope === 'object') {
        delete envelope.ingestion
        delete envelope.apply
    }
    return envelope
}

export async function requestHostedPlannerEnrollment({
    authClient,
    functionsClient,
    storage,
    keyVersion = 1,
    now = Date.now,
    cryptoApi = globalThis.crypto
} = {}) {
    const auth = authStateOrFail(authClient)
    if (!storage || typeof storage.createPendingDevice !== 'function') fail('Phone planner cloud storage is not initialized.')
    const timestamp = typeof now === 'function' ? now() : now
    const { device } = await storage.createPendingDevice({
        ownerUid: auth.uid,
        keyVersion
    })
    const pairingChallenge = createPairingChallenge(cryptoApi)
    const keyGrantId = createCloudSyncKeyGrantIdForDevice({
        deviceId: device.deviceId,
        keyVersion: device.keyVersion
    })
    const pendingState = await storage.loadPendingDeviceState(device.deviceId)
    if (!pendingState?.signingPrivateKey) fail('Phone planner signing key is not active.')

    const signature = await signAdminOperation({
        operation: CLOUD_SYNC_ADMIN_OPERATIONS.requestDeviceEnrollment,
        ownerUid: auth.uid,
        actorDevice: device,
        targetDeviceId: device.deviceId,
        documentId: device.deviceId,
        document: device,
        deviceSequence: device.deviceSequence,
        requestedAt: timestamp,
        signingPrivateKey: pendingState.signingPrivateKey,
        cryptoApi
    })
    const result = await callCloudFunction(functionsClient, 'requestCloudSyncDeviceEnrollment', {
        requestId: device.deviceId,
        documentId: device.deviceId,
        document: device,
        pairingChallenge,
        signature,
        requestedAt: timestamp
    })
    await storage.storeEnrollmentRequest({
        ownerUid: auth.uid,
        device,
        pairingChallenge,
        keyGrantId
    })
    return metadataResult({
        status: result.status || 'pending',
        requestId: device.deviceId,
        deviceId: device.deviceId,
        role: device.role,
        keyGrantId,
        pairingChallenge,
        pairingChallengeDisplay: pairingChallenge,
        deviceSessionClaimRequired: true
    })
}

export async function claimHostedPlannerDeviceSession({
    authClient,
    functionsClient,
    firestoreClient,
    storage,
    deviceId,
    now = Date.now,
    cryptoApi = globalThis.crypto
} = {}) {
    const auth = authStateOrFail(authClient)
    const request = await storage.loadEnrollmentRequest(deviceId)
    if (!request) fail('No pending hosted planner enrollment request is stored on this browser.')
    const pendingDevice = validateCloudSyncDeviceRecordForPhone(request.device)
    const keyGrantId = request.keyGrantId || createCloudSyncKeyGrantIdForDevice({
        deviceId: pendingDevice.deviceId,
        keyVersion: pendingDevice.keyVersion
    })
    const timestamp = typeof now === 'function' ? now() : now
    if (typeof storage.restoreSession === 'function') {
        await storage.restoreSession(pendingDevice.deviceId).catch(() => null)
    }
    const sessionState = await storage.loadSessionState()
    const claimDevice = sessionState?.device || pendingDevice
    const deviceSequence = claimDevice.deviceSequence + 1
    const pairingChallengeHash = await sha256Base64Url(request.pairingChallenge, cryptoApi)
    const claimDocument = createCloudSyncDeviceSessionClaimDocument({
        requestId: request.requestId,
        deviceId: claimDevice.deviceId,
        keyGrantId,
        pairingChallengeHash
    })
    const pendingState = sessionState?.signingPrivateKey
        ? sessionState
        : await storage.loadPendingDeviceState(claimDevice.deviceId)
    if (!pendingState?.signingPrivateKey) fail('Phone planner signing key is not active.')
    const signature = await signAdminOperation({
        operation: CLOUD_SYNC_ADMIN_OPERATIONS.claimDeviceSession,
        ownerUid: auth.uid,
        actorDevice: claimDevice,
        targetDeviceId: claimDevice.deviceId,
        documentId: request.requestId,
        document: claimDocument,
        deviceSequence,
        requestedAt: timestamp,
        signingPrivateKey: pendingState.signingPrivateKey,
        cryptoApi
    })
    const claim = await callCloudFunction(functionsClient, 'claimApprovedCloudSyncDeviceSession', {
        requestId: request.requestId,
        deviceId: claimDevice.deviceId,
        keyGrantId,
        pairingChallenge: request.pairingChallenge,
        signature,
        deviceSequence,
        requestedAt: timestamp
    })
    if (!claim?.deviceSessionToken) fail('Approved device session did not return a custom token.')
    await authClient.signInWithCustomToken(claim.deviceSessionToken)
    const activeDevice = {
        ...claimDevice,
        ...(claim.device || {}),
        status: 'active',
        deviceSequence
    }
    await storage.storeClaimedDeviceSessionMetadata({
        ownerUid: auth.uid,
        device: activeDevice,
        keyGrantId
    })
    const keyGrant = await getCloudDocument(firestoreClient, `users/${auth.uid}/keyGrants/${keyGrantId}`)
    if (!keyGrant) fail('Approved sync key grant is not readable yet.')
    await storage.activateKeyGrant({
        ownerUid: auth.uid,
        device: activeDevice,
        keyGrant
    })
    return metadataResult({
        status: claim.status || 'accepted',
        deviceId: activeDevice.deviceId,
        keyGrantId,
        keyVersion: activeDevice.keyVersion,
        deviceSequence,
        syncKeyActive: true
    })
}

export async function downloadLatestHostedPlannerSnapshot({
    firestoreClient,
    storage,
    revisionId = ''
} = {}) {
    const state = await storage.loadSessionState()
    if (!state?.device || !state.syncRootKey) fail('Hosted planner sync key is not active.')
    const syncState = revisionId
        ? null
        : await getCloudDocument(firestoreClient, `users/${state.ownerUid}/state/sync`)
    const targetRevisionId = revisionId || syncState?.latestSnapshotRevisionId
    if (!targetRevisionId) fail('No latest sanitized snapshot is available.')
    const rawEnvelope = await getCloudDocument(firestoreClient, `users/${state.ownerUid}/snapshots/${targetRevisionId}`)
    const envelope = validateCloudSyncEnvelopeForPhone(envelopeWithoutBackendMetadata(rawEnvelope), {
        expectedDocType: CLOUD_SYNC_SNAPSHOT_DOC_TYPE,
        activeKeyVersion: state.device.keyVersion
    })
    const authorDevice = await getCloudDocument(firestoreClient, `users/${state.ownerUid}/devices/${envelope.deviceId}`)
    const decrypted = await decryptCloudSyncEnvelopeBrowser({
        envelope,
        syncRootKey: state.syncRootKey,
        verifyPublicKeyRecord: authorDevice?.signingPublicKey,
        expectedOwnerUid: state.ownerUid,
        expectedDocType: CLOUD_SYNC_SNAPSHOT_DOC_TYPE,
        activeKeyVersion: state.device.keyVersion
    })
    if (typeof storage.cacheEncryptedSnapshotEnvelope === 'function') {
        await storage.cacheEncryptedSnapshotEnvelope(envelope)
    }
    return metadataResult({
        status: 'downloaded',
        snapshot: decrypted.payload,
        revisionId: envelope.revisionId,
        sourceDeviceId: envelope.deviceId
    })
}

export async function uploadHostedPlannerSafePatch({
    functionsClient,
    storage,
    editor,
    now = Date.now,
    cryptoApi = globalThis.crypto
} = {}) {
    const state = await storage.loadSessionState()
    if (!state?.device || !state.signingPrivateKey || !state.syncRootKey) {
        fail('Hosted planner device session and sync key are required before patch upload.')
    }
    const editorForUpload = {
        ...clone(editor),
        authorDeviceId: state.device.deviceId
    }
    const patch = JSON.parse(exportSafePresetPatchJson(editorForUpload))
    const timestamp = typeof now === 'function' ? now() : now
    const envelope = await createEncryptedCloudSyncEnvelopeBrowser({
        docType: CLOUD_SYNC_PATCH_DOC_TYPE,
        payload: patch,
        ownerUid: state.ownerUid,
        device: state.device,
        syncRootKey: state.syncRootKey,
        signingPrivateKey: state.signingPrivateKey,
        now: timestamp,
        snapshotForPatch: editorForUpload.snapshot,
        cryptoApi
    })
    const signature = await signPatchIngestion({
        ownerUid: state.ownerUid,
        device: state.device,
        documentId: envelope.revisionId,
        document: envelope,
        deviceSequence: envelope.deviceSequence,
        requestedAt: timestamp,
        signingPrivateKey: state.signingPrivateKey,
        cryptoApi
    })
    const result = await callCloudFunction(functionsClient, 'ingestCloudSyncDocument', {
        operation: CLOUD_SYNC_INGESTION_OPERATIONS.patchEnvelope,
        documentId: envelope.revisionId,
        document: envelope,
        signature,
        deviceSequence: envelope.deviceSequence,
        requestedAt: timestamp
    })
    if (typeof storage.cacheEncryptedPatchEnvelope === 'function') {
        await storage.cacheEncryptedPatchEnvelope(envelope)
    }
    await storage.updateDeviceSequence(envelope.deviceSequence)
    return metadataResult({
        status: result.status || 'accepted',
        patchRevisionId: envelope.revisionId,
        deviceSequence: envelope.deviceSequence,
        encrypted: true,
        uploaded: result.status === 'accepted'
    })
}

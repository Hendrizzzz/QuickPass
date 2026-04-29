'use strict'

const admin = require('firebase-admin')
const { onCall, HttpsError } = require('firebase-functions/v2/https')

if (!admin.apps.length) admin.initializeApp()

function httpsCodeForIngestionCode(code) {
    if (code === 'unauthenticated') return 'unauthenticated'
    if (code === 'permission-denied') return 'permission-denied'
    if (code === 'already-exists') return 'already-exists'
    if (code === 'resource-exhausted') return 'resource-exhausted'
    if (code === 'failed-precondition') return 'failed-precondition'
    if (code === 'invalid-argument') return 'invalid-argument'
    return 'internal'
}

exports.ingestCloudSyncDocument = onCall({ region: 'us-central1' }, async request => {
    const {
        createFirestoreAdminStore,
        ingestCloudSyncDocument
    } = await import('./shared/main/cloudSyncIngestion.js')

    try {
        return await ingestCloudSyncDocument({
            auth: request.auth
                ? { uid: request.auth.uid, token: request.auth.token || {} }
                : null,
            operation: request.data?.operation,
            documentId: request.data?.documentId,
            document: request.data?.document,
            signature: request.data?.signature,
            deviceSequence: request.data?.deviceSequence,
            requestedAt: request.data?.requestedAt,
            store: createFirestoreAdminStore(admin.firestore()),
            now: Date.now()
        })
    } catch (error) {
        throw new HttpsError(
            httpsCodeForIngestionCode(error.code),
            error.message || 'Cloud sync ingestion failed closed.'
        )
    }
})

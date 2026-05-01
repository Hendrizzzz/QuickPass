import assert from 'assert/strict'
import { test } from 'node:test'
import {
    approveCloudSyncDeviceEnrollmentAndGrantAfterUnlock,
    cloudSyncEnrollmentApprovalResultContainsForbiddenMaterial,
    listPendingCloudSyncDeviceEnrollmentsAfterUnlock
} from '../src/main/cloudSyncEnrollmentApproval.js'
import { validateCloudSyncEnrollmentApprovalPayload } from '../src/preload/cloudSyncPreloadValidation.js'

test('desktop enrollment approval preload payload is narrow and rejects authority material', () => {
    assert.deepEqual(
        validateCloudSyncEnrollmentApprovalPayload({ requestId: 'dev_web_phase31_request' }),
        { requestId: 'dev_web_phase31_request' }
    )
    assert.throws(
        () => validateCloudSyncEnrollmentApprovalPayload({
            requestId: 'dev_web_phase31_request',
            syncRootKey: 'syncRootKey: no'
        }),
        /not accepted|cannot|syncRootKey/
    )
    assert.throws(
        () => validateCloudSyncEnrollmentApprovalPayload({ requestId: '..\\vault.json' }),
        /safe enrollment request id|forbidden cloud sync invocation material/
    )
})

test('desktop enrollment approval requires unlocked storage before cloud calls', async () => {
    let cloudCalls = 0
    const storage = {
        async loadAfterUnlock() {
            throw new Error('vault is locked')
        }
    }
    const functionsClient = {
        async callCloudSyncFunction() {
            cloudCalls += 1
            throw new Error('should not call cloud while locked')
        }
    }
    const listed = await listPendingCloudSyncDeviceEnrollmentsAfterUnlock({
        storage,
        functionsClient
    })
    assert.equal(listed.success, false)
    assert.equal(listed.status, 'locked')

    const approved = await approveCloudSyncDeviceEnrollmentAndGrantAfterUnlock({
        input: { requestId: 'dev_web_phase31_request' },
        storage,
        functionsClient
    })
    assert.equal(approved.success, false)
    assert.equal(approved.status, 'locked')
    assert.equal(cloudCalls, 0)
})

test('desktop enrollment approval result scanner catches forbidden material', () => {
    assert.equal(cloudSyncEnrollmentApprovalResultContainsForbiddenMaterial({
        success: true,
        requestId: 'dev_web_phase31_request',
        deviceId: 'dev_web_phase31_request',
        metadataOnly: true
    }), false)
    assert.equal(cloudSyncEnrollmentApprovalResultContainsForbiddenMaterial({
        success: true,
        wrappedKeyCiphertext: 'not-for-renderer'
    }), true)
})

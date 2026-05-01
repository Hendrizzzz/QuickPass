import assert from 'assert/strict'
import { readFileSync } from 'fs'
import { test } from 'node:test'
import {
    CLOUD_SYNC_FIRESTORE_RULES_VERSION,
    evaluateCloudSyncFirestoreAccess
} from '../src/main/cloudSyncRulesPolicy.js'

const rulesCases = JSON.parse(readFileSync(new URL('./fixtures/cloudSyncRulesCases.json', import.meta.url), 'utf8'))
const firestoreRules = readFileSync(new URL('../firestore.rules', import.meta.url), 'utf8')

test('Firestore rules strategy fixtures enforce device-bound reads and deny direct client writes', () => {
    assert.equal(CLOUD_SYNC_FIRESTORE_RULES_VERSION, 2)

    for (const fixture of rulesCases) {
        const result = evaluateCloudSyncFirestoreAccess(fixture)
        assert.equal(result.allowed, fixture.allowed, fixture.name)
        assert.equal(result.reason, fixture.reason, fixture.name)
    }
})

test('Firestore rules file is default-deny and routes Phase 21.1 writes away from clients', () => {
    assert.match(firestoreRules, /match \/\{document=\*\*\}/)
    assert.match(firestoreRules, /allow read, write: if false;/)
    assert.match(firestoreRules, /allow create, update, delete: if false;/)
    assert.match(firestoreRules, /wipesnapDeviceId/)
    assert.match(firestoreRules, /enrolledDeviceExists/)
    assert.match(firestoreRules, /status == 'active'/)
    assert.match(firestoreRules, /revokedAt == null/)
    assert.match(firestoreRules, /syncScopes\.hasAny\(\['read'\]\)/)
    assert.match(firestoreRules, /readableTrustedDevice/)
    assert.match(firestoreRules, /allow get: if readableOwnDevice\(userId, deviceId\) \|\| readableTrustedDevice\(userId\);/)
    assert.doesNotMatch(firestoreRules, /allow get, list: if owns\(userId\)/)
    assert.doesNotMatch(firestoreRules, /allow create, update, delete: if owns\(userId\)/)
    assert.doesNotMatch(firestoreRules, /allow write: if owns\(userId\)/)
})

import assert from 'assert/strict'
import { test } from 'node:test'
import { existsSync, mkdtempSync, rmSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import {
    PIN_BASE_LOCKOUT_MS,
    assertPinAttemptAllowed,
    clearPinLockout,
    getPinLockoutEntry,
    isApprovedPinLockoutResetMethod,
    recordPinAttemptFailure,
    requireFreshPinProofForMediumRisk
} from '../src/main/pinLockout.js'

function createHarness() {
    const vaultDir = mkdtempSync(join(tmpdir(), 'wipesnap-pin-lockout-'))
    return {
        statePath: join(vaultDir, 'vault.state.json'),
        cleanup: () => {
            if (existsSync(vaultDir)) rmSync(vaultDir, { recursive: true, force: true })
        }
    }
}

function baseMeta(overrides = {}) {
    return {
        version: '1.0.0',
        vaultId: `vault_${'a'.repeat(32)}`,
        createdOn: 'USB1234',
        isRemovable: true,
        hasPIN: true,
        hiddenMaster: true,
        pinVault: { encrypted: true },
        ...overrides
    }
}

function drive(serialNumber = 'USB1234') {
    return {
        driveLetter: 'U:',
        isRemovable: true,
        serialKnown: true,
        serialNumber
    }
}

function recordFailures(count, options) {
    let result = null
    for (let index = 0; index < count; index += 1) {
        result = recordPinAttemptFailure(options)
    }
    return result
}

test('PIN failures persist across restart simulation', () => {
    const harness = createHarness()
    try {
        const meta = baseMeta()
        const driveInfo = drive()
        const now = 1_000
        const lockout = recordFailures(5, { statePath: harness.statePath, meta, driveInfo, now })

        assert.equal(lockout.lockoutCount, 1)
        assert.equal(lockout.lockedUntil, now + PIN_BASE_LOCKOUT_MS)
        assert.throws(() => assertPinAttemptAllowed({
            statePath: harness.statePath,
            meta,
            driveInfo,
            now: now + 1
        }), (err) => err.code === 'PIN_LOCKED' && err.retryAfterMs === PIN_BASE_LOCKOUT_MS - 1)
    } finally {
        harness.cleanup()
    }
})

test('PIN lockout backoff increases after repeated failure windows', () => {
    const harness = createHarness()
    try {
        const meta = baseMeta()
        const driveInfo = drive()
        const first = recordFailures(5, { statePath: harness.statePath, meta, driveInfo, now: 10_000 })
        const nextWindow = first.lockedUntil + 1

        recordFailures(4, { statePath: harness.statePath, meta, driveInfo, now: nextWindow })
        const second = recordPinAttemptFailure({
            statePath: harness.statePath,
            meta,
            driveInfo,
            now: nextWindow + 1
        })

        assert.equal(second.lockoutCount, 2)
        assert.equal(second.lockedUntil, nextWindow + 1 + (PIN_BASE_LOCKOUT_MS * 2))
    } finally {
        harness.cleanup()
    }
})

test('expired PIN lockout allows a later attempt', () => {
    const harness = createHarness()
    try {
        const meta = baseMeta()
        const driveInfo = drive()
        const lockout = recordFailures(5, { statePath: harness.statePath, meta, driveInfo, now: 20_000 })

        assert.throws(() => assertPinAttemptAllowed({
            statePath: harness.statePath,
            meta,
            driveInfo,
            now: lockout.lockedUntil - 1
        }), (err) => err.code === 'PIN_LOCKED' && err.retryAfterMs === 1)

        const allowed = assertPinAttemptAllowed({
            statePath: harness.statePath,
            meta,
            driveInfo,
            now: lockout.lockedUntil + 1
        })

        assert.equal(allowed.failedAttempts, 5)
        assert.equal(allowed.lockoutCount, 1)
    } finally {
        harness.cleanup()
    }
})

test('successful approved unlock clears persisted PIN lockout for the vault', () => {
    const harness = createHarness()
    try {
        const meta = baseMeta()
        const driveA = drive('USB1234')
        const driveB = drive('USB5678')
        recordFailures(5, { statePath: harness.statePath, meta, driveInfo: driveA, now: 1_000 })
        recordFailures(5, { statePath: harness.statePath, meta, driveInfo: driveB, now: 1_000 })

        clearPinLockout({ statePath: harness.statePath, meta, driveInfo: driveA, scope: 'vault' })

        assert.equal(getPinLockoutEntry({ statePath: harness.statePath, meta, driveInfo: driveA }).failedAttempts, 0)
        assert.equal(getPinLockoutEntry({ statePath: harness.statePath, meta, driveInfo: driveB }).failedAttempts, 0)
    } finally {
        harness.cleanup()
    }
})

test('FastBoot is not an approved PIN lockout reset method', () => {
    assert.equal(isApprovedPinLockoutResetMethod('master-password'), true)
    assert.equal(isApprovedPinLockoutResetMethod('fresh-pin'), true)
    assert.equal(isApprovedPinLockoutResetMethod('fastboot'), false)
})

test('failed hidden-master fresh PIN proofs persist failures through the PIN lockout path', () => {
    const harness = createHarness()
    try {
        const meta = baseMeta()
        const driveInfo = drive()
        let decryptCalls = 0
        const decryptVault = () => {
            decryptCalls += 1
            throw new Error('bad pin')
        }

        for (let index = 0; index < 5; index += 1) {
            assert.throws(() => requireFreshPinProofForMediumRisk({
                statePath: harness.statePath,
                meta,
                driveInfo,
                pin: '9999',
                activeMasterPassword: 'active-password',
                decryptVault,
                now: 30_000 + index
            }), (err) => err.code === 'FRESH_PIN_INVALID')
        }

        const entry = getPinLockoutEntry({ statePath: harness.statePath, meta, driveInfo })
        assert.equal(entry.failedAttempts, 5)
        assert.equal(entry.lockoutCount, 1)
        assert.equal(entry.lockedUntil, 30_004 + PIN_BASE_LOCKOUT_MS)
        assert.equal(decryptCalls, 5)

        assert.throws(() => requireFreshPinProofForMediumRisk({
            statePath: harness.statePath,
            meta,
            driveInfo,
            pin: '9999',
            activeMasterPassword: 'active-password',
            decryptVault,
            now: 30_005
        }), (err) => err.code === 'PIN_LOCKED')
        assert.equal(decryptCalls, 5)
    } finally {
        harness.cleanup()
    }
})

test('hidden-master medium-risk change requires fresh PIN proof', () => {
    const harness = createHarness()
    try {
        const meta = baseMeta()
        const driveInfo = drive()
        let decryptCalls = 0
        const decryptVault = (_pinVault, key) => {
            decryptCalls += 1
            assert.equal(key, '1234:USB1234')
            return { masterPassword: 'active-password' }
        }

        assert.throws(() => requireFreshPinProofForMediumRisk({
            statePath: harness.statePath,
            meta,
            driveInfo,
            pin: '',
            activeMasterPassword: 'active-password',
            decryptVault
        }), /PIN is required/)
        assert.equal(decryptCalls, 0)

        const proof = requireFreshPinProofForMediumRisk({
            statePath: harness.statePath,
            meta,
            driveInfo,
            pin: '1234',
            activeMasterPassword: 'active-password',
            decryptVault
        })

        assert.equal(proof.required, true)
        assert.equal(proof.approved, true)
        assert.equal(decryptCalls, 1)
    } finally {
        harness.cleanup()
    }
})

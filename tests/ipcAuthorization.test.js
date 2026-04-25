import assert from 'assert/strict'
import { test } from 'node:test'
import {
    hasUnlockedSession,
    requireActiveSessionState,
    requireConvenienceUnlockRequestSupported,
    requireSessionSetupAllowedState,
    requireUnlockedOrNoVaultState
} from '../src/main/ipcAuthorization.js'

test('authorization helpers identify unlocked session state', () => {
    assert.equal(hasUnlockedSession(Buffer.from('pw')), true)
    assert.equal(hasUnlockedSession(null), false)
})

test('authorization helpers allow no-vault setup but reject locked existing vault', () => {
    assert.doesNotThrow(() => requireSessionSetupAllowedState({
        vaultExists: false,
        hasActiveSession: false
    }))

    assert.throws(() => requireSessionSetupAllowedState({
        vaultExists: true,
        hasActiveSession: false
    }), /Session is locked/)

    assert.doesNotThrow(() => requireSessionSetupAllowedState({
        vaultExists: true,
        hasActiveSession: true
    }))
})

test('authorization helpers gate existing-vault actions on active session', () => {
    assert.doesNotThrow(() => requireUnlockedOrNoVaultState({
        vaultExists: false,
        hasActiveSession: false
    }))

    assert.throws(() => requireUnlockedOrNoVaultState({
        vaultExists: true,
        hasActiveSession: false
    }), /Session is locked/)

    assert.throws(() => requireActiveSessionState(false), /Session is locked/)
})

test('convenience unlock requests fail closed on unsupported drives', () => {
    assert.doesNotThrow(() => requireConvenienceUnlockRequestSupported({
        requested: false,
        driveInfo: { isRemovable: false, serialKnown: false }
    }))

    assert.doesNotThrow(() => requireConvenienceUnlockRequestSupported({
        requested: true,
        driveInfo: { isRemovable: true, serialKnown: true }
    }))

    assert.throws(() => requireConvenienceUnlockRequestSupported({
        requested: true,
        driveInfo: { isRemovable: false, serialKnown: true }
    }), /removable drives/)

    assert.throws(() => requireConvenienceUnlockRequestSupported({
        requested: true,
        driveInfo: { isRemovable: true, serialKnown: false }
    }), /serial could not be verified/)
})

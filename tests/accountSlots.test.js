import assert from 'assert/strict'
import { test } from 'node:test'
import { sanitizeVaultMetaForRenderer } from '../src/main/vaultMetadata.js'
import {
    createAccountSlot,
    createAccountSlotHandlerCore,
    deleteAccountSlot,
    deleteAccountSlotHandlerCore,
    loadAccountSlotsHandlerCore,
    normalizeAccountSlots,
    updateAccountSlot,
    updateAccountSlotHandlerCore,
    validateAccountSlotRecord
} from '../src/main/accountSlots.js'

const SLOT_ID = `acct_${'a1'.repeat(24)}`
const OTHER_SLOT_ID = `acct_${'b2'.repeat(24)}`

function clone(value) {
    return JSON.parse(JSON.stringify(value))
}

function canonicalSlot(overrides = {}) {
    return {
        id: SLOT_ID,
        provider: 'google',
        label: 'Personal',
        identifierHint: 'user@example.com',
        state: 'unknown',
        lastCheckedAt: 0,
        notes: '',
        ...overrides
    }
}

function createHarness({ locked = false, workspace = {}, meta = { version: '1.0.0' } } = {}) {
    const calls = {
        sessionChecks: 0,
        workspaceReads: 0,
        metaReads: 0,
        commits: [],
        encryptedPayload: null
    }

    const deps = {
        requireActiveSession: () => {
            calls.sessionChecks += 1
            if (locked) throw new Error('Session is locked')
        },
        loadActiveVaultWorkspace: () => {
            calls.workspaceReads += 1
            return clone({
                webTabs: [],
                desktopApps: [],
                ...workspace
            })
        },
        loadVaultMeta: () => {
            calls.metaReads += 1
            return clone(meta)
        },
        getDriveInfo: async () => ({ driveType: 3 }),
        getActiveMasterPassword: () => 'active-password',
        encryptVault: (payload, password, driveInfo) => {
            calls.encryptedPayload = clone(payload)
            return {
                ciphertext: Buffer.from(JSON.stringify(payload), 'utf-8').toString('base64'),
                passwordHash: Buffer.from(password).toString('base64'),
                hardwareBound: driveInfo.driveType === 3
            }
        },
        commitVaultMeta: ({ vault, meta: nextMeta, operation }) => {
            calls.commits.push({
                vault: clone(vault),
                meta: clone(nextMeta),
                operation
            })
        },
        honeyToken: { marker: true },
        randomBytes: (size) => Buffer.alloc(size, 0xab)
    }

    return { calls, deps }
}

test('validator accepts a canonical Google account slot and normalizes safe strings', () => {
    const slot = validateAccountSlotRecord(canonicalSlot({
        label: '  Personal  ',
        identifierHint: '  user@example.com  ',
        notes: '  Browser profile A  ',
        lastCheckedAt: 123.9
    }))

    assert.deepEqual(slot, {
        id: SLOT_ID,
        provider: 'google',
        label: 'Personal',
        identifierHint: 'user@example.com',
        state: 'unknown',
        lastCheckedAt: 123,
        notes: 'Browser profile A'
    })
})

test('validator rejects unsupported provider/state, malformed fields, duplicates, and oversized fields', () => {
    assert.throws(() => validateAccountSlotRecord(canonicalSlot({ provider: 'microsoft' })), /provider/)
    assert.throws(() => validateAccountSlotRecord(canonicalSlot({ state: 'verified' })), /state/)
    assert.throws(() => validateAccountSlotRecord(canonicalSlot({ label: ['Personal'] })), /label.*string/)
    assert.throws(() => validateAccountSlotRecord(canonicalSlot({ label: 'Personal\nGoogle' })), /control whitespace/)
    assert.throws(() => validateAccountSlotRecord(canonicalSlot({ notes: 'safe\u0001nope' })), /control whitespace/)
    assert.throws(() => validateAccountSlotRecord(canonicalSlot({ notes: 'password: do-not-store' })), /secret material/)
    assert.throws(() => validateAccountSlotRecord(canonicalSlot({ identifierHint: 'x'.repeat(161) })), /too long/)
    assert.throws(() => normalizeAccountSlots([
        canonicalSlot(),
        canonicalSlot({ label: 'Duplicate' })
    ]), /duplicate account slot id/)
})

test('create generates a random opaque main-issued id and rejects renderer ids', () => {
    const slot = createAccountSlot({
        provider: 'google',
        label: 'Personal',
        identifierHint: 'user@example.com'
    }, [], {
        randomBytes: (size) => Buffer.alloc(size, 0xab)
    })

    assert.equal(slot.id, `acct_${'ab'.repeat(24)}`)
    assert.equal(slot.id.includes('user'), false)
    assert.equal(slot.id.includes('Personal'), false)
    assert.throws(() => createAccountSlot({
        id: SLOT_ID,
        provider: 'google',
        label: 'Personal'
    }), /main process/)
})

test('update and delete require an existing slot id', () => {
    const existing = [canonicalSlot()]

    assert.throws(() => updateAccountSlot({
        id: OTHER_SLOT_ID,
        label: 'Work'
    }, existing), /not found/)
    assert.throws(() => deleteAccountSlot({
        id: OTHER_SLOT_ID
    }, existing), /not found/)

    const updated = updateAccountSlot({
        id: SLOT_ID,
        label: 'Personal Gmail',
        state: 'needs-recheck'
    }, existing)
    assert.equal(updated[0].label, 'Personal Gmail')
    assert.equal(updated[0].state, 'needs-recheck')

    assert.deepEqual(deleteAccountSlot({ id: SLOT_ID }, existing), [])
})

test('locked handlers reject before vault reads or writes', async () => {
    const { deps, calls } = createHarness({ locked: true })

    const loadResult = loadAccountSlotsHandlerCore({ deps })
    assert.equal(loadResult.success, false)
    assert.match(loadResult.error, /locked/i)

    const createResult = await createAccountSlotHandlerCore({
        input: { provider: 'google', label: 'Personal' },
        deps
    })
    assert.equal(createResult.success, false)
    assert.match(createResult.error, /locked/i)
    assert.equal(calls.sessionChecks, 2)
    assert.equal(calls.workspaceReads, 0)
    assert.equal(calls.commits.length, 0)
})

test('renderer cannot supply arbitrary path, vault material, or secret-looking fields', async () => {
    const { deps, calls } = createHarness()

    for (const payload of [
        { provider: 'google', label: 'Personal', vaultPath: 'C:\\vault.json' },
        { provider: 'google', label: 'Personal', launchCapabilityVault: { records: {} } },
        { provider: 'google', label: 'Personal', password: 'do-not-store' },
        { provider: 'google', label: 'Personal', oauthToken: 'do-not-store' },
        { provider: 'google', label: 'Personal', backupCode: 'do-not-store' }
    ]) {
        const result = await createAccountSlotHandlerCore({ input: payload, deps })
        assert.equal(result.success, false)
        assert.equal(JSON.stringify(result).includes('do-not-store'), false)
    }

    assert.equal(calls.commits.length, 0)
})

test('account slots persist through encrypted vault payload and stay out of sanitized meta', async () => {
    const { deps, calls } = createHarness({
        meta: {
            version: '1.0.0',
            vaultId: 'vault-123',
            hasPIN: false
        }
    })

    const result = await createAccountSlotHandlerCore({
        input: {
            provider: 'google',
            label: 'Personal',
            identifierHint: 'user@example.com',
            notes: 'No secrets here'
        },
        deps
    })

    assert.equal(result.success, true)
    assert.equal(result.accountSlots.length, 1)
    assert.equal(calls.commits.length, 1)
    assert.equal(calls.commits[0].operation, 'create-account-slot')
    assert.equal(calls.encryptedPayload.accountSlots[0].label, 'Personal')
    assert.equal(calls.encryptedPayload._honeyToken.marker, true)

    const serializedVault = JSON.stringify(calls.commits[0].vault)
    assert.equal(serializedVault.includes('Personal'), false)
    assert.equal(serializedVault.includes('user@example.com'), false)
    assert.equal('accountSlots' in calls.commits[0].meta, false)

    const rendererMeta = sanitizeVaultMetaForRenderer(calls.commits[0].meta, {
        driveLetter: 'C:',
        isRemovable: false,
        driveType: 3,
        driveTypeKnown: true,
        serialKnown: true,
        supportsConvenienceUnlock: false
    })
    assert.equal('accountSlots' in rendererMeta, false)
})

test('load, update, and delete return sanitized slots only', async () => {
    const { deps } = createHarness({
        workspace: {
            accountSlots: [canonicalSlot({ notes: 'Remember which browser profile to use.' })]
        }
    })

    const loadResult = loadAccountSlotsHandlerCore({ deps })
    assert.equal(loadResult.success, true)
    assert.deepEqual(Object.keys(loadResult.accountSlots[0]).sort(), [
        'id',
        'identifierHint',
        'label',
        'lastCheckedAt',
        'notes',
        'provider',
        'state'
    ].sort())

    const updateResult = await updateAccountSlotHandlerCore({
        input: { id: SLOT_ID, notes: 'Updated note' },
        deps
    })
    assert.equal(updateResult.success, true)
    assert.equal(updateResult.accountSlot.notes, 'Updated note')

    const deleteResult = await deleteAccountSlotHandlerCore({
        input: { id: SLOT_ID },
        deps
    })
    assert.equal(deleteResult.success, true)
    assert.deepEqual(deleteResult.accountSlots, [])
})

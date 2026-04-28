import assert from 'assert/strict'
import { test } from 'node:test'
import { planCloudDraftImport } from '../src/main/cloudDraftImport.js'

function clone(value) {
    return JSON.parse(JSON.stringify(value))
}

function aiStudioDraft(overrides = {}) {
    return {
        product: 'wipesnap',
        schemaVersion: 1,
        draftId: 'draft_ai_studio',
        revisionId: 'rev_ai_studio_1',
        baseRevisionId: 'rev_ai_studio_0',
        authorDeviceId: 'dev_phone_1',
        name: 'AI Studio with Personal Google',
        notes: '',
        isDefault: false,
        accountSlots: [
            {
                id: 'intent_google_personal',
                provider: 'google',
                label: 'Personal Google',
                identifierHint: 'p***@gmail.com',
                profileSlotId: 'profile_personal',
                state: 'needs-check'
            },
            {
                id: 'intent_google_new_ai',
                provider: 'google',
                label: 'New AI Google',
                identifierHint: 'n***@gmail.com',
                profileSlotId: 'profile_new_ai',
                state: 'unknown'
            }
        ],
        browserProfileSlots: [
            {
                id: 'profile_personal',
                label: 'Personal',
                provider: 'google'
            },
            {
                id: 'profile_new_ai',
                label: 'New AI',
                provider: 'google'
            }
        ],
        browserTabs: [
            {
                id: 'tab_ai_studio_new_ai',
                url: 'https://aistudio.google.com/',
                order: 1,
                label: 'AI Studio',
                notes: '',
                enabled: true,
                accountSlotId: 'intent_google_new_ai',
                profileSlotId: 'profile_new_ai'
            },
            {
                id: 'tab_ai_studio_personal',
                url: 'https://aistudio.google.com/',
                order: 0,
                label: 'AI Studio',
                notes: '',
                enabled: true,
                accountSlotId: 'intent_google_personal',
                profileSlotId: 'profile_personal'
            }
        ],
        desiredApps: [
            {
                id: 'wish_cursor',
                name: 'Cursor',
                label: 'Cursor',
                notes: '',
                enabled: true
            },
            {
                id: 'wish_discord',
                name: 'Discord',
                label: 'Discord',
                notes: 'Resolve later on desktop.',
                enabled: false
            }
        ],
        createdAt: 1770000000000,
        updatedAt: 1770000000001,
        ...overrides
    }
}

test('valid draft produces a deterministic metadata-only import plan', () => {
    const input = aiStudioDraft()
    const plan = planCloudDraftImport(input)
    const repeated = planCloudDraftImport(clone(input))

    assert.deepEqual(plan, repeated)
    assert.equal(plan.success, true)
    assert.equal(plan.source, 'cloud-draft')
    assert.deepEqual(plan.imported, {
        browserTabs: 2,
        accountIntentions: 2,
        profileIntentions: 2,
        desiredAppPlaceholders: 2
    })
    assert.deepEqual(plan.safeBrowserTabs.map(tab => tab.id), [
        'tab_ai_studio_personal',
        'tab_ai_studio_new_ai'
    ])
    assert.deepEqual(plan.safeBrowserTabs.map(tab => tab.url), [
        'https://aistudio.google.com/',
        'https://aistudio.google.com/'
    ])
    assert.equal(plan.safeBrowserTabs[0].accountIntentionId, 'intent_google_personal')
    assert.equal(plan.safeBrowserTabs[1].accountIntentionId, 'intent_google_new_ai')
    assert.equal(plan.accountIntentions[0].desktopState, 'needs-recheck')
    assert.equal(plan.accountIntentions.every(intent => intent.metadataOnly), true)
    assert.equal(plan.browserProfileIntentions.every(intent => intent.metadataOnly && intent.createsDesktopProfile === false), true)
})

test('AI Studio with Personal Google is URL plus account/profile intention without session or login claims', () => {
    const plan = planCloudDraftImport(aiStudioDraft({
        accountSlots: [aiStudioDraft().accountSlots[0]],
        browserProfileSlots: [aiStudioDraft().browserProfileSlots[0]],
        browserTabs: [aiStudioDraft().browserTabs[1]],
        desiredApps: []
    }))
    const serialized = JSON.stringify(plan).toLowerCase()

    assert.equal(plan.safeBrowserTabs[0].url, 'https://aistudio.google.com/')
    assert.equal(plan.safeBrowserTabs[0].accountIntentionId, 'intent_google_personal')
    assert.equal(plan.safeBrowserTabs[0].profileIntentionId, 'profile_personal')
    for (const forbidden of ['password', 'cookie', 'oauth', 'credential', 'session', 'backupcode']) {
        assert.equal(serialized.includes(forbidden), false, `plan leaked ${forbidden}`)
    }
    assert.equal(serialized.includes('signed-in'), false)
})

test('multiple Google account intentions remain metadata and do not create account slots', () => {
    const plan = planCloudDraftImport(aiStudioDraft())

    assert.equal(plan.accountIntentions.length, 2)
    assert.deepEqual(plan.accountIntentions.map(intent => intent.provider), ['google', 'google'])
    assert.equal('accountSlots' in plan, false)
    assert.equal('accountSlots' in plan.workspaceIntentMetadata, false)
    assert.equal(plan.workspaceIntentMetadata.accountIntentions[0].requiresDesktopVerification, true)
})

test('desired app placeholders are unresolved and cannot launch or create capabilities', () => {
    const plan = planCloudDraftImport(aiStudioDraft())
    const [cursor, discord] = plan.desiredAppPlaceholders
    const serialized = JSON.stringify(plan)

    assert.equal(cursor.status, 'unresolved')
    assert.equal(cursor.resolution, 'desktop-required')
    assert.equal(cursor.launchable, false)
    assert.equal(cursor.createsCapability, false)
    assert.equal(discord.enabled, false)
    assert.equal(plan.warnings.length, 1)
    assert.match(plan.warnings[0], /Cursor must be resolved on desktop/)

    for (const forbidden of [
        'capabilityId',
        'launchCapabilityVault',
        'launchSourceType',
        'launchMethod',
        'C:\\',
        '[USB]'
    ]) {
        assert.equal(serialized.includes(forbidden), false, `plan leaked ${forbidden}`)
    }
})

test('planner rejects malicious drafts before producing launch-capable data', () => {
    const malicious = aiStudioDraft()
    malicious.desiredApps[0].capabilityId = `cap_${'aa'.repeat(32)}`
    malicious.desiredApps[0].path = 'C:\\Windows\\System32\\notepad.exe'

    assert.throws(() => planCloudDraftImport(malicious), /not accepted/)
})

test('planner has no dependency on existing account slots or capability vaults and does not mutate them', () => {
    const existingWorkspace = Object.freeze({
        accountSlots: Object.freeze([
            Object.freeze({
                id: `acct_${'ab'.repeat(24)}`,
                provider: 'google',
                label: 'Existing',
                identifierHint: 'existing@example.com',
                state: 'unknown',
                lastCheckedAt: 0,
                notes: ''
            })
        ]),
        launchCapabilityVault: Object.freeze({
            version: 1,
            records: Object.freeze({
                [`cap_${'cd'.repeat(32)}`]: Object.freeze({ preserved: true })
            })
        })
    })
    const before = clone(existingWorkspace)

    const plan = planCloudDraftImport(aiStudioDraft(), { existingWorkspace })

    assert.deepEqual(existingWorkspace, before)
    assert.equal(JSON.stringify(plan).includes('launchCapabilityVault'), false)
    assert.equal(JSON.stringify(plan).includes(`acct_${'ab'.repeat(24)}`), false)
    assert.equal(JSON.stringify(plan).includes(`cap_${'cd'.repeat(32)}`), false)
})

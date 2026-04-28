import assert from 'assert/strict'
import { test } from 'node:test'
import { createCapabilityRecord } from '../src/main/capabilityStore.js'
import { planCloudDraftImport } from '../src/main/cloudDraftImport.js'
import { validateCloudDraft } from '../src/main/cloudDraftSchema.js'
import { buildSanitizedPresetSnapshot } from '../src/main/sanitizedPresetSnapshot.js'
import { planSafePresetPatchImport } from '../src/main/safePresetPatch.js'
import { WORKSPACE_CAPABILITY_VAULT_KEY } from '../src/main/workspaceCapabilityMigration.js'
import {
    PHONE_DRAFT_LIMITS,
    addExistingSnapshotItemToPreset,
    addSnapshotBrowserTabToPreset,
    addDraftItem,
    createAccountIntention,
    createBrowserProfileSlot,
    createBrowserTab,
    createDesiredAppPlaceholder,
    createDraftInState,
    createPhonePlannerState,
    deleteDraftFromState,
    duplicateDraftInState,
    exportSafePresetPatchJson,
    importSnapshotIntoPlannerState,
    moveSnapshotPresetInState,
    moveSnapshotPresetItemInState,
    removeSnapshotItemFromPreset,
    updateSnapshotEditorSelection,
    updateSnapshotPresetFields,
    updateSnapshotPresetItem,
    exportCloudDraftJson,
    updateDraftFields,
    validateSafePresetPatchForPhone
} from '../src/phone-planner/phonePlannerCore.js'
import {
    PHONE_PLANNER_STORAGE_KEY,
    loadPhonePlannerState,
    savePhonePlannerState
} from '../src/phone-planner/phonePlannerStorage.js'

const NOW = 1770000000000
const SNAPSHOT_SECRET = Buffer.from('phase-20-phone-preset-editor-secret-32-bytes')
const SNAPSHOT_ACCOUNT_ID = `acct_${'e5'.repeat(24)}`
const SNAPSHOT_PROFILE_ID = 'profile_personal'

function clone(value) {
    return JSON.parse(JSON.stringify(value))
}

function bytes(hexByte) {
    return size => Buffer.alloc(size, hexByte)
}

function idFactory() {
    let index = 0
    return prefix => `${prefix}_${++index}`
}

function hostExeRecord(hexByte = 0x51) {
    return createCapabilityRecord({
        type: 'host-exe',
        provenance: 'browse-exe',
        displayName: 'Cursor',
        launch: {
            path: 'C:\\Program Files\\Cursor\\Cursor.exe'
        },
        policy: {
            allowedArgs: 'none',
            canCloseFromWipesnap: true,
            ownership: 'owned-process'
        }
    }, {
        randomBytes: bytes(hexByte),
        now: '2026-04-28T00:00:00.000Z'
    })
}

function hostFolderRecord(hexByte = 0x52) {
    return createCapabilityRecord({
        type: 'host-folder',
        provenance: 'browse-folder',
        displayName: 'Projects',
        launch: {
            path: 'C:\\Users\\Alice\\Projects'
        },
        policy: {
            allowedArgs: 'none',
            canCloseFromWipesnap: false,
            ownership: 'external'
        }
    }, {
        randomBytes: bytes(hexByte),
        now: '2026-04-28T00:00:00.000Z'
    })
}

class MemoryStorage {
    constructor() {
        this.records = new Map()
    }

    getItem(key) {
        return this.records.has(key) ? this.records.get(key) : null
    }

    setItem(key, value) {
        this.records.set(key, String(value))
    }

    removeItem(key) {
        this.records.delete(key)
    }
}

function phase18SnapshotFixture(overrides = {}) {
    const appRecord = hostExeRecord()
    const folderRecord = hostFolderRecord()
    const workspace = {
        id: 'desktop-workspace-raw-id',
        name: 'Coding',
        defaultPresetId: 'coding-preset',
        nextPresetId: 'coding-preset',
        webTabs: [
            {
                id: 'raw-tab-ai-studio',
                url: 'https://aistudio.google.com/',
                label: 'AI Studio',
                enabled: true,
                accountSlotId: SNAPSHOT_ACCOUNT_ID,
                profileSlotId: SNAPSHOT_PROFILE_ID
            }
        ],
        desktopApps: [
            {
                id: 'raw-app-cursor',
                capabilityId: appRecord.capabilityId,
                displayName: 'Cursor',
                enabled: true
            },
            {
                id: 'raw-folder-projects',
                capabilityId: folderRecord.capabilityId,
                displayName: 'Projects',
                enabled: true
            }
        ],
        accountSlots: [
            {
                id: SNAPSHOT_ACCOUNT_ID,
                provider: 'google',
                label: 'Personal Google',
                identifierHint: 'p***@gmail.com',
                state: 'needs-recheck'
            }
        ],
        browserProfileSlots: [
            {
                id: SNAPSHOT_PROFILE_ID,
                provider: 'google',
                label: 'Personal'
            }
        ],
        [WORKSPACE_CAPABILITY_VAULT_KEY]: {
            version: 1,
            records: {
                [appRecord.capabilityId]: appRecord,
                [folderRecord.capabilityId]: folderRecord
            }
        }
    }

    return buildSanitizedPresetSnapshot({
        snapshotSafeIdSecret: SNAPSHOT_SECRET,
        sourceDeviceId: 'desktop-device-raw-id',
        snapshotId: 'desktop-snapshot-raw-id',
        revisionId: 'desktop-revision-raw-id',
        baseRevisionId: 'desktop-base-revision-raw-id',
        timestamp: NOW,
        workspace,
        presets: [
            {
                id: 'coding-preset',
                name: 'Coding',
                order: 0,
                enabled: true,
                itemRefs: [
                    {
                        browserTabId: 'raw-tab-ai-studio',
                        order: 0,
                        enabled: true,
                        accountSlotId: SNAPSHOT_ACCOUNT_ID,
                        profileSlotId: SNAPSHOT_PROFILE_ID
                    }
                ]
            },
            {
                id: 'school-preset',
                name: 'School',
                order: 1,
                enabled: true,
                itemRefs: [
                    {
                        desktopAppId: 'raw-folder-projects',
                        order: 0,
                        enabled: true
                    }
                ]
            }
        ],
        ...overrides
    })
}

function snapshotParts(snapshot) {
    return {
        coding: snapshot.presets.find(preset => preset.name === 'Coding'),
        school: snapshot.presets.find(preset => preset.name === 'School'),
        browser: snapshot.availableItems.find(item => item.type === 'browser-tab' && item.status === 'available'),
        desktop: snapshot.availableItems.find(item => item.type === 'desktop-app'),
        folder: snapshot.availableItems.find(item => item.type === 'host-folder'),
        account: snapshot.availableItems.find(item => item.type === 'account-intention'),
        profile: snapshot.availableItems.find(item => item.type === 'profile-intention')
    }
}

function buildAiStudioPlannerState() {
    const ids = idFactory()
    const options = { now: NOW, idFactory: ids }
    let state = createPhonePlannerState({
        ...options,
        name: 'AI Studio two-account plan',
        authorDeviceId: 'dev_phone_local'
    })
    const draftId = state.selectedDraftId
    state = updateDraftFields(state, draftId, {
        name: 'AI Studio two-account plan',
        notes: 'Open AI Studio with separate Google account intentions.'
    }, options)

    const personalProfile = createBrowserProfileSlot({ label: 'Personal', idFactory: ids })
    const newAiProfile = createBrowserProfileSlot({ label: 'New AI', idFactory: ids })
    state = addDraftItem(state, draftId, 'browserProfileSlots', personalProfile, options)
    state = addDraftItem(state, draftId, 'browserProfileSlots', newAiProfile, options)

    const personalAccount = createAccountIntention({
        label: 'Personal Google',
        identifierHint: 'p***@gmail.com',
        profileSlotId: personalProfile.id,
        state: 'needs-check',
        idFactory: ids
    })
    const newAiAccount = createAccountIntention({
        label: 'New AI Google',
        identifierHint: 'n***@gmail.com',
        profileSlotId: newAiProfile.id,
        state: 'needs-check',
        idFactory: ids
    })
    state = addDraftItem(state, draftId, 'accountSlots', personalAccount, options)
    state = addDraftItem(state, draftId, 'accountSlots', newAiAccount, options)

    state = addDraftItem(state, draftId, 'browserTabs', createBrowserTab({
        url: 'https://aistudio.google.com/',
        order: 0,
        label: 'AI Studio',
        accountSlotId: personalAccount.id,
        profileSlotId: personalProfile.id,
        idFactory: ids
    }), options)
    state = addDraftItem(state, draftId, 'browserTabs', createBrowserTab({
        url: 'https://aistudio.google.com/',
        order: 1,
        label: 'AI Studio',
        accountSlotId: newAiAccount.id,
        profileSlotId: newAiProfile.id,
        idFactory: ids
    }), options)
    state = addDraftItem(state, draftId, 'desiredApps', createDesiredAppPlaceholder({
        name: 'Cursor',
        label: 'Cursor',
        notes: 'Resolve on desktop later.',
        idFactory: ids
    }), options)

    return state
}

function selectedDraft(state) {
    return state.drafts.find(draft => draft.draftId === state.selectedDraftId)
}

test('phone planner imports a Phase 18 sanitized snapshot and exports a Phase 19-valid preset patch', () => {
    const ids = idFactory()
    const options = { now: NOW, idFactory: ids, authorDeviceId: 'dev_phone_phase20' }
    const snapshot = phase18SnapshotFixture()
    const parts = snapshotParts(snapshot)
    let state = createPhonePlannerState({ ...options, name: 'Local fallback draft' })

    state = importSnapshotIntoPlannerState(state, JSON.stringify(snapshot), options)
    assert.equal(state.snapshotEditor.snapshot.revisionId, snapshot.revisionId)
    assert.deepEqual(state.snapshotEditor.snapshot.presets.map(preset => preset.name), ['Coding', 'School'])
    assert.deepEqual(state.snapshotEditor.snapshot.availableItems.map(item => item.type), [
        'browser-tab',
        'desktop-app',
        'host-folder',
        'account-intention',
        'profile-intention'
    ])

    state = updateSnapshotPresetFields(state, parts.coding.id, {
        name: 'Coding Remote',
        enabled: false
    }, options)
    state = moveSnapshotPresetInState(state, parts.coding.id, 1, options)
    state = updateSnapshotEditorSelection(state, {
        defaultPresetId: parts.school.id,
        nextPresetId: parts.coding.id
    }, options)
    state = addExistingSnapshotItemToPreset(state, parts.coding.id, parts.desktop.id, options)
    state = addExistingSnapshotItemToPreset(state, parts.coding.id, parts.folder.id, options)
    state = moveSnapshotPresetItemInState(state, parts.coding.id, parts.desktop.id, -1, options)
    state = updateSnapshotPresetItem(state, parts.coding.id, parts.browser.id, {
        enabled: false,
        accountIntentionId: parts.account.id,
        profileIntentionId: parts.profile.id
    }, options)

    const patch = JSON.parse(exportSafePresetPatchJson(state.snapshotEditor))
    const patchJson = JSON.stringify(patch)
    const plan = planSafePresetPatchImport({ patch, sanitizedSnapshot: snapshot })
    const codingPlan = plan.presetPlans.find(item => item.presetId === parts.coding.id)
    const desktopRef = codingPlan.next.itemRefs.find(ref => ref.itemId === parts.desktop.id)
    const folderRef = codingPlan.next.itemRefs.find(ref => ref.itemId === parts.folder.id)
    const browserRef = codingPlan.next.itemRefs.find(ref => ref.itemId === parts.browser.id)

    assert.equal(patch.baseSnapshotRevisionId, snapshot.revisionId)
    assert.equal(patch.selection.defaultPresetId, parts.school.id)
    assert.equal(patch.selection.nextPresetId, parts.coding.id)
    assert.equal(codingPlan.next.name, 'Coding Remote')
    assert.equal(codingPlan.next.enabled, false)
    assert.equal(browserRef.enabled, false)
    assert.equal(browserRef.accountIntentionId, parts.account.id)
    assert.equal(browserRef.profileIntentionId, parts.profile.id)
    assert.equal(desktopRef.itemType, 'desktop-app')
    assert.equal(desktopRef.existingSnapshotItem, true)
    assert.equal(desktopRef.createsCapability, false)
    assert.equal(desktopRef.launchable, false)
    assert.equal(folderRef.itemType, 'host-folder')
    assert.equal(folderRef.createsHostFolderAuthority, false)
    assert.equal(folderRef.launchable, false)
    assert.equal(plan.sideEffects.createsCapability, false)
    assert.equal(plan.sideEffects.launches, false)
    for (const forbidden of ['C:\\', 'Program Files', 'capabilityId', 'vault', 'launch', 'args']) {
        assert.equal(patchJson.toLowerCase().includes(forbidden.toLowerCase()), false, `patch leaked ${forbidden}`)
    }
})

test('phone planner adds a new safe public browser tab mapped to snapshot account and profile intentions', () => {
    const ids = idFactory()
    const options = { now: NOW, idFactory: ids, authorDeviceId: 'dev_phone_phase20' }
    const snapshot = phase18SnapshotFixture()
    const parts = snapshotParts(snapshot)
    let state = createPhonePlannerState(options)
    state = importSnapshotIntoPlannerState(state, snapshot, options)

    state = addSnapshotBrowserTabToPreset(state, parts.coding.id, {
        url: 'aistudio.google.com',
        label: 'AI Studio Extra',
        notes: 'Open as a public tab only.',
        enabled: true,
        accountIntentionId: parts.account.id,
        profileIntentionId: parts.profile.id
    }, options)

    const patch = JSON.parse(exportSafePresetPatchJson(state.snapshotEditor))
    const plan = planSafePresetPatchImport({ patch, sanitizedSnapshot: snapshot })
    const newItem = plan.newBrowserItems[0]
    const newRef = plan.presetPlans
        .find(item => item.presetId === parts.coding.id)
        .next.itemRefs.find(ref => ref.itemId === newItem.id)

    assert.equal(newItem.id.startsWith('patch_item_'), true)
    assert.equal(newItem.url, 'https://aistudio.google.com/')
    assert.equal(newItem.accountIntentionId, parts.account.id)
    assert.equal(newItem.profileIntentionId, parts.profile.id)
    assert.equal(newItem.createsCapability, false)
    assert.equal(newItem.launchable, false)
    assert.equal(newRef.newBrowserItem, true)
    assert.equal(newRef.createsCapability, false)
})

test('phone planner rejects unknown safe ids and unsafe account mappings before export', () => {
    const ids = idFactory()
    const options = { now: NOW, idFactory: ids, authorDeviceId: 'dev_phone_phase20' }
    const snapshot = phase18SnapshotFixture()
    const parts = snapshotParts(snapshot)
    let state = createPhonePlannerState(options)
    state = importSnapshotIntoPlannerState(state, snapshot, options)

    assert.throws(() => addExistingSnapshotItemToPreset(state, parts.coding.id, 'item_missing_safe_item', options), /not found|unknown/)
    const withDesktop = addExistingSnapshotItemToPreset(state, parts.coding.id, parts.desktop.id, options)
    assert.throws(() => updateSnapshotPresetItem(withDesktop, parts.coding.id, parts.desktop.id, {
        accountIntentionId: parts.account.id
    }, options), /only allowed/)
    const removedDesktop = removeSnapshotItemFromPreset(withDesktop, parts.coding.id, parts.desktop.id, options)
    assert.equal(
        removedDesktop.snapshotEditor.presets.find(preset => preset.id === parts.coding.id).itemRefs.some(ref => ref.itemId === parts.desktop.id),
        false
    )

    const editor = clone(state.snapshotEditor)
    editor.presets[0].itemRefs.push({
        itemId: 'item_missing_safe_item',
        order: 99,
        enabled: true,
        metadataOnly: true
    })
    assert.throws(() => exportSafePresetPatchJson(editor), /unknown safe item id/)
})

test('phone preset patch export rejects raw paths, capabilities, secrets, unsafe URLs, and forbidden fields', () => {
    const ids = idFactory()
    const options = { now: NOW, idFactory: ids, authorDeviceId: 'dev_phone_phase20' }
    const snapshot = phase18SnapshotFixture()
    let state = createPhonePlannerState(options)
    state = importSnapshotIntoPlannerState(state, snapshot, options)
    const baseEditor = state.snapshotEditor
    const cases = [
        editor => { editor.presets[0].name = 'C:\\Windows\\System32\\notepad.exe' },
        editor => { editor.presets[0].name = 'password=do-not-store' },
        editor => { editor.presets[0].capabilityId = `cap_${'aa'.repeat(32)}` },
        editor => { editor.presets[0].itemRefs[0].args = '--token=do-not-store' },
        editor => { editor.selection.vaultJson = { ciphertext: 'nope' } },
        editor => {
            editor.newBrowserItems.push({
                id: 'patch_item_localhost',
                url: 'http://localhost:3000',
                label: 'Local',
                notes: '',
                enabled: true,
                metadataOnly: true
            })
            editor.presets[0].itemRefs.push({
                itemId: 'patch_item_localhost',
                order: 99,
                enabled: true,
                metadataOnly: true
            })
        },
        editor => {
            editor.newBrowserItems.push({
                id: 'patch_item_secret_url',
                url: 'https://example.com/?access_token=abc123',
                label: 'Secret URL',
                notes: '',
                enabled: true,
                metadataOnly: true
            })
            editor.presets[0].itemRefs.push({
                itemId: 'patch_item_secret_url',
                order: 99,
                enabled: true,
                metadataOnly: true
            })
        }
    ]

    for (const mutate of cases) {
        const editor = clone(baseEditor)
        mutate(editor)
        assert.throws(() => exportSafePresetPatchJson(editor), /forbidden|cannot contain|localhost|query parameters|valid web URL/)
    }
})

test('phone planner persists sanitized snapshot editor state in local storage', () => {
    const storage = new MemoryStorage()
    const ids = idFactory()
    const options = { now: NOW, idFactory: ids, authorDeviceId: 'dev_phone_phase20' }
    const snapshot = phase18SnapshotFixture()
    const parts = snapshotParts(snapshot)
    let state = createPhonePlannerState(options)
    state = importSnapshotIntoPlannerState(state, snapshot, options)
    state = updateSnapshotPresetFields(state, parts.coding.id, { name: 'Coding Stored' }, options)

    savePhonePlannerState(state, { storage })
    const reloaded = loadPhonePlannerState({ storage })
    const patch = JSON.parse(exportSafePresetPatchJson(reloaded.snapshotEditor))
    const plan = planSafePresetPatchImport({ patch, sanitizedSnapshot: snapshot })

    assert.equal(typeof storage.getItem(PHONE_PLANNER_STORAGE_KEY), 'string')
    assert.equal(reloaded.snapshotEditor.snapshot.revisionId, snapshot.revisionId)
    assert.equal(plan.presetPlans.find(item => item.presetId === parts.coding.id).next.name, 'Coding Stored')
})

test('phone safe preset patch validator rejects forbidden raw material independently of desktop planning', () => {
    const snapshot = phase18SnapshotFixture()
    const parts = snapshotParts(snapshot)
    const patch = {
        product: 'wipesnap',
        kind: 'safe-preset-patch',
        schemaVersion: 1,
        patchId: 'patch_phase20',
        patchRevisionId: 'patchrev_phase20_1',
        baseSnapshotRevisionId: snapshot.revisionId,
        authorDeviceId: 'dev_phone_phase20',
        createdAt: NOW,
        updatedAt: NOW,
        selection: {
            defaultPresetId: parts.coding.id,
            nextPresetId: parts.coding.id,
            metadataOnly: true,
            selectionKind: 'metadata-only'
        },
        presets: [{
            id: parts.coding.id,
            name: 'Coding',
            order: 0,
            enabled: true,
            itemRefs: [{
                itemId: parts.browser.id,
                order: 0,
                enabled: true,
                metadataOnly: true
            }],
            metadataOnly: true,
            launchCapability: `cap_${'bb'.repeat(32)}`
        }],
        newBrowserItems: []
    }

    assert.throws(() => validateSafePresetPatchForPhone(patch, snapshot), /forbidden|not accepted/)
})

test('phone planner creates an offline AI Studio draft export accepted by Phase 15 validation', () => {
    const state = buildAiStudioPlannerState()
    const exportedJson = exportCloudDraftJson(selectedDraft(state))
    const exported = JSON.parse(exportedJson)
    const validated = validateCloudDraft(exportedJson)
    const importPlan = planCloudDraftImport(exported)

    assert.equal(validated.name, 'AI Studio two-account plan')
    assert.equal(validated.browserTabs.length, 2)
    assert.deepEqual(validated.browserTabs.map(tab => tab.url), [
        'https://aistudio.google.com/',
        'https://aistudio.google.com/'
    ])
    assert.deepEqual(validated.accountSlots.map(slot => slot.state), ['needs-check', 'needs-check'])
    assert.deepEqual(importPlan.accountIntentions.map(intent => intent.desktopState), ['needs-recheck', 'needs-recheck'])
    assert.equal(importPlan.safeBrowserTabs[0].accountIntentionId, validated.accountSlots[0].id)
    assert.equal(importPlan.safeBrowserTabs[1].accountIntentionId, validated.accountSlots[1].id)
    assert.equal(importPlan.desiredAppPlaceholders[0].status, 'unresolved')
    assert.equal(importPlan.desiredAppPlaceholders[0].launchable, false)
})

test('phone planner supports creating, editing, duplicating, and deleting local drafts', () => {
    const ids = idFactory()
    const options = { now: NOW, idFactory: ids }
    let state = createPhonePlannerState({ ...options, name: 'First draft' })
    state = createDraftInState(state, { ...options, name: 'Second draft' })
    const secondDraftId = state.selectedDraftId
    state = updateDraftFields(state, secondDraftId, { notes: 'Edited locally.' }, options)
    state = duplicateDraftInState(state, secondDraftId, options)
    const duplicateDraftId = state.selectedDraftId
    state = deleteDraftFromState(state, secondDraftId, options)

    assert.equal(state.drafts.length, 2)
    assert.equal(state.drafts.some(draft => draft.draftId === secondDraftId), false)
    assert.equal(state.drafts.some(draft => draft.draftId === duplicateDraftId), true)
    assert.equal(selectedDraft(state).name.endsWith(' Copy'), true)
    assert.equal(selectedDraft(state).notes, 'Edited locally.')
})

test('phone planner persists drafts in local browser storage across reload', () => {
    const storage = new MemoryStorage()
    const state = buildAiStudioPlannerState()

    savePhonePlannerState(state, { storage })
    const stored = storage.getItem(PHONE_PLANNER_STORAGE_KEY)
    const reloaded = loadPhonePlannerState({ storage })
    const exported = validateCloudDraft(exportCloudDraftJson(selectedDraft(reloaded)))

    assert.equal(typeof stored, 'string')
    assert.equal(reloaded.drafts.length, state.drafts.length)
    assert.equal(reloaded.selectedDraftId, state.selectedDraftId)
    assert.equal(exported.browserTabs.length, 2)
    assert.equal(exported.desiredApps[0].name, 'Cursor')
})

test('desired apps export as name-only unresolved placeholders', () => {
    const draft = selectedDraft(buildAiStudioPlannerState())
    const exported = JSON.parse(exportCloudDraftJson(draft))
    const desiredApp = exported.desiredApps[0]

    assert.deepEqual(Object.keys(desiredApp).sort(), ['enabled', 'id', 'label', 'name', 'notes'].sort())
    assert.equal(desiredApp.name, 'Cursor')
    assert.equal(JSON.stringify(desiredApp).includes('path'), false)
    assert.equal(JSON.stringify(desiredApp).includes('capability'), false)
})

test('phone planner rejects forbidden paths, scripts, secrets, capabilities, and unsafe URLs before export', () => {
    const baseDraft = selectedDraft(buildAiStudioPlannerState())
    const cases = [
        draft => { draft.path = 'C:\\Windows\\System32\\notepad.exe' },
        draft => { draft.notes = 'password=do-not-store' },
        draft => { draft.accountSlots[0].identifierHint = 'Bearer abcdefghijklmnopqrstuvwxyz' },
        draft => { draft.browserTabs[0].url = 'http://localhost:3000' },
        draft => { draft.browserTabs[0].url = 'https://example.com/?access_token=abc123' },
        draft => { draft.browserTabs[0].capabilityId = `cap_${'aa'.repeat(32)}` },
        draft => { draft.desiredApps[0].name = 'C:\\Windows\\System32\\notepad.exe' },
        draft => { draft.desiredApps[0].name = 'notepad.exe' },
        draft => { draft.desiredApps[0].notes = 'Run helper.ps1' }
    ]

    for (const mutate of cases) {
        const draft = clone(baseDraft)
        mutate(draft)
        assert.throws(() => exportCloudDraftJson(draft), /not accepted|cannot contain|localhost|query parameters/)
    }
})

test('phone planner enforces Phase 14 hard schema limits before export', () => {
    const baseDraft = selectedDraft(buildAiStudioPlannerState())
    const ids = idFactory()
    const options = { idFactory: ids }
    const profiles = Array.from({ length: PHONE_DRAFT_LIMITS.maxBrowserProfileSlots + 1 }, (_, index) => createBrowserProfileSlot({
        label: `Profile ${index}`,
        idFactory: ids
    }))
    const accounts = Array.from({ length: PHONE_DRAFT_LIMITS.maxAccountIntentions + 1 }, (_, index) => createAccountIntention({
        label: `Google ${index}`,
        profileSlotId: baseDraft.browserProfileSlots[0].id,
        idFactory: ids
    }))
    const tabs = Array.from({ length: PHONE_DRAFT_LIMITS.maxBrowserTabs + 1 }, (_, index) => createBrowserTab({
        url: `https://example.com/${index}`,
        order: index,
        accountSlotId: baseDraft.accountSlots[0].id,
        profileSlotId: baseDraft.browserProfileSlots[0].id,
        idFactory: ids
    }))
    const apps = Array.from({ length: PHONE_DRAFT_LIMITS.maxDesiredApps + 1 }, (_, index) => createDesiredAppPlaceholder({
        name: `App ${index}`,
        idFactory: ids
    }))

    assert.throws(() => exportCloudDraftJson({ ...baseDraft, name: 'x'.repeat(PHONE_DRAFT_LIMITS.maxDraftNameLength + 1) }), /too long/)
    assert.throws(() => exportCloudDraftJson({ ...baseDraft, notes: 'x'.repeat(PHONE_DRAFT_LIMITS.maxDraftNotesLength + 1) }), /too long/)
    assert.throws(() => exportCloudDraftJson({ ...baseDraft, browserTabs: [{ ...baseDraft.browserTabs[0], label: 'x'.repeat(PHONE_DRAFT_LIMITS.maxBrowserTabLabelLength + 1) }] }), /too long/)
    assert.throws(() => exportCloudDraftJson({ ...baseDraft, accountSlots: [{ ...baseDraft.accountSlots[0], label: 'x'.repeat(PHONE_DRAFT_LIMITS.maxAccountIntentionLabelLength + 1) }] }), /too long/)
    assert.throws(() => exportCloudDraftJson({ ...baseDraft, browserProfileSlots: [{ ...baseDraft.browserProfileSlots[0], label: 'x'.repeat(PHONE_DRAFT_LIMITS.maxBrowserProfileSlotLabelLength + 1) }] }), /too long/)
    assert.throws(() => exportCloudDraftJson({ ...baseDraft, desiredApps: [{ ...baseDraft.desiredApps[0], notes: 'x'.repeat(PHONE_DRAFT_LIMITS.maxDesiredAppNotesLength + 1) }] }), /too long/)
    assert.throws(() => exportCloudDraftJson({ ...baseDraft, browserProfileSlots: profiles }), /browserProfileSlots/)
    assert.throws(() => exportCloudDraftJson({ ...baseDraft, accountSlots: accounts }), /accountSlots/)
    assert.throws(() => exportCloudDraftJson({ ...baseDraft, browserTabs: tabs }), /browserTabs/)
    assert.throws(() => exportCloudDraftJson({ ...baseDraft, desiredApps: apps }), /desiredApps/)

    let state = createPhonePlannerState({ ...options, now: NOW })
    for (let index = 1; index < PHONE_DRAFT_LIMITS.maxActiveDraftsPerUser; index += 1) {
        state = createDraftInState(state, { ...options, now: NOW, name: `Draft ${index}` })
    }
    assert.throws(() => createDraftInState(state, { ...options, now: NOW, name: 'Too many' }), /active drafts/)
})

import assert from 'assert/strict'
import { test } from 'node:test'
import { planCloudDraftImport } from '../src/main/cloudDraftImport.js'
import { validateCloudDraft } from '../src/main/cloudDraftSchema.js'
import {
    PHONE_DRAFT_LIMITS,
    addDraftItem,
    createAccountIntention,
    createBrowserProfileSlot,
    createBrowserTab,
    createDesiredAppPlaceholder,
    createDraftInState,
    createPhonePlannerState,
    deleteDraftFromState,
    duplicateDraftInState,
    exportCloudDraftJson,
    updateDraftFields
} from '../src/phone-planner/phonePlannerCore.js'
import {
    PHONE_PLANNER_STORAGE_KEY,
    loadPhonePlannerState,
    savePhonePlannerState
} from '../src/phone-planner/phonePlannerStorage.js'

const NOW = 1770000000000

function clone(value) {
    return JSON.parse(JSON.stringify(value))
}

function idFactory() {
    let index = 0
    return prefix => `${prefix}_${++index}`
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

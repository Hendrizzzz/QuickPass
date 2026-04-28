import assert from 'assert/strict'
import { test } from 'node:test'
import {
    CLOUD_DRAFT_LIMITS,
    mapCloudAccountStateToDesktopState,
    validateActiveCloudDraftLimit,
    validateCloudDraft,
    validateCloudDraftEnvelope
} from '../src/main/cloudDraftSchema.js'

function clone(value) {
    return JSON.parse(JSON.stringify(value))
}

function validDraft(overrides = {}) {
    return {
        product: 'wipesnap',
        schemaVersion: 1,
        draftId: 'draft_class_ai',
        revisionId: 'rev_class_ai_1',
        baseRevisionId: 'rev_class_ai_0',
        authorDeviceId: 'dev_phone_1',
        name: 'Class AI Workspace',
        notes: 'Open before lab.',
        isDefault: true,
        accountSlots: [
            {
                id: 'intent_google_personal',
                provider: 'google',
                label: 'Personal Google',
                identifierHint: 'p***@gmail.com',
                profileSlotId: 'profile_personal',
                state: 'needs-check'
            }
        ],
        browserProfileSlots: [
            {
                id: 'profile_personal',
                label: 'Personal',
                provider: 'google'
            }
        ],
        browserTabs: [
            {
                id: 'tab_ai_studio_personal',
                url: 'aistudio.google.com',
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
            }
        ],
        createdAt: 1770000000000,
        updatedAt: 1770000000001,
        ...overrides
    }
}

function makeProfiles(count) {
    return Array.from({ length: count }, (_, index) => ({
        id: `profile_${index}`,
        label: `Profile ${index}`,
        provider: 'google'
    }))
}

function makeAccounts(count) {
    return Array.from({ length: count }, (_, index) => ({
        id: `intent_google_${index}`,
        provider: 'google',
        label: `Google ${index}`,
        identifierHint: `user${index}@example.com`,
        profileSlotId: 'profile_0',
        state: 'unknown'
    }))
}

function makeTabs(count) {
    return Array.from({ length: count }, (_, index) => ({
        id: `tab_${index}`,
        url: `https://example.com/${index}`,
        order: index,
        label: `Tab ${index}`,
        notes: '',
        enabled: true,
        accountSlotId: 'intent_google_0',
        profileSlotId: 'profile_0'
    }))
}

function makeDesiredApps(count) {
    return Array.from({ length: count }, (_, index) => ({
        id: `wish_${index}`,
        name: `App ${index}`,
        label: `App ${index}`,
        notes: '',
        enabled: true
    }))
}

function mutateDraft(mutator) {
    const draft = validDraft()
    mutator(draft)
    return draft
}

function validEnvelope(overrides = {}) {
    return {
        ownerUid: 'user_1',
        draftId: 'draft_class_ai',
        schemaVersion: 1,
        revisionId: 'rev_class_ai_1',
        baseRevisionId: 'rev_class_ai_0',
        authorDeviceId: 'dev_phone_1',
        updatedAt: 1770000000001,
        createdAt: 1770000000000,
        deletedAt: null,
        isDefault: true,
        encrypted: true,
        encryption: {
            alg: 'AES-GCM',
            keyId: 'dsk_1',
            nonce: 'nonce_1'
        },
        blobHash: 'sha256-base64url',
        blobCiphertext: 'base64url_ciphertext',
        ...overrides
    }
}

test('draft schema accepts a safe canonical draft and normalizes URL and account state', () => {
    const draft = validateCloudDraft(validDraft({
        product: 'WIPESNAP',
        name: '  Class AI Workspace  ',
        notes: '  Open before lab.  '
    }))

    assert.equal(draft.product, 'wipesnap')
    assert.equal(draft.name, 'Class AI Workspace')
    assert.equal(draft.notes, 'Open before lab.')
    assert.equal(draft.browserTabs[0].url, 'https://aistudio.google.com/')
    assert.equal(draft.accountSlots[0].state, 'needs-check')
    assert.equal(draft.accountSlots[0].desktopState, 'needs-recheck')
    assert.equal(mapCloudAccountStateToDesktopState('blocked'), 'blocked-or-suspicious')
})

test('draft schema rejects unsupported versions, providers, states, duplicates, and broken references', () => {
    assert.throws(() => validateCloudDraft(validDraft({ schemaVersion: 2 })), /schemaVersion/)
    assert.throws(() => validateCloudDraft(mutateDraft(draft => { draft.accountSlots[0].provider = 'microsoft' })), /provider/)
    assert.throws(() => validateCloudDraft(mutateDraft(draft => { draft.accountSlots[0].state = 'needs-recheck' })), /state/)
    assert.throws(() => validateCloudDraft(mutateDraft(draft => { draft.browserTabs.push(clone(draft.browserTabs[0])) })), /duplicate id/)
    assert.throws(() => validateCloudDraft(mutateDraft(draft => { draft.browserTabs[0].accountSlotId = 'intent_missing' })), /unknown account slot/)
    assert.throws(() => validateCloudDraft(mutateDraft(draft => { draft.accountSlots[0].profileSlotId = 'profile_missing' })), /unknown browser profile/)
    assert.throws(() => validateCloudDraft(mutateDraft(draft => { draft.draftId = `cap_${'aa'.repeat(32)}` })), /launch capability id shape/)
})

test('unknown and forbidden fields fail closed at every draft level', () => {
    const cases = [
        draft => { draft.unexpected = true },
        draft => { draft.vaultJson = { ciphertext: 'nope' } },
        draft => { draft.launchCapabilityVault = { records: {} } },
        draft => { draft.accountSlots[0].password = 'do-not-store' },
        draft => { draft.accountSlots[0].oauthToken = 'do-not-store' },
        draft => { draft.browserProfileSlots[0].browserProfileData = {} },
        draft => { draft.browserTabs[0].capabilityId = `cap_${'aa'.repeat(32)}` },
        draft => { draft.browserTabs[0].path = 'C:\\Windows\\System32\\notepad.exe' },
        draft => { draft.desiredApps[0].registryKey = 'HKCU\\Software\\Bad' },
        draft => { draft.desiredApps[0].pid = 1234 }
    ]

    for (const mutator of cases) {
        assert.throws(() => validateCloudDraft(mutateDraft(mutator)), /not accepted/)
    }
})

test('unsafe browser URLs fail closed using desktop URL rules plus cloud-local restrictions', () => {
    for (const url of [
        'javascript:alert(1)',
        'file:///C:/Users/Alice/vault.json',
        'http://user:pass@example.com',
        'http://localhost:3000',
        'http://127.0.0.1:3000',
        'http://192.168.1.2',
        'https://example.com/callback?access_token=abc123'
    ]) {
        assert.throws(() => validateCloudDraft(mutateDraft(draft => { draft.browserTabs[0].url = url })), /url/)
    }
})

test('browser URL query and fragment values reject decoded forbidden material', () => {
    for (const url of [
        'https://example.com/?file=C:%5CUsers%5CAlice%5Cvault.json',
        'https://example.com/?next=C:%255CUsers%255CAlice%255CAppData%255CLocal',
        'https://example.com/?hint=BrowserProfile',
        'https://example.com/#vault.meta.json',
        'https://example.com/#C:%5CUsers%5CAlice%5CBrowserProfile',
        `https://example.com/?capability=cap_${'aa'.repeat(32)}`,
        `https://example.com/#cap_${'bb'.repeat(32)}`,
        'https://example.com/?note=token%3Ddo-not-store',
        'https://example.com/?note=setup.bat',
        'https://example.com/#helper.cmd'
    ]) {
        assert.throws(() => validateCloudDraft(mutateDraft(draft => { draft.browserTabs[0].url = url })), /url/)
    }
})

test('normal public browser URLs with ordinary web paths still pass', () => {
    const draft = validateCloudDraft(mutateDraft(draft => {
        draft.browserTabs[0].url = 'https://example.com/assets/app.js?next=%2Fapp.js#section'
    }))

    assert.equal(draft.browserTabs[0].url, 'https://example.com/assets/app.js?next=%2Fapp.js#section')
})

test('raw paths, executable placeholders, registry paths, commands, process selectors, and secrets fail closed in allowed strings', () => {
    const cases = [
        draft => { draft.notes = 'run setup.bat' },
        draft => { draft.notes = 'Open C:\\Users\\Alice\\AppData\\Local later.' },
        draft => { draft.notes = 'Registry key HKCU\\Software\\Bad should not be here.' },
        draft => { draft.browserTabs[0].label = 'Launch helper.lnk' },
        draft => { draft.browserTabs[0].notes = 'Use helper.cmd' },
        draft => { draft.browserTabs[0].notes = 'pid=1234' },
        draft => { draft.browserTabs[0].notes = 'powershell -EncodedCommand AAAA' },
        draft => { draft.accountSlots[0].label = 'Personal setup.exe' },
        draft => { draft.accountSlots[0].identifierHint = 'Bearer abcdefghijklmnopqrstuvwxyz' },
        draft => { draft.accountSlots[0].identifierHint = 'helper.ps1' },
        draft => { draft.browserProfileSlots[0].label = 'Profile helper.vbs' },
        draft => { draft.desiredApps[0].name = 'C:\\Windows\\System32\\notepad.exe' },
        draft => { draft.desiredApps[0].name = 'notepad.exe' },
        draft => { draft.desiredApps[0].label = 'Cursor --profile Work' },
        draft => { draft.desiredApps[0].notes = 'Resolve with installer.msi' },
        draft => { draft.desiredApps[0].notes = 'password=do-not-store' },
        draft => { draft.name = `cap_${'cc'.repeat(32)}` },
        draft => { draft.name = 'secret=0123456789abcdef0123456789abcdef01234567' }
    ]

    for (const mutator of cases) {
        assert.throws(() => validateCloudDraft(mutateDraft(mutator)), /cannot contain/)
    }
})

test('draft schema enforces exact collection limits and accepts boundary counts', () => {
    const boundary = validateCloudDraft(validDraft({
        browserProfileSlots: makeProfiles(CLOUD_DRAFT_LIMITS.maxBrowserProfileSlots),
        accountSlots: makeAccounts(CLOUD_DRAFT_LIMITS.maxAccountIntentions),
        browserTabs: makeTabs(CLOUD_DRAFT_LIMITS.maxBrowserTabs),
        desiredApps: makeDesiredApps(CLOUD_DRAFT_LIMITS.maxDesiredApps)
    }))

    assert.equal(boundary.browserProfileSlots.length, CLOUD_DRAFT_LIMITS.maxBrowserProfileSlots)
    assert.equal(boundary.accountSlots.length, CLOUD_DRAFT_LIMITS.maxAccountIntentions)
    assert.equal(boundary.browserTabs.length, CLOUD_DRAFT_LIMITS.maxBrowserTabs)
    assert.equal(boundary.desiredApps.length, CLOUD_DRAFT_LIMITS.maxDesiredApps)

    assert.throws(() => validateCloudDraft(validDraft({
        browserProfileSlots: makeProfiles(CLOUD_DRAFT_LIMITS.maxBrowserProfileSlots + 1)
    })), /browserProfileSlots/)
    assert.throws(() => validateCloudDraft(validDraft({
        browserProfileSlots: makeProfiles(1),
        accountSlots: makeAccounts(CLOUD_DRAFT_LIMITS.maxAccountIntentions + 1)
    })), /accountSlots/)
    assert.throws(() => validateCloudDraft(validDraft({
        browserProfileSlots: makeProfiles(1),
        accountSlots: makeAccounts(1),
        browserTabs: makeTabs(CLOUD_DRAFT_LIMITS.maxBrowserTabs + 1)
    })), /browserTabs/)
    assert.throws(() => validateCloudDraft(validDraft({
        desiredApps: makeDesiredApps(CLOUD_DRAFT_LIMITS.maxDesiredApps + 1)
    })), /desiredApps/)
})

test('draft schema enforces exact string and id limits', () => {
    const urlPrefix = 'https://example.com/'
    const overlongUrl = `${urlPrefix}${'a'.repeat(CLOUD_DRAFT_LIMITS.maxBrowserTabUrlLength - urlPrefix.length + 1)}`
    const cases = [
        draft => { draft.name = 'x'.repeat(CLOUD_DRAFT_LIMITS.maxDraftNameLength + 1) },
        draft => { draft.notes = 'x'.repeat(CLOUD_DRAFT_LIMITS.maxDraftNotesLength + 1) },
        draft => { draft.browserTabs[0].url = overlongUrl },
        draft => { draft.browserTabs[0].label = 'x'.repeat(CLOUD_DRAFT_LIMITS.maxBrowserTabLabelLength + 1) },
        draft => { draft.browserTabs[0].notes = 'x'.repeat(CLOUD_DRAFT_LIMITS.maxBrowserTabNotesLength + 1) },
        draft => { draft.accountSlots[0].label = 'x'.repeat(CLOUD_DRAFT_LIMITS.maxAccountIntentionLabelLength + 1) },
        draft => { draft.accountSlots[0].identifierHint = 'x'.repeat(CLOUD_DRAFT_LIMITS.maxAccountIdentifierHintLength + 1) },
        draft => { draft.browserProfileSlots[0].label = 'x'.repeat(CLOUD_DRAFT_LIMITS.maxBrowserProfileSlotLabelLength + 1) },
        draft => { draft.desiredApps[0].name = 'x'.repeat(CLOUD_DRAFT_LIMITS.maxDesiredAppNameLength + 1) },
        draft => { draft.desiredApps[0].label = 'x'.repeat(CLOUD_DRAFT_LIMITS.maxDesiredAppLabelLength + 1) },
        draft => { draft.desiredApps[0].notes = 'x'.repeat(CLOUD_DRAFT_LIMITS.maxDesiredAppNotesLength + 1) },
        draft => { draft.revisionId = `r${'x'.repeat(CLOUD_DRAFT_LIMITS.maxIdLength)}` }
    ]

    for (const mutator of cases) {
        assert.throws(() => validateCloudDraft(mutateDraft(mutator)), /too long|safe draft id/)
    }
})

test('oversized draft JSON fails before parsing attacker content', () => {
    const secret = 'password=do-not-store'
    const oversized = `${' '.repeat(CLOUD_DRAFT_LIMITS.maxDraftJsonBytes + 1)}{"notes":"${secret}"}`

    assert.throws(() => validateCloudDraft(oversized), /byte limit/)
})

test('cloud envelope validation enforces size, encryption, strict fields, and supported version', () => {
    const envelope = validateCloudDraftEnvelope(validEnvelope())
    assert.equal(envelope.encrypted, true)
    assert.equal(envelope.encryption.alg, 'AES-GCM')

    assert.throws(() => validateCloudDraftEnvelope(validEnvelope({ schemaVersion: 2 })), /schemaVersion/)
    assert.throws(() => validateCloudDraftEnvelope(validEnvelope({ encrypted: false })), /encrypted/)
    assert.throws(() => validateCloudDraftEnvelope(validEnvelope({ vaultMeta: {} })), /not accepted/)
    assert.throws(() => validateCloudDraftEnvelope({
        ...validEnvelope(),
        blobCiphertext: 'a'.repeat(CLOUD_DRAFT_LIMITS.maxCloudEnvelopeBytes)
    }), /byte limit/)
})

test('active draft limit counts only non-tombstone drafts', () => {
    const active = Array.from({ length: CLOUD_DRAFT_LIMITS.maxActiveDraftsPerUser }, (_, index) => ({
        draftId: `draft_${index}`,
        deletedAt: null
    }))
    const tombstones = [
        { draftId: 'draft_deleted_1', deletedAt: 1770000000000 },
        { draftId: 'draft_deleted_2', deletedAt: 1770000000001 }
    ]

    assert.deepEqual(validateActiveCloudDraftLimit([...active, ...tombstones]), {
        activeDrafts: CLOUD_DRAFT_LIMITS.maxActiveDraftsPerUser,
        maxActiveDrafts: CLOUD_DRAFT_LIMITS.maxActiveDraftsPerUser
    })
    assert.throws(() => validateActiveCloudDraftLimit([...active, { draftId: 'draft_too_many', deletedAt: null }]), /active drafts/)
})

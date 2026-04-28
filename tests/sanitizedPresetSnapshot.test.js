import assert from 'assert/strict'
import { test } from 'node:test'
import { createCapabilityRecord } from '../src/main/capabilityStore.js'
import { WORKSPACE_CAPABILITY_VAULT_KEY } from '../src/main/workspaceCapabilityMigration.js'
import {
    SANITIZED_PRESET_SNAPSHOT_LIMITS,
    buildSanitizedPresetSnapshot
} from '../src/main/sanitizedPresetSnapshot.js'

const SECRET = Buffer.from('phase-18-snapshot-safe-id-secret-32-bytes-minimum')
const TIMESTAMP = 1770000000000
const ACCOUNT_ID = `acct_${'a1'.repeat(24)}`
const PROFILE_ID = 'profile_personal'

function bytes(hexByte) {
    return (size) => Buffer.alloc(size, hexByte)
}

function clone(value) {
    return JSON.parse(JSON.stringify(value))
}

function hostExeRecord(hexByte = 0x11) {
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

function hostFolderRecord(hexByte = 0x22) {
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

function snapshotInput(overrides = {}) {
    const appRecord = hostExeRecord()
    const folderRecord = hostFolderRecord()
    const workspace = {
        id: 'desktop-workspace-raw-id',
        name: 'Coding',
        defaultPresetId: 'desktop-workspace-raw-id',
        nextPresetId: 'desktop-workspace-raw-id',
        webTabs: [
            {
                id: 'raw-tab-ai-studio',
                url: 'https://aistudio.google.com/',
                label: 'AI Studio',
                enabled: true,
                accountSlotId: ACCOUNT_ID,
                profileSlotId: PROFILE_ID
            },
            {
                id: 'raw-tab-unsafe-local',
                url: 'http://localhost:3000/callback?token=do-not-store',
                label: 'Local callback token=do-not-store',
                enabled: true
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
                id: ACCOUNT_ID,
                provider: 'google',
                label: 'Personal Google',
                identifierHint: 'p***@gmail.com',
                state: 'needs-recheck',
                lastCheckedAt: 0,
                notes: ''
            }
        ],
        browserProfileSlots: [
            {
                id: PROFILE_ID,
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

    return {
        snapshotSafeIdSecret: SECRET,
        sourceDeviceId: 'desktop-device-raw-id',
        snapshotId: 'desktop-snapshot-raw-id',
        revisionId: 'desktop-revision-raw-id',
        baseRevisionId: 'desktop-base-revision-raw-id',
        timestamp: TIMESTAMP,
        workspace,
        ...overrides
    }
}

function build(overrides = {}) {
    return buildSanitizedPresetSnapshot(snapshotInput(overrides))
}

function allIds(snapshot) {
    return [
        snapshot.snapshotId,
        snapshot.revisionId,
        snapshot.baseRevisionId,
        snapshot.sourceDeviceId,
        ...snapshot.presets.map(preset => preset.id),
        ...snapshot.presets.flatMap(preset => preset.itemRefs.map(ref => ref.id)),
        ...snapshot.availableItems.map(item => item.id)
    ].filter(Boolean)
}

test('capability-backed apps and folders map to safe item ids only', () => {
    const snapshot = build()
    const desktopItems = snapshot.availableItems.filter(item => item.source === 'desktop')

    assert.deepEqual(desktopItems.map(item => item.type), ['desktop-app', 'host-folder'])
    assert.equal(desktopItems.every(item => item.id.startsWith('item_')), true)
    assert.equal(desktopItems.every(item => item.id.length <= SANITIZED_PRESET_SNAPSHOT_LIMITS.maxIdLength), true)
    assert.equal(snapshot.presets[0].itemRefs.every(ref => ref.id.startsWith('pref_')), true)
    assert.equal(snapshot.presets[0].itemRefs.every(ref => snapshot.availableItems.some(item => item.id === ref.itemId)), true)
})

test('safe ids are domain separated, prefixed, bounded, and do not expose raw ids', () => {
    const snapshot = build()
    const serialized = JSON.stringify(snapshot)

    assert.match(snapshot.snapshotId, /^snap_[A-Za-z0-9_-]+$/)
    assert.match(snapshot.revisionId, /^srev_[A-Za-z0-9_-]+$/)
    assert.match(snapshot.sourceDeviceId, /^dev_[A-Za-z0-9_-]+$/)
    assert.match(snapshot.presets[0].id, /^preset_[A-Za-z0-9_-]+$/)
    assert.match(snapshot.presets[0].itemRefs[0].id, /^pref_[A-Za-z0-9_-]+$/)
    assert.match(snapshot.availableItems.find(item => item.type === 'account-intention').id, /^accti_[A-Za-z0-9_-]+$/)
    assert.match(snapshot.availableItems.find(item => item.type === 'profile-intention').id, /^profi_[A-Za-z0-9_-]+$/)
    assert.equal(new Set(allIds(snapshot)).size, allIds(snapshot).length)
    for (const id of allIds(snapshot)) assert.ok(id.length <= SANITIZED_PRESET_SNAPSHOT_LIMITS.maxIdLength)

    for (const raw of [
        'desktop-device-raw-id',
        'desktop-snapshot-raw-id',
        'desktop-revision-raw-id',
        'desktop-workspace-raw-id',
        'raw-tab-ai-studio',
        ACCOUNT_ID,
        PROFILE_ID
    ]) {
        assert.equal(serialized.includes(raw), false, `snapshot leaked ${raw}`)
    }
})

test('serialized snapshot contains no raw paths, capability ids, or capability records', () => {
    const input = snapshotInput()
    const serialized = JSON.stringify(buildSanitizedPresetSnapshot(input))
    const rawCapabilityIds = Object.keys(input.workspace[WORKSPACE_CAPABILITY_VAULT_KEY].records)

    for (const forbidden of [
        ...rawCapabilityIds,
        'C:\\',
        '[USB]',
        'Program Files',
        'Users\\Alice',
        'launch',
        'capability',
        'records',
        'registry',
        'process',
        'args',
        'manifestId',
        'storageId'
    ]) {
        assert.equal(serialized.toLowerCase().includes(forbidden.toLowerCase()), false, `snapshot leaked ${forbidden}`)
    }
})

test('unsafe browser URLs are redacted without leaking the URL or secret-looking query', () => {
    const snapshot = build()
    const browserItems = snapshot.availableItems.filter(item => item.type === 'browser-tab')
    const redacted = browserItems.find(item => item.status === 'redacted')
    const safe = browserItems.find(item => item.status === 'available')
    const serialized = JSON.stringify(snapshot)

    assert.equal(safe.url, 'https://aistudio.google.com/')
    assert.equal(redacted.url, undefined)
    assert.equal(redacted.label, 'Browser Tab')
    assert.equal(serialized.includes('localhost'), false)
    assert.equal(serialized.includes('do-not-store'), false)
    assert.equal(serialized.includes('token='), false)
})

test('account and profile intentions are metadata only', () => {
    const snapshot = build()
    const account = snapshot.availableItems.find(item => item.type === 'account-intention')
    const profile = snapshot.availableItems.find(item => item.type === 'profile-intention')
    const browserRef = snapshot.presets[0].itemRefs.find(ref => ref.accountIntentionId)
    const serialized = JSON.stringify(snapshot)

    assert.equal(account.metadataOnly, true)
    assert.equal(account.provider, 'google')
    assert.equal(account.identifierHint, 'p***@gmail.com')
    assert.equal(account.state, 'needs-recheck')
    assert.equal(profile.metadataOnly, true)
    assert.equal(browserRef.accountIntentionId, account.id)
    assert.equal(browserRef.profileIntentionId, profile.id)
    assert.equal(serialized.includes(ACCOUNT_ID), false)
    assert.equal(serialized.includes('accountSlots'), false)
})

test('default and next preset selection are metadata only and create no launch authority', () => {
    const snapshot = build()
    const serialized = JSON.stringify(snapshot).toLowerCase()

    assert.equal(snapshot.selection.metadataOnly, true)
    assert.equal(snapshot.selection.selectionKind, 'metadata-only')
    assert.equal(snapshot.selection.defaultPresetId, snapshot.presets[0].id)
    assert.equal(snapshot.selection.nextPresetId, snapshot.presets[0].id)
    assert.equal(serialized.includes('launch'), false)
    assert.equal(serialized.includes('authority'), false)
})

test('missing, short, and malformed snapshotSafeIdSecret values fail closed', () => {
    assert.throws(() => buildSanitizedPresetSnapshot(snapshotInput({ snapshotSafeIdSecret: undefined })), /snapshotSafeIdSecret/)
    assert.throws(() => buildSanitizedPresetSnapshot(snapshotInput({ snapshotSafeIdSecret: 'too-short' })), /snapshotSafeIdSecret/)
    assert.throws(() => buildSanitizedPresetSnapshot(snapshotInput({ snapshotSafeIdSecret: { raw: 'not accepted' } })), /snapshotSafeIdSecret/)
})

test('stale capability-backed entries become broken items and malformed capability vaults fail closed', () => {
    const input = snapshotInput()
    const staleWorkspace = clone(input.workspace)
    staleWorkspace.desktopApps = [{
        id: 'stale-app',
        capabilityId: `cap_${'bb'.repeat(32)}`,
        displayName: 'Stale App',
        enabled: true
    }]
    staleWorkspace[WORKSPACE_CAPABILITY_VAULT_KEY] = { version: 1, records: {} }

    const staleSnapshot = buildSanitizedPresetSnapshot({
        ...input,
        workspace: staleWorkspace
    })
    const item = staleSnapshot.availableItems.find(entry => entry.source === 'desktop')
    assert.equal(item.status, 'broken')
    assert.equal(JSON.stringify(staleSnapshot).includes(`cap_${'bb'.repeat(32)}`), false)

    assert.throws(() => buildSanitizedPresetSnapshot({
        ...input,
        workspace: {
            ...input.workspace,
            [WORKSPACE_CAPABILITY_VAULT_KEY]: { version: 1, records: { bad: { malformed: true } } }
        }
    }), /capability vault is malformed/)
})

test('duplicate generated item ids or preset references fail closed', () => {
    const input = snapshotInput()
    const duplicateWorkspace = clone(input.workspace)
    const [firstApp] = duplicateWorkspace.desktopApps
    duplicateWorkspace.desktopApps = [
        firstApp,
        { ...firstApp, id: 'different-row-name' }
    ]

    assert.throws(() => buildSanitizedPresetSnapshot({
        ...input,
        workspace: duplicateWorkspace
    }), /duplicate generated id/)

    assert.throws(() => buildSanitizedPresetSnapshot({
        ...input,
        presets: [
            { id: 'preset-a', name: 'A', itemRefs: [{ capabilityId: firstApp.capabilityId }] },
            { id: 'preset-a', name: 'Duplicate', itemRefs: [{ capabilityId: firstApp.capabilityId }] }
        ]
    }), /duplicate generated id|duplicate source ids/)
})

test('hard schema limits are enforced', () => {
    const input = snapshotInput()
    const tooManyTabsWorkspace = clone(input.workspace)
    tooManyTabsWorkspace.webTabs = Array.from({
        length: SANITIZED_PRESET_SNAPSHOT_LIMITS.maxBrowserItems + 1
    }, (_, index) => ({
        id: `tab-${index}`,
        url: `https://example.com/${index}`,
        enabled: true
    }))

    assert.throws(() => buildSanitizedPresetSnapshot({
        ...input,
        workspace: tooManyTabsWorkspace
    }), /webTabs exceeds/)

    const tooManyPresets = Array.from({
        length: SANITIZED_PRESET_SNAPSHOT_LIMITS.maxPresets + 1
    }, (_, index) => ({
        id: `preset-${index}`,
        name: `Preset ${index}`,
        itemRefs: []
    }))
    assert.throws(() => buildSanitizedPresetSnapshot({
        ...input,
        presets: tooManyPresets
    }), /presets exceeds/)
})

test('recursive forbidden-field and secret-looking fixture data is not serialized', () => {
    const input = snapshotInput()
    const workspace = clone(input.workspace)
    workspace.name = 'C:\\Users\\Alice\\vault.json'
    workspace.webTabs[0].label = 'password=do-not-store'
    workspace.webTabs[0].url = 'https://example.com/'
    workspace.desktopApps[0] = {
        ...workspace.desktopApps[0],
        displayName: 'C:\\Users\\Alice\\AppData\\Local\\secret.exe',
        path: 'C:\\Users\\Alice\\AppData\\Local\\secret.exe',
        args: ['--token=do-not-store'],
        registryKey: 'HKCU\\Software\\Bad'
    }
    workspace.accountSlots[0].label = 'Bearer abcdefghijklmnopqrstuvwxyz'
    workspace.accountSlots[0].identifierHint = 'token=do-not-store'
    workspace.browserProfileSlots[0].label = 'BrowserProfile\\Default'

    const snapshot = buildSanitizedPresetSnapshot({
        ...input,
        workspace
    })
    const serialized = JSON.stringify(snapshot)

    for (const forbidden of [
        'C:\\',
        'vault.json',
        'AppData',
        'BrowserProfile',
        'secret.exe',
        'token=',
        'password=',
        'do-not-store',
        'HKCU',
        'args',
        'registryKey'
    ]) {
        assert.equal(serialized.includes(forbidden), false, `snapshot leaked ${forbidden}`)
    }
    assert.equal(snapshot.presets[0].name, 'Current Workspace')
    assert.equal(snapshot.availableItems.find(item => item.source === 'desktop').label, 'Desktop App')
    assert.equal(snapshot.availableItems.find(item => item.type === 'account-intention').label, 'Account')
    assert.equal(snapshot.availableItems.find(item => item.type === 'profile-intention').label, 'Browser Profile')
})

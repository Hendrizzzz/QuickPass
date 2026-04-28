import assert from 'assert/strict'
import { test } from 'node:test'
import { createCapabilityRecord } from '../src/main/capabilityStore.js'
import { WORKSPACE_CAPABILITY_VAULT_KEY } from '../src/main/workspaceCapabilityMigration.js'
import { buildSanitizedPresetSnapshot } from '../src/main/sanitizedPresetSnapshot.js'
import {
    SAFE_PRESET_PATCH_KIND,
    SAFE_PRESET_PATCH_LIMITS,
    planSafePresetPatchImport,
    validateSafePresetPatch
} from '../src/main/safePresetPatch.js'

const SECRET = Buffer.from('phase-19-safe-preset-patch-secret-32-bytes')
const NOW = 1770000000000
const ACCOUNT_ID = `acct_${'d4'.repeat(24)}`
const PROFILE_ID = 'profile_personal'

function clone(value) {
    return JSON.parse(JSON.stringify(value))
}

function bytes(hexByte) {
    return (size) => Buffer.alloc(size, hexByte)
}

function hostExeRecord(hexByte = 0x31) {
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

function hostFolderRecord(hexByte = 0x32) {
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
        defaultPresetId: 'coding-preset',
        nextPresetId: 'coding-preset',
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
                id: 'raw-tab-local-callback',
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
                        accountSlotId: ACCOUNT_ID,
                        profileSlotId: PROFILE_ID
                    }
                ]
            }
        ],
        ...overrides
    }
}

function buildSnapshot(overrides = {}) {
    return buildSanitizedPresetSnapshot(snapshotInput(overrides))
}

function itemOf(snapshot, type) {
    const item = snapshot.availableItems.find(entry => entry.type === type && entry.status !== 'redacted')
    assert.ok(item, `Missing ${type}`)
    return item
}

function itemIds(snapshot) {
    return {
        preset: snapshot.presets[0],
        browser: itemOf(snapshot, 'browser-tab'),
        desktop: itemOf(snapshot, 'desktop-app'),
        folder: itemOf(snapshot, 'host-folder'),
        account: itemOf(snapshot, 'account-intention'),
        profile: itemOf(snapshot, 'profile-intention')
    }
}

function validPatch(snapshot, mutator = () => {}) {
    const ids = itemIds(snapshot)
    const patch = {
        product: 'wipesnap',
        kind: SAFE_PRESET_PATCH_KIND,
        schemaVersion: 1,
        patchId: 'patch_phase19',
        patchRevisionId: 'patchrev_phase19_1',
        baseSnapshotRevisionId: snapshot.revisionId,
        authorDeviceId: 'dev_phone_phase19',
        createdAt: NOW,
        updatedAt: NOW + 1,
        selection: {
            defaultPresetId: ids.preset.id,
            nextPresetId: ids.preset.id,
            metadataOnly: true,
            selectionKind: 'metadata-only'
        },
        newBrowserItems: [],
        presets: [
            {
                id: ids.preset.id,
                name: 'Coding Remote',
                order: 1,
                enabled: false,
                itemRefs: [
                    {
                        itemId: ids.browser.id,
                        order: 1,
                        enabled: true,
                        accountIntentionId: ids.account.id,
                        profileIntentionId: ids.profile.id,
                        metadataOnly: true
                    },
                    {
                        itemId: ids.desktop.id,
                        order: 0,
                        enabled: false,
                        metadataOnly: true
                    },
                    {
                        itemId: ids.folder.id,
                        order: 2,
                        enabled: true,
                        metadataOnly: true
                    }
                ],
                metadataOnly: true
            }
        ]
    }
    mutator(patch, ids)
    return patch
}

function patchWithNewTab(snapshot, mutator = () => {}) {
    return validPatch(snapshot, (patch, ids) => {
        patch.newBrowserItems = [
            {
                id: 'patch_item_ai_studio_extra',
                url: 'aistudio.google.com',
                label: 'AI Studio Extra',
                notes: '',
                enabled: true,
                accountIntentionId: ids.account.id,
                profileIntentionId: ids.profile.id,
                metadataOnly: true
            }
        ]
        patch.presets[0].itemRefs.push({
            itemId: 'patch_item_ai_studio_extra',
            order: 3,
            enabled: true,
            metadataOnly: true
        })
        mutator(patch, ids)
    })
}

test('accepted patch against a current sanitized snapshot produces a deterministic plan only', () => {
    const snapshot = buildSnapshot()
    const patch = validPatch(snapshot)
    const plan = planSafePresetPatchImport({ patch, sanitizedSnapshot: snapshot })
    const repeated = planSafePresetPatchImport({ patch: clone(patch), sanitizedSnapshot: clone(snapshot) })

    assert.deepEqual(plan, repeated)
    assert.equal(plan.success, true)
    assert.equal(plan.source, 'safe-preset-patch')
    assert.equal(plan.baseSnapshotRevisionId, snapshot.revisionId)
    assert.equal(plan.presetPlans[0].next.name, 'Coding Remote')
    assert.equal(plan.presetPlans[0].next.enabled, false)
    assert.deepEqual(plan.presetPlans[0].next.itemRefs.map(ref => ref.itemType), [
        'desktop-app',
        'browser-tab',
        'host-folder'
    ])
    assert.equal(plan.sideEffects.writesVault, false)
    assert.equal(plan.sideEffects.createsCapability, false)
    assert.equal(plan.sideEffects.launches, false)
})

test('stale baseSnapshotRevisionId is rejected before planning', () => {
    const snapshot = buildSnapshot()
    const patch = validPatch(snapshot, candidate => {
        candidate.baseSnapshotRevisionId = 'srev_stale_revision'
    })

    assert.throws(() => planSafePresetPatchImport({ patch, sanitizedSnapshot: snapshot }), /does not match/)
})

test('unknown safe item ids fail closed', () => {
    const snapshot = buildSnapshot()
    const patch = validPatch(snapshot, candidate => {
        candidate.presets[0].itemRefs[0].itemId = 'item_missing_safe_item'
    })

    assert.throws(() => planSafePresetPatchImport({ patch, sanitizedSnapshot: snapshot }), /unknown safe item id/)
})

test('raw path, capability, registry, process, shell, vault, and secret material is rejected', () => {
    const snapshot = buildSnapshot()
    const cases = [
        patch => { patch.vaultJson = { ciphertext: 'nope' } },
        patch => { patch.presets[0].path = 'C:\\Windows\\System32\\notepad.exe' },
        patch => { patch.presets[0].itemRefs[0].capabilityId = `cap_${'aa'.repeat(32)}` },
        patch => { patch.presets[0].registryKey = 'HKCU\\Software\\Bad' },
        patch => { patch.presets[0].itemRefs[0].pid = 1234 },
        patch => { patch.presets[0].name = 'powershell -EncodedCommand AAAA' },
        patch => { patch.presets[0].name = 'C:\\Users\\Alice\\AppData\\Local\\secret.exe' },
        patch => { patch.presets[0].name = 'password=do-not-store' },
        patch => { patch.newBrowserItems = [{ id: 'patch_item_secret', url: 'https://example.com/', notes: 'Bearer abcdefghijklmnopqrstuvwxyz' }] }
    ]

    for (const mutate of cases) {
        assert.throws(() => validateSafePresetPatch(validPatch(snapshot, mutate)), /forbidden|not accepted|public browser URL/)
    }
})

test('phone cannot create desktop-app or host-folder authority', () => {
    const snapshot = buildSnapshot()
    const ids = itemIds(snapshot)

    assert.throws(() => validateSafePresetPatch(patchWithNewTab(snapshot, patch => {
        patch.newBrowserItems[0].type = 'desktop-app'
    })), /not accepted/)
    assert.throws(() => validateSafePresetPatch(validPatch(snapshot, patch => {
        patch.desktopApps = [{ id: 'app_cursor', label: 'Cursor' }]
    })), /not accepted/)

    const plan = planSafePresetPatchImport({
        sanitizedSnapshot: snapshot,
        patch: validPatch(snapshot, patch => {
            patch.presets[0].itemRefs = [{
                itemId: ids.desktop.id,
                order: 0,
                enabled: true,
                metadataOnly: true
            }]
        })
    })
    const [ref] = plan.presetPlans[0].next.itemRefs
    assert.equal(ref.itemType, 'desktop-app')
    assert.equal(ref.existingSnapshotItem, true)
    assert.equal(ref.createsCapability, false)
    assert.equal(ref.createsDesktopAppAuthority, false)
})

test('safe public browser tab additions are normalized and remain metadata only', () => {
    const snapshot = buildSnapshot()
    const ids = itemIds(snapshot)
    const patch = patchWithNewTab(snapshot)
    const plan = planSafePresetPatchImport({ patch, sanitizedSnapshot: snapshot })
    const newItem = plan.newBrowserItems[0]
    const newRef = plan.presetPlans[0].next.itemRefs.find(ref => ref.itemId === newItem.id)

    assert.equal(newItem.url, 'https://aistudio.google.com/')
    assert.equal(newItem.accountIntentionId, ids.account.id)
    assert.equal(newItem.profileIntentionId, ids.profile.id)
    assert.equal(newItem.metadataOnly, true)
    assert.equal(newItem.createsCapability, false)
    assert.equal(newRef.itemType, 'browser-tab')
    assert.equal(newRef.newBrowserItem, true)
})

test('unsafe browser URLs are rejected while unsafe snapshot browser URLs stay redacted', () => {
    const snapshot = buildSnapshot()
    const serializedSnapshot = JSON.stringify(snapshot)
    const redacted = snapshot.availableItems.find(item => item.type === 'browser-tab' && item.status === 'redacted')

    assert.equal(redacted.url, undefined)
    assert.equal(serializedSnapshot.includes('localhost'), false)
    assert.equal(serializedSnapshot.includes('do-not-store'), false)

    for (const url of [
        'http://localhost:3000',
        'http://127.0.0.1:3000',
        'https://example.com/?access_token=abc123',
        'file:///C:/Users/Alice/vault.json'
    ]) {
        assert.throws(() => validateSafePresetPatch(patchWithNewTab(snapshot, patch => {
            patch.newBrowserItems[0].url = url
        })), /public browser URL/)
    }
})

test('account and profile mappings must target existing snapshot intention ids', () => {
    const snapshot = buildSnapshot()
    const ids = itemIds(snapshot)

    assert.throws(() => planSafePresetPatchImport({
        sanitizedSnapshot: snapshot,
        patch: patchWithNewTab(snapshot, patch => {
            patch.newBrowserItems[0].accountIntentionId = 'accti_missing_account'
        })
    }), /unknown account intention/)

    assert.throws(() => planSafePresetPatchImport({
        sanitizedSnapshot: snapshot,
        patch: patchWithNewTab(snapshot, patch => {
            patch.newBrowserItems[0].profileIntentionId = 'profi_missing_profile'
        })
    }), /unknown profile intention/)

    assert.throws(() => planSafePresetPatchImport({
        sanitizedSnapshot: snapshot,
        patch: validPatch(snapshot, patch => {
            patch.presets[0].itemRefs = [{
                itemId: ids.desktop.id,
                order: 0,
                enabled: true,
                accountIntentionId: ids.account.id,
                metadataOnly: true
            }]
        })
    }), /only allowed on browser tabs/)
})

test('default and next preset selection remains metadata only and does not authorize launch', () => {
    const snapshot = buildSnapshot()
    const plan = planSafePresetPatchImport({
        patch: validPatch(snapshot),
        sanitizedSnapshot: snapshot
    })

    assert.equal(plan.selection.defaultPresetId, snapshot.presets[0].id)
    assert.equal(plan.selection.nextPresetId, snapshot.presets[0].id)
    assert.equal(plan.selection.metadataOnly, true)
    assert.equal(plan.selection.authorizesLaunch, false)
    assert.equal(plan.sideEffects.launches, false)
})

test('duplicate ids and references fail closed', () => {
    const snapshot = buildSnapshot()

    assert.throws(() => validateSafePresetPatch(validPatch(snapshot, patch => {
        patch.presets.push(clone(patch.presets[0]))
    })), /duplicate id/)

    assert.throws(() => validateSafePresetPatch(patchWithNewTab(snapshot, patch => {
        patch.newBrowserItems.push(clone(patch.newBrowserItems[0]))
    })), /duplicate id/)

    assert.throws(() => validateSafePresetPatch(validPatch(snapshot, patch => {
        patch.presets[0].itemRefs.push(clone(patch.presets[0].itemRefs[0]))
    })), /duplicate id/)

    assert.throws(() => planSafePresetPatchImport({
        sanitizedSnapshot: snapshot,
        patch: patchWithNewTab(snapshot, patch => {
            patch.presets[0].itemRefs.push({
                itemId: patch.newBrowserItems[0].id,
                order: 99,
                enabled: true,
                metadataOnly: true
            })
        })
    }), /duplicate id|duplicate new browser item reference/)
})

test('hard schema limits are enforced', () => {
    const snapshot = buildSnapshot()
    const tooManyBrowserItems = validPatch(snapshot, patch => {
        patch.newBrowserItems = Array.from({
            length: SAFE_PRESET_PATCH_LIMITS.maxNewBrowserItems + 1
        }, (_, index) => ({
            id: `patch_item_${index}`,
            url: `https://example.com/${index}`,
            enabled: true,
            metadataOnly: true
        }))
    })
    assert.throws(() => validateSafePresetPatch(tooManyBrowserItems), /newBrowserItems/)
    assert.throws(() => validateSafePresetPatch(validPatch(snapshot, patch => {
        patch.presets[0].name = 'x'.repeat(SAFE_PRESET_PATCH_LIMITS.maxPresetNameLength + 1)
    })), /too long/)
    assert.throws(() => validateSafePresetPatch(validPatch(snapshot, patch => {
        patch.presets[0].itemRefs = Array.from({
            length: SAFE_PRESET_PATCH_LIMITS.maxPresetItemRefs + 1
        }, (_, index) => ({
            itemId: `item_missing_${index}`,
            order: index,
            enabled: true,
            metadataOnly: true
        }))
    })), /itemRefs/)
})

test('recursive forbidden-field leakage fixtures fail before planning', () => {
    const snapshot = buildSnapshot()
    const patch = validPatch(snapshot, candidate => {
        candidate.presets[0].itemRefs[0].metadata = {
            nested: {
                launchCapabilityVault: {
                    records: {
                        [`cap_${'bb'.repeat(32)}`]: { path: 'C:\\Windows\\System32\\notepad.exe' }
                    }
                }
            }
        }
    })

    assert.throws(() => validateSafePresetPatch(patch), /forbidden/)
})

test('planner returns an import plan only and does not call vault, capability, write, or launch hooks', () => {
    const snapshot = buildSnapshot()
    const patch = patchWithNewTab(snapshot)
    const beforeSnapshot = clone(snapshot)
    const beforePatch = clone(patch)
    const calls = []
    const hooks = {
        writeVault: () => calls.push('writeVault'),
        saveVaultMeta: () => calls.push('saveVaultMeta'),
        createCapability: () => calls.push('createCapability'),
        launchWorkspace: () => calls.push('launchWorkspace'),
        createAccountSlot: () => calls.push('createAccountSlot')
    }

    const plan = planSafePresetPatchImport({
        patch,
        sanitizedSnapshot: snapshot,
        deps: hooks,
        hooks
    })

    assert.deepEqual(calls, [])
    assert.deepEqual(snapshot, beforeSnapshot)
    assert.deepEqual(patch, beforePatch)
    assert.equal(plan.sideEffects.writesVault, false)
    assert.equal(plan.sideEffects.writesCapabilityVault, false)
    assert.equal(plan.sideEffects.createsAccountSlots, false)
    assert.equal(plan.sideEffects.createsBrowserProfiles, false)
    assert.equal(plan.sideEffects.launches, false)
})

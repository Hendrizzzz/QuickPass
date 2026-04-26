import assert from 'assert/strict'
import { test } from 'node:test'
import { createCapabilityRecord } from '../src/main/capabilityStore.js'
import { mergeLaunchCapabilitiesIntoMeta } from '../src/main/workspaceCapabilityHandlers.js'
import { WORKSPACE_CAPABILITY_VAULT_KEY } from '../src/main/workspaceCapabilityMigration.js'
import {
    metaHasLaunchCapabilityMaterial,
    sanitizeVaultMetaForRenderer,
    stripLaunchCapabilityMaterialFromMeta
} from '../src/main/vaultMetadata.js'

test('sanitized metadata contains no capability authority or summaries', () => {
    const record = createCapabilityRecord({
        type: 'host-exe',
        provenance: 'browse-exe',
        displayName: 'Sensitive Launch Target',
        launch: {
            path: 'C:\\Program Files\\Sensitive\\Sensitive.exe'
        },
        policy: {
            allowedArgs: 'none',
            canCloseFromWipesnap: true,
            ownership: 'owned-process'
        }
    })

    const sanitized = sanitizeVaultMetaForRenderer({
        version: '1.0.0',
        hasPIN: true,
        fastBoot: true,
        clearCacheOnExit: true,
        isRemovable: true,
        createdOn: 'USB1234',
        [WORKSPACE_CAPABILITY_VAULT_KEY]: {
            version: 1,
            records: {
                [record.capabilityId]: record
            }
        },
        capabilityVault: {
            version: 1,
            records: {
                [record.capabilityId]: record
            }
        },
        launchCapabilities: {
            [record.capabilityId]: record
        },
        launchCapabilityMigration: {
            version: 1,
            verified: 1,
            displayName: record.displayName
        },
        launchCapabilitySummaries: [{
            capabilityId: record.capabilityId,
            displayName: record.displayName
        }],
        capabilitySummaries: [{
            capabilityId: record.capabilityId,
            displayName: record.displayName
        }]
    }, {
        serialKnown: true,
        serialNumber: 'USB1234',
        isRemovable: true
    })

    assert.deepEqual(Object.keys(sanitized).sort(), [
        'clearCacheOnExit',
        'createdOnMatchesCurrentDrive',
        'fastBoot',
        'hardwareMismatch',
        'hasPIN',
        'hiddenMaster',
        'isRemovable',
        'supportsConvenienceUnlock',
        'version'
    ].sort())
    assert.equal(WORKSPACE_CAPABILITY_VAULT_KEY in sanitized, false)
    assert.equal('capabilityVault' in sanitized, false)
    assert.equal('launchCapabilities' in sanitized, false)
    assert.equal('launchCapabilityMigration' in sanitized, false)
    assert.equal('launchCapabilitySummaries' in sanitized, false)
    assert.equal('capabilitySummaries' in sanitized, false)
    assert.equal(JSON.stringify(sanitized).includes('Sensitive Launch Target'), false)
    assert.equal(JSON.stringify(sanitized).includes('Sensitive.exe'), false)
})

test('sidecar metadata persistence strips legacy capability material', () => {
    const stripped = mergeLaunchCapabilitiesIntoMeta({
        version: '1.0.0',
        hasPIN: true,
        [WORKSPACE_CAPABILITY_VAULT_KEY]: {
            version: 1,
            records: {}
        },
        capabilityVault: {
            version: 1,
            records: {}
        },
        launchCapabilities: {
            legacy: { id: 'legacy', path: 'C:\\Program Files\\Legacy\\Legacy.exe' }
        },
        launchCapabilityMigration: {
            version: 1,
            verified: 1
        },
        launchCapabilitySummaries: [{ displayName: 'Legacy' }],
        capabilitySummaries: [{ displayName: 'Legacy' }]
    })

    assert.deepEqual(stripped, {
        version: '1.0.0',
        hasPIN: true
    })
})

test('metadata strip helper removes launch material from every metadata write path', () => {
    const meta = {
        version: '1.0.0',
        fastBoot: true,
        [WORKSPACE_CAPABILITY_VAULT_KEY]: { version: 1, records: {} },
        capabilityVault: { version: 1, records: {} },
        launchCapabilities: { legacy: {} },
        launchCapabilityMigration: { verified: 1 },
        launchCapabilitySummaries: [{ displayName: 'Legacy' }],
        capabilitySummaries: [{ displayName: 'Legacy' }]
    }

    assert.equal(metaHasLaunchCapabilityMaterial(meta), true)
    assert.equal(metaHasLaunchCapabilityMaterial({ version: '1.0.0', fastBoot: true }), false)
    assert.deepEqual(stripLaunchCapabilityMaterialFromMeta(meta), {
        version: '1.0.0',
        fastBoot: true
    })
})

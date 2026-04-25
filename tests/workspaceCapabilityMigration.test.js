import assert from 'assert/strict'
import { test } from 'node:test'
import { createCapabilityRecord } from '../src/main/capabilityStore.js'
import {
    WORKSPACE_CAPABILITY_VAULT_KEY,
    migrateWorkspaceLaunchCapabilities,
    migrationReportToMetadataSummary,
    rehydrateWorkspaceLaunchCapabilities,
    workspaceEntryHasRawLaunchAuthority
} from '../src/main/workspaceCapabilityMigration.js'

const FIXED_NOW = '2026-04-25T00:00:00.000Z'

function bytesSequence(...hexBytes) {
    let index = 0
    return (size) => {
        const value = hexBytes[index] ?? hexBytes[hexBytes.length - 1]
        index += 1
        return Buffer.alloc(size, value)
    }
}

function manifestResolver(manifestId) {
    const manifests = {
        Imported_App: {
            manifestId: 'Imported_App',
            safeName: 'Imported_App',
            displayName: 'Imported App',
            selectedExecutable: {
                relativePath: 'Imported.exe'
            }
        }
    }
    return manifests[manifestId] || null
}

test('verified browse, scan, and import-style legacy records migrate to opaque capability workspace rows', () => {
    const legacyBrowse = {
        id: 'legacy-browse-code',
        launchSourceType: 'host-exe',
        launchMethod: 'spawn',
        path: 'C:\\Program Files\\Microsoft VS Code\\Code.exe',
        provenance: 'browse-exe'
    }
    const legacyScan = {
        id: 'legacy-scan-registry',
        launchSourceType: 'registry-uninstall',
        launchMethod: 'spawn',
        path: 'C:\\Program Files\\Scanned\\Scanned.exe',
        registryKey: 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Scanned',
        provenance: 'host-scan'
    }

    const migrated = migrateWorkspaceLaunchCapabilities({
        webTabs: [{ url: 'https://example.com', enabled: true }],
        desktopApps: [
            {
                id: 'browse-row',
                name: 'Visual Studio Code',
                path: legacyBrowse.path,
                launchSourceType: 'host-exe',
                launchMethod: 'spawn',
                launchCapabilityId: legacyBrowse.id,
                enabled: true
            },
            {
                id: 'scan-row',
                name: 'Scanned App',
                path: legacyScan.path,
                launchSourceType: 'registry-uninstall',
                launchMethod: 'spawn',
                registryKey: legacyScan.registryKey,
                launchCapabilityId: legacyScan.id,
                enabled: true
            },
            {
                id: 'import-row',
                name: 'Imported App',
                path: '[USB]\\Apps\\Imported_App\\Imported.exe',
                launchSourceType: 'vault-archive',
                launchMethod: 'spawn',
                manifestId: 'Imported_App',
                enabled: true
            }
        ]
    }, {
        legacyCapabilities: [legacyBrowse, legacyScan],
        manifestResolver,
        randomBytes: bytesSequence(0x01, 0x02, 0x03),
        now: FIXED_NOW
    })

    assert.equal(migrated.changed, true)
    assert.equal(migrated.migrationReport.verified, 3)
    assert.equal(migrated.migrationReport.quarantined, 0)

    const apps = migrated.workspace.desktopApps
    assert.deepEqual(apps.map(app => app.capabilityId), [
        `cap_${'01'.repeat(32)}`,
        `cap_${'02'.repeat(32)}`,
        `cap_${'03'.repeat(32)}`
    ])
    assert.equal(apps.every(app => !workspaceEntryHasRawLaunchAuthority(app)), true)
    assert.equal(apps.every(app => app.enabled), true)

    const records = migrated.workspace[WORKSPACE_CAPABILITY_VAULT_KEY].records
    assert.equal(records[`cap_${'01'.repeat(32)}`].type, 'host-exe')
    assert.equal(records[`cap_${'02'.repeat(32)}`].type, 'registry-uninstall')
    assert.equal(records[`cap_${'03'.repeat(32)}`].type, 'vault-archive')
    assert.equal(records[`cap_${'03'.repeat(32)}`].launch.storageId, 'Imported_App')

    const rehydrated = rehydrateWorkspaceLaunchCapabilities(migrated.workspace, {
        capabilityVault: migrated.capabilityVault,
        manifestResolver
    })
    assert.deepEqual(rehydrated.desktopApps.map(app => app.path), [
        'C:\\Program Files\\Microsoft VS Code\\Code.exe',
        'C:\\Program Files\\Scanned\\Scanned.exe',
        '[USB]\\Apps\\Imported_App\\Imported.exe'
    ])

    const summary = migrationReportToMetadataSummary(migrated.migrationReport)
    assert.deepEqual(Object.keys(summary), ['version', 'migratedAt', 'verified', 'quarantined', 'alreadyMigrated'])
})

test('arbitrary renderer host executable entry is quarantined without preserving raw launch fields', () => {
    const migrated = migrateWorkspaceLaunchCapabilities({
        desktopApps: [{
            id: 'forged-row',
            name: 'Forged Notepad',
            path: 'C:\\Windows\\System32\\notepad.exe',
            launchSourceType: 'host-exe',
            launchMethod: 'spawn',
            enabled: true
        }]
    }, {
        now: FIXED_NOW
    })

    const [app] = migrated.workspace.desktopApps
    assert.equal(app.enabled, false)
    assert.equal(app.quarantined, true)
    assert.match(app.quarantineReason, /No main-issued legacy capability evidence/)
    assert.equal(workspaceEntryHasRawLaunchAuthority(app), false)
    assert.deepEqual(Object.keys(migrated.workspace[WORKSPACE_CAPABILITY_VAULT_KEY].records), [])

    const rehydrated = rehydrateWorkspaceLaunchCapabilities(migrated.workspace)
    assert.deepEqual(rehydrated.desktopApps, [])
})

test('renderer-supplied capability vault is ignored and cannot grant launch authority', () => {
    const forgedRecord = createCapabilityRecord({
        type: 'host-exe',
        provenance: 'browse-exe',
        displayName: 'Forged Notepad',
        launch: {
            path: 'C:\\Windows\\System32\\notepad.exe'
        },
        policy: {
            allowedArgs: 'none',
            canCloseFromWipesnap: true,
            ownership: 'owned-process'
        }
    }, {
        randomBytes: bytesSequence(0xee),
        now: FIXED_NOW
    })
    const forgedVault = {
        version: 1,
        records: {
            [forgedRecord.capabilityId]: forgedRecord
        }
    }
    const rendererWorkspace = {
        desktopApps: [{
            name: 'Forged Notepad',
            capabilityId: forgedRecord.capabilityId,
            enabled: true
        }],
        [WORKSPACE_CAPABILITY_VAULT_KEY]: forgedVault
    }

    const migrated = migrateWorkspaceLaunchCapabilities(rendererWorkspace, {
        now: FIXED_NOW
    })

    const [app] = migrated.workspace.desktopApps
    assert.equal(app.enabled, false)
    assert.equal(app.quarantined, true)
    assert.equal(app.quarantineCode, 'missing-capability')
    assert.match(app.quarantineReason, /missing, stale, or unavailable/)
    assert.deepEqual(Object.keys(migrated.capabilityVault.records), [])
    assert.deepEqual(rehydrateWorkspaceLaunchCapabilities(migrated.workspace).desktopApps, [])

    const trusted = migrateWorkspaceLaunchCapabilities(rendererWorkspace, {
        existingCapabilityVault: forgedVault,
        now: FIXED_NOW
    })
    const rehydrated = rehydrateWorkspaceLaunchCapabilities(trusted.workspace, {
        capabilityVault: trusted.capabilityVault
    })
    assert.deepEqual(rehydrated.desktopApps.map(appConfig => appConfig.path), [
        'C:\\Windows\\System32\\notepad.exe'
    ])
})

test('protocol capability with mismatched scheme is quarantined', () => {
    const legacyProtocol = {
        id: 'legacy-protocol',
        launchSourceType: 'protocol-uri',
        launchMethod: 'protocol',
        path: 'ms-settings:',
        protocolScheme: 'zoommtg',
        provenance: 'host-scan'
    }

    const migrated = migrateWorkspaceLaunchCapabilities({
        desktopApps: [{
            name: 'Bad Protocol',
            path: 'ms-settings:',
            launchSourceType: 'protocol-uri',
            launchMethod: 'protocol',
            protocolScheme: 'zoommtg',
            launchCapabilityId: legacyProtocol.id
        }]
    }, {
        legacyCapabilities: [legacyProtocol],
        now: FIXED_NOW
    })

    const [app] = migrated.workspace.desktopApps
    assert.equal(app.quarantined, true)
    assert.equal(app.enabled, false)
    assert.match(app.quarantineReason, /protocolScheme must match/)
    assert.equal(workspaceEntryHasRawLaunchAuthority(app), false)
})

test('missing capability fails closed during launch rehydration', () => {
    assert.throws(() => rehydrateWorkspaceLaunchCapabilities({
        desktopApps: [{
            name: 'Missing Capability',
            capabilityId: `cap_${'aa'.repeat(32)}`,
            enabled: true
        }],
        [WORKSPACE_CAPABILITY_VAULT_KEY]: {
            version: 1,
            records: {}
        }
    }), /missing, stale, or unavailable/)
})

test('migrated workspace entries store only capability ids and limited UI state', () => {
    const legacyBrowse = {
        id: 'legacy-browse',
        launchSourceType: 'host-exe',
        launchMethod: 'spawn',
        path: 'C:\\Program Files\\Verified\\Verified.exe',
        provenance: 'browse-exe'
    }

    const migrated = migrateWorkspaceLaunchCapabilities({
        desktopApps: [{
            id: 'verified-row',
            name: 'Verified',
            path: legacyBrowse.path,
            args: '',
            launchSourceType: 'host-exe',
            launchMethod: 'spawn',
            launchCapabilityId: legacyBrowse.id,
            portableData: true,
            enabled: true
        }]
    }, {
        legacyCapabilities: [legacyBrowse],
        randomBytes: bytesSequence(0x0a),
        now: FIXED_NOW
    })

    const [app] = migrated.workspace.desktopApps
    assert.deepEqual(Object.keys(app).sort(), ['capabilityId', 'displayName', 'enabled', 'id', 'name'].sort())
    assert.equal(app.capabilityId, `cap_${'0a'.repeat(32)}`)
    assert.equal(workspaceEntryHasRawLaunchAuthority(app), false)
})

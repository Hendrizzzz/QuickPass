import assert from 'assert/strict'
import { test } from 'node:test'
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import { createCapabilityRecord } from '../src/main/capabilityStore.js'
import { APP_MANIFEST_SUFFIX } from '../src/main/appManifest.js'
import { DEFAULT_IMPORT_RESERVATION_STALE_MS } from '../src/main/importReservations.js'
import {
    WORKSPACE_HEALTH_STATUSES,
    loadWorkspaceHealthSummary,
    loadWorkspaceHealthSummaryHandlerCore
} from '../src/main/workspaceHealth.js'
import { WORKSPACE_CAPABILITY_VAULT_KEY } from '../src/main/workspaceCapabilityMigration.js'

function withVaultDir(fn) {
    const vaultDir = mkdtempSync(join(tmpdir(), 'wipesnap-workspace-health-'))
    try {
        return fn(vaultDir)
    } finally {
        if (existsSync(vaultDir)) rmSync(vaultDir, { recursive: true, force: true })
    }
}

function capabilityVault(...records) {
    return {
        version: 1,
        records: Object.fromEntries(records.map(record => [record.capabilityId, record]))
    }
}

function workspaceFor(records, apps) {
    return {
        webTabs: [],
        desktopApps: apps,
        [WORKSPACE_CAPABILITY_VAULT_KEY]: capabilityVault(...records)
    }
}

function createHostExeRecord(pathValue) {
    return createCapabilityRecord({
        type: 'host-exe',
        provenance: 'test',
        displayName: 'Host EXE',
        launch: { path: pathValue },
        policy: {
            allowedArgs: 'none',
            canCloseFromWipesnap: true,
            ownership: 'owned-process'
        }
    })
}

function createHostFolderRecord(pathValue) {
    return createCapabilityRecord({
        type: 'host-folder',
        provenance: 'test',
        displayName: 'Host Folder',
        launch: { path: pathValue },
        policy: {
            allowedArgs: 'none',
            canCloseFromWipesnap: false,
            ownership: 'external'
        }
    })
}

function createImportedRecord(storageId) {
    return createCapabilityRecord({
        type: 'vault-archive',
        provenance: 'test',
        displayName: storageId,
        launch: {
            storageId,
            manifestId: storageId
        },
        policy: {
            allowedArgs: 'none',
            canCloseFromWipesnap: true,
            ownership: 'owned-process'
        }
    })
}

function appEntry(record, overrides = {}) {
    return {
        capabilityId: record.capabilityId,
        displayName: record.displayName,
        enabled: true,
        ...overrides
    }
}

function writeManifest(vaultDir, storageId, overrides = {}) {
    mkdirSync(join(vaultDir, 'Apps'), { recursive: true })
    writeFileSync(join(vaultDir, 'Apps', `${storageId}${APP_MANIFEST_SUFFIX}`), JSON.stringify({
        schemaVersion: 2,
        manifestId: storageId,
        safeName: storageId,
        displayName: storageId,
        archiveName: `${storageId}.tar.zst`,
        selectedExecutable: { relativePath: `${storageId}.exe` },
        ...overrides
    }, null, 2), 'utf-8')
}

function reasonCodes(summary) {
    return new Set((summary.reasons || []).map(reason => reason.code))
}

test('missing capability fails closed as a broken health result', () => withVaultDir((vaultDir) => {
    const missingCapabilityId = `cap_${'aa'.repeat(32)}`
    const summary = loadWorkspaceHealthSummary({
        vaultDir,
        workspace: {
            webTabs: [],
            desktopApps: [{
                capabilityId: missingCapabilityId,
                displayName: 'Missing Capability',
                enabled: true
            }],
            [WORKSPACE_CAPABILITY_VAULT_KEY]: { version: 1, records: {} }
        }
    })

    assert.equal(summary.success, true)
    assert.equal(summary.status, WORKSPACE_HEALTH_STATUSES.BROKEN)
    assert.equal(reasonCodes(summary).has('missing-capability'), true)
    assert.equal(JSON.stringify(summary).includes(missingCapabilityId), false)
}))

test('missing host executable and host folder are detected without returning paths', () => withVaultDir((vaultDir) => {
    const missingExe = join(vaultDir, 'Missing.exe')
    const missingFolder = join(vaultDir, 'MissingFolder')
    const exeRecord = createHostExeRecord(missingExe)
    const folderRecord = createHostFolderRecord(missingFolder)

    const summary = loadWorkspaceHealthSummary({
        vaultDir,
        workspace: workspaceFor(
            [exeRecord, folderRecord],
            [appEntry(exeRecord), appEntry(folderRecord)]
        )
    })
    const serialized = JSON.stringify(summary)

    assert.equal(summary.status, WORKSPACE_HEALTH_STATUSES.BROKEN)
    assert.equal(reasonCodes(summary).has('missing-host-executable'), true)
    assert.equal(reasonCodes(summary).has('missing-host-folder'), true)
    assert.equal(serialized.includes(missingExe), false)
    assert.equal(serialized.includes(missingFolder), false)
}))

test('missing imported manifests and archives are detected', () => withVaultDir((vaultDir) => {
    const noManifest = createImportedRecord('No_Manifest')
    const noArchive = createImportedRecord('No_Archive')
    writeManifest(vaultDir, 'No_Archive')

    const summary = loadWorkspaceHealthSummary({
        vaultDir,
        workspace: workspaceFor(
            [noManifest, noArchive],
            [appEntry(noManifest), appEntry(noArchive)]
        )
    })

    assert.equal(summary.status, WORKSPACE_HEALTH_STATUSES.BROKEN)
    assert.equal(reasonCodes(summary).has('missing-imported-manifest'), true)
    assert.equal(reasonCodes(summary).has('missing-imported-archive'), true)
    assert.equal(JSON.stringify(summary).includes(join(vaultDir, 'Apps')), false)
}))

test('malformed capability records fail closed', () => withVaultDir((vaultDir) => {
    const capabilityId = `cap_${'bb'.repeat(32)}`
    const summary = loadWorkspaceHealthSummary({
        vaultDir,
        workspace: {
            webTabs: [],
            desktopApps: [{
                capabilityId,
                displayName: 'Malformed Capability',
                enabled: true
            }],
            [WORKSPACE_CAPABILITY_VAULT_KEY]: {
                version: 1,
                records: {
                    [capabilityId]: {
                        version: 1,
                        capabilityId,
                        type: 'host-exe',
                        provenance: 'test',
                        displayName: 'Malformed Capability',
                        launch: { method: 'spawn', path: 'relative.exe' },
                        policy: {
                            allowedArgs: 'none',
                            canCloseFromWipesnap: true,
                            ownership: 'owned-process'
                        },
                        verification: { lastVerifiedAt: new Date(0).toISOString() }
                    }
                }
            }
        }
    })

    assert.equal(summary.success, false)
    assert.equal(summary.state, 'malformed')
    assert.equal(summary.status, WORKSPACE_HEALTH_STATUSES.BROKEN)
    assert.equal(JSON.stringify(summary).includes(capabilityId), false)
}))

test('browser profile missing is needs-attention and present profile is ready', () => withVaultDir((vaultDir) => {
    const workspace = {
        webTabs: [{ url: 'https://example.com', enabled: true }],
        desktopApps: [],
        [WORKSPACE_CAPABILITY_VAULT_KEY]: { version: 1, records: {} }
    }

    const missing = loadWorkspaceHealthSummary({ vaultDir, workspace })
    assert.equal(missing.status, WORKSPACE_HEALTH_STATUSES.NEEDS_ATTENTION)
    assert.equal(missing.browserProfile.status, 'missing')
    assert.equal(reasonCodes(missing).has('missing-browser-profile'), true)

    mkdirSync(join(vaultDir, 'BrowserProfile'), { recursive: true })
    const present = loadWorkspaceHealthSummary({ vaultDir, workspace })
    assert.equal(present.status, WORKSPACE_HEALTH_STATUSES.READY)
    assert.equal(present.browserProfile.status, 'present')
}))

test('pending and stale import reservations are reported without cleanup', () => withVaultDir((vaultDir) => {
    const reservationsDir = join(vaultDir, 'Apps', '.reservations')
    mkdirSync(reservationsDir, { recursive: true })
    const now = 1_000_000_000
    const pendingPath = join(reservationsDir, 'Pending.lock')
    const stalePath = join(reservationsDir, 'Stale.lock')
    writeFileSync(pendingPath, JSON.stringify({ storageId: 'Pending', createdAtMs: now - 1000 }), 'utf-8')
    writeFileSync(stalePath, JSON.stringify({ storageId: 'Stale', createdAtMs: now - DEFAULT_IMPORT_RESERVATION_STALE_MS - 1000 }), 'utf-8')

    const summary = loadWorkspaceHealthSummary({
        vaultDir,
        now: () => now,
        workspace: {
            webTabs: [],
            desktopApps: [],
            [WORKSPACE_CAPABILITY_VAULT_KEY]: { version: 1, records: {} }
        }
    })

    assert.equal(summary.status, WORKSPACE_HEALTH_STATUSES.NEEDS_ATTENTION)
    assert.equal(summary.importReservations.pending, 1)
    assert.equal(summary.importReservations.stale, 1)
    assert.equal(reasonCodes(summary).has('pending-import-reservations'), true)
    assert.equal(reasonCodes(summary).has('stale-import-reservations'), true)
    assert.equal(existsSync(pendingPath), true)
    assert.equal(existsSync(stalePath), true)
}))

test('recent failed diagnostics are summarized from sanitized diagnostics state', () => withVaultDir((vaultDir) => {
    const secretPath = join(vaultDir, 'secret.exe')
    const summary = loadWorkspaceHealthSummary({
        vaultDir,
        workspace: {
            webTabs: [],
            desktopApps: [],
            [WORKSPACE_CAPABILITY_VAULT_KEY]: { version: 1, records: {} }
        },
        diagnosticsSummary: {
            success: true,
            available: true,
            state: 'ready',
            status: 'failed',
            counts: { failures: 2, warnings: 0 }
        }
    })

    assert.equal(summary.status, WORKSPACE_HEALTH_STATUSES.NEEDS_ATTENTION)
    assert.equal(reasonCodes(summary).has('recent-diagnostics-failures'), true)
    assert.equal(JSON.stringify(summary).includes(secretPath), false)
}))

test('health handler rejects locked state before reading workspace or paths', () => {
    let loadWorkspaceCalled = false
    let getVaultDirCalled = false
    const summary = loadWorkspaceHealthSummaryHandlerCore({
        input: undefined,
        deps: {
            requireActiveSession: () => {
                throw new Error('Session is locked')
            },
            loadActiveVaultWorkspace: () => {
                loadWorkspaceCalled = true
                return {}
            },
            getVaultDir: () => {
                getVaultDirCalled = true
                return 'C:\\ShouldNotRead'
            }
        }
    })

    assert.equal(summary.success, false)
    assert.equal(summary.state, 'locked')
    assert.equal(loadWorkspaceCalled, false)
    assert.equal(getVaultDirCalled, false)
})

test('health handler rejects renderer-supplied arbitrary paths', () => withVaultDir((vaultDir) => {
    let loadWorkspaceCalled = false
    let getVaultDirCalled = false
    const attackerPath = join(vaultDir, 'attacker-secret.json')
    const summary = loadWorkspaceHealthSummaryHandlerCore({
        input: { path: attackerPath },
        deps: {
            requireActiveSession: () => {},
            loadActiveVaultWorkspace: () => {
                loadWorkspaceCalled = true
                return {}
            },
            getVaultDir: () => {
                getVaultDirCalled = true
                return vaultDir
            }
        }
    })

    const serialized = JSON.stringify(summary)
    assert.equal(summary.success, false)
    assert.equal(summary.state, 'invalid-request')
    assert.equal(loadWorkspaceCalled, false)
    assert.equal(getVaultDirCalled, false)
    assert.equal(serialized.includes(attackerPath), false)
}))

test('health handler does not call launch, delete, repair, or cleanup hooks', () => withVaultDir((vaultDir) => {
    let sideEffects = 0
    const summary = loadWorkspaceHealthSummaryHandlerCore({
        input: undefined,
        deps: {
            requireActiveSession: () => {},
            loadActiveVaultWorkspace: () => ({
                webTabs: [],
                desktopApps: [],
                [WORKSPACE_CAPABILITY_VAULT_KEY]: { version: 1, records: {} }
            }),
            getVaultDir: () => vaultDir,
            diagnosticsSummary: {
                success: true,
                available: false,
                state: 'missing',
                status: 'missing',
                counts: {}
            },
            launchWorkspace: () => { sideEffects += 1 },
            closeDesktopApps: () => { sideEffects += 1 },
            cleanupStaleAppData: () => { sideEffects += 1 },
            repairLegacyAppConfig: () => { sideEffects += 1 },
            deletePayload: () => { sideEffects += 1 }
        }
    })

    assert.equal(summary.success, true)
    assert.equal(summary.status, WORKSPACE_HEALTH_STATUSES.READY)
    assert.equal(sideEffects, 0)
}))

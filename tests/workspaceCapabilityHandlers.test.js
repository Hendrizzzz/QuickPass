import assert from 'assert/strict'
import { test } from 'node:test'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import { createCapabilityRecord } from '../src/main/capabilityStore.js'
import {
    authorizeWorkspaceLaunchCapabilitiesForMain,
    browseExecutableHandlerCore,
    browseFolderHandlerCore,
    createWorkspaceCapabilityHandlerState,
    launchWorkspaceHandlerCore,
    saveVaultHandlerCore,
    saveWorkspaceHandlerCore
} from '../src/main/workspaceCapabilityHandlers.js'
import { WORKSPACE_CAPABILITY_VAULT_KEY } from '../src/main/workspaceCapabilityMigration.js'

function clone(value) {
    return JSON.parse(JSON.stringify(value))
}

function createHarness() {
    const vaultDir = mkdtempSync(join(tmpdir(), 'omnilaunch-phase2d-'))
    const vaultPath = join(vaultDir, 'vault.json')
    const metaPath = join(vaultDir, 'vault.meta.json')
    let activeMasterPassword = 'active-password'
    const calls = {
        vaultWrites: 0,
        metaWrites: 0,
        activePasswords: [],
        resetPinUnlockFailures: 0,
        activeSessionChecks: 0,
        unlockedOrNoVaultChecks: 0,
        closeBrowser: 0,
        closeDesktopApps: 0,
        diagnostics: [],
        sent: [],
        launchedWorkspace: null,
        launchOptions: null,
        launchVaultDir: null,
        launchPromise: null,
        persistedMigrations: []
    }

    const encryptVault = (payload, password, isHardwareBound = false) => ({
        payload: clone(payload),
        password,
        isHardwareBound
    })
    const decryptVault = (encryptedVault, password) => {
        if (!encryptedVault || encryptedVault.password !== password) {
            throw new Error('bad password')
        }
        return clone(encryptedVault.payload)
    }
    const writeVault = (encryptedVault) => {
        calls.vaultWrites += 1
        writeFileSync(vaultPath, JSON.stringify(encryptedVault, null, 2), 'utf-8')
    }
    const readVault = () => JSON.parse(readFileSync(vaultPath, 'utf-8'))
    const writeWorkspace = (workspace, password = activeMasterPassword) => {
        writeVault(encryptVault({ ...workspace, _honeyToken: { marker: true } }, password))
        calls.vaultWrites = 0
    }
    const loadActiveVaultWorkspace = () => {
        const workspace = decryptVault(readVault(), activeMasterPassword)
        if (workspace._honeyToken) delete workspace._honeyToken
        return {
            ...workspace,
            webTabs: Array.isArray(workspace.webTabs) ? workspace.webTabs : [],
            desktopApps: Array.isArray(workspace.desktopApps) ? workspace.desktopApps : []
        }
    }
    const loadVaultMeta = () => {
        if (!existsSync(metaPath)) return null
        return JSON.parse(readFileSync(metaPath, 'utf-8'))
    }
    const saveVaultMeta = (meta) => {
        calls.metaWrites += 1
        writeFileSync(metaPath, JSON.stringify(meta, null, 2), 'utf-8')
    }
    const manifestResolver = (manifestId) => {
        const manifestPath = join(vaultDir, 'Apps', `${manifestId}.quickpass-app.json`)
        if (!existsSync(manifestPath)) return null
        return JSON.parse(readFileSync(manifestPath, 'utf-8'))
    }
    const writeManifest = (manifest) => {
        mkdirSync(join(vaultDir, 'Apps', manifest.safeName), { recursive: true })
        writeFileSync(join(vaultDir, 'Apps', `${manifest.safeName}.quickpass-app.json`), JSON.stringify(manifest, null, 2), 'utf-8')
    }
    const createSaveDeps = () => ({
        requireActiveSession: () => {
            calls.activeSessionChecks += 1
            if (!activeMasterPassword) throw new Error('Session is locked')
        },
        loadVaultMeta,
        saveVaultMeta,
        loadActiveVaultWorkspace,
        getDriveInfo: async () => ({ driveType: 2, serialNumber: 'USB1234', isRemovable: true }),
        getActiveMasterPassword: () => activeMasterPassword,
        encryptVault,
        decryptVault,
        readVault,
        writeVault,
        validateSaveVaultSecurityInput: (input) => input,
        vaultExists: () => existsSync(vaultPath),
        requireConvenienceUnlockRequestSupported: ({ requested }) => {
            if (requested) throw new Error('Convenience unlock not expected in this test')
        },
        setActiveMasterPassword: (password) => {
            activeMasterPassword = password
            calls.activePasswords.push(password)
        },
        resetPinUnlockFailures: () => {
            calls.resetPinUnlockFailures += 1
        },
        honeyToken: { marker: true }
    })
    const createBrowseDeps = (selectedPath) => ({
        requireUnlockedOrNoVault: () => {
            calls.unlockedOrNoVaultChecks += 1
            if (existsSync(vaultPath) && !activeMasterPassword) throw new Error('Session is locked')
        },
        showOpenDialog: async () => ({ canceled: false, filePaths: [selectedPath] }),
        getVaultDir: () => vaultDir,
        readAppManifest: (_vaultDir, storageId) => manifestResolver(storageId),
        now: () => 12345
    })
    const createLaunchDeps = () => {
        const win = {
            isDestroyed: () => false,
            webContents: {
                send: (channel, payload) => {
                    calls.sent.push({ channel, payload })
                }
            }
        }
        return {
            getWindowFromSender: () => win,
            loadActiveVaultWorkspace,
            loadVaultMeta,
            authorizeWorkspaceLaunchCapabilities: (workspace, options = {}) => authorizeWorkspaceLaunchCapabilitiesForMain(workspace, {
                ...options,
                manifestResolver
            }),
            persistMigratedWorkspaceIfChanged: async (workspace, password, migration) => {
                calls.persistedMigrations.push({ workspace, password, migration })
            },
            getActiveMasterPassword: () => activeMasterPassword,
            manifestResolver,
            getVaultDir: () => vaultDir,
            beginDiagnosticsCycle: (mode) => {
                calls.diagnostics.push(mode)
            },
            closeBrowser: async () => {
                calls.closeBrowser += 1
            },
            closeDesktopApps: async () => {
                calls.closeDesktopApps += 1
            },
            prepareLaunchWorkspaceConfig: async (workspace) => workspace,
            launchWorkspace: async (workspace, status, launchVaultDir, options) => {
                calls.launchedWorkspace = clone(workspace)
                calls.launchVaultDir = launchVaultDir
                calls.launchOptions = options
                status('launching')
                return [{ ok: true }]
            },
            onLaunchPromise: (promise) => {
                calls.launchPromise = promise
            },
            onLaunchError: (err) => {
                calls.launchError = err.message
            }
        }
    }

    return {
        vaultDir,
        vaultPath,
        metaPath,
        calls,
        cleanup: () => {
            if (existsSync(vaultDir)) rmSync(vaultDir, { recursive: true, force: true })
        },
        readVault,
        loadVaultMeta,
        writeWorkspace,
        writeManifest,
        createSaveDeps,
        createBrowseDeps,
        createLaunchDeps
    }
}

test('browse-exe plus save-workspace persists only opaque capability rows and encrypted authority', async () => {
    const harness = createHarness()
    const state = createWorkspaceCapabilityHandlerState()
    try {
        harness.writeWorkspace({ webTabs: [], desktopApps: [] })
        const selected = await browseExecutableHandlerCore({
            state,
            deps: harness.createBrowseDeps('C:\\Program Files\\Verified\\Verified.exe')
        })

        assert.match(selected.capabilityId, /^cap_[a-f0-9]{64}$/)
        assert.equal(state.pendingLaunchCapabilityRecords.size, 1)

        const result = await saveWorkspaceHandlerCore({
            state,
            deps: harness.createSaveDeps(),
            workspace: {
                webTabs: [{ url: 'https://example.com', enabled: true }],
                desktopApps: [{
                    id: 'verified-row',
                    capabilityId: selected.capabilityId,
                    displayName: 'Verified Renamed',
                    enabled: true
                }]
            }
        })

        assert.equal(result.success, true)
        assert.equal(state.pendingLaunchCapabilityRecords.size, 0)
        assert.equal(WORKSPACE_CAPABILITY_VAULT_KEY in result.workspace, false)

        const stored = harness.readVault().payload
        assert.equal(stored.desktopApps[0].path, undefined)
        assert.equal(stored.desktopApps[0].launchSourceType, undefined)
        const record = stored[WORKSPACE_CAPABILITY_VAULT_KEY].records[selected.capabilityId]
        assert.equal(record.type, 'host-exe')
        assert.equal(record.launch.path, 'C:\\Program Files\\Verified\\Verified.exe')
        assert.equal(harness.loadVaultMeta().launchCapabilities, undefined)
    } finally {
        harness.cleanup()
    }
})

test('pending capability ids are process-memory scoped and stale ids fail closed before vault write', async () => {
    const harness = createHarness()
    const issuingState = createWorkspaceCapabilityHandlerState()
    const restartedState = createWorkspaceCapabilityHandlerState()
    try {
        harness.writeWorkspace({ webTabs: [], desktopApps: [] })
        const selected = await browseExecutableHandlerCore({
            state: issuingState,
            deps: harness.createBrowseDeps('C:\\Program Files\\Verified\\Verified.exe')
        })
        assert.equal(issuingState.pendingLaunchCapabilityRecords.size, 1)

        const result = await saveWorkspaceHandlerCore({
            state: restartedState,
            deps: harness.createSaveDeps(),
            workspace: {
                desktopApps: [{
                    capabilityId: selected.capabilityId,
                    displayName: 'Stale after restart',
                    enabled: true
                }]
            }
        })

        assert.equal(result.success, false)
        assert.match(result.error, /missing, stale, or unavailable/)
        assert.equal(harness.calls.vaultWrites, 0)
        assert.equal(restartedState.pendingLaunchCapabilityRecords.size, 0)
    } finally {
        harness.cleanup()
    }
})

test('raw renderer metadata injection is rejected at save-workspace handler boundary', async () => {
    const harness = createHarness()
    const state = createWorkspaceCapabilityHandlerState()
    try {
        harness.writeWorkspace({ webTabs: [], desktopApps: [] })
        const selected = await browseExecutableHandlerCore({
            state,
            deps: harness.createBrowseDeps('C:\\Program Files\\Verified\\Verified.exe')
        })

        const result = await saveWorkspaceHandlerCore({
            state,
            deps: harness.createSaveDeps(),
            workspace: {
                desktopApps: [{
                    capabilityId: selected.capabilityId,
                    displayName: 'Injected',
                    enabled: true,
                    path: 'C:\\Windows\\System32\\notepad.exe',
                    registryKey: 'HKCU\\Injected',
                    closePolicy: 'owned-tree'
                }]
            }
        })

        assert.equal(result.success, false)
        assert.match(result.error, /path is not accepted/)
        assert.equal(harness.calls.vaultWrites, 0)
        assert.equal(state.pendingLaunchCapabilityRecords.size, 1)
    } finally {
        harness.cleanup()
    }
})

test('USB-local executable browse saves and launches through manifest-backed vault capability', async () => {
    const harness = createHarness()
    const state = createWorkspaceCapabilityHandlerState()
    try {
        harness.writeManifest({
            manifestId: 'Imported_App',
            safeName: 'Imported_App',
            displayName: 'Imported App',
            selectedExecutable: { relativePath: 'Imported.exe' }
        })
        harness.writeWorkspace({ webTabs: [], desktopApps: [] })

        const selectedPath = join(harness.vaultDir, 'Apps', 'Imported_App', 'Imported.exe')
        const selected = await browseExecutableHandlerCore({
            state,
            deps: harness.createBrowseDeps(selectedPath)
        })
        assert.equal(selected.path, '[USB]\\Apps\\Imported_App\\Imported.exe')
        assert.equal(selected.launchSourceType, 'vault-archive')

        const saved = await saveWorkspaceHandlerCore({
            state,
            deps: harness.createSaveDeps(),
            workspace: {
                desktopApps: [{
                    capabilityId: selected.capabilityId,
                    displayName: selected.displayName,
                    enabled: true
                }]
            }
        })
        assert.equal(saved.success, true)

        const launchResult = await launchWorkspaceHandlerCore({
            event: { sender: { id: 1 } },
            deps: harness.createLaunchDeps()
        })
        assert.equal(launchResult.success, true)
        await harness.calls.launchPromise

        assert.equal(harness.calls.diagnostics[0], 'launch')
        assert.equal(harness.calls.closeBrowser, 1)
        assert.equal(harness.calls.closeDesktopApps, 1)
        assert.equal(harness.calls.launchVaultDir, harness.vaultDir)
        assert.deepEqual(harness.calls.launchOptions, { skipDiagnosticsCycle: true })
        assert.equal(harness.calls.launchedWorkspace.desktopApps[0].path, join(harness.vaultDir, 'Apps', 'Imported_App', 'Imported.exe'))
        assert.equal(harness.calls.launchedWorkspace.desktopApps[0].launchSourceType, 'vault-archive')
        assert.deepEqual(harness.calls.sent.map(item => item.channel), ['launch-status', 'launch-complete'])
    } finally {
        harness.cleanup()
    }
})

test('metadata-only host capability does not authorize launch or process side effects', async () => {
    const harness = createHarness()
    try {
        const legacyCapability = {
            id: 'legacy-host-capability',
            launchSourceType: 'host-exe',
            launchMethod: 'spawn',
            path: 'C:\\Program Files\\Legacy\\Legacy.exe',
            provenance: 'browse-exe'
        }
        writeFileSync(harness.metaPath, JSON.stringify({
            version: '1.0.0',
            launchCapabilities: {
                [legacyCapability.id]: legacyCapability
            }
        }, null, 2), 'utf-8')
        harness.writeWorkspace({
            desktopApps: [{
                id: 'legacy-row',
                name: 'Legacy App',
                path: legacyCapability.path,
                launchSourceType: 'host-exe',
                launchMethod: 'spawn',
                launchCapabilityId: legacyCapability.id,
                enabled: true
            }]
        })

        const result = await launchWorkspaceHandlerCore({
            event: { sender: { id: 1 } },
            deps: harness.createLaunchDeps()
        })

        assert.equal(result.success, false)
        assert.match(result.error, /No main-issued legacy capability evidence/)
        assert.equal(harness.calls.closeBrowser, 0)
        assert.equal(harness.calls.closeDesktopApps, 0)
        assert.equal(harness.calls.launchedWorkspace, null)
        assert.equal(harness.calls.launchPromise, null)
    } finally {
        harness.cleanup()
    }
})

test('encrypted-vault capability authorizes launch after unlock', async () => {
    const harness = createHarness()
    try {
        const record = createCapabilityRecord({
            type: 'host-exe',
            provenance: 'browse-exe',
            displayName: 'Verified App',
            launch: {
                path: 'C:\\Program Files\\Verified\\Verified.exe'
            },
            policy: {
                allowedArgs: 'none',
                canCloseFromWipesnap: true,
                ownership: 'owned-process'
            }
        })
        harness.writeWorkspace({
            desktopApps: [{
                id: 'verified-row',
                capabilityId: record.capabilityId,
                displayName: 'Verified App',
                enabled: true
            }],
            [WORKSPACE_CAPABILITY_VAULT_KEY]: {
                version: 1,
                records: {
                    [record.capabilityId]: record
                }
            }
        })

        const result = await launchWorkspaceHandlerCore({
            event: { sender: { id: 1 } },
            deps: harness.createLaunchDeps()
        })

        assert.equal(result.success, true)
        await harness.calls.launchPromise
        assert.equal(harness.calls.launchedWorkspace.desktopApps[0].path, 'C:\\Program Files\\Verified\\Verified.exe')
        assert.equal(harness.calls.launchedWorkspace.desktopApps[0].capabilityId, record.capabilityId)
        assert.equal(harness.calls.closeBrowser, 1)
        assert.equal(harness.calls.closeDesktopApps, 1)
    } finally {
        harness.cleanup()
    }
})

test('USB-local folder browse fails closed instead of returning raw USB launch authority', async () => {
    const harness = createHarness()
    const state = createWorkspaceCapabilityHandlerState()
    try {
        harness.writeWorkspace({ webTabs: [], desktopApps: [] })
        const result = await browseFolderHandlerCore({
            state,
            deps: harness.createBrowseDeps(join(harness.vaultDir, 'Apps', 'Imported_App'))
        })

        assert.equal(result.success, false)
        assert.match(result.error, /USB-local folders cannot be added/)
        assert.equal(state.pendingLaunchCapabilityRecords.size, 0)
    } finally {
        harness.cleanup()
    }
})

test('save-vault persists pending capabilities and clears pending process authority', async () => {
    const harness = createHarness()
    const state = createWorkspaceCapabilityHandlerState()
    try {
        const selected = await browseExecutableHandlerCore({
            state,
            deps: harness.createBrowseDeps('C:\\Program Files\\Verified\\Verified.exe')
        })

        const result = await saveVaultHandlerCore({
            state,
            deps: harness.createSaveDeps(),
            input: {
                masterPassword: 'new-password',
                currentPassword: '',
                pin: null,
                fastBoot: false,
                workspace: {
                    desktopApps: [{
                        capabilityId: selected.capabilityId,
                        displayName: 'Verified',
                        enabled: true
                    }]
                }
            }
        })

        assert.equal(result.success, true)
        assert.equal(state.pendingLaunchCapabilityRecords.size, 0)
        assert.deepEqual(harness.calls.activePasswords, ['new-password'])
        assert.equal(harness.calls.resetPinUnlockFailures, 1)
        const stored = harness.readVault().payload
        assert.equal(stored.desktopApps[0].path, undefined)
        assert.equal(stored[WORKSPACE_CAPABILITY_VAULT_KEY].records[selected.capabilityId].launch.path, 'C:\\Program Files\\Verified\\Verified.exe')
        assert.equal(harness.loadVaultMeta().launchCapabilities, undefined)
    } finally {
        harness.cleanup()
    }
})

test('launch-workspace fails closed before process side effects when encrypted vault capability is stale', async () => {
    const harness = createHarness()
    try {
        harness.writeWorkspace({
            desktopApps: [{
                capabilityId: `cap_${'aa'.repeat(32)}`,
                displayName: 'Stale App',
                enabled: true
            }],
            [WORKSPACE_CAPABILITY_VAULT_KEY]: {
                version: 1,
                records: {}
            }
        })

        const result = await launchWorkspaceHandlerCore({
            event: { sender: { id: 1 } },
            deps: harness.createLaunchDeps()
        })

        assert.equal(result.success, false)
        assert.match(result.error, /missing, stale, or unavailable/)
        assert.equal(harness.calls.closeBrowser, 0)
        assert.equal(harness.calls.closeDesktopApps, 0)
        assert.equal(harness.calls.launchedWorkspace, null)
        assert.equal(harness.calls.launchPromise, null)
    } finally {
        harness.cleanup()
    }
})

test('launch-workspace fails closed before process side effects when persisted args violate capability policy', async () => {
    const harness = createHarness()
    try {
        const record = createCapabilityRecord({
            type: 'host-exe',
            provenance: 'browse-exe',
            displayName: 'Verified App',
            launch: {
                path: 'C:\\Program Files\\Verified\\Verified.exe'
            },
            policy: {
                allowedArgs: 'allowlist',
                allowedPrefixes: ['--profile'],
                maxArgs: 1,
                maxArgLength: 32,
                canCloseFromWipesnap: true,
                ownership: 'owned-process'
            }
        })
        harness.writeWorkspace({
            desktopApps: [{
                capabilityId: record.capabilityId,
                displayName: 'Verified App',
                enabled: true,
                userArgs: ['--debug']
            }],
            [WORKSPACE_CAPABILITY_VAULT_KEY]: {
                version: 1,
                records: {
                    [record.capabilityId]: record
                }
            }
        })

        const result = await launchWorkspaceHandlerCore({
            event: { sender: { id: 1 } },
            deps: harness.createLaunchDeps()
        })

        assert.equal(result.success, false)
        assert.match(result.error, /outside its allowlist/)
        assert.equal(harness.calls.closeBrowser, 0)
        assert.equal(harness.calls.closeDesktopApps, 0)
        assert.equal(harness.calls.launchedWorkspace, null)
        assert.equal(harness.calls.launchPromise, null)
    } finally {
        harness.cleanup()
    }
})

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
import { APP_MANIFEST_SUFFIX, LEGACY_APP_MANIFEST_SUFFIX } from '../src/main/appManifest.js'

function clone(value) {
    return JSON.parse(JSON.stringify(value))
}

function delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms))
}

function assertNoRendererLaunchLeaks(value) {
    assert.doesNotMatch(value, /https?:\/\//i)
    assert.doesNotMatch(value, /accounts\.example\/callback/i)
    assert.doesNotMatch(value, /localhost/i)
    assert.doesNotMatch(value, /127\.0\.0\.1/i)
    assert.doesNotMatch(value, /\[::1\]/i)
    assert.doesNotMatch(value, /3000\/callback/i)
    assert.doesNotMatch(value, /3000\/path/i)
    assert.doesNotMatch(value, /5173\/path/i)
    assert.doesNotMatch(value, /5173\/callback/i)
    assert.doesNotMatch(value, /code=abc/i)
    assert.doesNotMatch(value, /tokenish=value/i)
    assert.doesNotMatch(value, /dev\.a1/i)
    assert.doesNotMatch(value, /dev\.abc/i)
    assert.doesNotMatch(value, /dev\.abc-1/i)
    assert.doesNotMatch(value, /dev\.\.example/i)
    assert.doesNotMatch(value, /example\.\.com/i)
    assert.doesNotMatch(value, /\ba\.\.b\b/i)
    assert.doesNotMatch(value, /abc-1/i)
    assert.doesNotMatch(value, /team\.env2/i)
    assert.doesNotMatch(value, /dev_a/i)
    assert.doesNotMatch(value, /foo_bar/i)
    assert.doesNotMatch(value, /\bbaz1\b/i)
    assert.doesNotMatch(value, /a_b/i)
    assert.doesNotMatch(value, /\u4f8b\u5b50\.\u6d4b\u8bd5/u)
    assert.doesNotMatch(value, /\u03b4\u03bf\u03ba\u03b9\u03bc\u03ae\.example/u)
    assert.doesNotMatch(value, /xn--fsqu00a/i)
    assert.doesNotMatch(value, /xn--0zwm56d/i)
    assert.doesNotMatch(value, /xn--jxalpdlp/i)
    assert.doesNotMatch(value, /\ba1\b/i)
    assert.doesNotMatch(value, /\benv2\b/i)
    assert.doesNotMatch(value, /env2:5173/i)
    assert.doesNotMatch(value, /a1:3000/i)
    assert.doesNotMatch(value, /\[redacted-url\]-1/i)
    assert.doesNotMatch(value, /a_b\.\[redacted-url\]/i)
    assert.doesNotMatch(value, /-1:3000/i)
    assert.doesNotMatch(value, /raw-launch-token/i)
    assert.doesNotMatch(value, /hunter2/i)
    assert.doesNotMatch(value, /C:\\/i)
    assert.doesNotMatch(value, /Users\\Alice/i)
    assert.doesNotMatch(value, /BrowserProfile/i)
    assert.doesNotMatch(value, /\bcap_[a-f0-9]{12,96}\b/i)
    assert.doesNotMatch(value, /--token/i)
    assert.doesNotMatch(value, /--password/i)
    assert.doesNotMatch(value, /normalizedUrl/i)
    assert.doesNotMatch(value, /finalUrl/i)
    assert.doesNotMatch(value, /launchArgs/i)
    assert.doesNotMatch(value, /capabilityId/i)
    assert.doesNotMatch(value, /realPid/i)
    assert.doesNotMatch(value, /pid["\s:=]*4242/i)
    assert.doesNotMatch(value, /pid["\s:=]*9999/i)
}

const ACCOUNT_SLOT = {
    id: `acct_${'c3'.repeat(24)}`,
    provider: 'google',
    label: 'Personal',
    identifierHint: 'user@example.com',
    state: 'unknown',
    lastCheckedAt: 0,
    notes: ''
}

function createHarness() {
    const vaultDir = mkdtempSync(join(tmpdir(), 'wipesnap-phase2d-'))
    const vaultPath = join(vaultDir, 'vault.json')
    const metaPath = join(vaultDir, 'vault.meta.json')
    let activeMasterPassword = 'active-password'
    const calls = {
        vaultWrites: 0,
        metaWrites: 0,
        transactionalCommits: [],
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
        const manifestPath = [APP_MANIFEST_SUFFIX, LEGACY_APP_MANIFEST_SUFFIX]
            .map(suffix => join(vaultDir, 'Apps', `${manifestId}${suffix}`))
            .find(candidate => existsSync(candidate))
        if (!manifestPath) return null
        return JSON.parse(readFileSync(manifestPath, 'utf-8'))
    }
    const writeManifest = (manifest) => {
        mkdirSync(join(vaultDir, 'Apps', manifest.safeName), { recursive: true })
        writeFileSync(join(vaultDir, 'Apps', `${manifest.safeName}${APP_MANIFEST_SUFFIX}`), JSON.stringify(manifest, null, 2), 'utf-8')
    }
    const createSaveDeps = (overrides = {}) => ({
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
        honeyToken: { marker: true },
        ...overrides
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

test('save-workspace preserves existing encrypted account slots without returning them as workspace data', async () => {
    const harness = createHarness()
    const state = createWorkspaceCapabilityHandlerState()
    try {
        harness.writeWorkspace({
            webTabs: [{ url: 'https://old.example', enabled: true }],
            desktopApps: [],
            accountSlots: [ACCOUNT_SLOT]
        })

        const result = await saveWorkspaceHandlerCore({
            state,
            deps: harness.createSaveDeps(),
            workspace: {
                webTabs: [{ url: 'https://example.com', enabled: true }],
                desktopApps: []
            }
        })

        assert.equal(result.success, true)
        const stored = harness.readVault().payload
        assert.deepEqual(stored.accountSlots, [ACCOUNT_SLOT])
        assert.equal(result.workspace.accountSlots, undefined)
        assert.equal(harness.loadVaultMeta().accountSlots, undefined)
    } finally {
        harness.cleanup()
    }
})

test('browse-exe rejects Windows script launch files without issuing host capability', async () => {
    const harness = createHarness()
    const state = createWorkspaceCapabilityHandlerState()
    try {
        harness.writeWorkspace({ webTabs: [], desktopApps: [] })

        for (const selectedPath of ['C:\\Scripts\\Launch.cmd', 'C:\\Scripts\\Launch.bat']) {
            const selected = await browseExecutableHandlerCore({
                state,
                deps: harness.createBrowseDeps(selectedPath)
            })

            assert.equal(selected.success, false)
            assert.match(selected.error, /Script launch files \(\.bat\/\.cmd\) are not supported/)
            assert.equal(state.pendingLaunchCapabilityRecords.size, 0)
        }
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

test('launch handler does not send launch-complete until launch work settles', async () => {
    const harness = createHarness()
    try {
        harness.writeWorkspace({
            webTabs: [{ url: 'https://example.com', enabled: true }],
            desktopApps: []
        })

        let resolveLaunch
        const launchGate = new Promise(resolve => {
            resolveLaunch = resolve
        })
        const deps = harness.createLaunchDeps()
        deps.launchWorkspace = async (workspace, status, launchVaultDir, options) => {
            harness.calls.launchedWorkspace = clone(workspace)
            harness.calls.launchVaultDir = launchVaultDir
            harness.calls.launchOptions = options
            status('launching slow app')
            await launchGate
            return {
                webResults: [],
                appResults: [{ type: 'app', success: true, name: 'Slow App' }]
            }
        }

        const result = await launchWorkspaceHandlerCore({
            event: { sender: { id: 1 } },
            deps
        })

        assert.equal(result.success, true)
        await delay(5)
        assert.equal(harness.calls.launchPromise instanceof Promise, true)
        assert.deepEqual(harness.calls.sent.map(item => item.channel), ['launch-status'])

        resolveLaunch()
        await harness.calls.launchPromise
        assert.deepEqual(harness.calls.sent.map(item => item.channel), ['launch-status', 'launch-complete'])
        assert.equal(harness.calls.sent[1].payload.success, true)
    } finally {
        harness.cleanup()
    }
})

test('manual launch IPC redacts status and complete results while preserving partial metadata', async () => {
    const harness = createHarness()
    try {
        const record = createCapabilityRecord({
            type: 'host-exe',
            provenance: 'browse-exe',
            displayName: 'Portable Notes',
            launch: {
                path: 'C:\\Program Files\\Portable Notes\\Notes.exe'
            },
            policy: {
                allowedArgs: 'none',
                canCloseFromWipesnap: true,
                ownership: 'owned-process'
            }
        })
        harness.writeWorkspace({
            webTabs: [{ url: 'https://accounts.example/callback?token=raw-launch-token#frag', enabled: true }],
            desktopApps: [{
                capabilityId: record.capabilityId,
                displayName: 'Portable Notes',
                enabled: true
            }],
            [WORKSPACE_CAPABILITY_VAULT_KEY]: {
                version: 1,
                records: {
                    [record.capabilityId]: record
                }
            }
        })

        let finishAppLaunch
        const appLaunchGate = new Promise(resolve => {
            finishAppLaunch = resolve
        })
        const deps = harness.createLaunchDeps()
        deps.launchWorkspace = async (workspace, status, launchVaultDir, options) => {
            harness.calls.launchedWorkspace = clone(workspace)
            harness.calls.launchVaultDir = launchVaultDir
            harness.calls.launchOptions = options
            status('[Tab 1] Loading https://accounts.example/callback?token=raw-launch-token#frag...')
            status('[Tab 1] [WARN] https://accounts.example/callback?token=raw-launch-token#frag - Failed at C:\\Users\\Alice\\BrowserProfile token=raw-launch-token')
            status('[App 1] Launching Portable Notes...')
            status(`[App 1] [WARN] Portable Notes - Resolved path not found: C:\\Users\\Alice\\Portable.exe --token=raw-launch-token ${record.capabilityId} pid=4242`)
            await appLaunchGate
            status('[App 1] [OK] Portable Notes - launched pid=4242')
            return {
                webResults: [{
                    type: 'web',
                    tabIndex: 1,
                    url: 'https://accounts.example/callback?token=raw-launch-token#frag',
                    normalizedUrl: 'https://accounts.example/callback?token=raw-launch-token#frag',
                    finalUrl: 'https://accounts.example/final?token=raw-launch-token#done',
                    title: 'Token raw-launch-token',
                    success: false,
                    error: 'Failed at C:\\Users\\Alice\\BrowserProfile token=raw-launch-token',
                    errors: [{ message: `blocked ${record.capabilityId}`, pid: 4242 }]
                }],
                appResults: [{
                    type: 'app',
                    name: 'Portable Notes',
                    success: true,
                    path: 'C:\\Users\\Alice\\Portable.exe',
                    exePath: 'C:\\Users\\Alice\\Portable.exe',
                    capabilityId: record.capabilityId,
                    launchArgs: ['--token=raw-launch-token'],
                    pid: 4242,
                    realPid: 4242
                }]
            }
        }

        const result = await launchWorkspaceHandlerCore({
            event: { sender: { id: 1 } },
            deps
        })

        assert.equal(result.success, true)
        await delay(5)
        assert.equal(harness.calls.launchPromise instanceof Promise, true)
        assert.equal(harness.calls.sent.some(item => item.channel === 'launch-complete'), false)

        finishAppLaunch()
        await harness.calls.launchPromise

        const serializedSent = JSON.stringify(harness.calls.sent)
        assertNoRendererLaunchLeaks(serializedSent)
        assert.ok(harness.calls.sent.some(item => item.channel === 'launch-status' && item.payload === '[Tab 1] Loading Saved browser tab 1...'))
        assert.ok(harness.calls.sent.some(item => item.channel === 'launch-status' && item.payload === '[Tab 1] [WARN] Saved browser tab 1 - Browser tab failed to load.'))
        assert.ok(harness.calls.sent.some(item => item.channel === 'launch-status' && item.payload === '[App 1] Launching Portable Notes...'))
        assert.ok(harness.calls.sent.some(item => item.channel === 'launch-status' && item.payload === '[App 1] [WARN] Portable Notes - Desktop item failed to launch.'))

        const complete = harness.calls.sent.find(item => item.channel === 'launch-complete')
        assert.equal(complete.payload.success, true)
        assert.equal(complete.payload.results.metadataOnly, true)
        assert.deepEqual(complete.payload.results.webResults, [{
            type: 'web',
            itemKey: 'tab-1',
            tabIndex: 1,
            url: 'Saved browser tab 1',
            success: false,
            skipped: false,
            error: 'Browser tab failed to load.',
            reason: 'Browser tab failed to load.'
        }])
        assert.deepEqual(complete.payload.results.appResults, [{
            type: 'app',
            itemKey: 'app-1',
            appIndex: 1,
            name: 'Portable Notes',
            success: true,
            skipped: false
        }])
        assert.deepEqual(complete.payload.results.summary.browserTabs, {
            total: 1,
            succeeded: 0,
            failed: 1,
            skipped: 0
        })
        assert.deepEqual(complete.payload.results.summary.desktopApps, {
            total: 1,
            succeeded: 1,
            failed: 0,
            skipped: 0
        })
    } finally {
        harness.cleanup()
    }
})

test('manual launch IPC redacts no-scheme local URLs across status and result metadata', async () => {
    const harness = createHarness()
    try {
        const record = createCapabilityRecord({
            type: 'host-exe',
            provenance: 'browse-exe',
            displayName: 'Local Dev Tool',
            launch: {
                path: 'C:\\Program Files\\Local Dev Tool\\Tool.exe'
            },
            policy: {
                allowedArgs: 'none',
                canCloseFromWipesnap: true,
                ownership: 'owned-process'
            }
        })
        harness.writeWorkspace({
            webTabs: [{ url: 'https://example.com', enabled: true }],
            desktopApps: [{
                capabilityId: record.capabilityId,
                displayName: 'Local Dev Tool',
                enabled: true
            }],
            [WORKSPACE_CAPABILITY_VAULT_KEY]: {
                version: 1,
                records: {
                    [record.capabilityId]: record
                }
            }
        })

        const deps = harness.createLaunchDeps()
        deps.launchWorkspace = async (workspace, status, launchVaultDir, options) => {
            harness.calls.launchedWorkspace = clone(workspace)
            harness.calls.launchVaultDir = launchVaultDir
            harness.calls.launchOptions = options
            status('[Tab 1] [WARN] localhost:3000/callback?code=abc#frag failed (Timeout); retrying...')
            status('[Tab 1] [WARN] localhost/callback?code=abc#frag - Local retry')
            status('[Tab 1] [WARN] 127.0.0.1:5173/path?tokenish=value#frag - Timeout')
            status('[Tab 1] [WARN] [::1]:3000/path?code=abc - Timeout')
            status('[App 1] Launching [::1]:3000/path?code=abc...')
            status('[App 1] [WARN] localhost:3000/callback?code=abc#frag - failed near 127.0.0.1:5173/path?tokenish=value#frag')
            return {
                webResults: [{
                    type: 'web',
                    tabIndex: 1,
                    url: 'localhost:3000/callback?code=abc#frag',
                    normalizedUrl: '127.0.0.1:5173/path?tokenish=value#frag',
                    finalUrl: '[::1]:3000/path?code=abc',
                    success: false,
                    error: '[::1]:3000/path?code=abc'
                }],
                appResults: [{
                    type: 'app',
                    name: '127.0.0.1:5173/path?tokenish=value#frag',
                    success: false,
                    error: 'localhost:3000/callback?code=abc#frag'
                }]
            }
        }

        const result = await launchWorkspaceHandlerCore({
            event: { sender: { id: 1 } },
            deps
        })

        assert.equal(result.success, true)
        await harness.calls.launchPromise

        const serializedSent = JSON.stringify(harness.calls.sent)
        assertNoRendererLaunchLeaks(serializedSent)
        assert.ok(harness.calls.sent.some(item => item.channel === 'launch-status' && item.payload === '[Tab 1] [WARN] Saved browser tab 1 - Browser tab failed to load.'))
        assert.ok(harness.calls.sent.some(item => item.channel === 'launch-status' && item.payload === '[Tab 1] [WARN] Saved browser tab 1 - Local retry'))
        assert.ok(harness.calls.sent.some(item => item.channel === 'launch-status' && item.payload === '[Tab 1] [WARN] Saved browser tab 1 - Timeout'))
        assert.ok(harness.calls.sent.some(item => item.channel === 'launch-status' && item.payload === '[App 1] Launching Desktop item 1...'))
        assert.ok(harness.calls.sent.some(item => item.channel === 'launch-status' && item.payload === '[App 1] [WARN] Desktop item 1 - Desktop item failed to launch.'))

        const complete = harness.calls.sent.find(item => item.channel === 'launch-complete')
        assert.equal(complete.payload.success, true)
        assert.deepEqual(complete.payload.results.webResults, [{
            type: 'web',
            itemKey: 'tab-1',
            tabIndex: 1,
            url: 'Saved browser tab 1',
            success: false,
            skipped: false,
            error: 'Browser tab failed to load.',
            reason: 'Browser tab failed to load.'
        }])
        assert.deepEqual(complete.payload.results.appResults, [{
            type: 'app',
            itemKey: 'app-1',
            appIndex: 1,
            name: 'Desktop item 1',
            success: false,
            skipped: false,
            error: 'Desktop item failed to launch.',
            reason: 'Desktop item failed to launch.'
        }])
    } finally {
        harness.cleanup()
    }
})

test('manual launch IPC redacts accepted dotted no-scheme host URLs', async () => {
    const harness = createHarness()
    try {
        const record = createCapabilityRecord({
            type: 'host-exe',
            provenance: 'browse-exe',
            displayName: 'Host Port Tool',
            launch: {
                path: 'C:\\Program Files\\Host Port Tool\\Tool.exe'
            },
            policy: {
                allowedArgs: 'none',
                canCloseFromWipesnap: true,
                ownership: 'owned-process'
            }
        })
        harness.writeWorkspace({
            webTabs: [{ url: 'https://example.com', enabled: true }],
            desktopApps: [{
                capabilityId: record.capabilityId,
                displayName: 'Host Port Tool',
                enabled: true
            }],
            [WORKSPACE_CAPABILITY_VAULT_KEY]: {
                version: 1,
                records: {
                    [record.capabilityId]: record
                }
            }
        })

        const deps = harness.createLaunchDeps()
        const idnChineseUrl = '\u4f8b\u5b50.\u6d4b\u8bd5/path?code=abc#frag'
        const idnGreekUrl = '\u03b4\u03bf\u03ba\u03b9\u03bc\u03ae.example/path?code=abc#frag'
        deps.launchWorkspace = async (workspace, status, launchVaultDir, options) => {
            harness.calls.launchedWorkspace = clone(workspace)
            harness.calls.launchVaultDir = launchVaultDir
            harness.calls.launchOptions = options
            status('[Tab 1] Loading dev.a1...')
            status('[Tab 1] Loading dev.abc-1...')
            status('[Tab 1] Loading dev_a.example...')
            status('[Tab 1] Loading dev..example...')
            status('[Tab 1] Loading foo_bar.baz1...')
            status('[Tab 1] [WARN] dev.a1:3000/callback?code=abc#frag failed (Timeout); retrying...')
            status('[Tab 1] [WARN] dev.abc-1 failed (Timeout); retrying...')
            status('[Tab 1] [WARN] dev_a.example:3000/path?code=abc#frag failed (Timeout); retrying...')
            status('[Tab 1] [WARN] dev..example:3000/path?code=abc#frag failed (Timeout); retrying...')
            status('[Tab 1] [WARN] a..b:5173/callback?tokenish=value failed (Timeout); retrying...')
            status('[Tab 1] [WARN] saved browser tab - failed:dev..example:3000/path?code=abc#frag')
            status('[Tab 1] [WARN] saved browser tab - failed/dev..example:3000/path?code=abc#frag')
            status(`[Tab 1] [WARN] saved browser tab - failed/${idnChineseUrl}`)
            status(`[Tab 1] [WARN] saved browser tab - failed/${idnGreekUrl}`)
            status('[Tab 1] [WARN] a_b.localhost/callback?tokenish=value failed (Timeout); retrying...')
            status('[App 1] Launching dev.abc-1:3000/path?code=abc#frag...')
            status('[App 1] Launching foo_bar.baz1...')
            status('[App 1] Launching example..com...')
            status('[App 1] [WARN] dev_a.example - a_b.localhost/callback?tokenish=value failed')
            status('[App 1] [WARN] a..b - dev..example:3000/path?code=abc#frag failed')
            status('[App 1] [WARN] label:a..b:5173/callback?tokenish=value - failed:dev..example:3000/path?code=abc#frag')
            status('[App 1] [WARN] label/foo_bar.baz1 - failed/dev..example:3000/path?code=abc#frag')
            status(`[App 1] [WARN] label/${idnChineseUrl} - failed/${idnGreekUrl}`)
            return {
                webResults: [{
                    type: 'web',
                    tabIndex: 1,
                    url: 'dev..example',
                    normalizedUrl: 'https://dev.abc-1:3000/path?code=abc#frag',
                    finalUrl: 'foo_bar.baz1',
                    success: true,
                    error: null
                }],
                appResults: [{
                    type: 'app',
                    name: 'example..com',
                    success: false,
                    error: 'a..b:5173/callback?tokenish=value'
                }]
            }
        }

        const result = await launchWorkspaceHandlerCore({
            event: { sender: { id: 1 } },
            deps
        })

        assert.equal(result.success, true)
        await harness.calls.launchPromise

        const serializedSent = JSON.stringify(harness.calls.sent)
        assertNoRendererLaunchLeaks(serializedSent)
        assert.ok(harness.calls.sent.some(item => item.channel === 'launch-status' && item.payload === '[Tab 1] Loading Saved browser tab 1...'))
        assert.ok(harness.calls.sent.some(item => item.channel === 'launch-status' && item.payload === '[Tab 1] [WARN] Saved browser tab 1 - Browser tab failed to load.'))
        assert.ok(harness.calls.sent.some(item => item.channel === 'launch-status' && item.payload === '[App 1] Launching Desktop item 1...'))
        assert.ok(harness.calls.sent.some(item => item.channel === 'launch-status' && item.payload === '[App 1] [WARN] Desktop item 1 - Desktop item failed to launch.'))

        const complete = harness.calls.sent.find(item => item.channel === 'launch-complete')
        assert.equal(complete.payload.success, true)
        assert.deepEqual(complete.payload.results.webResults, [{
            type: 'web',
            itemKey: 'tab-1',
            tabIndex: 1,
            url: 'Saved browser tab 1',
            success: true,
            skipped: false
        }])
        assert.deepEqual(complete.payload.results.appResults, [{
            type: 'app',
            itemKey: 'app-1',
            appIndex: 1,
            name: 'Desktop item 1',
            success: false,
            skipped: false,
            error: 'Desktop item failed to launch.',
            reason: 'Desktop item failed to launch.'
        }])
    } finally {
        harness.cleanup()
    }
})

test('manual launch IPC preserves ordinary dotted sentence punctuation', async () => {
    const harness = createHarness()
    try {
        harness.writeWorkspace({
            webTabs: [{ url: 'https://example.com', enabled: true }],
            desktopApps: []
        })

        const deps = harness.createLaunchDeps()
        deps.launchWorkspace = async (_workspace, status) => {
            status('Workspace unavailable.')
            status('[Tab 1] [WARN] Saved browser tab - unavailable.')
            status('[App 1] [INFO] Desktop item - ready.')
            return { webResults: [], appResults: [] }
        }

        const result = await launchWorkspaceHandlerCore({
            event: { sender: { id: 1 } },
            deps
        })

        assert.equal(result.success, true)
        await harness.calls.launchPromise

        assert.ok(harness.calls.sent.some(item => item.channel === 'launch-status' && item.payload === 'Workspace unavailable.'))
        assert.ok(harness.calls.sent.some(item => item.channel === 'launch-status' && item.payload === '[Tab 1] [WARN] Saved browser tab 1 - unavailable.'))
        assert.ok(harness.calls.sent.some(item => item.channel === 'launch-status' && item.payload === '[App 1] [INFO] Desktop item - ready.'))
    } finally {
        harness.cleanup()
    }
})

test('manual launch-complete failure errors are sanitized before reaching renderer', async () => {
    const harness = createHarness()
    try {
        harness.writeWorkspace({
            webTabs: [{ url: 'https://example.com', enabled: true }],
            desktopApps: []
        })

        const deps = harness.createLaunchDeps()
        const idnChineseUrl = '\u4f8b\u5b50.\u6d4b\u8bd5/path?code=abc#frag'
        const idnGreekUrl = '\u03b4\u03bf\u03ba\u03b9\u03bc\u03ae.example/path?code=abc#frag'
        deps.launchWorkspace = async () => {
            throw new Error(`spawn C:\\Users\\Alice\\Portable.exe --password=hunter2 token=raw-launch-token localhost:3000/callback?code=abc#frag 127.0.0.1:5173/path?tokenish=value#frag [::1]:3000/path?code=abc dev.a1 dev.abc-1 team.env2 dev_a.example foo_bar.baz1 a_b.localhost/callback?tokenish=value dev..example:3000/path?code=abc#frag failed:dev..example:3000/path?code=abc#frag failed/dev..example:3000/path?code=abc#frag failed/${idnChineseUrl} failed/${idnGreekUrl} label:a..b:5173/callback?tokenish=value a..b:5173/callback?tokenish=value example..com cap_aaaaaaaaaaaaaaaaaaaaaaaa pid=9999`)
        }

        const result = await launchWorkspaceHandlerCore({
            event: { sender: { id: 1 } },
            deps
        })

        assert.equal(result.success, true)
        await harness.calls.launchPromise

        const complete = harness.calls.sent.find(item => item.channel === 'launch-complete')
        assert.equal(complete.payload.success, false)
        assert.equal(complete.payload.error, 'Workspace launch failed. Review diagnostics before retrying.')
        assertNoRendererLaunchLeaks(JSON.stringify(complete.payload))
    } finally {
        harness.cleanup()
    }
})

test('manual launch start failures returned by invoke are sanitized', async () => {
    const harness = createHarness()
    try {
        harness.writeWorkspace({ webTabs: [], desktopApps: [] })
        const deps = harness.createLaunchDeps()
        const idnChineseUrl = '\u4f8b\u5b50.\u6d4b\u8bd5/path?code=abc#frag'
        const idnGreekUrl = '\u03b4\u03bf\u03ba\u03b9\u03bc\u03ae.example/path?code=abc#frag'
        deps.loadActiveVaultWorkspace = () => {
            throw new Error(`Vault load failed at C:\\Users\\Alice\\vault.json token=raw-launch-token dev.abc-1:3000/path?code=abc#frag dev_a.example:3000/path?code=abc#frag dev..example:3000/path?code=abc#frag failed:dev..example:3000/path?code=abc#frag failed/dev..example:3000/path?code=abc#frag failed/${idnChineseUrl} failed/${idnGreekUrl} label:a..b:5173/callback?tokenish=value a..b example..com cap_aaaaaaaaaaaaaaaaaaaaaaaa`)
        }

        const result = await launchWorkspaceHandlerCore({
            event: { sender: { id: 1 } },
            deps
        })

        assert.equal(result.success, false)
        assert.equal(result.error, 'Workspace launch could not start.')
        assertNoRendererLaunchLeaks(JSON.stringify(result))
        assert.equal(harness.calls.closeBrowser, 0)
        assert.equal(harness.calls.closeDesktopApps, 0)
        assert.equal(harness.calls.launchPromise, null)
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

test('save-vault password rotation preserves existing encrypted account slots', async () => {
    const harness = createHarness()
    const state = createWorkspaceCapabilityHandlerState()
    try {
        harness.writeWorkspace({
            webTabs: [],
            desktopApps: [],
            accountSlots: [ACCOUNT_SLOT]
        })

        const result = await saveVaultHandlerCore({
            state,
            deps: harness.createSaveDeps(),
            input: {
                masterPassword: 'rotated-password',
                currentPassword: 'active-password',
                pin: null,
                fastBoot: false,
                workspace: { webTabs: [], desktopApps: [] }
            }
        })

        assert.equal(result.success, true)
        const stored = harness.readVault().payload
        assert.deepEqual(stored.accountSlots, [ACCOUNT_SLOT])
        assert.equal(harness.loadVaultMeta().accountSlots, undefined)
    } finally {
        harness.cleanup()
    }
})

test('save-vault uses transactional commit without standalone vault write when available', async () => {
    const harness = createHarness()
    const state = createWorkspaceCapabilityHandlerState()
    try {
        const result = await saveVaultHandlerCore({
            state,
            deps: harness.createSaveDeps({
                commitVaultMeta: ({ vault, meta, operation }) => {
                    harness.calls.transactionalCommits.push({
                        vault: clone(vault),
                        meta: clone(meta),
                        operation
                    })
                }
            }),
            input: {
                masterPassword: 'new-password',
                currentPassword: '',
                pin: null,
                fastBoot: false,
                workspace: { webTabs: [], desktopApps: [] }
            }
        })

        assert.equal(result.success, true)
        assert.equal(harness.calls.vaultWrites, 0)
        assert.equal(harness.calls.metaWrites, 0)
        assert.equal(harness.calls.transactionalCommits.length, 1)
        assert.equal(harness.calls.transactionalCommits[0].operation, 'save-vault-create')
        assert.deepEqual(harness.calls.activePasswords, ['new-password'])
        assert.equal(harness.calls.resetPinUnlockFailures, 1)
    } finally {
        harness.cleanup()
    }
})

test('save-vault transactional commit failure leaves authority and session state untouched', async () => {
    const harness = createHarness()
    const state = createWorkspaceCapabilityHandlerState()
    try {
        const selected = await browseExecutableHandlerCore({
            state,
            deps: harness.createBrowseDeps('C:\\Program Files\\Verified\\Verified.exe')
        })

        const result = await saveVaultHandlerCore({
            state,
            deps: harness.createSaveDeps({
                commitVaultMeta: () => {
                    harness.calls.transactionalCommits.push({ operation: 'attempted' })
                    throw new Error('transaction failed')
                }
            }),
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

        assert.equal(result.success, false)
        assert.match(result.error, /transaction failed/)
        assert.equal(harness.calls.transactionalCommits.length, 1)
        assert.equal(harness.calls.vaultWrites, 0)
        assert.equal(harness.calls.metaWrites, 0)
        assert.equal(state.pendingLaunchCapabilityRecords.size, 1)
        assert.deepEqual(harness.calls.activePasswords, [])
        assert.equal(harness.calls.resetPinUnlockFailures, 0)
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

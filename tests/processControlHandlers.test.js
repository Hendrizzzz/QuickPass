import assert from 'assert/strict'
import { test } from 'node:test'
import { basename, join } from 'path'
import {
    beforeQuitLifecycleCleanupCore,
    closeDesktopAppsHandlerCore,
    closeWindowHandlerCore,
    factoryResetHandlerCore,
    getFactoryResetVaultFilePaths,
    quitAndRelaunchHandlerCore,
    startSessionEditHandlerCore,
    startSessionSetupHandlerCore
} from '../src/main/processControlHandlers.js'

const VALID_RESET_TOKEN = '0123456789abcdef0123456789abcdef'
const NOW = 1_000

function createWindow(calls) {
    return {
        close: () => {
            calls.windowClosed = true
            if (calls.onWindowClose) calls.onWindowClose()
        },
        isDestroyed: () => false,
        webContents: {
            send: (channel, payload) => {
                calls.sent.push({ channel, payload })
            }
        }
    }
}

function createDeps(overrides = {}) {
    const vaultDir = 'C:\\Vault'
    const resetPaths = new Set(getFactoryResetVaultFilePaths(vaultDir))
    const calls = {
        diagnostics: [],
        closeBrowser: 0,
        closeDesktopApps: 0,
        launchSessionSetup: 0,
        launchArgs: null,
        readVault: 0,
        decryptVault: 0,
        quitApp: 0,
        windowClosed: false,
        onWindowClose: null,
        sent: [],
        browserAllClosed: null,
        unlinked: [],
        attrib: [],
        setActiveMasterPassword: [],
        resetPinUnlockFailures: 0,
        preventDefault: 0,
        wipeRuntimeAppProfiles: [],
        persistDiagnostics: 0,
        removeTempTraces: 0,
        closeBrowserErrors: []
    }

    const deps = {
        vaultExists: () => true,
        hasActiveSession: () => true,
        getActiveMasterPassword: () => 'active-password',
        beginDiagnosticsCycle: (mode) => {
            calls.diagnostics.push(mode)
        },
        closeBrowser: async () => {
            calls.closeBrowser += 1
        },
        closeDesktopApps: async () => {
            calls.closeDesktopApps += 1
        },
        getWindowFromWebContents: () => createWindow(calls),
        getFocusedWindow: () => createWindow(calls),
        getVaultDir: () => vaultDir,
        onBrowserAllClosed: (callback) => {
            calls.browserAllClosed = callback
        },
        launchSessionSetup: async (_status, launchVaultDir, urls, options) => {
            calls.launchSessionSetup += 1
            calls.launchArgs = { vaultDir: launchVaultDir, urls, options }
            return { success: true }
        },
        readVault: () => {
            calls.readVault += 1
            return { encrypted: true }
        },
        decryptVault: () => {
            calls.decryptVault += 1
            return {
                webTabs: [
                    { url: 'https://enabled.example', enabled: true },
                    { url: 'https://disabled.example', enabled: false }
                ]
            }
        },
        validateQuitOptions: (input = {}) => ({ closeApps: !!input.closeApps }),
        quitApp: () => {
            calls.quitApp += 1
        },
        exists: (filePath) => resetPaths.has(filePath),
        clearHiddenReadOnly: (filePath) => {
            calls.attrib.push(filePath)
        },
        unlink: (filePath) => {
            calls.unlinked.push(filePath)
        },
        setActiveMasterPassword: (value) => {
            calls.setActiveMasterPassword.push(value)
        },
        resetPinUnlockFailures: () => {
            calls.resetPinUnlockFailures += 1
        },
        onCloseBrowserError: (err) => {
            calls.closeBrowserErrors.push(err.message)
        },
        wipeRuntimeAppProfiles: (options) => {
            calls.wipeRuntimeAppProfiles.push(options)
        },
        persistDiagnostics: () => {
            calls.persistDiagnostics += 1
        },
        removeTempTraces: () => {
            calls.removeTempTraces += 1
        },
        ...overrides
    }

    return {
        deps,
        calls,
        event: { sender: { id: 1 } },
        quitEvent: {
            preventDefault: () => {
                calls.preventDefault += 1
            }
        },
        vaultDir
    }
}

function assertNoProcessSideEffects(calls) {
    assert.deepEqual(calls.diagnostics, [])
    assert.equal(calls.closeBrowser, 0)
    assert.equal(calls.closeDesktopApps, 0)
    assert.equal(calls.launchSessionSetup, 0)
    assert.equal(calls.quitApp, 0)
}

test('locked start-session-edit rejects before diagnostics or process cleanup', async () => {
    const { deps, calls, event } = createDeps({
        hasActiveSession: () => false
    })

    await assert.rejects(() => startSessionEditHandlerCore({ event, deps }), /Session is locked/)

    assertNoProcessSideEffects(calls)
    assert.equal(calls.readVault, 0)
    assert.equal(calls.decryptVault, 0)
})

test('existing-vault locked start-session-setup rejects before diagnostics or process cleanup', async () => {
    const { deps, calls, event } = createDeps({
        vaultExists: () => true,
        hasActiveSession: () => false
    })

    await assert.rejects(() => startSessionSetupHandlerCore({ event, deps }), /Session is locked/)

    assertNoProcessSideEffects(calls)
})

test('no-vault start-session-setup is allowed and launches setup after cleanup', async () => {
    const { deps, calls, event, vaultDir } = createDeps({
        vaultExists: () => false,
        hasActiveSession: () => false
    })

    const result = await startSessionSetupHandlerCore({ event, deps })

    assert.equal(result.success, true)
    assert.deepEqual(calls.diagnostics, ['setup'])
    assert.equal(calls.closeBrowser, 1)
    assert.equal(calls.closeDesktopApps, 1)
    assert.equal(calls.launchSessionSetup, 1)
    assert.deepEqual(calls.launchArgs, {
        vaultDir,
        urls: [],
        options: { skipDiagnosticsCycle: true }
    })
})

test('locked quit-and-relaunch rejects before closing browser, apps, or app quit', async () => {
    const { deps, calls } = createDeps({
        vaultExists: () => true,
        hasActiveSession: () => false
    })

    await assert.rejects(() => quitAndRelaunchHandlerCore({
        input: { closeApps: true },
        deps
    }), /Session is locked/)

    assertNoProcessSideEffects(calls)
})

test('unlocked quit-and-relaunch follows closeApps policy before app quit', async () => {
    const { deps, calls } = createDeps()

    const result = await quitAndRelaunchHandlerCore({
        input: { closeApps: true },
        deps
    })

    assert.equal(result.success, true)
    assert.equal(calls.closeBrowser, 1)
    assert.equal(calls.closeDesktopApps, 1)
    assert.equal(calls.quitApp, 1)
})

test('locked close-desktop-apps rejects before side effects', async () => {
    const { deps, calls } = createDeps({
        hasActiveSession: () => false
    })

    await assert.rejects(() => closeDesktopAppsHandlerCore({ deps }), /Session is locked/)

    assert.equal(calls.closeDesktopApps, 0)
})

test('close-window is allowed while locked and reaches before-quit lifecycle cleanup', async () => {
    const { deps, calls, quitEvent } = createDeps({
        hasActiveSession: () => false
    })
    const state = { isQuitting: false }
    calls.onWindowClose = () => {
        calls.lifecycleCleanup = beforeQuitLifecycleCleanupCore({
            event: quitEvent,
            state,
            deps
        })
    }

    closeWindowHandlerCore({ deps })
    await calls.lifecycleCleanup

    assert.equal(calls.windowClosed, true)
    assert.equal(calls.preventDefault, 1)
    assert.equal(calls.closeBrowser, 1)
    assert.equal(calls.closeDesktopApps, 1)
    assert.deepEqual(calls.setActiveMasterPassword, [null])
    assert.deepEqual(calls.wipeRuntimeAppProfiles, [{ staleOnly: true }])
    assert.equal(calls.persistDiagnostics, 1)
    assert.equal(calls.removeTempTraces, 1)
    assert.equal(calls.quitApp, 1)
    assert.equal(state.isQuitting, true)
})

test('factory-reset missing token rejects before deletion', () => {
    const { deps, calls, event } = createDeps()

    assert.throws(() => factoryResetHandlerCore({
        event,
        input: {},
        resetToken: { token: VALID_RESET_TOKEN, expiresAt: NOW + 1, webContentsId: 1 },
        now: NOW,
        deps
    }), /required/)

    assert.deepEqual(calls.unlinked, [])
    assert.deepEqual(calls.setActiveMasterPassword, [])
})

test('factory-reset wrong-window token rejects before deletion', () => {
    const { deps, calls, event } = createDeps()

    assert.throws(() => factoryResetHandlerCore({
        event,
        input: { token: VALID_RESET_TOKEN },
        resetToken: { token: VALID_RESET_TOKEN, expiresAt: NOW + 1, webContentsId: 2 },
        now: NOW,
        deps
    }), /invalid or expired/)

    assert.deepEqual(calls.unlinked, [])
})

test('factory-reset expired token rejects before deletion', () => {
    const { deps, calls, event } = createDeps()

    assert.throws(() => factoryResetHandlerCore({
        event,
        input: { token: VALID_RESET_TOKEN },
        resetToken: { token: VALID_RESET_TOKEN, expiresAt: NOW - 1, webContentsId: 1 },
        now: NOW,
        deps
    }), /invalid or expired/)

    assert.deepEqual(calls.unlinked, [])
})

test('factory-reset is unauthenticated and deletes only vault files', () => {
    const { deps, calls, event, vaultDir } = createDeps({
        hasActiveSession: () => {
            throw new Error('factory reset must not require an unlocked session')
        }
    })

    const reset = factoryResetHandlerCore({
        event,
        input: { token: VALID_RESET_TOKEN },
        resetToken: { token: VALID_RESET_TOKEN, expiresAt: NOW + 1, webContentsId: 1 },
        now: NOW,
        deps
    })

    assert.deepEqual(reset, {
        result: { success: true },
        resetToken: null
    })
    assert.deepEqual(calls.unlinked.map(filePath => basename(filePath)), [
        'vault.json',
        'vault.meta.json',
        'vault.state.json'
    ])
    assert.deepEqual(calls.unlinked, [
        join(vaultDir, 'vault.json'),
        join(vaultDir, 'vault.meta.json'),
        join(vaultDir, 'vault.state.json')
    ])
    assert.equal(calls.unlinked.some(filePath => filePath.includes('Apps')), false)
    assert.equal(calls.unlinked.some(filePath => filePath.includes('AppData')), false)
    assert.deepEqual(calls.setActiveMasterPassword, [null])
    assert.equal(calls.resetPinUnlockFailures, 1)
})

test('factory-reset reused token rejects before deletion', () => {
    const { deps, calls, event } = createDeps()
    const reset = factoryResetHandlerCore({
        event,
        input: { token: VALID_RESET_TOKEN },
        resetToken: { token: VALID_RESET_TOKEN, expiresAt: NOW + 1, webContentsId: 1 },
        now: NOW,
        deps
    })
    calls.unlinked = []

    assert.throws(() => factoryResetHandlerCore({
        event,
        input: { token: VALID_RESET_TOKEN },
        resetToken: reset.resetToken,
        now: NOW,
        deps
    }), /invalid or expired/)

    assert.deepEqual(calls.unlinked, [])
})

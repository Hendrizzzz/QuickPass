import { join } from 'path'
import {
    requireActiveSessionState,
    requireSessionSetupAllowedState,
    requireUnlockedOrNoVaultState
} from './ipcAuthorization.js'
import {
    validateFactoryResetInput,
    validateQuitOptions
} from './ipcValidation.js'

const FACTORY_RESET_FILE_NAMES = ['vault.json', 'vault.meta.json', 'vault.state.json']
const FACTORY_RESET_TOKEN_TTL_MS = 60_000

function isWindowUsable(win) {
    return win && (typeof win.isDestroyed !== 'function' || !win.isDestroyed())
}

function sendToWindow(win, channel, payload) {
    if (isWindowUsable(win)) win.webContents.send(channel, payload)
}

function getActiveMasterPassword(deps) {
    return deps.getActiveMasterPassword ? String(deps.getActiveMasterPassword() || '') : ''
}

function getFactoryResetNow(now) {
    return typeof now === 'function' ? now() : now
}

function beginSetupDiagnosticsCycle(deps) {
    if (deps.beginSetupDiagnosticsCycle) deps.beginSetupDiagnosticsCycle()
    else deps.beginDiagnosticsCycle('setup')
}

function beginEditDiagnosticsCycle(deps) {
    if (deps.beginEditDiagnosticsCycle) deps.beginEditDiagnosticsCycle()
    else deps.beginDiagnosticsCycle('edit')
}

export function createFactoryResetTokenRecord({
    token,
    webContentsId,
    now = Date.now(),
    ttlMs = FACTORY_RESET_TOKEN_TTL_MS
}) {
    return {
        token,
        expiresAt: getFactoryResetNow(now) + ttlMs,
        webContentsId: Number(webContentsId)
    }
}

export function consumeFactoryResetTokenRecord({
    resetToken,
    token,
    webContentsId,
    now = Date.now()
}) {
    const currentTime = getFactoryResetNow(now)
    if (!resetToken ||
        resetToken.expiresAt < currentTime ||
        resetToken.token !== token ||
        resetToken.webContentsId !== Number(webContentsId)) {
        throw new Error('Factory reset token is invalid or expired.')
    }

    return null
}

export function getFactoryResetVaultFilePaths(vaultDir) {
    return FACTORY_RESET_FILE_NAMES.map(fileName => join(vaultDir, fileName))
}

export function deleteFactoryResetVaultFiles({
    vaultDir,
    exists,
    clearHiddenReadOnly = () => { },
    unlink
}) {
    const paths = getFactoryResetVaultFilePaths(vaultDir)
    for (const filePath of paths) {
        if (exists(filePath)) {
            try { clearHiddenReadOnly(filePath) } catch (_) { }
            unlink(filePath)
        }
    }
    return paths
}

export async function startSessionSetupHandlerCore({ event, deps }) {
    requireSessionSetupAllowedState({
        vaultExists: deps.vaultExists(),
        hasActiveSession: deps.hasActiveSession()
    })

    beginSetupDiagnosticsCycle(deps)
    await deps.closeBrowser()
    await deps.closeDesktopApps()

    const win = deps.getWindowFromWebContents(event.sender)
    const vaultDir = deps.getVaultDir()

    deps.onBrowserAllClosed(() => {
        if (isWindowUsable(win)) win.webContents.send('browser-disconnected')
    })

    return deps.launchSessionSetup((statusMsg) => {
        sendToWindow(win, 'launch-status', statusMsg)
    }, vaultDir, [], { skipDiagnosticsCycle: true })
}

export async function startSessionEditHandlerCore({ event, deps }) {
    requireActiveSessionState(deps.hasActiveSession())

    beginEditDiagnosticsCycle(deps)
    await deps.closeBrowser()
    await deps.closeDesktopApps()

    const win = deps.getWindowFromWebContents(event.sender)
    const masterPassword = getActiveMasterPassword(deps)
    if (!masterPassword) return { success: false, error: 'No master password' }

    const vaultDir = deps.getVaultDir()
    let urls = []
    try {
        if (deps.vaultExists()) {
            const workspace = deps.decryptVault(deps.readVault(), masterPassword)
            urls = (workspace.webTabs || []).filter(tab => tab.enabled).map(tab => tab.url)
        }
    } catch (_) { }

    deps.onBrowserAllClosed(() => {
        if (isWindowUsable(win)) win.webContents.send('browser-disconnected')
    })

    return deps.launchSessionSetup((statusMsg) => {
        sendToWindow(win, 'launch-status', statusMsg)
    }, vaultDir, urls, { skipDiagnosticsCycle: true })
}

export async function quitAndRelaunchHandlerCore({ input = {}, deps }) {
    const { closeApps } = (deps.validateQuitOptions || validateQuitOptions)(input)
    requireUnlockedOrNoVaultState({
        vaultExists: deps.vaultExists(),
        hasActiveSession: deps.hasActiveSession()
    })

    await deps.closeBrowser()
    if (closeApps) await deps.closeDesktopApps()
    deps.quitApp()

    return { success: true }
}

export async function closeDesktopAppsHandlerCore({ deps }) {
    requireActiveSessionState(deps.hasActiveSession())
    await deps.closeDesktopApps()
    return { success: true }
}

export function closeWindowHandlerCore({ deps }) {
    const win = deps.getFocusedWindow()
    if (win) win.close()
}

export async function beforeQuitLifecycleCleanupCore({ event, state, deps }) {
    if (state.isQuitting) return
    event.preventDefault()

    try {
        await deps.closeBrowser()
    } catch (err) {
        if (deps.onCloseBrowserError) deps.onCloseBrowserError(err)
    } finally {
        deps.setActiveMasterPassword(null)
        await deps.closeDesktopApps()
        try { deps.wipeRuntimeAppProfiles({ staleOnly: true }) } catch (_) { }
        try { deps.persistDiagnostics() } catch (_) { }
        try { deps.removeTempTraces() } catch (_) { }
        state.isQuitting = true
        deps.quitApp()
    }
}

export function factoryResetHandlerCore({
    event,
    input,
    resetToken,
    now = Date.now(),
    deps
}) {
    const { token } = (deps.validateFactoryResetInput || validateFactoryResetInput)(input, {
        expectedToken: resetToken?.token
    })
    const nextResetToken = consumeFactoryResetTokenRecord({
        resetToken,
        token,
        webContentsId: event.sender.id,
        now
    })
    if (deps.onResetTokenConsumed) deps.onResetTokenConsumed(nextResetToken)

    deleteFactoryResetVaultFiles({
        vaultDir: deps.getVaultDir(),
        exists: deps.exists,
        clearHiddenReadOnly: deps.clearHiddenReadOnly,
        unlink: deps.unlink
    })
    deps.setActiveMasterPassword(null)
    deps.resetPinUnlockFailures()

    return {
        result: { success: true },
        resetToken: nextResetToken
    }
}

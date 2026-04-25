import { requireActiveSessionState } from './ipcAuthorization.js'
import {
    validateCaptureSessionInput,
    validatePasswordInput,
    validateWorkspaceInput
} from './ipcValidation.js'

function normalizeWorkspace(workspace) {
    return {
        ...(workspace && typeof workspace === 'object' ? workspace : {}),
        webTabs: Array.isArray(workspace?.webTabs) ? workspace.webTabs : [],
        desktopApps: Array.isArray(workspace?.desktopApps) ? workspace.desktopApps : []
    }
}

function stripHoneyToken(workspace) {
    if (workspace && typeof workspace === 'object' && '_honeyToken' in workspace) {
        const next = { ...workspace }
        delete next._honeyToken
        return next
    }
    return workspace
}

export function resolveSessionCapturePassword({
    vaultExists,
    activeMasterPassword,
    suppliedMasterPassword,
    requireActiveSession = false,
    allowNewVaultPassword = true
}) {
    const activePassword = activeMasterPassword ? String(activeMasterPassword) : ''

    if (vaultExists || requireActiveSession) {
        requireActiveSessionState(!!activePassword)
        return activePassword
    }

    if (!allowNewVaultPassword) {
        requireActiveSessionState(!!activePassword)
        return activePassword
    }

    return validatePasswordInput(suppliedMasterPassword, 'masterPassword')
}

export function loadExistingWorkspaceForSessionCapture({
    vaultExists,
    readVault,
    decryptVault,
    masterPassword
}) {
    if (!vaultExists) return { webTabs: [], desktopApps: [] }

    try {
        const encryptedVault = readVault()
        return normalizeWorkspace(stripHoneyToken(decryptVault(encryptedVault, masterPassword)))
    } catch (err) {
        throw new Error('Existing vault could not be decrypted. Session capture was not saved.')
    }
}

export async function saveCapturedSessionToVault({
    input = {},
    vaultExists,
    activeMasterPassword,
    capture,
    readVault,
    decryptVault,
    encryptVault,
    writeVault,
    getDriveInfo,
    loadMeta,
    saveMeta,
    mergeMeta,
    authorizeWorkspaceLaunchCapabilities,
    honeyToken,
    validateInput = validateCaptureSessionInput,
    validateWorkspace = validateWorkspaceInput,
    requireActiveSession = false,
    allowNewVaultPassword = true
}) {
    const { masterPassword: suppliedMasterPassword } = validateInput(input)
    const masterPassword = resolveSessionCapturePassword({
        vaultExists,
        activeMasterPassword,
        suppliedMasterPassword,
        requireActiveSession,
        allowNewVaultPassword
    })

    const existingWorkspace = loadExistingWorkspaceForSessionCapture({
        vaultExists,
        readVault,
        decryptVault,
        masterPassword
    })

    const result = await capture()
    if (!result.success) return result

    const urls = Array.isArray(result.urls) ? result.urls : []
    const workspace = {
        ...existingWorkspace,
        webTabs: urls.map(url => ({ url, enabled: true }))
    }

    const safeWorkspace = validateWorkspace(workspace)
    const existingMeta = loadMeta()
    const authorized = authorizeWorkspaceLaunchCapabilities(safeWorkspace, { existingMeta, existingWorkspace })
    const payload = { ...authorized.workspace, _honeyToken: honeyToken }
    const driveInfo = await getDriveInfo()
    const encryptedVault = encryptVault(payload, masterPassword, driveInfo)

    writeVault(encryptedVault)
    saveMeta(mergeMeta(existingMeta || { version: '1.0.0' }, authorized.capabilities))

    return {
        success: true,
        tabCount: result.tabCount,
        urls,
        skippedUrls: result.skippedUrls || [],
        skippedCount: result.skippedCount || 0
    }
}

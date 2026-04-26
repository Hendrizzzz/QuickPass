import { basename, isAbsolute, relative } from 'path'
import { createCapabilityRecord, normalizeCapabilityArgsPolicy } from './capabilityStore.js'
import { readAppManifest } from './appManifest.js'
import { stripLaunchCapabilityMaterialFromMeta } from './vaultMetadata.js'
import {
    WORKSPACE_CAPABILITY_VAULT_KEY,
    createVaultLocalExecutableCapability,
    prepareRendererWorkspaceSave,
    migrateWorkspaceLaunchCapabilities,
    rehydrateWorkspaceLaunchCapabilities,
    sanitizeWorkspaceForRenderer
} from './workspaceCapabilityMigration.js'

const HOST_WORKSPACE_LAUNCH_TYPES = new Set([
    'host-exe',
    'host-folder',
    'registry-uninstall',
    'app-paths',
    'start-menu-shortcut',
    'shell-execute',
    'protocol-uri',
    'packaged-app'
])

export function createWorkspaceCapabilityHandlerState({
    pendingLaunchCapabilityRecords = new Map()
} = {}) {
    return { pendingLaunchCapabilityRecords }
}

function pendingRecordsForState(state) {
    if (!state?.pendingLaunchCapabilityRecords) {
        throw new Error('Workspace capability handler state is missing pending capability storage.')
    }
    return state.pendingLaunchCapabilityRecords
}

function launchCapabilityPolicyForType(type) {
    const ownedProcessTypes = new Set([
        'host-exe',
        'registry-uninstall',
        'app-paths',
        'start-menu-shortcut'
    ])
    return {
        allowedArgs: 'none',
        canCloseFromWipesnap: ownedProcessTypes.has(type),
        ownership: ownedProcessTypes.has(type) ? 'owned-process' : 'external'
    }
}

function capabilityInputForHostLaunch(appConfig, provenance) {
    const type = appConfig?.launchSourceType
    if (!HOST_WORKSPACE_LAUNCH_TYPES.has(type)) return null

    const launch = {
        method: appConfig.launchMethod || (type === 'host-folder' || type === 'shell-execute'
            ? 'shell-execute'
            : type === 'protocol-uri'
                ? 'protocol'
                : type === 'packaged-app'
                    ? 'packaged-app'
                    : 'spawn')
    }

    if (type === 'protocol-uri') {
        launch.uri = appConfig.path
    } else {
        launch.path = appConfig.path
    }

    const optionalFields = {
        'registry-uninstall': ['registryKey', 'registryDisplayName', 'registryInstallLocation', 'registryDisplayIcon'],
        'app-paths': ['appPathsKey', 'appPathsExecutableName', 'appPathsPathValue'],
        'start-menu-shortcut': ['shortcutPath', 'shortcutTargetPath', 'shortcutArguments', 'shortcutWorkingDirectory', 'shortcutIconLocation'],
        'shell-execute': ['shortcutPath', 'shortcutTargetPath', 'shortcutArguments', 'shortcutWorkingDirectory', 'shortcutIconLocation'],
        'protocol-uri': ['protocolScheme', 'protocolCommand', 'protocolRegistryKey'],
        'packaged-app': ['packagedAppId']
    }

    for (const key of optionalFields[type] || []) {
        if (appConfig[key]) launch[key] = appConfig[key]
    }

    return {
        type,
        provenance,
        displayName: appConfig.displayName || appConfig.name || basename(String(appConfig.path || 'App')),
        launch,
        policy: launchCapabilityPolicyForType(type)
    }
}

function importedManifestArgsPolicy(manifest) {
    if (manifest?.launchArgsPolicy == null) return {}
    if (typeof manifest.launchArgsPolicy !== 'object' || Array.isArray(manifest.launchArgsPolicy)) {
        throw new Error('Imported app manifest launchArgsPolicy must be an object.')
    }
    const argsPolicy = normalizeCapabilityArgsPolicy(
        manifest.launchArgsPolicy,
        'imported app manifest launchArgsPolicy'
    )
    return argsPolicy.allowedArgs === 'none' ? {} : argsPolicy
}

function capabilityInputForImportedApp({ name, safeName, manifestId, launchSourceType = 'vault-archive', manifest = null }) {
    return {
        type: launchSourceType === 'vault-directory' ? 'vault-directory' : 'vault-archive',
        provenance: 'import-manifest',
        displayName: name,
        launch: {
            method: 'spawn',
            storageId: safeName,
            manifestId
        },
        policy: {
            allowedArgs: 'none',
            ...importedManifestArgsPolicy(manifest),
            canCloseFromWipesnap: true,
            ownership: 'owned-process'
        }
    }
}

function rendererCapabilityEntry(appConfig, record) {
    const displayName = appConfig.displayName || appConfig.name || record.displayName
    return {
        capabilityId: record.capabilityId,
        displayName,
        name: displayName,
        enabled: appConfig.enabled !== false,
        ...(appConfig.id ? { id: appConfig.id } : {})
    }
}

export function registerLaunchCapability(appConfig, {
    state,
    provenance = 'main',
    createRecord = createCapabilityRecord
} = {}) {
    const input = capabilityInputForHostLaunch(appConfig, provenance)
    if (!input) return appConfig
    const record = createRecord(input)
    pendingRecordsForState(state).set(record.capabilityId, record)
    return {
        ...appConfig,
        ...rendererCapabilityEntry(appConfig, record)
    }
}

export function registerImportedLaunchCapability(appConfig, {
    state,
    createRecord = createCapabilityRecord
} = {}) {
    const record = createRecord(capabilityInputForImportedApp(appConfig))
    pendingRecordsForState(state).set(record.capabilityId, record)
    return rendererCapabilityEntry(appConfig, record)
}

function unsupportedBrowseResult(error) {
    return { success: false, error }
}

function vaultRelativeSelectionPath(selectedPath, vaultDir) {
    const relativePath = relative(vaultDir, selectedPath)
    if (relativePath === '..' || relativePath.startsWith('..\\') || relativePath.startsWith('../') || isAbsolute(relativePath)) return null
    return relativePath.replace(/\//g, '\\')
}

function storageIdFromVaultRelativePath(vaultRelativePath) {
    const parts = String(vaultRelativePath || '').split(/[\\/]+/)
    if (parts.length < 3 || parts[0].toLowerCase() !== 'apps' || !parts[1]) return ''
    return parts[1]
}

export function registerVaultLocalExecutableSelection(selectedPath, vaultDir, {
    state,
    readManifest = readAppManifest,
    now = Date.now
} = {}) {
    const vaultRelativePath = vaultRelativeSelectionPath(selectedPath, vaultDir)
    if (vaultRelativePath == null) return null

    const storageId = storageIdFromVaultRelativePath(vaultRelativePath)
    if (!storageId) {
        return unsupportedBrowseResult('USB-local executable selections must be inside Apps\\<imported-app> and match an imported app manifest.')
    }

    try {
        const manifest = readManifest(vaultDir, storageId)
        const { record, appConfig } = createVaultLocalExecutableCapability({
            vaultRelativePath,
            manifest,
            id: now()
        })
        pendingRecordsForState(state).set(record.capabilityId, record)
        return appConfig
    } catch (err) {
        return unsupportedBrowseResult(err?.message || 'USB-local executable selection could not be verified.')
    }
}

export function unsupportedVaultLocalFolderSelection(selectedPath, vaultDir) {
    const vaultRelativePath = vaultRelativeSelectionPath(selectedPath, vaultDir)
    if (vaultRelativePath == null) return null
    return unsupportedBrowseResult('USB-local folders cannot be added through the folder picker. Import the app or select its verified executable under Apps so a launch capability can be issued.')
}

export async function browseExecutableHandlerCore({ state, deps }) {
    deps.requireUnlockedOrNoVault()
    const result = await deps.showOpenDialog({
        properties: ['openFile'],
        filters: [{ name: 'Executables', extensions: ['exe', 'bat', 'cmd'] }]
    })
    if (result.canceled) return null

    const vaultDir = deps.getVaultDir()
    const selectedPath = result.filePaths[0]
    const vaultLocalSelection = registerVaultLocalExecutableSelection(selectedPath, vaultDir, {
        state,
        readManifest: deps.readAppManifest || readAppManifest,
        now: deps.now || Date.now
    })
    if (vaultLocalSelection) return vaultLocalSelection

    return registerLaunchCapability({
        name: basename(selectedPath).replace(/\.(exe|bat|cmd)$/i, ''),
        path: selectedPath,
        launchSourceType: 'host-exe',
        launchMethod: 'spawn'
    }, { state, provenance: 'browse-exe' })
}

export async function browseFolderHandlerCore({ state, deps }) {
    deps.requireUnlockedOrNoVault()
    const result = await deps.showOpenDialog({
        properties: ['openDirectory']
    })
    if (result.canceled) return null

    const vaultDir = deps.getVaultDir()
    const selectedPath = result.filePaths[0]
    const vaultLocalSelection = unsupportedVaultLocalFolderSelection(selectedPath, vaultDir)
    if (vaultLocalSelection) return vaultLocalSelection

    return registerLaunchCapability({
        name: basename(selectedPath),
        path: selectedPath,
        launchSourceType: 'host-folder',
        launchMethod: 'shell-execute'
    }, { state, provenance: 'browse-folder' })
}

export function authorizeRendererWorkspaceSave(workspace, {
    state,
    existingWorkspace = null
} = {}) {
    return prepareRendererWorkspaceSave(workspace, {
        existingCapabilityVault: existingWorkspace?.[WORKSPACE_CAPABILITY_VAULT_KEY] || null,
        pendingCapabilityRecords: pendingRecordsForState(state)
    })
}

export function mergeLaunchCapabilitiesIntoMeta(meta, migration = null) {
    return stripLaunchCapabilityMaterialFromMeta(meta)
}

function persistVaultAndMeta(deps, { vault, meta, operation }) {
    if (deps.commitVaultMeta) {
        deps.commitVaultMeta({ vault, meta, operation })
        return
    }
    deps.writeVault(vault)
    deps.saveVaultMeta(meta)
}

export function authorizeWorkspaceLaunchCapabilitiesForMain(workspace, {
    existingWorkspace = null,
    manifestResolver = null,
    failClosedOnUnverifiedEnabled = false,
    randomBytes,
    now = Date.now
} = {}) {
    const migrated = migrateWorkspaceLaunchCapabilities(workspace, {
        existingCapabilityVault: existingWorkspace?.[WORKSPACE_CAPABILITY_VAULT_KEY] || workspace?.[WORKSPACE_CAPABILITY_VAULT_KEY] || null,
        manifestResolver,
        failClosedOnUnverifiedEnabled,
        randomBytes,
        now
    })

    return {
        workspace: migrated.workspace,
        capabilityVault: migrated.capabilityVault,
        migrationReport: migrated.migrationReport,
        changed: migrated.changed,
        capabilities: {}
    }
}

export function rehydrateWorkspaceForMain(workspace, options = {}) {
    return rehydrateWorkspaceLaunchCapabilities(workspace, {
        capabilityVault: workspace?.[WORKSPACE_CAPABILITY_VAULT_KEY] || null,
        ...options
    })
}

export async function saveWorkspaceHandlerCore({ workspace, state, deps }) {
    try {
        deps.requireActiveSession()

        const existingMeta = deps.loadVaultMeta()
        const existingWorkspace = deps.loadActiveVaultWorkspace()
        const authorized = authorizeRendererWorkspaceSave(workspace, { state, existingWorkspace })
        const payload = { ...authorized.workspace, _honeyToken: deps.honeyToken }
        const driveInfo = await deps.getDriveInfo()
        const encryptedVault = deps.encryptVault(payload, deps.getActiveMasterPassword(), driveInfo.driveType === 3)
        const meta = mergeLaunchCapabilitiesIntoMeta(existingMeta || { version: '1.0.0' }, authorized)

        persistVaultAndMeta(deps, {
            vault: encryptedVault,
            meta,
            operation: 'save-workspace'
        })
        pendingRecordsForState(state).clear()

        return { success: true, workspace: sanitizeWorkspaceForRenderer(authorized.workspace) }
    } catch (e) {
        return { success: false, error: e.message }
    }
}

export async function saveVaultHandlerCore({ input, state, deps }) {
    try {
        const { masterPassword, currentPassword, pin, fastBoot, workspace } = deps.validateSaveVaultSecurityInput(input)
        const driveInfo = await deps.getDriveInfo()
        const vaultExists = deps.vaultExists()
        let existingWorkspace = null

        if (vaultExists) {
            deps.requireActiveSession()
            if (!currentPassword) throw new Error('Current password is required to change the vault password.')
            deps.decryptVault(deps.readVault(), currentPassword)
            existingWorkspace = deps.loadActiveVaultWorkspace()
        }
        deps.requireConvenienceUnlockRequestSupported({
            requested: !!(pin || fastBoot),
            driveInfo,
            featureName: 'Convenience unlock'
        })

        const authorized = authorizeRendererWorkspaceSave(workspace, { state, existingWorkspace })
        const payload = { ...authorized.workspace, _honeyToken: deps.honeyToken }
        const encryptedVault = deps.encryptVault(payload, masterPassword, driveInfo.driveType === 3)

        let meta = {
            version: '1.0.0',
            createdOn: driveInfo.serialNumber,
            isRemovable: driveInfo.isRemovable,
            fastBoot: false
        }

        if (pin) {
            const pinKey = `${pin}:${driveInfo.serialNumber}`
            meta.pinVault = deps.encryptVault({ masterPassword }, pinKey)
            meta.hasPIN = true
        } else {
            meta.hasPIN = false
        }

        if (fastBoot) {
            const serialKey = `FASTBOOT:${driveInfo.serialNumber}`
            meta.fastBootVault = deps.encryptVault({ masterPassword }, serialKey)
            meta.fastBoot = true
        }

        meta = mergeLaunchCapabilitiesIntoMeta(meta, authorized)
        persistVaultAndMeta(deps, {
            vault: encryptedVault,
            meta,
            operation: vaultExists ? 'save-vault-password-rotation' : 'save-vault-create'
        })
        pendingRecordsForState(state).clear()
        deps.setActiveMasterPassword(masterPassword)
        deps.resetPinUnlockFailures()

        return { success: true }
    } catch (e) {
        return { success: false, error: e.message }
    }
}

function resolveUsbMacros(workspace, vaultDir) {
    if (!workspace?.desktopApps) return workspace
    return {
        ...workspace,
        desktopApps: workspace.desktopApps.map(appConfig => {
            if (appConfig.path && appConfig.path.startsWith('[USB]')) {
                return { ...appConfig, path: appConfig.path.replace('[USB]', vaultDir) }
            }
            return appConfig
        })
    }
}

export async function rehydrateWorkspaceForLaunchCore({ deps }) {
    const vaultWorkspace = deps.loadActiveVaultWorkspace()
    const authorized = deps.authorizeWorkspaceLaunchCapabilities(vaultWorkspace, {
        existingWorkspace: vaultWorkspace,
        failClosedOnUnverifiedEnabled: true,
        manifestResolver: deps.manifestResolver
    })
    await deps.persistMigratedWorkspaceIfChanged(
        authorized.workspace,
        deps.getActiveMasterPassword(),
        authorized
    )
    const safeWorkspace = rehydrateWorkspaceLaunchCapabilities(authorized.workspace, {
        capabilityVault: authorized.capabilityVault,
        manifestResolver: deps.manifestResolver
    })
    return resolveUsbMacros(safeWorkspace, deps.getVaultDir())
}

function sendIfAlive(win, channel, payload) {
    if (win && !win.isDestroyed()) {
        win.webContents.send(channel, payload)
    }
}

export async function launchWorkspaceHandlerCore({ event, deps }) {
    try {
        const win = deps.getWindowFromSender(event.sender)
        const safeWorkspace = await rehydrateWorkspaceForLaunchCore({ deps })
        const vaultDir = deps.getVaultDir()

        const doLaunch = async () => {
            deps.beginDiagnosticsCycle('launch')
            await deps.closeBrowser()
            await deps.closeDesktopApps()
            const launchWorkspaceConfig = await deps.prepareLaunchWorkspaceConfig(safeWorkspace)
            return deps.launchWorkspace(launchWorkspaceConfig, (statusMsg) => {
                sendIfAlive(win, 'launch-status', statusMsg)
            }, vaultDir, { skipDiagnosticsCycle: true })
        }

        const launchPromise = doLaunch().then((results) => {
            sendIfAlive(win, 'launch-complete', { success: true, results })
            return results
        }).catch((err) => {
            if (deps.onLaunchError) deps.onLaunchError(err)
            sendIfAlive(win, 'launch-complete', { success: false, error: err.message })
            return null
        })
        if (deps.onLaunchPromise) deps.onLaunchPromise(launchPromise)

        return { success: true }
    } catch (err) {
        return { success: false, error: err.message }
    }
}

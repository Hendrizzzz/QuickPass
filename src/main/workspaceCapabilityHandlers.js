import { basename, isAbsolute, relative } from 'path'
import { createCapabilityRecord, normalizeCapabilityArgsPolicy } from './capabilityStore.js'
import { attachAccountSlots } from './accountSlots.js'
import { readAppManifest } from './appManifest.js'
import { validateBrowserUrl } from './ipcValidation.js'
import { stripLaunchCapabilityMaterialFromMeta } from './vaultMetadata.js'
import { ensureVaultId, isHiddenMasterVault } from './pinLockout.js'
import {
    WORKSPACE_CAPABILITY_VAULT_KEY,
    createVaultLocalExecutableCapability,
    prepareRendererWorkspaceSave,
    migrateWorkspaceLaunchCapabilities,
    rejectRendererSuppliedInternalWorkspaceFields,
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

function isWindowsScriptLaunchPath(value) {
    return /\.(?:bat|cmd)$/i.test(String(value || '').trim())
}

function isSupportedHostExecutableSelection(value) {
    return /\.exe$/i.test(String(value || '').trim())
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
        filters: [{ name: 'Executables', extensions: ['exe'] }]
    })
    if (result.canceled) return null

    const vaultDir = deps.getVaultDir()
    const selectedPath = result.filePaths[0]
    if (isWindowsScriptLaunchPath(selectedPath)) {
        return unsupportedBrowseResult('Script launch files (.bat/.cmd) are not supported as host executable picks in this release candidate. Select an .exe instead.')
    }
    if (!isSupportedHostExecutableSelection(selectedPath)) {
        return unsupportedBrowseResult('Host executable selections must be .exe files in this release candidate.')
    }

    const vaultLocalSelection = registerVaultLocalExecutableSelection(selectedPath, vaultDir, {
        state,
        readManifest: deps.readAppManifest || readAppManifest,
        now: deps.now || Date.now
    })
    if (vaultLocalSelection) return vaultLocalSelection

    return registerLaunchCapability({
        name: basename(selectedPath).replace(/\.exe$/i, ''),
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
        rejectRendererSuppliedInternalWorkspaceFields(workspace || {})

        const existingMeta = deps.loadVaultMeta()
        const existingWorkspace = deps.loadActiveVaultWorkspace()
        const authorized = authorizeRendererWorkspaceSave(workspace, { state, existingWorkspace })
        const persistedWorkspace = attachAccountSlots(authorized.workspace, existingWorkspace?.accountSlots || [])
        const payload = { ...persistedWorkspace, _honeyToken: deps.honeyToken }
        const driveInfo = await deps.getDriveInfo()
        const encryptedVault = deps.encryptVault(payload, deps.getActiveMasterPassword(), driveInfo.driveType === 3)
        const meta = mergeLaunchCapabilitiesIntoMeta(existingMeta || { version: '1.0.0' }, authorized)

        persistVaultAndMeta(deps, {
            vault: encryptedVault,
            meta,
            operation: 'save-workspace'
        })
        pendingRecordsForState(state).clear()

        return { success: true, workspace: sanitizeWorkspaceForRenderer(persistedWorkspace) }
    } catch (e) {
        return { success: false, error: e.message }
    }
}

export async function saveVaultHandlerCore({ input, state, deps }) {
    try {
        const { masterPassword, currentPassword, pin, fastBoot, hiddenMaster, workspace } = deps.validateSaveVaultSecurityInput(input)
        rejectRendererSuppliedInternalWorkspaceFields(workspace || {})
        const driveInfo = await deps.getDriveInfo()
        const vaultExists = deps.vaultExists()
        const existingMeta = deps.loadVaultMeta ? deps.loadVaultMeta() : null
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
        const persistedWorkspace = attachAccountSlots(authorized.workspace, existingWorkspace?.accountSlots || [])
        const payload = { ...persistedWorkspace, _honeyToken: deps.honeyToken }
        const encryptedVault = deps.encryptVault(payload, masterPassword, driveInfo.driveType === 3)

        let meta = {
            version: '1.0.0',
            vaultId: ensureVaultId(existingMeta || {}),
            createdOn: driveInfo.serialNumber,
            isRemovable: driveInfo.isRemovable,
            fastBoot: false,
            hiddenMaster: vaultExists
                ? isHiddenMasterVault(existingMeta)
                : !!(driveInfo.isRemovable && driveInfo.serialNumber && driveInfo.serialNumber !== 'UNKNOWN' && (hiddenMaster || pin || fastBoot))
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
        deps.resetPinUnlockFailures({ meta, driveInfo, scope: 'vault', method: 'master-password' })

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

const MANUAL_LAUNCH_TEXT_LIMIT = 180
const MANUAL_LAUNCH_LABEL_LIMIT = 80
const MANUAL_LAUNCH_TOKEN_PATTERN = /[^\s"'<>]+/g

function shouldCheckManualBrowserUrlToken(value) {
    return /^https?:\/\//i.test(value) ||
        value.includes('.') ||
        /^localhost(?::|[/?#]|$)/i.test(value) ||
        /^(?:\d{1,3}\.){3}\d{1,3}/.test(value) ||
        /^\[[0-9a-f:.]+\]/i.test(value)
}

function isValidatedManualBrowserUrlToken(value) {
    if (!shouldCheckManualBrowserUrlToken(value)) return false
    try {
        validateBrowserUrl(value, 'launch status URL')
        return true
    } catch (_) {
        return false
    }
}

function splitManualBrowserUrlCandidate(value) {
    const leading = value.match(/^[([{]+/)?.[0] || ''
    const trailing = value.match(/[)\].,;:!?]+$/)?.[0] || ''
    const core = value.slice(leading.length, value.length - trailing.length)
    return { leading, trailing, core }
}

function isManualBrowserUrlContinuationChar(value) {
    if (!value) return false
    const code = value.codePointAt(0)
    return code > 0x7f || /[A-Za-z0-9_.-]/.test(value)
}

function isManualBrowserUrlSubstringStart(value, index) {
    if (index <= 0) return true
    return !isManualBrowserUrlContinuationChar(value[index - 1])
}

function findValidatedManualBrowserUrlSubstring(value) {
    for (let index = 0; index < value.length; index += 1) {
        if (!isManualBrowserUrlSubstringStart(value, index)) continue
        const suffix = value.slice(index)
        const { leading, trailing, core } = splitManualBrowserUrlCandidate(suffix)
        if (!core || !isValidatedManualBrowserUrlToken(core)) continue
        return {
            start: index,
            leading,
            trailing
        }
    }
    return null
}

function redactValidatedManualBrowserUrlToken(token) {
    const { leading, trailing, core } = splitManualBrowserUrlCandidate(token)

    if (!core) return token
    if (isValidatedManualBrowserUrlToken(core)) {
        return `${leading}[redacted-url]${trailing}`
    }

    const match = findValidatedManualBrowserUrlSubstring(core)
    if (match) {
        return `${leading}${core.slice(0, match.start)}${match.leading}[redacted-url]${match.trailing}${trailing}`
    }

    return token
}

function redactValidatedManualBrowserUrls(text) {
    return text.replace(MANUAL_LAUNCH_TOKEN_PATTERN, redactValidatedManualBrowserUrlToken)
}

function limitManualLaunchText(value, limit = MANUAL_LAUNCH_TEXT_LIMIT) {
    const text = String(value || '').replace(/\s+/g, ' ').trim()
    if (text.length <= limit) return text
    return `${text.slice(0, Math.max(0, limit - 3)).trim()}...`
}

function sanitizeManualLaunchText(value, fallback = 'Launch status unavailable.') {
    if (typeof value !== 'string') return fallback
    let text = value
        .replace(/[\u0000-\u001f\u007f]+/g, ' ')
        .replace(/\s+/g, ' ')
        .trim()
    if (!text) return fallback

    text = text
        .replace(/\b[a-z][a-z0-9+.-]*:\/\/[^\s"'<>]+/gi, '[redacted-url]')
        .replace(/\[[0-9A-Fa-f:.]+\](?::\d{1,5})?(?:[/?#][^\s"'<>]*)?/g, '[redacted-url]')
        .replace(/\b(?:[A-Za-z0-9_-]+\.)+[A-Za-z0-9_-]+(?::\d{1,5})?(?:[/?#][^\s"'<>]*)?/g, '[redacted-url]')
        .replace(/\blocalhost(?::\d{1,5})?(?:[/?#][^\s"'<>]*)?/gi, '[redacted-url]')
        .replace(/\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?(?:[/?#][^\s"'<>]*)?/g, '[redacted-url]')
        .replace(/\b(?:[A-Za-z0-9_-]+\.)+[A-Za-z]{2,}(?::\d{1,5})?(?:[/?#][^\s"'<>]*)?/g, '[redacted-url]')
    text = redactValidatedManualBrowserUrls(text)
    text = text
        .replace(/\bHK(?:CU|LM|CR|U|CC)\\[^\s"'<>]+/gi, '[redacted-registry]')
        .replace(/\b[A-Za-z]:\\[^\r\n"'<>|]+/g, '[redacted-path]')
        .replace(/\\\\[^\s"'<>|]+/g, '[redacted-path]')
        .replace(/\bcap_[a-f0-9]{12,96}\b/gi, '[redacted-id]')
        .replace(/\b(?:pid|process(?:\s+id)?)\s*[:=#]?\s*\d{2,10}\b/gi, '[redacted-process]')
        .replace(/\b(?:password|passwd|pass|pin|token|secret|cookie|credential|auth|key|session|synckey|privatekey)([\w.-]{0,24})\s*[:=]\s*[^,;\s)]+/gi, (match) => {
            const name = match.split(/[:=]/)[0]?.trim() || 'value'
            return `${name}=[redacted]`
        })
        .replace(/(?:^|\s)--?[A-Za-z0-9][A-Za-z0-9_.:-]*(?:=(?:"[^"]*"|'[^']*'|[^\s]+))?/g, ' [redacted-arg]')
        .replace(/\b[A-Fa-f0-9]{32,}\b/g, '[redacted-token]')
        .replace(/\b[A-Za-z0-9+/]{40,}={0,2}\b/g, '[redacted-token]')
        .replace(/\b(?:powershell(?:\.exe)?|cmd(?:\.exe)?|taskkill|robocopy|reg(?:\.exe)?|start-process)\b[^\r\n]*/gi, '[redacted-command]')
        .replace(/\s+/g, ' ')
        .trim()

    return text ? limitManualLaunchText(text) : fallback
}

function hasManualLaunchRedaction(value) {
    return /\[redacted-(?:url|path|registry|id|process|arg|token|command)\]|\b(?:password|passwd|pass|pin|token|secret|cookie|credential|auth|key|session|synckey|privatekey)[\w.-]*=\[redacted\]/i.test(String(value || ''))
}

function sanitizeManualLaunchReason(value, fallback) {
    const text = sanitizeManualLaunchText(value, fallback)
    return hasManualLaunchRedaction(text) ? fallback : text
}

function sanitizeManualLaunchLabel(value, fallback) {
    const text = sanitizeManualLaunchText(value, fallback)
    if (!text || hasManualLaunchRedaction(text)) return fallback
    return limitManualLaunchText(text, MANUAL_LAUNCH_LABEL_LIMIT)
}

function splitStatusLabelAndReason(body) {
    const parts = String(body || '').split(/\s+-\s+/)
    return {
        label: parts[0]?.trim() || '',
        reason: parts.slice(1).join(' - ').trim()
    }
}

function sanitizeManualLaunchStatusMessage(message) {
    const rawMessage = typeof message === 'string' ? message : ''
    const tabMatch = rawMessage.match(/^\[Tab\s+(\d+)\]\s*(.*)$/i)
    if (tabMatch) {
        const tabIndex = Number(tabMatch[1])
        const label = `Saved browser tab ${Number.isFinite(tabIndex) ? tabIndex : 1}`
        const body = tabMatch[2] || ''
        if (/^\[OK\]/i.test(body)) {
            return `[Tab ${tabIndex}] [OK] ${label} - ready`
        }
        if (/^\[WARN\]/i.test(body)) {
            const { reason } = splitStatusLabelAndReason(body.replace(/^\[WARN\]\s*/i, ''))
            const safeReason = sanitizeManualLaunchReason(reason || body, 'Browser tab failed to load.')
            return `[Tab ${tabIndex}] [WARN] ${label} - ${safeReason}`
        }
        if (/^Loading\b/i.test(body)) {
            return `[Tab ${tabIndex}] Loading ${label}...`
        }
        return `[Tab ${tabIndex}] ${sanitizeManualLaunchReason(body, 'Browser tab status updated.')}`
    }

    const appMatch = rawMessage.match(/^\[App\s+(\d+)\]\s*(.*)$/i)
    if (appMatch) {
        const appIndex = Number(appMatch[1])
        const fallbackLabel = `Desktop item ${Number.isFinite(appIndex) ? appIndex : 1}`
        const body = appMatch[2] || ''
        const statusPrefix = body.match(/^\[(OK|WARN|INFO)\]\s*/i)?.[0] || ''
        const bodyWithoutStatus = statusPrefix ? body.slice(statusPrefix.length).trim() : body.trim()
        let labelText = bodyWithoutStatus
        let reasonText = ''

        if (/^Launching\s+/i.test(bodyWithoutStatus)) {
            labelText = bodyWithoutStatus.replace(/^Launching\s+/i, '').replace(/\.\.\.$/, '')
        } else if (/^Extracting\s+/i.test(bodyWithoutStatus)) {
            labelText = bodyWithoutStatus.replace(/^Extracting\s+/i, '').replace(/\.\.\.$/, '')
        } else if (/^Refreshing\s+/i.test(bodyWithoutStatus)) {
            labelText = bodyWithoutStatus.replace(/^Refreshing\s+/i, '').replace(/\s+local cache\.\.\.$/i, '')
        } else if (/^Syncing\s+/i.test(bodyWithoutStatus)) {
            labelText = bodyWithoutStatus.replace(/^Syncing\s+/i, '').replace(/\s+data to local\.\.\.$/i, '')
        } else {
            const split = splitStatusLabelAndReason(bodyWithoutStatus)
            labelText = split.label
            reasonText = split.reason
        }

        const label = sanitizeManualLaunchLabel(labelText, fallbackLabel)
        if (/^\[OK\]/i.test(statusPrefix)) {
            return `[App ${appIndex}] [OK] ${label} - ready`
        }
        if (/^\[WARN\]/i.test(statusPrefix)) {
            const safeReason = sanitizeManualLaunchReason(reasonText || bodyWithoutStatus, 'Desktop item failed to launch.')
            return `[App ${appIndex}] [WARN] ${label} - ${safeReason}`
        }
        if (/^\[INFO\]/i.test(statusPrefix)) {
            const safeReason = sanitizeManualLaunchReason(reasonText || bodyWithoutStatus, 'Desktop item status updated.')
            return `[App ${appIndex}] [INFO] ${label} - ${safeReason}`
        }
        if (/^Launching\s+/i.test(bodyWithoutStatus)) {
            return `[App ${appIndex}] Launching ${label}...`
        }
        if (/^Extracting\s+/i.test(bodyWithoutStatus)) {
            return `[App ${appIndex}] Extracting ${label}...`
        }
        if (/^Refreshing\s+/i.test(bodyWithoutStatus)) {
            return `[App ${appIndex}] [INFO] ${label} - Refreshing local cache.`
        }
        if (/^Syncing\s+/i.test(bodyWithoutStatus)) {
            return `[App ${appIndex}] [INFO] ${label} - Syncing local app data.`
        }
        return `[App ${appIndex}] ${sanitizeManualLaunchReason(body, 'Desktop item status updated.')}`
    }

    return sanitizeManualLaunchReason(rawMessage, 'Workspace launch status updated.')
}

function countManualLaunchResults(items = []) {
    return {
        total: items.length,
        succeeded: items.filter(item => item?.success === true && !item?.skipped).length,
        failed: items.filter(item => item?.success === false && !item?.skipped).length,
        skipped: items.filter(item => item?.skipped === true).length
    }
}

function sanitizeManualBrowserResult(item, index) {
    const tabIndex = Number.isFinite(Number(item?.tabIndex)) ? Number(item.tabIndex) : index + 1
    const skipped = item?.skipped === true
    const success = item?.success === true && !skipped
    const error = success
        ? null
        : skipped
            ? 'Skipped browser-owned or unsupported URL.'
            : 'Browser tab failed to load.'
    return {
        type: 'web',
        itemKey: `tab-${tabIndex}`,
        tabIndex,
        url: `Saved browser tab ${tabIndex}`,
        success,
        skipped,
        ...(error ? { error, reason: error } : {})
    }
}

function sanitizeManualAppResult(item, index) {
    const appIndex = index + 1
    const fallbackLabel = `Desktop item ${appIndex}`
    const skipped = item?.skipped === true
    const success = item?.success === true && !skipped
    const reason = success
        ? null
        : skipped
            ? sanitizeManualLaunchReason(item?.reason || item?.error, 'Desktop item skipped.')
            : sanitizeManualLaunchReason(item?.error || item?.reason, 'Desktop item failed to launch.')
    return {
        type: 'app',
        itemKey: `app-${appIndex}`,
        appIndex,
        name: sanitizeManualLaunchLabel(item?.name || item?.displayName, fallbackLabel),
        success,
        skipped,
        ...(reason ? { error: reason, reason } : {})
    }
}

function sanitizeManualLaunchResults(results) {
    const webResults = Array.isArray(results?.webResults)
        ? results.webResults.map(sanitizeManualBrowserResult)
        : []
    const appResults = Array.isArray(results?.appResults)
        ? results.appResults.map(sanitizeManualAppResult)
        : []

    return {
        metadataOnly: true,
        webResults,
        appResults,
        summary: {
            browserTabs: countManualLaunchResults(webResults),
            desktopApps: countManualLaunchResults(appResults)
        }
    }
}

function sanitizeManualLaunchError(err, fallback = 'Workspace launch failed. Review diagnostics before retrying.') {
    const raw = typeof err === 'string' ? err : err?.message
    if (/received a launch argument outside its allowlist/i.test(String(raw || ''))) {
        return 'Saved app received a launch argument outside its allowlist.'
    }
    if (/does not allow renderer-supplied launch arguments/i.test(String(raw || ''))) {
        return 'Saved app does not allow custom launch arguments.'
    }
    if (/received too many launch arguments/i.test(String(raw || ''))) {
        return 'Saved app received too many launch arguments.'
    }
    if (/received an overlong launch argument/i.test(String(raw || ''))) {
        return 'Saved app received an overlong launch argument.'
    }
    if (/manifest is missing or unavailable/i.test(String(raw || ''))) {
        return 'Saved app manifest is missing or unavailable.'
    }
    if (/manifest storage id mismatch/i.test(String(raw || ''))) {
        return 'Saved app manifest storage mismatch.'
    }
    return sanitizeManualLaunchReason(raw, fallback)
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
                sendIfAlive(win, 'launch-status', sanitizeManualLaunchStatusMessage(statusMsg))
            }, vaultDir, { skipDiagnosticsCycle: true })
        }

        const launchPromise = doLaunch().then((results) => {
            sendIfAlive(win, 'launch-complete', {
                success: true,
                results: sanitizeManualLaunchResults(results)
            })
            return results
        }).catch((err) => {
            if (deps.onLaunchError) deps.onLaunchError(err)
            sendIfAlive(win, 'launch-complete', {
                success: false,
                error: sanitizeManualLaunchError(err)
            })
            return null
        })
        if (deps.onLaunchPromise) deps.onLaunchPromise(launchPromise)

        return { success: true }
    } catch (err) {
        return { success: false, error: sanitizeManualLaunchError(err, 'Workspace launch could not start.') }
    }
}

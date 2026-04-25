import { app, BrowserWindow, ipcMain, dialog, session } from 'electron'
import { join, basename } from 'path'
import { pathToFileURL } from 'url'
import { existsSync, readFileSync, writeFileSync, readdirSync, statSync, mkdirSync, rmSync, renameSync, unlinkSync, openSync, closeSync } from 'fs'
import { execSync, spawn, exec, execFile } from 'child_process'
import os from 'os'
import util from 'util'
const execAsync = util.promisify(exec)
const execFileAsync = util.promisify(execFile)
import crypto from 'crypto'
import { launchWorkspace, launchSessionSetup, captureSession, captureCurrentSession, closeBrowser, closeDesktopApps, emergencyKillDesktopAppsSync, onBrowserAllClosed, hasActiveBrowserSession, wipeLocalTraces, wipeAllLocalProfiles, wipeAllLocalAppData, wipeLocalAppCache, wipeAllRuntimeAppProfiles, runDiagnostics, diagError, beginDiagnosticsCycle } from './engine.js'
import {
    APPDATA_SKIP_DIRS,
    BINARY_ARCHIVE_EXCLUDE_DIRS,
    BINARY_ARCHIVE_EXCLUDE_FILES,
    BINARY_ARCHIVE_POLICY_VERSION,
    createImportManifest,
    detectRequiredFilesFromRoot,
    extractExeFromCommand,
    hashFile,
    inferAppType,
    isDangerousExecutablePath,
    pickSupportFields,
    repairLegacyAppConfig,
    resolveAppPathsSupportFields,
    resolveHostExeSupportFields,
    resolveHostFolderSupportFields,
    resolveImportedAppDataCapability,
    resolveManifestSupportFields,
    resolvePackagedAppSupportFields,
    resolveProtocolUriSupportFields,
    resolveRegistryUninstallSupportFields,
    resolveShellExecuteSupportFields,
    resolveStartMenuShortcutSupportFields,
    safeAppName,
    selectBestExecutable,
    writeAppManifest
} from './appManifest.js'
import {
    findStaleUnsupportedAppDataPayloads,
    isSafePayloadDirectory,
    selectStaleAppDataPayloads
} from './staleAppData.js'
import {
    createAvailableAppStorageId,
    validateBooleanInput,
    validateCaptureSessionInput,
    validateFactoryResetInput,
    validateImportAppInput,
    validatePayloadIdsInput,
    validatePasswordInput,
    validatePinInput,
    validateQuitOptions
} from './ipcValidation.js'
import {
    assertTrustedIpcSender,
    blockedIpcResponse,
    configureTrustedIpcRenderer
} from './ipcTrust.js'
import {
    hasUnlockedSession,
    requireActiveSessionState,
    requireConvenienceUnlockRequestSupported,
    requireSessionSetupAllowedState,
    requireUnlockedOrNoVaultState
} from './ipcAuthorization.js'
import { saveCapturedSessionToVault } from './sessionVaultCapture.js'
import {
    beforeQuitLifecycleCleanupCore,
    closeDesktopAppsHandlerCore,
    closeWindowHandlerCore,
    createFactoryResetTokenRecord,
    factoryResetHandlerCore,
    quitAndRelaunchHandlerCore,
    startSessionEditHandlerCore,
    startSessionSetupHandlerCore
} from './processControlHandlers.js'
import {
    WORKSPACE_CAPABILITY_VAULT_KEY,
    migrateWorkspaceLaunchCapabilities,
    migrationReportToMetadataSummary,
    rehydrateWorkspaceLaunchCapabilities
} from './workspaceCapabilityMigration.js'

// Phase 11: The Honey Token
const HONEY_TOKEN = {
    aws_tracking_key: "AKIA-FAKE-DO-NOT-USE-QUICKPASS-HONEY-TOKEN"
}

// ─── Vault Path Resolution ─────────────────────────────────────────────────────
function getVaultDir() {
    if (app.isPackaged) {
        // In electron-builder portable builds, the actual .exe sits on the USB,
        // but it extracts and runs from a temporary folder. 
        // PORTABLE_EXECUTABLE_DIR gives us the actual USB drive path.
        if (process.env.PORTABLE_EXECUTABLE_DIR) {
            return process.env.PORTABLE_EXECUTABLE_DIR
        }
        return join(app.getPath('exe'), '..')
    } else {
        return join(__dirname, '..', '..')
    }
}

// ─── Drive Detection ───────────────────────────────────────────────────────────
let cachedDriveInfo = null
async function getDriveInfo() {
    if (cachedDriveInfo) return cachedDriveInfo

    const vaultDir = getVaultDir()
    const driveLetter = vaultDir.split(':')[0] + ':'

    let serialNumber = 'UNKNOWN'
    let driveType = 0

    try {
        const escapedDrive = driveLetter.replace(/'/g, "''")
        const script = `$d = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='${escapedDrive}'"; if ($d) { [pscustomobject]@{ DriveType = $d.DriveType; VolumeSerialNumber = $d.VolumeSerialNumber } | ConvertTo-Json -Compress }`
        const { stdout } = await execFileAsync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], { encoding: 'utf-8' })
        const parsed = stdout.trim() ? JSON.parse(stdout.trim()) : null
        if (parsed) {
            driveType = Number(parsed.DriveType) || 0
            if (parsed.VolumeSerialNumber) serialNumber = String(parsed.VolumeSerialNumber).trim()
        }
    } catch (_) {
        try {
            const { stdout } = await execAsync(`vol ${driveLetter}`, { encoding: 'utf-8' })
            const lines = stdout.trim().split('\n')
            const serialLine = lines.find(l => l.toLowerCase().includes('serial number'))
            if (serialLine) serialNumber = serialLine.split(' ').pop().trim()
        } catch (_) { }
    }

    const serialKnown = !!serialNumber && serialNumber !== 'UNKNOWN'
    cachedDriveInfo = {
        driveLetter,
        isRemovable: driveType === 2,
        serialNumber: serialKnown ? serialNumber : 'UNKNOWN',
        serialKnown,
        driveType,
        driveTypeKnown: driveType > 0
    }
    return cachedDriveInfo
}

function sanitizeDriveInfoForRenderer(driveInfo) {
    return {
        driveLetter: driveInfo.driveLetter,
        isRemovable: driveInfo.isRemovable,
        driveType: driveInfo.driveType,
        driveTypeKnown: driveInfo.driveTypeKnown,
        serialKnown: driveInfo.serialKnown,
        supportsConvenienceUnlock: driveInfo.isRemovable && driveInfo.serialKnown
    }
}

function getVaultPath() {
    return join(getVaultDir(), 'vault.json')
}

function getStatePath() {
    return join(getVaultDir(), 'vault.state.json')
}

// ─── AES-256-GCM Encryption ────────────────────────────────────────────────────
let cachedHardwareUUID = null
function getHardwareUUID() {
    if (cachedHardwareUUID) return cachedHardwareUUID

    try {
        // Fast UUID fetch
        cachedHardwareUUID = execSync('wmic csproduct get uuid', { encoding: 'utf-8' }).split('\n')[1].trim()
        return cachedHardwareUUID
    } catch (_) {
        cachedHardwareUUID = 'UNKNOWN_UUID'
        return cachedHardwareUUID
    }
}

function deriveKey(password, salt, isFixedDrive = false) {
    let finalSalt = salt
    if (isFixedDrive) {
        const uuid = getHardwareUUID()
        // Removed `path` binding so you can rename the folder or change drive letters!
        finalSalt = Buffer.concat([salt, Buffer.from(uuid, 'utf-8')])
    }
    return crypto.pbkdf2Sync(password, finalSalt, 100000, 32, 'sha512')
}

function encrypt(data, password, isFixedDrive = false) {
    const salt = crypto.randomBytes(16)
    const key = deriveKey(password, salt, isFixedDrive)
    const iv = crypto.randomBytes(12)
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv)

    let encrypted = cipher.update(JSON.stringify(data), 'utf-8', 'hex')
    encrypted += cipher.final('hex')
    const authTag = cipher.getAuthTag()

    return {
        salt: salt.toString('hex'),
        iv: iv.toString('hex'),
        authTag: authTag.toString('hex'),
        data: encrypted,
        isHardwareBound: isFixedDrive
    }
}

function decrypt(encryptedObj, password) {
    const salt = Buffer.from(encryptedObj.salt, 'hex')
    const iv = Buffer.from(encryptedObj.iv, 'hex')
    const authTag = Buffer.from(encryptedObj.authTag, 'hex')
    const isHardwareBound = !!encryptedObj.isHardwareBound
    const key = deriveKey(password, salt, isHardwareBound)

    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv)
    decipher.setAuthTag(authTag)

    let decrypted = decipher.update(encryptedObj.data, 'hex', 'utf-8')
    decrypted += decipher.final('utf-8')

    return JSON.parse(decrypted)
}

function loadActiveVaultWorkspace() {
    if (!activeMasterPasswordBuffer) throw new Error('Session is locked')
    if (!existsSync(getVaultPath())) return { webTabs: [], desktopApps: [] }

    const encryptedVault = JSON.parse(readFileSync(getVaultPath(), 'utf-8'))
    const workspace = decrypt(encryptedVault, activeMasterPasswordBuffer.toString('utf-8'))
    if (workspace?._honeyToken) delete workspace._honeyToken

    return {
        ...workspace,
        webTabs: Array.isArray(workspace?.webTabs) ? workspace.webTabs : [],
        desktopApps: Array.isArray(workspace?.desktopApps) ? workspace.desktopApps : []
    }
}

function validateSaveVaultSecurityInput(input) {
    if (!input || typeof input !== 'object' || Array.isArray(input)) {
        throw new Error('save-vault payload must be an object.')
    }
    return {
        masterPassword: validatePasswordInput(input.masterPassword),
        currentPassword: input.currentPassword ? validatePasswordInput(input.currentPassword, 'currentPassword') : '',
        pin: validatePinInput(input.pin),
        fastBoot: validateBooleanInput(input.fastBoot, 'fastBoot'),
        workspace: input.workspace || {}
    }
}

async function persistMigratedWorkspaceIfChanged(workspace, masterPassword, migrationResult) {
    const existingMeta = loadVaultMeta()
    const metaHasLegacyLaunchAuthority = !!existingMeta?.launchCapabilities
    if (!migrationResult?.changed && !metaHasLegacyLaunchAuthority) return
    if (migrationResult?.changed) {
        const driveInfo = await getDriveInfo()
        const payload = { ...workspace, _honeyToken: HONEY_TOKEN }
        const encryptedVault = encrypt(payload, masterPassword, driveInfo.driveType === 3)
        writeJsonFileAtomic(getVaultPath(), encryptedVault)
    }
    saveVaultMeta(mergeLaunchCapabilitiesIntoMeta(existingMeta || { version: '1.0.0' }, migrationResult))
}

async function migrateUnlockedWorkspaceForRenderer(workspace, masterPassword) {
    const existingMeta = loadVaultMeta()
    const migrated = authorizeWorkspaceLaunchCapabilities(workspace, {
        existingMeta,
        existingWorkspace: workspace
    })
    await persistMigratedWorkspaceIfChanged(migrated.workspace, masterPassword, migrated)
    return migrated.workspace
}

// ─── Vault Metadata ────────────────────────────────────────────────────────────
function getMetaPath() {
    return join(getVaultDir(), 'vault.meta.json')
}

function writeJsonFileAtomic(filePath, data) {
    const tempPath = `${filePath}.${process.pid}.${Date.now()}.tmp`
    if (existsSync(filePath)) {
        try { execSync(`attrib -H -R "${filePath}"`) } catch (_) { }
    }
    writeFileSync(tempPath, JSON.stringify(data, null, 2), 'utf-8')
    renameSync(tempPath, filePath)
    try { execSync(`attrib +H "${filePath}"`) } catch (_) { }
}

function isAppStorageIdTaken(vaultDir, candidate) {
    return existsSync(join(vaultDir, 'Apps', candidate)) ||
        existsSync(join(vaultDir, 'Apps', `${candidate}.tar.zst`)) ||
        existsSync(join(vaultDir, 'Apps', `${candidate}.quickpass-app.json`)) ||
        existsSync(join(vaultDir, 'AppData', candidate))
}

function reserveAppStorageId(vaultDir, name) {
    const reservationsDir = join(vaultDir, 'Apps', '.reservations')
    mkdirSync(reservationsDir, { recursive: true })
    const rejected = new Set()

    for (let attempt = 0; attempt < 1000; attempt += 1) {
        const storageId = createAvailableAppStorageId(name, candidate => (
            rejected.has(candidate) ||
            isAppStorageIdTaken(vaultDir, candidate) ||
            existsSync(join(reservationsDir, `${candidate}.lock`))
        ))
        const lockPath = join(reservationsDir, `${storageId}.lock`)
        let fd = null
        try {
            fd = openSync(lockPath, 'wx')
            writeFileSync(fd, JSON.stringify({
                storageId,
                pid: process.pid,
                createdAt: new Date().toISOString()
            }), 'utf-8')
            closeSync(fd)
            fd = null
            return {
                storageId,
                release() {
                    try { unlinkSync(lockPath) } catch (_) { }
                }
            }
        } catch (err) {
            if (fd != null) {
                try { closeSync(fd) } catch (_) { }
            }
            if (err?.code !== 'EEXIST') throw err
            rejected.add(storageId)
        }
    }

    throw new Error('Could not reserve an app storage id.')
}

function saveVaultMeta(meta) {
    writeJsonFileAtomic(getMetaPath(), meta)
}

function loadVaultMeta() {
    const metaPath = getMetaPath()
    if (!existsSync(metaPath)) return null
    try {
        return JSON.parse(readFileSync(metaPath, 'utf-8'))
    } catch (e) {
        return null
    }
}

function sanitizeVaultMetaForRenderer(meta, driveInfo) {
    if (!meta) return null
    const createdOnMatchesCurrentDrive = meta.createdOn && driveInfo.serialKnown
        ? meta.createdOn === driveInfo.serialNumber
        : null
    return {
        version: meta.version || '1.0.0',
        hasPIN: !!meta.hasPIN,
        fastBoot: !!meta.fastBoot,
        clearCacheOnExit: meta.clearCacheOnExit !== false,
        isRemovable: !!meta.isRemovable,
        createdOnMatchesCurrentDrive,
        hardwareMismatch: createdOnMatchesCurrentDrive === false,
        supportsConvenienceUnlock: driveInfo.isRemovable && driveInfo.serialKnown
    }
}

async function loadVaultMetaForRenderer() {
    const meta = loadVaultMeta()
    if (!meta) return null
    return sanitizeVaultMetaForRenderer(meta, await getDriveInfo())
}

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

const issuedLaunchCapabilities = new Map()

function launchCapabilityReference(appConfig) {
    const reference = {
        launchSourceType: appConfig.launchSourceType,
        launchMethod: appConfig.launchMethod,
        path: appConfig.path
    }
    for (const key of [
        'registryKey',
        'appPathsKey',
        'shortcutPath',
        'protocolScheme',
        'packagedAppId'
    ]) {
        if (appConfig[key]) reference[key] = appConfig[key]
    }
    return reference
}

function launchCapabilityIdFor(reference) {
    return `cap_${crypto.createHash('sha256').update(JSON.stringify(reference)).digest('hex').slice(0, 24)}`
}

function registerLaunchCapability(appConfig, provenance = 'main') {
    if (!HOST_WORKSPACE_LAUNCH_TYPES.has(appConfig?.launchSourceType)) return appConfig
    const reference = launchCapabilityReference(appConfig)
    const capability = {
        id: launchCapabilityIdFor(reference),
        ...reference,
        provenance,
        issuedAt: new Date().toISOString()
    }
    issuedLaunchCapabilities.set(capability.id, capability)
    return { ...appConfig, launchCapabilityId: capability.id }
}

function readStoredLaunchCapabilities(meta = loadVaultMeta()) {
    const records = meta?.launchCapabilities
    if (!records || typeof records !== 'object' || Array.isArray(records)) return new Map()
    return new Map(Object.values(records)
        .filter(record => record?.id)
        .map(record => [record.id, record]))
}

function readMigrationManifest(manifestId, context = {}) {
    try {
        return readAppManifest(getVaultDir(), manifestId || context.storageId || context?.capability?.launch?.storageId)
    } catch (_) {
        return null
    }
}

function legacyLaunchCapabilitiesForMigration(existingMeta = loadVaultMeta()) {
    return new Map([
        ...readStoredLaunchCapabilities(existingMeta),
        ...issuedLaunchCapabilities
    ])
}

function authorizeWorkspaceLaunchCapabilities(workspace, {
    existingMeta = loadVaultMeta(),
    existingWorkspace = null
} = {}) {
    const migrated = migrateWorkspaceLaunchCapabilities(workspace, {
        existingCapabilityVault: existingWorkspace?.[WORKSPACE_CAPABILITY_VAULT_KEY] || null,
        legacyCapabilities: legacyLaunchCapabilitiesForMigration(existingMeta),
        manifestResolver: readMigrationManifest
    })

    return {
        workspace: migrated.workspace,
        capabilityVault: migrated.capabilityVault,
        migrationReport: migrated.migrationReport,
        changed: migrated.changed,
        capabilities: {}
    }
}

function mergeLaunchCapabilitiesIntoMeta(meta, migration = null) {
    const next = { ...(meta || { version: '1.0.0' }) }
    delete next.launchCapabilities

    const report = migration?.migrationReport || null
    const summary = migrationReportToMetadataSummary(report)
    if (summary) next.launchCapabilityMigration = summary
    return next
}

// ─── Cryptographic Memory Buffer ───────────────────────────────────────────────
let activeMasterPasswordBuffer = null
const PIN_MAX_FAILURES = 5
const PIN_LOCKOUT_MS = 60_000
const pinUnlockState = {
    failedAttempts: 0,
    lockedUntil: 0
}
let factoryResetToken = null

function setActiveMasterPassword(password) {
    if (!password) {
        if (activeMasterPasswordBuffer) activeMasterPasswordBuffer.fill(0)
        activeMasterPasswordBuffer = null
    } else {
        if (activeMasterPasswordBuffer) activeMasterPasswordBuffer.fill(0)
        activeMasterPasswordBuffer = Buffer.from(password, 'utf-8')
    }
}

function hasActiveSession() {
    return hasUnlockedSession(activeMasterPasswordBuffer)
}

function requireActiveSession() {
    requireActiveSessionState(hasActiveSession())
}

function requireUnlockedOrNoVault() {
    requireUnlockedOrNoVaultState({
        vaultExists: existsSync(getVaultPath()),
        hasActiveSession: hasActiveSession()
    })
}

function requireSessionSetupAllowed() {
    requireSessionSetupAllowedState({
        vaultExists: existsSync(getVaultPath()),
        hasActiveSession: hasActiveSession()
    })
}

function requireConvenienceUnlockDrive(driveInfo, featureName) {
    requireConvenienceUnlockRequestSupported({
        requested: true,
        driveInfo,
        featureName
    })
}

function resetPinUnlockFailures() {
    pinUnlockState.failedAttempts = 0
    pinUnlockState.lockedUntil = 0
}

function assertPinUnlockAllowed() {
    const now = Date.now()
    if (pinUnlockState.lockedUntil > now) {
        const retryAfterMs = pinUnlockState.lockedUntil - now
        const err = new Error('PIN temporarily locked')
        err.code = 'PIN_LOCKED'
        err.retryAfterMs = retryAfterMs
        throw err
    }
}

function recordPinUnlockFailure() {
    pinUnlockState.failedAttempts += 1
    if (pinUnlockState.failedAttempts >= PIN_MAX_FAILURES) {
        pinUnlockState.lockedUntil = Date.now() + PIN_LOCKOUT_MS
    }
}

function createFactoryResetToken(webContentsId) {
    factoryResetToken = createFactoryResetTokenRecord({
        token: crypto.randomBytes(24).toString('hex'),
        webContentsId
    })
    return factoryResetToken
}

function consumeFactoryResetToken(token, webContentsId) {
    if (!factoryResetToken ||
        factoryResetToken.expiresAt < Date.now() ||
        factoryResetToken.token !== token ||
        factoryResetToken.webContentsId !== Number(webContentsId)) {
        throw new Error('Factory reset token is invalid or expired.')
    }
    factoryResetToken = null
}

// ─── IPC Handlers ──────────────────────────────────────────────────────────────
function getActiveMasterPasswordText() {
    return activeMasterPasswordBuffer ? activeMasterPasswordBuffer.toString('utf-8') : ''
}

function createProcessControlHandlerDeps() {
    return {
        vaultExists: () => existsSync(getVaultPath()),
        hasActiveSession,
        getActiveMasterPassword: getActiveMasterPasswordText,
        beginDiagnosticsCycle,
        beginSetupDiagnosticsCycle: () => beginDiagnosticsCycle('setup'),
        beginEditDiagnosticsCycle: () => beginDiagnosticsCycle('edit'),
        closeBrowser,
        closeDesktopApps,
        getWindowFromWebContents: (sender) => BrowserWindow.fromWebContents(sender),
        getFocusedWindow: () => BrowserWindow.getFocusedWindow(),
        getVaultDir,
        onBrowserAllClosed,
        launchSessionSetup,
        readVault: () => JSON.parse(readFileSync(getVaultPath(), 'utf-8')),
        decryptVault: decrypt,
        validateQuitOptions,
        quitApp: () => app.quit(),
        exists: existsSync,
        clearHiddenReadOnly: (filePath) => execSync(`attrib -H -R "${filePath}"`),
        unlink: unlinkSync,
        setActiveMasterPassword,
        resetPinUnlockFailures,
        onResetTokenConsumed: (nextResetToken) => {
            factoryResetToken = nextResetToken
        },
        validateFactoryResetInput,
        onCloseBrowserError: (err) => {
            console.error('[QuickPass] Profile sync during quit failed:', err)
            diagError('before-quit', err.message)
        },
        wipeRuntimeAppProfiles: wipeAllRuntimeAppProfiles,
        persistDiagnostics: () => {
            const vd = getVaultDir()
            if (existsSync(vd)) {
                writeFileSync(join(vd, 'run-diagnostics.json'), JSON.stringify(runDiagnostics, null, 2), 'utf-8')
            }
        },
        removeTempTraces: () => rmSync(tmpPath, { recursive: true, force: true })
    }
}

function trustedHandle(channel, handler) {
    ipcMain.handle(channel, async (event, ...args) => {
        try {
            assertTrustedIpcSender(event)
            return await handler(event, ...args)
        } catch (err) {
            return blockedIpcResponse(err.message)
        }
    })
}

function trustedOn(channel, listener) {
    ipcMain.on(channel, (event, ...args) => {
        try {
            assertTrustedIpcSender(event)
            listener(event, ...args)
        } catch (_) { }
    })
}

function registerIpcHandlers() {

    trustedHandle('get-drive-info', async () => sanitizeDriveInfoForRenderer(await getDriveInfo()))
    trustedHandle('vault-exists', () => existsSync(getVaultPath()))
    trustedHandle('load-vault-meta', async () => loadVaultMetaForRenderer())

    trustedHandle('begin-factory-reset', (event) => {
        const reset = createFactoryResetToken(event.sender.id)
        return { success: true, token: reset.token, expiresAt: reset.expiresAt }
    })

    trustedHandle('factory-reset', (event, input) => {
        try {
            const reset = factoryResetHandlerCore({
                event,
                input,
                resetToken: factoryResetToken,
                deps: createProcessControlHandlerDeps()
            })
            factoryResetToken = reset.resetToken
            return reset.result
        } catch (e) {
            return { success: false, error: e.message }
        }
    })

    trustedHandle('save-workspace', async (_, workspace) => {
        try {
            requireActiveSession()

            const existingMeta = loadVaultMeta()
            const existingWorkspace = loadActiveVaultWorkspace()
            const authorized = authorizeWorkspaceLaunchCapabilities(workspace, { existingMeta, existingWorkspace })
            const payload = { ...authorized.workspace, _honeyToken: HONEY_TOKEN }
            const driveInfo = await getDriveInfo()
            const encryptedVault = encrypt(payload, activeMasterPasswordBuffer.toString('utf-8'), driveInfo.driveType === 3)

            writeJsonFileAtomic(getVaultPath(), encryptedVault)
            saveVaultMeta(mergeLaunchCapabilitiesIntoMeta(existingMeta || { version: '1.0.0' }, authorized))

            return { success: true }
        } catch (e) {
            return { success: false, error: e.message }
        }
    })

    trustedHandle('save-vault', async (_, input) => {
        try {
            const { masterPassword, currentPassword, pin, fastBoot, workspace } = validateSaveVaultSecurityInput(input)
            const driveInfo = await getDriveInfo()
            const vaultExists = existsSync(getVaultPath())
            let existingWorkspace = null

            if (vaultExists) {
                requireActiveSession()
                if (!currentPassword) throw new Error('Current password is required to change the vault password.')
                const existingVault = JSON.parse(readFileSync(getVaultPath(), 'utf-8'))
                decrypt(existingVault, currentPassword)
                existingWorkspace = loadActiveVaultWorkspace()
            }
            requireConvenienceUnlockRequestSupported({
                requested: !!(pin || fastBoot),
                driveInfo,
                featureName: 'Convenience unlock'
            })

            const existingMeta = loadVaultMeta()
            const authorized = authorizeWorkspaceLaunchCapabilities(workspace, { existingMeta, existingWorkspace })
            const payload = { ...authorized.workspace, _honeyToken: HONEY_TOKEN }
            const encryptedVault = encrypt(payload, masterPassword, driveInfo.driveType === 3)

            writeJsonFileAtomic(getVaultPath(), encryptedVault)

            let meta = {
                version: '1.0.0',
                createdOn: driveInfo.serialNumber,
                isRemovable: driveInfo.isRemovable,
                fastBoot: false
            }

            if (pin) {
                const pinKey = pin + ':' + driveInfo.serialNumber
                const encryptedMasterPw = encrypt({ masterPassword }, pinKey)
                meta.pinVault = encryptedMasterPw
                meta.hasPIN = true
            } else {
                meta.hasPIN = false
            }

            if (fastBoot) {
                const serialKey = 'FASTBOOT:' + driveInfo.serialNumber
                const encryptedMasterPw = encrypt({ masterPassword }, serialKey)
                meta.fastBootVault = encryptedMasterPw
                meta.fastBoot = true
            }

            meta = mergeLaunchCapabilitiesIntoMeta(meta, authorized)
            saveVaultMeta(meta)

            // Cache the active master password so that subsequent actions 
            // (like secondary PIN/FastBoot toggles or Workspace edits) process correctly without requiring restart
            setActiveMasterPassword(masterPassword)
            resetPinUnlockFailures()

            return { success: true }
        } catch (e) {
            return { success: false, error: e.message }
        }
    })

    // --- Isolated Security Handlers ---
    trustedHandle('update-pin', async (_, newPin) => {
        try {
            const safePin = validatePinInput(newPin)
            requireActiveSession()
            const driveInfo = await getDriveInfo()
            requireConvenienceUnlockDrive(driveInfo, 'PIN')

            let meta = loadVaultMeta() || { version: '1.0.0', createdOn: driveInfo.serialNumber, isRemovable: driveInfo.isRemovable }

            if (safePin) {
                const pinKey = safePin + ':' + driveInfo.serialNumber
                meta.pinVault = encrypt({ masterPassword: activeMasterPasswordBuffer.toString('utf-8') }, pinKey)
                meta.hasPIN = true
            } else {
                // Phase 17.2: Prevent lockout — refuse if FastBoot is also off
                if (!meta.fastBoot) {
                    return { success: false, error: 'Cannot disable PIN: no other unlock method is available' }
                }
                delete meta.pinVault
                meta.hasPIN = false
            }
            saveVaultMeta(meta)
            return { success: true }
        } catch (e) {
            return { success: false, error: e.message }
        }
    })

    trustedHandle('update-fastboot', async (_, enable) => {
        try {
            const safeEnable = validateBooleanInput(enable, 'enable')
            requireActiveSession()
            const driveInfo = await getDriveInfo()
            requireConvenienceUnlockDrive(driveInfo, 'FastBoot')

            let meta = loadVaultMeta() || { version: '1.0.0', createdOn: driveInfo.serialNumber, isRemovable: driveInfo.isRemovable }

            if (safeEnable) {
                const serialKey = 'FASTBOOT:' + driveInfo.serialNumber
                meta.fastBootVault = encrypt({ masterPassword: activeMasterPasswordBuffer.toString('utf-8') }, serialKey)
                meta.fastBoot = true
            } else {
                // Phase 17.2: Prevent lockout — refuse if PIN is also off
                if (!meta.hasPIN) {
                    return { success: false, error: 'Cannot disable Fast Boot: no other unlock method is available' }
                }
                delete meta.fastBootVault
                meta.fastBoot = false
            }
            saveVaultMeta(meta)
            return { success: true }
        } catch (e) {
            return { success: false, error: e.message }
        }
    })

    // Phase 17.1: Toggle for clearing extracted app cache on exit
    // ON  = Zero-footprint mode (safe for public/school PCs)
    // OFF = Keep cache for instant launches (ideal for home PC)
    trustedHandle('update-clear-cache', async (_, enable) => {
        try {
            const safeEnable = validateBooleanInput(enable, 'enable')
            requireActiveSession()
            let meta = loadVaultMeta() || { version: '1.0.0' }
            meta.clearCacheOnExit = safeEnable
            saveVaultMeta(meta)
            return { success: true }
        } catch (e) {
            return { success: false, error: e.message }
        }
    })

    trustedHandle('unlock-with-pin', async (_, pin) => {
        try {
            assertPinUnlockAllowed()
            const safePin = validatePinInput(pin, { allowNull: false })
            const meta = loadVaultMeta()
            if (!meta || !meta.hasPIN || !meta.pinVault) {
                return { success: false, error: 'PIN not configured' }
            }

            const driveInfo = await getDriveInfo()
            requireConvenienceUnlockDrive(driveInfo, 'PIN')

            if (meta.createdOn !== driveInfo.serialNumber) {
                return {
                    success: false,
                    error: 'HARDWARE_MISMATCH',
                    message: 'Hardware change detected. PIN disabled. Enter your Master Password.'
                }
            }

            const pinKey = safePin + ':' + driveInfo.serialNumber
            const { masterPassword } = decrypt(meta.pinVault, pinKey)

            const encryptedVault = JSON.parse(readFileSync(getVaultPath(), 'utf-8'))
            let workspace = decrypt(encryptedVault, masterPassword)

            // Remove honey token before sending to frontend
            if (workspace._honeyToken) delete workspace._honeyToken
            workspace = await migrateUnlockedWorkspaceForRenderer(workspace, masterPassword)

            // Cache the actual master password for future localized state saves / setting updates
            setActiveMasterPassword(masterPassword)
            resetPinUnlockFailures()

            return { success: true, workspace }
        } catch (e) {
            if (e.code === 'PIN_LOCKED') {
                return { success: false, error: 'PIN_LOCKED', retryAfterMs: e.retryAfterMs }
            }
            recordPinUnlockFailure()
            return { success: false, error: 'Invalid PIN' }
        }
    })

    trustedHandle('unlock-with-password', async (_, password) => {
        try {
            const safePassword = validatePasswordInput(password)
            const encryptedVault = JSON.parse(readFileSync(getVaultPath(), 'utf-8'))
            let workspace = decrypt(encryptedVault, safePassword)

            if (workspace._honeyToken) delete workspace._honeyToken
            workspace = await migrateUnlockedWorkspaceForRenderer(workspace, safePassword)

            // Cache the actual master password for future localized state saves / setting updates
            setActiveMasterPassword(safePassword)
            resetPinUnlockFailures()

            return { success: true, workspace }
        } catch (e) {
            return { success: false, error: 'Invalid password' }
        }
    })

    trustedHandle('try-fast-boot', async () => {
        try {
            const meta = loadVaultMeta()
            if (!meta || !meta.fastBoot || !meta.fastBootVault) {
                return { success: false }
            }

            const driveInfo = await getDriveInfo()
            requireConvenienceUnlockDrive(driveInfo, 'FastBoot')
            if (meta.createdOn !== driveInfo.serialNumber) {
                return { success: false }
            }

            const serialKey = 'FASTBOOT:' + driveInfo.serialNumber
            const { masterPassword } = decrypt(meta.fastBootVault, serialKey)

            const encryptedVault = JSON.parse(readFileSync(getVaultPath(), 'utf-8'))
            let workspace = decrypt(encryptedVault, masterPassword)

            if (workspace._honeyToken) delete workspace._honeyToken
            workspace = await migrateUnlockedWorkspaceForRenderer(workspace, masterPassword)

            // Store the master password for session state encryption
            setActiveMasterPassword(masterPassword)
            resetPinUnlockFailures()

            return { success: true, workspace }
        } catch (e) {
            return { success: false }
        }
    })

    trustedHandle('browse-exe', async () => {
        requireUnlockedOrNoVault()
        const result = await dialog.showOpenDialog({
            properties: ['openFile'],
            filters: [{ name: 'Executables', extensions: ['exe', 'bat', 'cmd'] }]
        })
        if (result.canceled) return null

        const vaultDir = getVaultDir()
        const selectedPath = result.filePaths[0]
        if (selectedPath.startsWith(vaultDir)) {
            return selectedPath.replace(vaultDir, '[USB]')
        }
        registerLaunchCapability({
            name: basename(selectedPath).replace(/\.(exe|bat|cmd)$/i, ''),
            path: selectedPath,
            launchSourceType: 'host-exe',
            launchMethod: 'spawn'
        }, 'browse-exe')
        return selectedPath
    })

    trustedHandle('browse-folder', async () => {
        requireUnlockedOrNoVault()
        const result = await dialog.showOpenDialog({
            properties: ['openDirectory']
        })
        if (result.canceled) return null

        const vaultDir = getVaultDir()
        const selectedPath = result.filePaths[0]
        if (selectedPath.startsWith(vaultDir)) {
            return selectedPath.replace(vaultDir, '[USB]')
        }
        registerLaunchCapability({
            name: basename(selectedPath),
            path: selectedPath,
            launchSourceType: 'host-folder',
            launchMethod: 'shell-execute'
        }, 'browse-folder')
        return selectedPath
    })

    // ─── App Scanner & Importer ────────────────────────────────────────────

    function isPortableApp(dirPath) {
        try {
            const hasResources = existsSync(join(dirPath, 'resources'))
            const hasAsar = existsSync(join(dirPath, 'resources', 'app.asar'))
            const hasAppDir = existsSync(join(dirPath, 'resources', 'app'))
            const hasLocales = existsSync(join(dirPath, 'locales'))
            return (hasResources && (hasAsar || hasAppDir)) || hasLocales
        } catch (_) { return false }
    }

    function getDirSize(dirPath, skipDirs = new Set()) {
        let total = 0
        try {
            const entries = readdirSync(dirPath, { withFileTypes: true })
            for (const entry of entries) {
                if (entry.isDirectory()) {
                    if (skipDirs.has(entry.name)) continue
                    total += getDirSize(join(dirPath, entry.name), skipDirs)
                } else {
                    try { total += statSync(join(dirPath, entry.name)).size } catch (_) { }
                }
            }
        } catch (_) { }
        return total
    }

    function findAppDataPath(appName) {
        const APPDATA = process.env.APPDATA || ''
        const LOCALAPPDATA = process.env.LOCALAPPDATA || ''

        // Known mappings for browsers
        const browserMappings = {
            'chrome': join(LOCALAPPDATA, 'Google', 'Chrome', 'User Data'),
            'msedge': join(LOCALAPPDATA, 'Microsoft', 'Edge', 'User Data'),
            'opera': join(APPDATA, 'Opera Software', 'Opera Stable'),
            'opera gx': join(APPDATA, 'Opera Software', 'Opera GX Stable')
        }

        const lowerName = appName.toLowerCase()
        for (const [key, dataPath] of Object.entries(browserMappings)) {
            if (lowerName.includes(key) && existsSync(dataPath)) return dataPath
        }

        // Electron apps: try %APPDATA%/<name> (various casings)
        const tryPaths = [
            join(APPDATA, appName),
            join(APPDATA, appName.toLowerCase()),
            join(APPDATA, appName.charAt(0).toUpperCase() + appName.slice(1))
        ]
        for (const p of tryPaths) {
            if (existsSync(p)) return p
        }

        // Scan %APPDATA% for case-insensitive match
        try {
            const entries = readdirSync(APPDATA)
            const match = entries.find(e => e.toLowerCase() === lowerName)
            if (match) return join(APPDATA, match)
        } catch (_) { }

        return null
    }

    async function getDirSizeAsync(dirPath, skipDirs = new Set()) {
        let total = 0
        try {
            const fs = require('fs').promises
            const entries = await fs.readdir(dirPath, { withFileTypes: true })
            const tasks = entries.map(async (entry) => {
                if (entry.isDirectory()) {
                    if (skipDirs.has(entry.name)) return 0
                    return await getDirSizeAsync(join(dirPath, entry.name), skipDirs)
                } else {
                    try { const stat = await fs.stat(join(dirPath, entry.name)); return stat.size } catch (_) { return 0 }
                }
            })
            const sizes = await Promise.all(tasks)
            total = sizes.reduce((a, b) => a + b, 0)
        } catch (_) { }
        return total
    }

    const HOST_APP_BLACKLIST_PATTERNS = [
        /microsoft visual c\+\+/i, /microsoft \.net/i, /\.net (framework|runtime|sdk)/i,
        /windows sdk/i, /windows kit/i, /nvidia/i, /amd software/i, /intel\b/i,
        /java\b.*\b(update|development|runtime)/i, /python\b/i, /node\.?js/i,
        /vulkan/i, /directx/i, /microsoft onedrive/i, /microsoft update/i,
        /microsoft edge update/i, /google update/i, /windows driver/i,
        /redistributable/i, /bonjour/i, /apple (mobile|application) support/i,
        /quickpass/i, /omnilaunch/i
    ]

    const REGISTRY_UNINSTALL_ROOTS = [
        'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
        'HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
        'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall'
    ]

    const APP_PATHS_ROOTS = [
        'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths',
        'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths'
    ]

    function isBlacklistedHostApp(name) {
        return HOST_APP_BLACKLIST_PATTERNS.some(pattern => pattern.test(name || ''))
    }

    function cleanRegistryPath(value) {
        return String(value || '').replace(/["]/g, '').replace(/\\$/, '').trim()
    }

    function readRegistryValue(line) {
        return String(line || '').trim().split(/\s{2,}REG_[A-Z_]*SZ\s{2,}/)[1]?.trim() || ''
    }

    function normalizeInstallRoot(installDir) {
        try {
            let currentDir = require('path').resolve(installDir)
            for (let i = 0; i < 3; i++) {
                const base = basename(currentDir).toLowerCase()
                if (base === '64bit' || base === '32bit' || base === 'bin' || base === 'core' || base === 'uninst' || /^app-\d+\.\d+\.\d+$/.test(base)) {
                    currentDir = require('path').resolve(currentDir, '..')
                    continue
                }
                break
            }
            return currentDir
        } catch (_) {
            return installDir
        }
    }

    async function readRegistryUninstallEntries() {
        const entries = []

        await Promise.all(REGISTRY_UNINSTALL_ROOTS.map(async (regRoot) => {
            try {
                const { stdout } = await execAsync(`reg query "${regRoot}" /s`, { encoding: 'utf-8', maxBuffer: 10 * 1024 * 1024 })
                let currentEntry = { registryKey: '', displayName: '', installLocation: '', displayIcon: '' }

                for (const line of stdout.split(/\r?\n/)) {
                    if (line.startsWith('HKEY_')) {
                        if (currentEntry.displayName && !isBlacklistedHostApp(currentEntry.displayName)) {
                            entries.push(currentEntry)
                        }
                        currentEntry = { registryKey: line.trim(), displayName: '', installLocation: '', displayIcon: '' }
                        continue
                    }

                    const trimmed = line.trim()
                    if (trimmed.startsWith('DisplayName')) {
                        currentEntry.displayName = readRegistryValue(trimmed)
                    } else if (trimmed.startsWith('InstallLocation')) {
                        currentEntry.installLocation = readRegistryValue(trimmed)
                    } else if (trimmed.startsWith('DisplayIcon')) {
                        currentEntry.displayIcon = readRegistryValue(trimmed)
                    }
                }

                if (currentEntry.displayName && !isBlacklistedHostApp(currentEntry.displayName)) {
                    entries.push(currentEntry)
                }
            } catch (_) { }
        }))

        return entries
    }

    function resolveRegistryEntryExecutable(entry) {
        const name = entry?.displayName || ''
        if (!name) return { success: false, reason: 'missing-display-name' }

        const displayIconExe = extractExeFromCommand(entry.displayIcon)
        let installDir = cleanRegistryPath(entry.installLocation)

        if (!installDir || !existsSync(installDir)) {
            if (!displayIconExe || !existsSync(displayIconExe)) {
                return { success: false, reason: 'install-location-and-display-icon-missing' }
            }
            installDir = require('path').dirname(displayIconExe)
        }

        installDir = normalizeInstallRoot(installDir)
        if (!existsSync(installDir)) return { success: false, reason: 'install-location-missing' }

        const selection = selectBestExecutable(installDir, name, displayIconExe ? [{ path: displayIconExe, source: 'registry-display-icon-hint' }] : [])
        if (!selection.selected) return { success: false, reason: 'no-safe-executable-candidate' }

        const relativeExePath = selection.selected.relativePath
        const exePath = join(installDir, relativeExePath)
        if (!existsSync(exePath)) return { success: false, reason: 'resolved-executable-missing' }

        return {
            success: true,
            name,
            path: exePath,
            exe: basename(exePath),
            sourcePath: installDir,
            relativeExePath,
            selectedExecutable: {
                relativePath: relativeExePath,
                confidence: selection.selected.confidence,
                score: selection.selected.score,
                reasons: selection.selected.reasons || []
            },
            candidateExecutables: selection.candidates || [],
            registryKey: entry.registryKey || null,
            registryDisplayName: name,
            registryInstallLocation: entry.installLocation || '',
            registryDisplayIcon: entry.displayIcon || ''
        }
    }

    function buildRegistryLaunchReference(resolved, availabilityStatus = 'available') {
        return {
            name: resolved.name,
            path: resolved.path,
            args: '',
            portableData: false,
            enabled: true,
            id: Date.now(),
            ...resolveRegistryUninstallSupportFields({
                appName: resolved.name,
                availabilityStatus
            }),
            sourcePath: resolved.sourcePath,
            relativeExePath: resolved.relativeExePath,
            selectedExecutable: resolved.selectedExecutable,
            candidateExecutables: resolved.candidateExecutables,
            registryKey: resolved.registryKey,
            registryDisplayName: resolved.registryDisplayName,
            registryInstallLocation: resolved.registryInstallLocation,
            registryDisplayIcon: resolved.registryDisplayIcon,
            registryResolution: {
                status: availabilityStatus,
                resolvedPath: resolved.path,
                resolvedAt: Date.now(),
                usedDisplayIconAsHint: !!resolved.registryDisplayIcon
            }
        }
    }

    function buildAppPathsLaunchReference(resolved, availabilityStatus = 'available') {
        return {
            name: resolved.name,
            path: resolved.path,
            args: '',
            portableData: false,
            enabled: true,
            id: Date.now(),
            ...resolveAppPathsSupportFields({
                appName: resolved.name,
                availabilityStatus
            }),
            appPathsKey: resolved.appPathsKey,
            appPathsExecutableName: resolved.appPathsExecutableName,
            appPathsPathValue: resolved.appPathsPathValue || '',
            appPathsResolution: {
                status: availabilityStatus,
                resolvedPath: resolved.path,
                resolvedAt: Date.now()
            }
        }
    }

    function classifyShortcutTarget(shortcut) {
        const targetPath = String(shortcut?.targetPath || '').trim()
        const args = String(shortcut?.arguments || '').trim()
        const lowerTarget = targetPath.toLowerCase()
        const isDirectExe = lowerTarget.endsWith('.exe') && existsSync(targetPath)
        const dangerous = isDirectExe && isDangerousExecutablePath(targetPath)
        const hasArgs = !!args
        const warnings = []

        if (!isDirectExe) warnings.push('Shortcut target is not a direct executable.')
        if (hasArgs) warnings.push(`Shortcut has launch arguments: ${args}`)
        if (dangerous) warnings.push('Shortcut target looks like a helper, updater, or uninstaller.')

        const strongDirectExecutable = isDirectExe && !hasArgs && !dangerous
        return {
            strongDirectExecutable,
            ownershipProofLevel: strongDirectExecutable ? 'none' : 'weak',
            closePolicy: 'never',
            canQuitFromOmniLaunch: false,
            closeManagedAfterSpawn: strongDirectExecutable,
            warning: warnings.join(' ')
        }
    }

    function buildShortcutLaunchReference(shortcut, availabilityStatus = 'available') {
        const classification = classifyShortcutTarget(shortcut)
        const name = shortcut.name || basename(shortcut.shortcutPath || '').replace(/\.lnk$/i, '')
        return {
            name,
            path: shortcut.targetPath || '',
            args: shortcut.arguments || '',
            portableData: false,
            enabled: true,
            id: Date.now(),
            ...resolveStartMenuShortcutSupportFields({
                appName: name,
                availabilityStatus,
                strongDirectExecutable: classification.strongDirectExecutable,
                warning: classification.warning
            }),
            ownershipProofLevel: classification.ownershipProofLevel,
            closePolicy: classification.closePolicy,
            canQuitFromOmniLaunch: classification.canQuitFromOmniLaunch,
            closeManagedAfterSpawn: classification.closeManagedAfterSpawn,
            shortcutPath: shortcut.shortcutPath || '',
            shortcutTargetPath: shortcut.targetPath || '',
            shortcutArguments: shortcut.arguments || '',
            shortcutWorkingDirectory: shortcut.workingDirectory || '',
            shortcutIconLocation: shortcut.iconLocation || '',
            shortcutClassification: {
                status: classification.strongDirectExecutable ? 'strong-direct-exe' : 'ambiguous',
                warning: classification.warning,
                resolvedAt: Date.now()
            }
        }
    }

    function buildShellExecuteLaunchReference(shortcut, availabilityStatus = 'available') {
        const name = shortcut.name || basename(shortcut.shortcutPath || '').replace(/\.lnk$/i, '')
        const warning = shortcut?.shortcutClassification?.warning || 'Shortcut will be launched through Windows ShellExecute with weak ownership.'
        return {
            name,
            path: shortcut.shortcutPath || shortcut.targetPath || '',
            args: shortcut.arguments || '',
            portableData: false,
            enabled: true,
            id: Date.now(),
            ...resolveShellExecuteSupportFields({
                appName: name,
                availabilityStatus,
                warning
            }),
            shortcutPath: shortcut.shortcutPath || '',
            shortcutTargetPath: shortcut.targetPath || '',
            shortcutArguments: shortcut.arguments || '',
            shortcutWorkingDirectory: shortcut.workingDirectory || '',
            shortcutIconLocation: shortcut.iconLocation || '',
            shellExecuteResolution: {
                status: availabilityStatus,
                resolvedPath: shortcut.shortcutPath || shortcut.targetPath || '',
                resolvedAt: Date.now()
            },
            shortcutClassification: {
                status: 'shell-execute-weak',
                warning,
                resolvedAt: Date.now()
            }
        }
    }

    function buildProtocolUriLaunchReference(entry, availabilityStatus = 'available') {
        const scheme = String(entry?.scheme || '').trim()
        const uri = String(entry?.uri || `${scheme}:`).trim()
        return {
            name: entry?.name || `${scheme}:`,
            path: uri,
            args: '',
            portableData: false,
            enabled: true,
            id: Date.now(),
            ...resolveProtocolUriSupportFields({
                appName: entry?.name || `${scheme}:`,
                availabilityStatus
            }),
            protocolScheme: scheme,
            protocolCommand: entry?.command || '',
            protocolRegistryKey: entry?.registryKey || '',
            protocolResolution: {
                status: availabilityStatus,
                resolvedUri: uri,
                resolvedAt: Date.now()
            }
        }
    }

    function buildPackagedAppLaunchReference(entry, availabilityStatus = 'available') {
        const appId = String(entry?.appId || '').trim()
        const activationPath = appId ? `shell:AppsFolder\\${appId}` : ''
        return {
            name: entry?.name || appId,
            path: activationPath,
            args: '',
            portableData: false,
            enabled: true,
            id: Date.now(),
            ...resolvePackagedAppSupportFields({
                appName: entry?.name || appId,
                availabilityStatus
            }),
            packagedAppId: appId,
            packagedAppResolution: {
                status: availabilityStatus,
                appId,
                resolvedPath: activationPath,
                resolvedAt: Date.now()
            }
        }
    }

    async function readAppPathsEntries() {
        const entries = []
        await Promise.all(APP_PATHS_ROOTS.map(async (regRoot) => {
            try {
                const { stdout } = await execAsync(`reg query "${regRoot}" /s`, { encoding: 'utf-8', maxBuffer: 10 * 1024 * 1024 })
                let currentEntry = { appPathsKey: '', executableName: '', targetPath: '', pathValue: '' }

                for (const line of stdout.split(/\r?\n/)) {
                    if (line.startsWith('HKEY_')) {
                        if (currentEntry.targetPath) entries.push(currentEntry)
                        const key = line.trim()
                        currentEntry = {
                            appPathsKey: key,
                            executableName: basename(key),
                            targetPath: '',
                            pathValue: ''
                        }
                        continue
                    }

                    const trimmed = line.trim()
                    if (trimmed.startsWith('(Default)')) {
                        currentEntry.targetPath = readRegistryValue(trimmed)
                    } else if (trimmed.startsWith('Path')) {
                        currentEntry.pathValue = readRegistryValue(trimmed)
                    }
                }

                if (currentEntry.targetPath) entries.push(currentEntry)
            } catch (_) { }
        }))
        return entries
    }

    function resolveAppPathEntryExecutable(entry) {
        const targetPath = cleanRegistryPath(entry?.targetPath)
        if (!targetPath || !targetPath.toLowerCase().endsWith('.exe')) {
            return { success: false, reason: 'app-paths-target-not-exe' }
        }
        if (!existsSync(targetPath)) return { success: false, reason: 'app-paths-target-missing' }
        if (isDangerousExecutablePath(targetPath)) return { success: false, reason: 'app-paths-target-dangerous' }

        const name = basename(entry.executableName || targetPath).replace(/\.exe$/i, '')
        return {
            success: true,
            name,
            path: targetPath,
            appPathsKey: entry.appPathsKey || '',
            appPathsExecutableName: entry.executableName || basename(targetPath),
            appPathsPathValue: entry.pathValue || ''
        }
    }

    async function readStartMenuShortcuts() {
        const script = `
$ErrorActionPreference = 'SilentlyContinue'
$roots = @(
  [System.IO.Path]::Combine($env:ProgramData, 'Microsoft\\Windows\\Start Menu\\Programs'),
  [System.IO.Path]::Combine($env:APPDATA, 'Microsoft\\Windows\\Start Menu\\Programs')
) | Where-Object { $_ -and (Test-Path $_) }
$shell = New-Object -ComObject WScript.Shell
$items = @()
foreach ($root in $roots) {
  Get-ChildItem -LiteralPath $root -Filter '*.lnk' -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
    try {
      $shortcut = $shell.CreateShortcut($_.FullName)
      $items += [pscustomobject]@{
        name = [System.IO.Path]::GetFileNameWithoutExtension($_.Name)
        shortcutPath = $_.FullName
        targetPath = $shortcut.TargetPath
        arguments = $shortcut.Arguments
        workingDirectory = $shortcut.WorkingDirectory
        iconLocation = $shortcut.IconLocation
      }
    } catch {}
  }
}
$items | ConvertTo-Json -Depth 3 -Compress
`
        try {
            const { stdout } = await execFileAsync('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', script], {
                encoding: 'utf8',
                maxBuffer: 10 * 1024 * 1024
            })
            const trimmed = stdout.trim()
            if (!trimmed) return []
            const parsed = JSON.parse(trimmed)
            return Array.isArray(parsed) ? parsed : [parsed]
        } catch (_) {
            return []
        }
    }

    async function readProtocolUriEntries() {
        const script = `
$ErrorActionPreference = 'SilentlyContinue'
$roots = @('Registry::HKEY_CURRENT_USER\\Software\\Classes', 'Registry::HKEY_CLASSES_ROOT')
$blocked = @('file', 'javascript', 'vbscript', 'data', 'http', 'https')
$items = @()
foreach ($root in $roots) {
  Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue | ForEach-Object {
    try {
      $scheme = $_.PSChildName
      if (-not $scheme -or $scheme -notmatch '^[a-z][a-z0-9+.-]{1,39}$') { return }
      if ($blocked -contains $scheme.ToLowerInvariant()) { return }
      $props = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
      if ($null -eq $props -or $null -eq $props.'URL Protocol') { return }
      $commandKey = Join-Path $_.PSPath 'shell\\open\\command'
      $commandProps = Get-ItemProperty -LiteralPath $commandKey -ErrorAction SilentlyContinue
      $command = ''
      if ($commandProps) { $command = [string]$commandProps.'(default)' }
      $items += [pscustomobject]@{
        name = "$scheme:"
        scheme = $scheme
        uri = "$scheme:"
        command = $command
        registryKey = $_.Name
      }
    } catch {}
  }
}
$items | Sort-Object scheme -Unique | Select-Object -First 80 | ConvertTo-Json -Depth 3 -Compress
`
        try {
            const { stdout } = await execFileAsync('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', script], {
                encoding: 'utf8',
                maxBuffer: 10 * 1024 * 1024
            })
            const trimmed = stdout.trim()
            if (!trimmed) return []
            const parsed = JSON.parse(trimmed)
            return Array.isArray(parsed) ? parsed : [parsed]
        } catch (_) {
            return []
        }
    }

    async function readPackagedApps() {
        const script = `
$ErrorActionPreference = 'SilentlyContinue'
Get-StartApps | Where-Object { $_.Name -and $_.AppID } |
  Select-Object -First 120 -Property @{Name='name';Expression={$_.Name}}, @{Name='appId';Expression={$_.AppID}} |
  ConvertTo-Json -Depth 3 -Compress
`
        try {
            const { stdout } = await execFileAsync('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', script], {
                encoding: 'utf8',
                maxBuffer: 10 * 1024 * 1024
            })
            const trimmed = stdout.trim()
            if (!trimmed) return []
            const parsed = JSON.parse(trimmed)
            return Array.isArray(parsed) ? parsed : [parsed]
        } catch (_) {
            return []
        }
    }

    function isValidProtocolUri(uri) {
        const value = String(uri || '').trim()
        const match = value.match(/^([a-z][a-z0-9+.-]{1,39}):/i)
        if (!match) return false
        const scheme = match[1].toLowerCase()
        return !['file', 'javascript', 'vbscript', 'data', 'http', 'https'].includes(scheme)
    }

    async function resolveAppPathsLaunchReference(appConfig) {
        const entries = await readAppPathsEntries()
        const key = String(appConfig?.appPathsKey || '').toLowerCase()
        const exeName = String(appConfig?.appPathsExecutableName || '').toLowerCase()
        const entry = entries.find(item => key && String(item.appPathsKey || '').toLowerCase() === key) ||
            entries.find(item => exeName && String(item.executableName || '').toLowerCase() === exeName)

        if (!entry) {
            return {
                ...appConfig,
                ...resolveAppPathsSupportFields({ appName: appConfig?.name, availabilityStatus: 'stale-app-path-reference' }),
                appPathsResolution: { status: 'stale-app-path-reference', reason: 'App Paths registry entry was not found on this PC.', resolvedAt: Date.now() }
            }
        }

        const resolved = resolveAppPathEntryExecutable(entry)
        if (!resolved.success) {
            return {
                ...appConfig,
                ...resolveAppPathsSupportFields({ appName: appConfig?.name || entry.executableName, availabilityStatus: 'missing-on-this-PC' }),
                appPathsResolution: { status: 'missing-on-this-PC', reason: resolved.reason, resolvedAt: Date.now() }
            }
        }

        return {
            ...appConfig,
            ...buildAppPathsLaunchReference(resolved, 'available'),
            id: appConfig?.id || Date.now(),
            enabled: appConfig?.enabled !== false,
            args: appConfig?.args || ''
        }
    }

    async function resolveStartMenuShortcutLaunchReference(appConfig) {
        const shortcuts = await readStartMenuShortcuts()
        const shortcutPath = String(appConfig?.shortcutPath || '').toLowerCase()
        const shortcut = shortcuts.find(item => shortcutPath && String(item.shortcutPath || '').toLowerCase() === shortcutPath)

        if (!shortcut) {
            return {
                ...appConfig,
                ...resolveStartMenuShortcutSupportFields({ appName: appConfig?.name, availabilityStatus: 'stale-shortcut-reference' }),
                shortcutClassification: { status: 'stale-shortcut-reference', warning: 'Start Menu shortcut was not found on this PC.', resolvedAt: Date.now() }
            }
        }

        if (!shortcut.targetPath || !existsSync(shortcut.targetPath)) {
            return {
                ...appConfig,
                path: shortcut.targetPath || appConfig?.path || '',
                ...resolveStartMenuShortcutSupportFields({
                    appName: appConfig?.name || shortcut.name,
                    availabilityStatus: 'missing-on-this-PC',
                    strongDirectExecutable: false,
                    warning: 'Shortcut target is missing on this PC.'
                }),
                shortcutClassification: { status: 'missing-on-this-PC', warning: 'Shortcut target is missing on this PC.', resolvedAt: Date.now() }
            }
        }

        return {
            ...appConfig,
            ...buildShortcutLaunchReference(shortcut, 'available'),
            id: appConfig?.id || Date.now(),
            enabled: appConfig?.enabled !== false
        }
    }

    async function resolveShellExecuteLaunchReference(appConfig) {
        const shortcutPath = String(appConfig?.shortcutPath || appConfig?.path || '')
        if (!shortcutPath || !existsSync(shortcutPath)) {
            return {
                ...appConfig,
                ...resolveShellExecuteSupportFields({
                    appName: appConfig?.name,
                    availabilityStatus: 'stale-shell-execute-reference',
                    warning: 'ShellExecute shortcut was not found on this PC.'
                }),
                shellExecuteResolution: {
                    status: 'stale-shell-execute-reference',
                    reason: 'ShellExecute shortcut was not found on this PC.',
                    resolvedAt: Date.now()
                }
            }
        }

        return {
            ...appConfig,
            path: shortcutPath,
            ...resolveShellExecuteSupportFields({
                appName: appConfig?.name,
                availabilityStatus: 'available',
                warning: appConfig?.shortcutClassification?.warning
            }),
            shellExecuteResolution: {
                status: 'available',
                resolvedPath: shortcutPath,
                resolvedAt: Date.now()
            }
        }
    }

    async function resolveProtocolUriLaunchReference(appConfig) {
        const entries = await readProtocolUriEntries()
        const scheme = String(appConfig?.protocolScheme || '').toLowerCase()
        const entry = entries.find(item => scheme && String(item.scheme || '').toLowerCase() === scheme)
        const uri = appConfig?.path || appConfig?.protocolResolution?.resolvedUri || (scheme ? `${scheme}:` : '')

        if (!entry || !isValidProtocolUri(uri)) {
            return {
                ...appConfig,
                ...resolveProtocolUriSupportFields({
                    appName: appConfig?.name,
                    availabilityStatus: 'stale-protocol-reference'
                }),
                protocolResolution: {
                    status: 'stale-protocol-reference',
                    reason: !entry ? 'Protocol handler was not found on this PC.' : 'Protocol URI is not allowed.',
                    resolvedAt: Date.now()
                }
            }
        }

        return {
            ...appConfig,
            ...buildProtocolUriLaunchReference({
                ...entry,
                uri,
                name: appConfig?.name || entry.name
            }, 'available'),
            id: appConfig?.id || Date.now(),
            enabled: appConfig?.enabled !== false
        }
    }

    async function resolvePackagedAppLaunchReference(appConfig) {
        const apps = await readPackagedApps()
        const appId = String(appConfig?.packagedAppId || '').toLowerCase()
        const entry = apps.find(item => appId && String(item.appId || '').toLowerCase() === appId)

        if (!entry) {
            return {
                ...appConfig,
                ...resolvePackagedAppSupportFields({
                    appName: appConfig?.name,
                    availabilityStatus: 'stale-packaged-app-reference'
                }),
                packagedAppResolution: {
                    status: 'stale-packaged-app-reference',
                    reason: 'Packaged app was not found on this PC.',
                    resolvedAt: Date.now()
                }
            }
        }

        return {
            ...appConfig,
            ...buildPackagedAppLaunchReference(entry, 'available'),
            id: appConfig?.id || Date.now(),
            enabled: appConfig?.enabled !== false
        }
    }

    function resolveHostLaunchFailureSupportFields(desktopApp, availabilityStatus = 'missing-on-this-PC') {
        if (desktopApp?.launchSourceType === 'host-folder') {
            return resolveHostFolderSupportFields({
                appName: desktopApp.name,
                availabilityStatus
            })
        }
        if (desktopApp?.launchSourceType === 'shell-execute') {
            return resolveShellExecuteSupportFields({
                appName: desktopApp.name,
                availabilityStatus,
                warning: 'ShellExecute launch reference could not be resolved on this PC.'
            })
        }
        if (desktopApp?.launchSourceType === 'protocol-uri') {
            return resolveProtocolUriSupportFields({ appName: desktopApp.name, availabilityStatus })
        }
        if (desktopApp?.launchSourceType === 'packaged-app') {
            return resolvePackagedAppSupportFields({ appName: desktopApp.name, availabilityStatus })
        }
        return resolveHostExeSupportFields({
            appName: desktopApp.name,
            availabilityStatus,
            launchSourceType: desktopApp.launchSourceType || 'host-exe'
        })
    }

    async function resolveRegistryUninstallLaunchReference(appConfig) {
        const entries = await readRegistryUninstallEntries()
        const nameKey = String(appConfig?.registryDisplayName || appConfig?.name || '').toLowerCase()
        const registryKey = String(appConfig?.registryKey || '').toLowerCase()
        const entry = entries.find(item => registryKey && String(item.registryKey || '').toLowerCase() === registryKey) ||
            entries.find(item => String(item.displayName || '').toLowerCase() === nameKey)

        if (!entry) {
            return {
                ...appConfig,
                path: appConfig?.path || '',
                ...resolveRegistryUninstallSupportFields({
                    appName: appConfig?.name,
                    availabilityStatus: 'stale-registry-reference'
                }),
                registryResolution: {
                    status: 'stale-registry-reference',
                    reason: 'Registry uninstall entry was not found on this PC.',
                    resolvedAt: Date.now()
                }
            }
        }

        const resolved = resolveRegistryEntryExecutable(entry)
        if (!resolved.success) {
            return {
                ...appConfig,
                path: appConfig?.path || '',
                ...resolveRegistryUninstallSupportFields({
                    appName: appConfig?.name || entry.displayName,
                    availabilityStatus: 'missing-on-this-PC'
                }),
                registryKey: entry.registryKey || appConfig?.registryKey || null,
                registryDisplayName: entry.displayName || appConfig?.registryDisplayName || appConfig?.name,
                registryInstallLocation: entry.installLocation || '',
                registryDisplayIcon: entry.displayIcon || '',
                registryResolution: {
                    status: 'missing-on-this-PC',
                    reason: resolved.reason,
                    resolvedAt: Date.now()
                }
            }
        }

        return {
            ...appConfig,
            ...buildRegistryLaunchReference(resolved, 'available'),
            id: appConfig?.id || Date.now(),
            enabled: appConfig?.enabled !== false,
            args: appConfig?.args || ''
        }
    }

    trustedHandle('scan-stale-appdata', async () => {
        try {
            const workspace = loadActiveVaultWorkspace()
            const payloads = await findStaleUnsupportedAppDataPayloads(workspace, getVaultDir(), {
                onError: (desktopApp, err) => diagError('unsupported-appdata-scan', `${desktopApp?.name || desktopApp?.path || 'unknown'}: ${err.message}`)
            })
            return { success: true, payloads }
        } catch (e) {
            return { success: false, error: e.message, payloads: [] }
        }
    })

    trustedHandle('cleanup-stale-appdata', async (_, input = {}) => {
        try {
            const { payloadIds } = validatePayloadIdsInput(input)

            const workspace = loadActiveVaultWorkspace()
            const appDataRoot = join(getVaultDir(), 'AppData')
            const payloads = await findStaleUnsupportedAppDataPayloads(workspace, getVaultDir(), {
                onError: (desktopApp, err) => diagError('unsupported-appdata-scan', `${desktopApp?.name || desktopApp?.path || 'unknown'}: ${err.message}`)
            })
            const selectedPayloads = selectStaleAppDataPayloads(payloadIds, payloads)

            const removed = []
            const failed = []
            for (const payload of selectedPayloads) {
                const safety = isSafePayloadDirectory(appDataRoot, payload.path)
                if (!safety.safe) {
                    failed.push({ ...payload, error: safety.reason })
                    continue
                }

                try {
                    rmSync(payload.path, { recursive: true, force: true, maxRetries: 3, retryDelay: 200 })
                    console.log(`[QuickPass] Removed stale AppData payload: ${payload.path} (${payload.sizeBytes || 0} bytes)`)
                    removed.push(payload)
                } catch (err) {
                    failed.push({ ...payload, error: err.message })
                }
            }

            const remainingPayloads = await findStaleUnsupportedAppDataPayloads(workspace, getVaultDir(), {
                onError: (desktopApp, err) => diagError('unsupported-appdata-scan', `${desktopApp?.name || desktopApp?.path || 'unknown'}: ${err.message}`)
            })
            return {
                success: failed.length === 0,
                removed,
                failed,
                remainingPayloads,
                error: failed.length > 0 ? 'Some stale AppData payloads could not be removed.' : null
            }
        } catch (e) {
            return { success: false, error: e.message, removed: [], failed: [], remainingPayloads: [] }
        }
    })

    trustedHandle('scan-host-installed-apps', async () => {
        try {
            requireUnlockedOrNoVault()
            const entries = await readRegistryUninstallEntries()
            const appPathEntries = await readAppPathsEntries()
            const shortcuts = await readStartMenuShortcuts()
            const protocolEntries = await readProtocolUriEntries()
            const packagedApps = await readPackagedApps()
            const seen = new Set()
            const results = []

            const addResult = (result) => {
                if (!result?.name || !result?.path) return
                const key = `${String(result.launchSourceType || '').toLowerCase()}:${String(result.name).toLowerCase()}:${String(result.path).toLowerCase()}`
                if (seen.has(key)) return
                seen.add(key)
                results.push(registerLaunchCapability(result, 'host-scan'))
            }

            for (const entry of entries) {
                const name = entry.displayName
                if (!name) continue
                const resolved = resolveRegistryEntryExecutable(entry)
                if (!resolved.success) continue
                addResult(buildRegistryLaunchReference(resolved, 'available'))
            }

            for (const entry of appPathEntries) {
                const resolved = resolveAppPathEntryExecutable(entry)
                if (!resolved.success) continue
                addResult(buildAppPathsLaunchReference(resolved, 'available'))
            }

            for (const shortcut of shortcuts) {
                if (!shortcut?.targetPath || !existsSync(shortcut.targetPath)) continue
                const directReference = buildShortcutLaunchReference(shortcut, 'available')
                if (directReference.shortcutClassification?.status === 'strong-direct-exe') {
                    addResult(directReference)
                } else if (shortcut.shortcutPath && existsSync(shortcut.shortcutPath)) {
                    addResult(buildShellExecuteLaunchReference({
                        ...shortcut,
                        shortcutClassification: directReference.shortcutClassification
                    }, 'available'))
                }
            }

            for (const entry of protocolEntries) {
                if (!entry?.scheme || !isValidProtocolUri(entry.uri)) continue
                addResult(buildProtocolUriLaunchReference(entry, 'available'))
            }

            for (const entry of packagedApps) {
                if (!entry?.appId) continue
                addResult(buildPackagedAppLaunchReference(entry, 'available'))
            }

            results.sort((a, b) => a.name.localeCompare(b.name))
            return { success: true, apps: results }
        } catch (err) {
            return { success: false, error: err.message, apps: [] }
        }
    })

    trustedHandle('scan-apps', async () => {
        requireUnlockedOrNoVault()
        const vaultDir = getVaultDir()
        const appsDir = join(vaultDir, 'Apps')
        const results = []
        const seen = new Set()

        // Blacklist: filter out system utilities, runtimes, and drivers
        const BLACKLIST_PATTERNS = [
            /microsoft visual c\+\+/i, /microsoft \.net/i, /\.net (framework|runtime|sdk)/i,
            /windows sdk/i, /windows kit/i, /nvidia/i, /amd software/i, /intel\b/i,
            /java\b.*\b(update|development|runtime)/i, /python\b/i, /node\.?js/i,
            /vulkan/i, /directx/i, /microsoft onedrive/i, /microsoft update/i,
            /microsoft edge update/i, /google update/i, /windows driver/i,
            /redistributable/i, /bonjour/i, /apple (mobile|application) support/i,
            /quickpass/i, /omnilaunch/i
        ]

        function isBlacklisted(name) {
            return BLACKLIST_PATTERNS.some(pattern => pattern.test(name))
        }

        async function processRegistryEntry(entry, results, seen, appsDir) {
            const name = entry.displayName
            if (!name) return
            const nameKey = name.toLowerCase()
            if (seen.has(nameKey)) return

            // Find the installation root and treat registry DisplayIcon as a hint,
            // not as the final executable. DisplayIcon often points at uninstallers.
            let installDir = entry.installLocation?.replace(/["]/g, '').replace(/\\$/, '') || ''
            const displayIconExe = extractExeFromCommand(entry.displayIcon)

            if (!installDir || !existsSync(installDir)) {
                if (!displayIconExe || !existsSync(displayIconExe)) return
                installDir = require('path').dirname(displayIconExe)
            }

            // Phase 15 plus import hardening: climb out of launcher/helper folders
            // such as \bin\64bit or \uninst before scoring candidate executables.
            try {
                let currentDir = require('path').resolve(installDir)
                for (let i = 0; i < 3; i++) {
                    const base = basename(currentDir).toLowerCase()
                    if (base === '64bit' || base === '32bit' || base === 'bin' || base === 'core' || base === 'uninst' || /^app-\d+\.\d+\.\d+$/.test(base)) {
                        currentDir = require('path').resolve(currentDir, '..')
                        continue
                    }
                    break
                }
                installDir = currentDir
            } catch (_) { }

            if (!existsSync(installDir)) return

            const selection = selectBestExecutable(installDir, name, displayIconExe ? [{ path: displayIconExe, source: 'registry-display-icon' }] : [])
            if (!selection.selected) return

            const relativeExePath = selection.selected.relativePath
            const exePath = join(installDir, relativeExePath)
            if (!existsSync(exePath)) return

            seen.add(nameKey)

            const exe = basename(exePath)
            // Phase 15: Store the relative path from installDir to the exe,
            // so nested exes (e.g. bin\64bit\obs64.exe) resolve correctly after import
            const type = inferAppType(installDir)
            
            // Calculate sizes async
            let sizeMB = 0
            try { sizeMB = Math.round((await getDirSizeAsync(installDir, BINARY_ARCHIVE_EXCLUDE_DIRS)) / (1024 * 1024)) } catch (_) { }
            
            const dataPath = findAppDataPath(name)
            let dataSizeMB = 0
            if (dataPath) {
                try { dataSizeMB = Math.round((await getDirSizeAsync(dataPath, APPDATA_SKIP_DIRS)) / (1024 * 1024)) } catch (_) { }
            }
            const importedDataCapability = resolveImportedAppDataCapability({
                appType: type,
                appName: name
            })
            const supportFields = resolveManifestSupportFields({
                appType: type,
                appName: name,
                launchSourceType: 'vault-archive'
            })

            const storageId = safeAppName(name)
            const alreadyImported = existsSync(join(appsDir, storageId)) ||
                existsSync(join(appsDir, `${storageId}.tar.zst`)) ||
                existsSync(join(appsDir, `${storageId}.quickpass-app.json`)) ||
                existsSync(join(appsDir, name)) ||
                existsSync(join(appsDir, `${name}.tar.zst`))

            results.push({
                name,
                exe,
                relativeExePath,
                selectedExecutable: {
                    relativePath: relativeExePath,
                    confidence: selection.selected.confidence,
                    score: selection.selected.score,
                    reasons: selection.selected.reasons || []
                },
                candidateExecutables: selection.candidates,
                sourcePath: installDir,
                sizeMB,
                type,
                dataPath: dataPath || null,
                dataSizeMB,
                ...supportFields,
                importedDataSupported: importedDataCapability.importedDataSupported,
                importedDataSupportLevel: importedDataCapability.importedDataSupportLevel,
                importedDataAdapterId: importedDataCapability.importedDataAdapterId,
                importedDataSupportReason: importedDataCapability.importedDataSupportReason,
                alreadyImported
            })
        }

        // ── Phase 1: Registry scan ──────────────────────────────────────
        const regKeys = [
            'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
            'HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
            'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall'
        ]

        await Promise.all(regKeys.map(async (regKey) => {
            try {
                const { stdout } = await execAsync(`reg query "${regKey}" /s`, { encoding: 'utf-8', maxBuffer: 10 * 1024 * 1024 })
                // Split into individual entries (each starts with HKEY_)
                const entries = stdout.split(/\r?\n\r?\n/).filter(e => e.trim())
                
                let currentEntry = { displayName: '', installLocation: '', displayIcon: '' }
                
                for (const line of stdout.split(/\r?\n/)) {
                    // New key header
                    if (line.startsWith('HKEY_')) {
                        // Process previous entry
                        if (currentEntry.displayName && !isBlacklisted(currentEntry.displayName)) {
                            await processRegistryEntry(currentEntry, results, seen, appsDir)
                        }
                        currentEntry = { displayName: '', installLocation: '', displayIcon: '' }
                        continue
                    }
                    
                    const trimmed = line.trim()
                    if (trimmed.startsWith('DisplayName')) {
                        currentEntry.displayName = trimmed.split(/\s{2,}REG_[A-Z_]*SZ\s{2,}/)[1]?.trim() || ''
                    } else if (trimmed.startsWith('InstallLocation')) {
                        currentEntry.installLocation = trimmed.split(/\s{2,}REG_[A-Z_]*SZ\s{2,}/)[1]?.trim() || ''
                    } else if (trimmed.startsWith('DisplayIcon')) {
                        currentEntry.displayIcon = trimmed.split(/\s{2,}REG_[A-Z_]*SZ\s{2,}/)[1]?.trim() || ''
                    }
                }
                // Process last entry
                if (currentEntry.displayName && !isBlacklisted(currentEntry.displayName)) {
                    await processRegistryEntry(currentEntry, results, seen, appsDir)
                }
            } catch (_) { }
        }))

        // ── Phase 2: Supplementary filesystem scan for apps not in registry ──
        const LOCALAPPDATA = process.env.LOCALAPPDATA || ''
        const PROGRAMFILES = process.env.PROGRAMFILES || ''
        const PROGRAMFILESX86 = process.env['PROGRAMFILES(X86)'] || ''

        const scanPaths = [
            join(LOCALAPPDATA, 'Programs'),
            PROGRAMFILES,
            PROGRAMFILESX86
        ].filter(p => p && existsSync(p))

        // Process sequentially so as not to overwhelm I/O, but await sizing
        for (const scanPath of scanPaths) {
            let dirs = []
            try { dirs = readdirSync(scanPath, { withFileTypes: true }).filter(d => d.isDirectory()) } catch (_) { continue }

            for (const dir of dirs) {
                const fullPath = join(scanPath, dir.name)
                if (seen.has(dir.name.toLowerCase())) continue

                const checkPaths = [fullPath]
                try {
                    const subDirs = readdirSync(fullPath, { withFileTypes: true }).filter(d => d.isDirectory())
                    for (const sub of subDirs) {
                        const subPath = join(fullPath, sub.name)
                        try {
                            const subSubs = readdirSync(subPath, { withFileTypes: true }).filter(d => d.isDirectory())
                            for (const ss of subSubs) {
                                checkPaths.push(join(subPath, ss.name))
                            }
                        } catch (_) { }
                        checkPaths.push(subPath)
                    }
                } catch (_) { }

                for (const checkPath of checkPaths) {
                    if (!isPortableApp(checkPath)) continue

                    const selection = selectBestExecutable(checkPath, dir.name)
                    if (!selection.selected) continue

                    const relativeExePath = selection.selected.relativePath
                    const exe = basename(relativeExePath)
                    const name = exe.replace(/\.exe$/i, '')
                    const nameKey = name.toLowerCase()
                    if (seen.has(nameKey)) continue
                    if (isBlacklisted(name)) continue
                    seen.add(nameKey)

                    const sizeMB = Math.round((await getDirSizeAsync(checkPath, BINARY_ARCHIVE_EXCLUDE_DIRS)) / (1024 * 1024))
                    const dataPath = findAppDataPath(name)
                    let dataSizeMB = 0
                    if (dataPath) {
                        dataSizeMB = Math.round((await getDirSizeAsync(dataPath, APPDATA_SKIP_DIRS)) / (1024 * 1024))
                    }
                    const type = inferAppType(checkPath)
                    const importedDataCapability = resolveImportedAppDataCapability({
                        appType: type,
                        appName: name
                    })
                    const supportFields = resolveManifestSupportFields({
                        appType: type,
                        appName: name,
                        launchSourceType: 'vault-archive'
                    })

                    const storageId = safeAppName(name)
                    const alreadyImported = existsSync(join(appsDir, storageId)) ||
                        existsSync(join(appsDir, `${storageId}.tar.zst`)) ||
                        existsSync(join(appsDir, `${storageId}.quickpass-app.json`)) ||
                        existsSync(join(appsDir, name)) ||
                        existsSync(join(appsDir, `${name}.tar.zst`))

                    results.push({
                        name,
                        exe,
                        relativeExePath,
                        selectedExecutable: {
                            relativePath: relativeExePath,
                            confidence: selection.selected.confidence,
                            score: selection.selected.score,
                            reasons: selection.selected.reasons || []
                        },
                        candidateExecutables: selection.candidates,
                        sourcePath: checkPath,
                        sizeMB,
                        type,
                        dataPath: dataPath || null,
                        dataSizeMB,
                        ...supportFields,
                        importedDataSupported: importedDataCapability.importedDataSupported,
                        importedDataSupportLevel: importedDataCapability.importedDataSupportLevel,
                        importedDataAdapterId: importedDataCapability.importedDataAdapterId,
                        importedDataSupportReason: importedDataCapability.importedDataSupportReason,
                        alreadyImported
                    })
                }
            }
        }

        // Sort: Electron apps first, then native, then by name
        results.sort((a, b) => {
            const typeOrder = { electron: 0, chromium: 1, native: 2 }
            const aOrder = typeOrder[a.type] ?? 2
            const bOrder = typeOrder[b.type] ?? 2
            if (aOrder !== bOrder) return aOrder - bOrder
            return a.name.localeCompare(b.name)
        })

        return results
    })

    trustedHandle('import-app', async (event, input) => {
        requireUnlockedOrNoVault()
        const win = BrowserWindow.fromWebContents(event.sender)
        const vaultDir = getVaultDir()
        let tempArchive = null
        let storageReservation = null

        try {
            const {
                sourcePath,
                name,
                exe,
                relativeExePath,
                importData,
                dataPath,
                sizeMB,
                dataSizeMB,
            } = validateImportAppInput(input)
            storageReservation = reserveAppStorageId(vaultDir, name)
            const storageId = storageReservation.storageId
            const archiveName = `${storageId}.tar.zst`
            const safeName = storageId
            const dataDest = join(vaultDir, 'AppData', safeName)
            tempArchive = join(os.tmpdir(), `omnilaunch-import-${safeName}-${Date.now()}.tar.zst`)

            if (!sourcePath || !existsSync(sourcePath)) {
                throw new Error(`Source app folder not found: ${sourcePath}`)
            }

            const seedExePath = relativeExePath
                ? join(sourcePath, relativeExePath)
                : (exe ? join(sourcePath, exe) : null)
            const selection = selectBestExecutable(sourcePath, name, seedExePath ? [{ path: seedExePath, source: 'import-selection' }] : [])
            if (!selection.selected) {
                throw new Error(`No safe launch executable found for ${name}`)
            }
            if (selection.selected.confidence === 'low') {
                const candidates = (selection.candidates || [])
                    .filter(candidate => !candidate.dangerous)
                    .slice(0, 5)
                    .map(candidate => `${candidate.relativePath} (${candidate.confidence}, score ${candidate.score})`)
                    .join('; ')
                throw new Error(`Executable selection for ${name} is low confidence. Manual executable selection is required before importing.${candidates ? ` Candidates: ${candidates}` : ''}`)
            }

            const selectedExecutable = {
                relativePath: selection.selected.relativePath,
                selectionSource: selection.selected.source || 'scored-candidate',
                confidence: selection.selected.confidence,
                score: selection.selected.score,
                reasons: selection.selected.reasons || []
            }
            const exePathInApp = selectedExecutable.relativePath
            let appType = inferAppType(sourcePath)
            if (String(name || '').toLowerCase().includes('microsoft edge') ||
                selectedExecutable.relativePath.toLowerCase().replace(/\\/g, '/').endsWith('/msedge.exe') ||
                selectedExecutable.relativePath.toLowerCase() === 'msedge.exe') {
                appType = 'chromium'
            }
            const importedDataCapability = resolveImportedAppDataCapability({
                appType,
                appName: name
            })
            const requestedImportData = !!importData
            if (requestedImportData && (!dataPath || !existsSync(dataPath))) {
                throw new Error(`${name} was selected with AppData, but the detected AppData path is no longer available.`)
            }
            if (requestedImportData && !importedDataCapability.importedDataSupported) {
                throw new Error(`${name} was selected with AppData, but QuickPass cannot safely import AppData for this app profile. ${importedDataCapability.importedDataSupportReason}`)
            }
            const effectiveImportData = requestedImportData && importedDataCapability.importedDataSupported
            const requiredFiles = detectRequiredFilesFromRoot(sourcePath)

            // ─── Phase 17: Archive-Based Import ───────────────────────────
            // Instead of copying thousands of small files to USB (which chokes
            // the KIOXIA's flash controller at 0.01 MB/s random write), we:
            //   1. Compress the source dir on local SSD (fast: SSD→SSD)
            //   2. Copy ONE large compressed file to USB (fast: sequential write)
            // This turns a 25-minute import into ~2-3 minutes.

            const archiveDest = join(vaultDir, 'Apps', archiveName)

            // Phase 1: Compress on SSD (fast — no USB involved)
            if (win && !win.isDestroyed()) {
                win.webContents.send('import-progress', {
                    name, phase: 'compressing', percent: 0, copiedMB: 0, totalMB: sizeMB || 0
                })
            }

            // Build tar args as proper array (NOT string concatenation)
            // Spaces in dir names like "Code Cache", "Service Worker" break cmd /c
            const srcParent = require('path').dirname(sourcePath)
            const srcBasename = require('path').basename(sourcePath)

            const tarArgs = ['--zstd']
            for (const d of BINARY_ARCHIVE_EXCLUDE_DIRS) {
                tarArgs.push(`--exclude=${d}`)
            }
            for (const f of BINARY_ARCHIVE_EXCLUDE_FILES) {
                tarArgs.push(`--exclude=${f}`)
            }
            tarArgs.push('-cf', tempArchive, '-C', srcParent, srcBasename)

            await new Promise((resolve, reject) => {
                const proc = spawn('tar', tarArgs, { stdio: ['ignore', 'ignore', 'pipe'] })
                let stderr = ''
                proc.stderr.on('data', (d) => { stderr += d.toString() })
                proc.on('close', (code) => {
                    if (code === 0) resolve()
                    else reject(new Error(`Compression failed (tar exit ${code}): ${stderr.trim()}`))
                })
                proc.on('error', reject)
            })

            // Get compressed size for accurate progress
            const fs = require('fs')
            const compressedSize = fs.statSync(tempArchive).size

            if (win && !win.isDestroyed()) {
                win.webContents.send('import-progress', {
                    name, phase: 'compressing', percent: 100, copiedMB: sizeMB || 0, totalMB: sizeMB || 0
                })
            }

            // Phase 2: Copy single file to USB (fast — sequential write)
            // Ensure Apps directory exists
            const appsDir = join(vaultDir, 'Apps')
            if (!existsSync(appsDir)) mkdirSync(appsDir, { recursive: true })

            await copyFileWithProgress(tempArchive, archiveDest, compressedSize, (progress) => {
                if (win && !win.isDestroyed()) {
                    win.webContents.send('import-progress', { name, phase: 'binary', ...progress })
                }
            })

            const archiveHash = await hashFile(archiveDest)

            // Cleanup temp archive
            try { fs.unlinkSync(tempArchive) } catch (_) {}
            tempArchive = null

            // Phase 3: Copy user data (if requested) — still uses robocopy
            // because AppData needs incremental sync (robocopy /MIR) later
            if (effectiveImportData && dataPath && existsSync(dataPath)) {
                await copyDirWithProgress(dataPath, dataDest, APPDATA_SKIP_DIRS, (progress) => {
                    if (win && !win.isDestroyed()) {
                        win.webContents.send('import-progress', { name, phase: 'data', ...progress })
                    }
                }, dataSizeMB || 0)
            }

            const manifest = createImportManifest({
                displayName: name,
                safeName,
                sourcePath,
                archiveName,
                archiveRoot: srcBasename,
                selectedExecutable,
                candidateExecutables: selection.candidates,
                appType,
                importData: effectiveImportData,
                archiveHash,
                archiveSizeBytes: compressedSize,
                legacyPath: `[USB]\\Apps\\${safeName}\\${exePathInApp}`,
                requiredFiles
            })
            writeAppManifest(vaultDir, manifest)

            return {
                success: true,
                appConfig: {
                    name,
                    // Store the ORIGINAL relative exe path — launch flow will handle extraction
                    path: `[USB]\\Apps\\${safeName}\\${exePathInApp}`,
                    args: '',
                    portableData: !!effectiveImportData,
                    manifestId: manifest.manifestId,
                    launchProfile: manifest.launchProfile,
                    dataProfile: manifest.dataProfile,
                    readinessProfile: manifest.readinessProfile,
                    ...pickSupportFields(manifest),
                    importedDataSupported: importedDataCapability.importedDataSupported,
                    importedDataSupportLevel: importedDataCapability.importedDataSupportLevel,
                    importedDataAdapterId: importedDataCapability.importedDataAdapterId,
                    importedDataSupportReason: importedDataCapability.importedDataSupportReason,
                    binaryArchivePolicyVersion: BINARY_ARCHIVE_POLICY_VERSION,
                    id: Date.now(),
                    enabled: true
                }
            }
        } catch (err) {
            // Fix 1: Clean up the ACTUAL temp archive (not a new Date.now() filename)
            if (tempArchive) {
                try { require('fs').unlinkSync(tempArchive) } catch (_) {}
            }
            return { success: false, error: err.message }
        } finally {
            if (storageReservation) storageReservation.release()
        }
    })

    /**
     * Copy a single file with byte-level progress tracking.
     * Used for copying compressed archives to USB (sequential write = fast).
     */
    async function copyFileWithProgress(src, dest, totalBytes, onProgress) {
        const fs = require('fs')
        const totalMB = Math.round(totalBytes / (1024 * 1024))

        return new Promise((resolve, reject) => {
            const readStream = fs.createReadStream(src, { highWaterMark: 1024 * 1024 }) // 1 MB chunks
            const writeStream = fs.createWriteStream(dest)
            let copiedBytes = 0
            let lastEmit = 0

            readStream.on('data', (chunk) => {
                copiedBytes += chunk.length
                const now = Date.now()
                if (now - lastEmit >= 500) {
                    lastEmit = now
                    onProgress({
                        copiedMB: Math.round(copiedBytes / (1024 * 1024)),
                        totalMB,
                        percent: totalBytes > 0 ? Math.min(99, Math.round((copiedBytes / totalBytes) * 100)) : 0
                    })
                }
            })

            writeStream.on('finish', () => {
                onProgress({ copiedMB: totalMB, totalMB, percent: 100 })
                resolve()
            })

            // Fix 2: Destroy both streams on error to prevent file descriptor leaks
            readStream.on('error', (err) => { readStream.destroy(); writeStream.destroy(); reject(err) })
            writeStream.on('error', (err) => { readStream.destroy(); writeStream.destroy(); reject(err) })
            readStream.pipe(writeStream)
        })
    }

    /**
     * Copy a directory with progress tracking (robocopy).
     * Still used for AppData imports (needs incremental sync later).
     */
    async function copyDirWithProgress(src, dest, skipDirs, onProgress, knownSizeMB = 0) {
        let totalBytes = knownSizeMB * 1024 * 1024
        if (totalBytes === 0) {
            try { totalBytes = await getDirSizeAsync(src, skipDirs) } catch (_) {}
        }
        const totalMB = knownSizeMB || Math.round(totalBytes / (1024 * 1024))

        // Single-threaded for USB — /MT:N overwhelms cheap flash controllers
        const args = [src, dest, '/E', '/R:0', '/W:0', '/BYTES', '/NJH', '/NJS', '/NDL', '/NC']
        if (skipDirs.size > 0) args.push('/XD', ...skipDirs)
        args.push('/XF', 'unins000.exe', 'unins000.dat')

        return new Promise((resolve, reject) => {
            const proc = spawn('robocopy', args, { stdio: ['ignore', 'pipe', 'ignore'] })
            let copiedBytes = 0
            let lastEmit = 0

            proc.stdout.on('data', (data) => {
                for (const line of data.toString().split('\n')) {
                    const match = line.match(/\s+(\d+)\s+[^\s]+/)
                    if (match && parseInt(match[1]) > 100) {
                        copiedBytes += parseInt(match[1])
                        const now = Date.now()
                        if (now - lastEmit >= 500) {
                            lastEmit = now
                            onProgress({
                                copiedMB: Math.round(copiedBytes / (1024 * 1024)),
                                totalMB,
                                percent: totalBytes > 0 ? Math.min(99, Math.round((copiedBytes / totalBytes) * 100)) : 0
                            })
                        }
                    }
                }
            })

            proc.on('close', (code) => {
                onProgress({ copiedMB: totalMB, totalMB, percent: 100 })
                if (code >= 16) reject(new Error(`Copy failed (robocopy exit ${code})`))
                else resolve()
            })
        })
    }

    // ─── Session State & Setup ─────────────────────────────────────────────

    trustedHandle('start-session-setup', async (event) => {
        try {
            return await startSessionSetupHandlerCore({
                event,
                deps: createProcessControlHandlerDeps()
            })
        } catch (err) {
            return { success: false, error: err.message }
        }
    })

    trustedHandle('has-active-browser-session', async () => {
        try {
            return { success: true, active: hasActiveBrowserSession() }
        } catch (err) {
            return { success: false, active: false, error: err.message }
        }
    })

    const saveSessionCaptureResult = async ({
        input = {},
        capture,
        requireActiveSession = false,
        allowNewVaultPassword = true
    }) => {
        const vaultPath = getVaultPath()
        const vaultExists = existsSync(vaultPath)

        return saveCapturedSessionToVault({
            input,
            vaultExists,
            activeMasterPassword: activeMasterPasswordBuffer ? activeMasterPasswordBuffer.toString('utf-8') : '',
            capture,
            requireActiveSession,
            allowNewVaultPassword,
            readVault: () => JSON.parse(readFileSync(vaultPath, 'utf-8')),
            decryptVault: decrypt,
            encryptVault: (payload, masterPassword, driveInfo) => encrypt(payload, masterPassword, driveInfo.driveType === 3),
            writeVault: (encryptedVault) => {
                if (vaultExists) {
                    try { execSync(`attrib -H -R "${vaultPath}"`) } catch (_) { }
                }
                writeJsonFileAtomic(vaultPath, encryptedVault)
            },
            getDriveInfo,
            loadMeta: loadVaultMeta,
            saveMeta: saveVaultMeta,
            mergeMeta: mergeLaunchCapabilitiesIntoMeta,
            authorizeWorkspaceLaunchCapabilities,
            honeyToken: HONEY_TOKEN,
            validateInput: validateCaptureSessionInput,
            validateWorkspace: (workspace) => workspace
        })
    }

    trustedHandle('capture-session', async (_, input = {}) => {
        try {
            return await saveSessionCaptureResult({
                input,
                capture: captureSession
            })
        } catch (err) {
            console.error('Failed to capture session:', err)
            return { success: false, error: err.message }
        }
    })

    // ─── Session Edit (opens browser with saved tabs) ────────────────────
    trustedHandle('start-session-edit', async (event) => {
        try {
            return await startSessionEditHandlerCore({
                event,
                deps: createProcessControlHandlerDeps()
            })
        } catch (err) {
            return { success: false, error: err.message }
        }
    })

    // ─── Save Current Session (without closing browser) ──────────────────
    trustedHandle('save-current-session', async () => {
        try {
            return await saveSessionCaptureResult({
                capture: captureCurrentSession,
                requireActiveSession: true,
                allowNewVaultPassword: false
            })
        } catch (err) {
            return { success: false, error: err.message }
        }
    })

    // ─── Quit & Relaunch ─────────────────────────────────────────────────
    trustedHandle('quit-and-relaunch', async (_, input = {}) => {
        try {
            return await quitAndRelaunchHandlerCore({
                input,
                deps: createProcessControlHandlerDeps()
            })
        } catch (err) {
            return { success: false, error: err.message }
        }
    })

    // ─── Close Desktop Apps ──────────────────────────────────────────────
    trustedHandle('close-desktop-apps', async () => {
        return closeDesktopAppsHandlerCore({
            deps: createProcessControlHandlerDeps()
        })
    })

    // ─── Launch Workspace Engine ─────────────────────────────────────────
    trustedHandle('launch-workspace', async (event) => {
        try {
            const win = BrowserWindow.fromWebContents(event.sender)
            const vaultWorkspace = loadActiveVaultWorkspace()
            const authorized = authorizeWorkspaceLaunchCapabilities(vaultWorkspace, {
                existingMeta: loadVaultMeta(),
                existingWorkspace: vaultWorkspace
            })
            await persistMigratedWorkspaceIfChanged(
                authorized.workspace,
                activeMasterPasswordBuffer.toString('utf-8'),
                authorized
            )
            const safeWorkspace = rehydrateWorkspaceLaunchCapabilities(authorized.workspace, {
                capabilityVault: authorized.capabilityVault,
                manifestResolver: readMigrationManifest
            })

            // Phase 12: Dynamically resolve [USB] portable macros back into absolute paths
            if (safeWorkspace && safeWorkspace.desktopApps) {
                safeWorkspace.desktopApps = safeWorkspace.desktopApps.map(app => {
                    if (app.path && app.path.startsWith('[USB]')) {
                        return { ...app, path: app.path.replace('[USB]', vaultDir) }
                    }
                    return app
                })
            }

            // Phase 16: Fire-and-forget — the ENTIRE sequence (close previous + launch new)
            // runs asynchronously so the IPC response is instant and the UI stays responsive.
            const doLaunch = async () => {
                beginDiagnosticsCycle('launch')
                await closeBrowser()
                await closeDesktopApps()
                const launchWorkspaceConfig = {
                    ...safeWorkspace,
                    desktopApps: (safeWorkspace.desktopApps || []).map((desktopApp) => {
                        try {
                            if (['host-folder', 'registry-uninstall', 'app-paths', 'start-menu-shortcut', 'shell-execute', 'protocol-uri', 'packaged-app'].includes(desktopApp?.launchSourceType)) {
                                return desktopApp
                            }
                            const repair = repairLegacyAppConfig(desktopApp, vaultDir)
                            return {
                                ...repair.appConfig,
                                ...(repair.manifest ? { manifest: repair.manifest } : {})
                            }
                        } catch (err) {
                            diagError('app-legacy-repair', `${desktopApp.name || desktopApp.path}: ${err.message}`)
                            return desktopApp
                        }
                    })
                }
                launchWorkspaceConfig.desktopApps = await Promise.all((launchWorkspaceConfig.desktopApps || []).map(async (desktopApp) => {
                    if (!['host-folder', 'registry-uninstall', 'app-paths', 'start-menu-shortcut', 'shell-execute', 'protocol-uri', 'packaged-app'].includes(desktopApp?.launchSourceType)) return desktopApp
                    try {
                        if (desktopApp.launchSourceType === 'host-folder') {
                            return desktopApp
                        }
                        if (desktopApp.launchSourceType === 'registry-uninstall') {
                            return await resolveRegistryUninstallLaunchReference(desktopApp)
                        }
                        if (desktopApp.launchSourceType === 'app-paths') {
                            return await resolveAppPathsLaunchReference(desktopApp)
                        }
                        if (desktopApp.launchSourceType === 'start-menu-shortcut') {
                            return await resolveStartMenuShortcutLaunchReference(desktopApp)
                        }
                        if (desktopApp.launchSourceType === 'shell-execute') {
                            return await resolveShellExecuteLaunchReference(desktopApp)
                        }
                        if (desktopApp.launchSourceType === 'protocol-uri') {
                            return await resolveProtocolUriLaunchReference(desktopApp)
                        }
                        return await resolvePackagedAppLaunchReference(desktopApp)
                    } catch (err) {
                        diagError('host-launch-resolve', `${desktopApp.name || desktopApp.path}: ${err.message}`)
                        return {
                            ...desktopApp,
                            ...resolveHostLaunchFailureSupportFields(desktopApp, 'missing-on-this-PC'),
                            hostResolution: {
                                status: 'missing-on-this-PC',
                                reason: err.message,
                                resolvedAt: Date.now()
                            }
                        }
                    }
                }))

                return launchWorkspace(launchWorkspaceConfig, (statusMsg) => {
                    if (win && !win.isDestroyed()) {
                        win.webContents.send('launch-status', statusMsg)
                    }
                }, vaultDir, { skipDiagnosticsCycle: true })
            }

            doLaunch().then((results) => {
                if (win && !win.isDestroyed()) {
                    win.webContents.send('launch-complete', { success: true, results })
                }
            }).catch((err) => {
                diagError('launch-workspace', err.message)
                if (win && !win.isDestroyed()) {
                    win.webContents.send('launch-complete', { success: false, error: err.message })
                }
            })

            // Return immediately — status updates come via 'launch-status' events
            return { success: true }
        } catch (err) {
            return { success: false, error: err.message }
        }
    })

    // ─── Window Controls ─────────────────────────────────────────────────
    trustedHandle('close-window', () => {
        return closeWindowHandlerCore({
            deps: createProcessControlHandlerDeps()
        })
    })

    trustedHandle('minimize-window', () => {
        const win = BrowserWindow.getFocusedWindow()
        if (win) win.minimize()
    })

    // ─── Import Close Guard ─────────────────────────────────────────────
    trustedOn('import-started', (event) => {
        importInProgress = true
    })

    trustedOn('import-finished', (event) => {
        importInProgress = false
    })
}

// ─── Import Guard State ────────────────────────────────────────────────────────
let importInProgress = false
let electronSecurityHandlersInstalled = false

function normalizeRendererTrustUrl(value) {
    try {
        const parsed = new URL(String(value || ''))
        parsed.hash = ''
        return parsed.toString()
    } catch (_) {
        return ''
    }
}

function installElectronSecurityHandlers() {
    if (electronSecurityHandlersInstalled) return
    electronSecurityHandlersInstalled = true
    session.defaultSession.setPermissionRequestHandler((_webContents, _permission, callback) => callback(false))
    app.on('web-contents-created', (_event, contents) => {
        if (typeof contents.setWindowOpenHandler === 'function') {
            contents.setWindowOpenHandler(() => ({ action: 'deny' }))
        }
    })
}

// ─── Window Creation ───────────────────────────────────────────────────────────
function createWindow() {
    const mainWindow = new BrowserWindow({
        width: 480,
        height: 640,
        resizable: false,
        frame: false,
        transparent: false,
        backgroundColor: '#1a1a24',

        show: false,
        webPreferences: {
            preload: join(__dirname, '../preload/index.js'),
            sandbox: true,
            contextIsolation: true,
            nodeIntegration: false
        }
    })

    const devRendererUrl = !app.isPackaged ? process.env['ELECTRON_RENDERER_URL'] : ''
    const rendererIndexPath = join(__dirname, '../renderer/index.html')
    const expectedRendererUrl = devRendererUrl || pathToFileURL(rendererIndexPath).toString()
    configureTrustedIpcRenderer({
        urls: [expectedRendererUrl],
        webContentsId: mainWindow.webContents.id
    })

    mainWindow.webContents.setWindowOpenHandler(() => ({ action: 'deny' }))
    mainWindow.webContents.on('will-navigate', (event, navigationUrl) => {
        if (normalizeRendererTrustUrl(navigationUrl) !== normalizeRendererTrustUrl(expectedRendererUrl)) {
            event.preventDefault()
        }
    })

    mainWindow.once('ready-to-show', () => {
        mainWindow.show()
    })

    // Import close guard — prevent accidental close during import
    mainWindow.on('close', (e) => {
        if (importInProgress) {
            e.preventDefault()
            dialog.showMessageBox(mainWindow, {
                type: 'warning',
                title: 'Import in Progress',
                message: 'An app import is currently in progress.',
                detail: 'Closing now may corrupt the imported files. Are you sure you want to close?',
                buttons: ['Keep Open', 'Close Anyway'],
                defaultId: 0,
                cancelId: 0
            }).then(({ response }) => {
                if (response === 1) {
                    importInProgress = false
                    mainWindow.close()
                }
            })
        }
    })

    if (devRendererUrl) {
        mainWindow.loadURL(devRendererUrl)
    } else {
        mainWindow.loadFile(rendererIndexPath)
    }



    return mainWindow
}

// ─── App Lifecycle ─────────────────────────────────────────────────────────────

function setupKillCord() {
    const checkYank = async () => {
        const driveInfo = await getDriveInfo()
        if (driveInfo.isRemovable && !existsSync(getVaultDir())) {
            // Nuke it — wipe credentials + local traces
            // USB is GONE — never attempt sync, only kill + wipe
            setActiveMasterPassword(null)
            emergencyKillDesktopAppsSync()
            // Phase 14: Wipe local Chrome profile + Electron temp traces
            try { wipeLocalTraces(getVaultDir()) } catch (_) { }
            // Kill cord = security emergency: ALWAYS wipe everything
            try { wipeAllLocalAppData() } catch (_) { }
            try { wipeAllRuntimeAppProfiles({ staleOnly: true }) } catch (_) { }
            try { wipeLocalAppCache() } catch (_) { }
            try { require('fs').rmSync(tmpPath, { recursive: true, force: true }) } catch (_) { }
            process.exit(1)
        }
    }

    try {
        const { usb } = require('usb')
        const usbListener = () => checkYank()
        usb.on('detach', usbListener)
    } catch (_) { }

    setInterval(checkYank, 1000)
}

// Phase 14: Redirect Electron temp to LOCAL PC (not USB) to avoid USB I/O
const tmpPath = join(require('os').tmpdir(), 'QuickPass-electron')
if (!existsSync(tmpPath)) {
    try { require('fs').mkdirSync(tmpPath, { recursive: true }) } catch (_) { }
}
app.setPath('userData', join(tmpPath, 'electron-user-data'))
app.setPath('temp', join(tmpPath, 'electron-temp'))

app.whenReady().then(() => {
    runDiagnostics.machineId = crypto.createHash('sha256')
        .update(`${os.hostname()}:${os.userInfo().username}`)
        .digest('hex')
        .slice(0, 16)
    runDiagnostics.osVersion = os.release()
    runDiagnostics.startTime = Date.now()

    installElectronSecurityHandlers()
    registerIpcHandlers()
    createWindow()
    setupKillCord()

    app.on('activate', () => {
        if (BrowserWindow.getAllWindows().length === 0) createWindow()
    })
})

// Phase 14: before-quit with try/finally — guarantees profile sync + cleanup
let isQuitting = false
app.on('before-quit', async (e) => {
    await beforeQuitLifecycleCleanupCore({
        event: e,
        state: {
            get isQuitting() {
                return isQuitting
            },
            set isQuitting(value) {
                isQuitting = value
            }
        },
        deps: createProcessControlHandlerDeps()
    })
})

// Belt-and-suspenders: wipe ALL traces on ANY exit path (including kill cord crash)
process.on('exit', () => {
    const fs = require('fs')
    // Wipe Electron temp
    try { fs.rmSync(tmpPath, { recursive: true, force: true }) } catch (_) { }
    // Wipe ALL QuickPass Chrome profiles (wildcard — no dependency on vault dir)
    wipeAllLocalProfiles()
    // ALWAYS wipe auth tokens/profiles — these must never persist on host PCs
    wipeAllLocalAppData()
    wipeAllRuntimeAppProfiles({ staleOnly: true })
    // Only wipe app BINARY cache if clearCacheOnExit toggle is ON (default: true)
    try {
        const meta = loadVaultMeta()
        const shouldClear = !meta || meta.clearCacheOnExit !== false
        if (shouldClear) wipeLocalAppCache()
    } catch (_) {
        wipeLocalAppCache() // If we can't read meta, wipe for safety
    }
})

app.on('window-all-closed', () => {
    app.quit()
})

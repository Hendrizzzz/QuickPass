import { app, BrowserWindow, ipcMain, dialog } from 'electron'
import { join, basename } from 'path'
import { existsSync, readFileSync, writeFileSync, readdirSync, statSync, mkdirSync, rmSync } from 'fs'
import { execSync, spawn, exec } from 'child_process'
import os from 'os'
import util from 'util'
const execAsync = util.promisify(exec)
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
    pickSupportFields,
    repairLegacyAppConfig,
    resolveImportedAppDataCapability,
    resolveManifestSupportFields,
    safeAppName,
    selectBestExecutable,
    writeAppManifest
} from './appManifest.js'
import {
    findStaleUnsupportedAppDataPayloads,
    isSafePayloadDirectory,
    selectStaleAppDataPayloads
} from './staleAppData.js'

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

    try {
        let serialNumber = 'UNKNOWN'
        
        try {
            const { stdout } = await execAsync(`vol ${driveLetter}`, { encoding: 'utf-8' })
            const lines = stdout.trim().split('\n')
            const serialLine = lines.find(l => l.toLowerCase().includes('serial number'))
            if (serialLine) {
                serialNumber = serialLine.split(' ').pop().trim()
            }
        } catch (_) {}

        cachedDriveInfo = {
            driveLetter,
            isRemovable: true, // Always assume removable for the portable build to allow PIN
            serialNumber,
            driveType: 2 // Treat as removable
        }
        return cachedDriveInfo
    } catch (e) {
        cachedDriveInfo = { driveLetter, isRemovable: true, serialNumber: 'UNKNOWN', driveType: 2 }
        return cachedDriveInfo
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

// ─── Vault Metadata ────────────────────────────────────────────────────────────
function getMetaPath() {
    return join(getVaultDir(), 'vault.meta.json')
}

function saveVaultMeta(meta) {
    const metaPath = getMetaPath()
    if (existsSync(metaPath)) {
        try { execSync(`attrib -H -R "${metaPath}"`) } catch (_) { }
    }
    writeFileSync(metaPath, JSON.stringify(meta, null, 2), 'utf-8')
    try { execSync(`attrib +H "${metaPath}"`) } catch (_) { }
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

// ─── Cryptographic Memory Buffer ───────────────────────────────────────────────
let activeMasterPasswordBuffer = null

function setActiveMasterPassword(password) {
    if (!password) {
        if (activeMasterPasswordBuffer) activeMasterPasswordBuffer.fill(0)
        activeMasterPasswordBuffer = null
    } else {
        if (activeMasterPasswordBuffer) activeMasterPasswordBuffer.fill(0)
        activeMasterPasswordBuffer = Buffer.from(password, 'utf-8')
    }
}

// ─── IPC Handlers ──────────────────────────────────────────────────────────────
function registerIpcHandlers() {

    ipcMain.handle('get-drive-info', async () => await getDriveInfo())
    ipcMain.handle('vault-exists', () => existsSync(getVaultPath()))
    ipcMain.handle('load-vault-meta', () => loadVaultMeta())

    ipcMain.handle('factory-reset', () => {
        try {
            const paths = [getVaultPath(), getMetaPath(), getStatePath()]
            for (const p of paths) {
                if (existsSync(p)) {
                    try { execSync(`attrib -H -R "${p}"`) } catch (_) { }
                    require('fs').unlinkSync(p)
                }
            }
            return { success: true }
        } catch (e) {
            return { success: false, error: e.message }
        }
    })

    ipcMain.handle('save-workspace', async (_, workspace) => {
        try {
            if (!activeMasterPasswordBuffer) throw new Error('Session is locked')

            const payload = { ...workspace, _honeyToken: HONEY_TOKEN }
            const driveInfo = await getDriveInfo()
            const encryptedVault = encrypt(payload, activeMasterPasswordBuffer.toString('utf-8'), driveInfo.driveType === 3)

            if (existsSync(getVaultPath())) {
                try { execSync(`attrib -H -R "${getVaultPath()}"`) } catch (_) { }
            }
            writeFileSync(getVaultPath(), JSON.stringify(encryptedVault, null, 2), 'utf-8')
            try { execSync(`attrib +H "${getVaultPath()}"`) } catch (_) { }

            return { success: true }
        } catch (e) {
            return { success: false, error: e.message }
        }
    })

    ipcMain.handle('save-vault', async (_, { masterPassword, pin, fastBoot, workspace }) => {
        try {
            const driveInfo = await getDriveInfo()

            const payload = { ...workspace, _honeyToken: HONEY_TOKEN }
            const encryptedVault = encrypt(payload, masterPassword, driveInfo.driveType === 3)

            if (existsSync(getVaultPath())) {
                try { execSync(`attrib -H -R "${getVaultPath()}"`) } catch (_) { }
            }

            writeFileSync(getVaultPath(), JSON.stringify(encryptedVault, null, 2), 'utf-8')
            try { execSync(`attrib +H "${getVaultPath()}"`) } catch (_) { }

            const meta = {
                version: '1.0.0',
                createdOn: driveInfo.serialNumber,
                isRemovable: driveInfo.isRemovable,
                fastBoot: fastBoot || false
            }

            if (driveInfo.isRemovable && pin) {
                const pinKey = pin + ':' + driveInfo.serialNumber
                const encryptedMasterPw = encrypt({ masterPassword }, pinKey)
                meta.pinVault = encryptedMasterPw
                meta.hasPIN = true
            } else {
                meta.hasPIN = false
            }

            if (driveInfo.isRemovable && fastBoot) {
                const serialKey = 'FASTBOOT:' + driveInfo.serialNumber
                const encryptedMasterPw = encrypt({ masterPassword }, serialKey)
                meta.fastBootVault = encryptedMasterPw
            }

            saveVaultMeta(meta)

            // Cache the active master password so that subsequent actions 
            // (like secondary PIN/FastBoot toggles or Workspace edits) process correctly without requiring restart
            setActiveMasterPassword(masterPassword)

            return { success: true }
        } catch (e) {
            return { success: false, error: e.message }
        }
    })

    // --- Isolated Security Handlers ---
    ipcMain.handle('update-pin', async (_, newPin) => {
        try {
            if (!activeMasterPasswordBuffer) throw new Error('Session locked')
            const driveInfo = await getDriveInfo()
            if (!driveInfo.isRemovable) throw new Error('PIN only supported on removable drives')

            let meta = loadVaultMeta() || { version: '1.0.0', createdOn: driveInfo.serialNumber, isRemovable: true }

            if (newPin) {
                const pinKey = newPin + ':' + driveInfo.serialNumber
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

    ipcMain.handle('update-fastboot', async (_, enable) => {
        try {
            if (!activeMasterPasswordBuffer) throw new Error('Session locked')
            const driveInfo = await getDriveInfo()
            if (!driveInfo.isRemovable) throw new Error('FastBoot only supported on removable drives')

            let meta = loadVaultMeta() || { version: '1.0.0', createdOn: driveInfo.serialNumber, isRemovable: true }

            if (enable) {
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
    ipcMain.handle('update-clear-cache', async (_, enable) => {
        try {
            let meta = loadVaultMeta() || { version: '1.0.0' }
            meta.clearCacheOnExit = enable
            saveVaultMeta(meta)
            return { success: true }
        } catch (e) {
            return { success: false, error: e.message }
        }
    })

    ipcMain.handle('unlock-with-pin', async (_, pin) => {
        try {
            const meta = loadVaultMeta()
            if (!meta || !meta.hasPIN || !meta.pinVault) {
                return { success: false, error: 'PIN not configured' }
            }

            const driveInfo = await getDriveInfo()

            if (meta.createdOn !== driveInfo.serialNumber) {
                return {
                    success: false,
                    error: 'HARDWARE_MISMATCH',
                    message: 'Hardware change detected. PIN disabled. Enter your Master Password.'
                }
            }

            const pinKey = pin + ':' + driveInfo.serialNumber
            const { masterPassword } = decrypt(meta.pinVault, pinKey)

            const encryptedVault = JSON.parse(readFileSync(getVaultPath(), 'utf-8'))
            let workspace = decrypt(encryptedVault, masterPassword)

            // Remove honey token before sending to frontend
            if (workspace._honeyToken) delete workspace._honeyToken

            // Cache the actual master password for future localized state saves / setting updates
            setActiveMasterPassword(masterPassword)

            return { success: true, workspace }
        } catch (e) {
            return { success: false, error: 'Invalid PIN' }
        }
    })

    ipcMain.handle('unlock-with-password', (_, password) => {
        try {
            const encryptedVault = JSON.parse(readFileSync(getVaultPath(), 'utf-8'))
            let workspace = decrypt(encryptedVault, password)

            if (workspace._honeyToken) delete workspace._honeyToken

            // Cache the actual master password for future localized state saves / setting updates
            setActiveMasterPassword(password)

            return { success: true, workspace }
        } catch (e) {
            return { success: false, error: 'Invalid password' }
        }
    })

    ipcMain.handle('try-fast-boot', async () => {
        try {
            const meta = loadVaultMeta()
            if (!meta || !meta.fastBoot || !meta.fastBootVault) {
                return { success: false }
            }

            const driveInfo = await getDriveInfo()
            if (meta.createdOn !== driveInfo.serialNumber) {
                return { success: false }
            }

            const serialKey = 'FASTBOOT:' + driveInfo.serialNumber
            const { masterPassword } = decrypt(meta.fastBootVault, serialKey)

            const encryptedVault = JSON.parse(readFileSync(getVaultPath(), 'utf-8'))
            let workspace = decrypt(encryptedVault, masterPassword)

            if (workspace._honeyToken) delete workspace._honeyToken

            // Store the master password for session state encryption
            setActiveMasterPassword(masterPassword)

            return { success: true, workspace }
        } catch (e) {
            return { success: false }
        }
    })

    ipcMain.handle('browse-exe', async () => {
        const result = await dialog.showOpenDialog({
            properties: ['openFile'],
            filters: [{ name: 'Executables', extensions: ['exe', 'bat', 'cmd'] }]
        })
        if (result.canceled) return null

        const vaultDir = getVaultDir()
        if (result.filePaths[0].startsWith(vaultDir)) {
            return result.filePaths[0].replace(vaultDir, '[USB]')
        }
        return result.filePaths[0]
    })

    ipcMain.handle('browse-folder', async () => {
        const result = await dialog.showOpenDialog({
            properties: ['openDirectory']
        })
        if (result.canceled) return null

        const vaultDir = getVaultDir()
        if (result.filePaths[0].startsWith(vaultDir)) {
            return result.filePaths[0].replace(vaultDir, '[USB]')
        }
        return result.filePaths[0]
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

    ipcMain.handle('scan-stale-appdata', async () => {
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

    ipcMain.handle('cleanup-stale-appdata', async (_, { payloadIds } = {}) => {
        try {
            if (!Array.isArray(payloadIds) || payloadIds.length === 0) {
                throw new Error('Select at least one AppData payload to remove.')
            }

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

    ipcMain.handle('scan-apps', async () => {
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

            const alreadyImported = existsSync(join(appsDir, name)) ||
                existsSync(join(appsDir, `${name}.tar.zst`)) ||
                existsSync(join(appsDir, `${safeAppName(name)}.quickpass-app.json`))

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

                    const alreadyImported = existsSync(join(appsDir, name)) ||
                        existsSync(join(appsDir, `${name}.tar.zst`)) ||
                        existsSync(join(appsDir, `${safeAppName(name)}.quickpass-app.json`))

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

    ipcMain.handle('import-app', async (event, { sourcePath, name, exe, relativeExePath, importData, dataPath, sizeMB, dataSizeMB }) => {
        const win = BrowserWindow.fromWebContents(event.sender)
        const vaultDir = getVaultDir()
        // Phase 17.2: Sanitize AppData folder name to match engine.js launch path
        const safeName = safeAppName(name)
        const dataDest = join(vaultDir, 'AppData', safeName)
        // Fix 1: Hoist tempArchive so catch block can clean it up on failure
        const tempArchive = join(os.tmpdir(), `omnilaunch-import-${name}-${Date.now()}.tar.zst`)

        try {
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

            const archiveName = `${name}.tar.zst`
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
                legacyPath: `[USB]\\Apps\\${name}\\${exePathInApp}`,
                requiredFiles
            })
            writeAppManifest(vaultDir, manifest)

            return {
                success: true,
                appConfig: {
                    name,
                    // Store the ORIGINAL relative exe path — launch flow will handle extraction
                    path: `[USB]\\Apps\\${name}\\${exePathInApp}`,
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
            try { require('fs').unlinkSync(tempArchive) } catch (_) {}
            return { success: false, error: err.message }
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

    ipcMain.handle('set-master-password', (_, password) => {
        setActiveMasterPassword(password)
        return { success: true }
    })

    ipcMain.handle('start-session-setup', async (event) => {
        try {
            beginDiagnosticsCycle('setup')
            await closeBrowser()
            await closeDesktopApps()

            const win = BrowserWindow.fromWebContents(event.sender)
            const vaultDir = getVaultDir()

            // Register disconnect callback BEFORE launching
            // This fires when the user closes all Chrome windows
            onBrowserAllClosed(() => {
                if (win && !win.isDestroyed()) {
                    win.webContents.send('browser-disconnected')
                }
            })

            // Phase 13: Pass vaultDir for persistent Chrome profile on USB
            const result = await launchSessionSetup((statusMsg) => {
                if (win && !win.isDestroyed()) {
                    win.webContents.send('launch-status', statusMsg)
                }
            }, vaultDir, [], { skipDiagnosticsCycle: true })

            return result
        } catch (err) {
            return { success: false, error: err.message }
        }
    })

    ipcMain.handle('has-active-browser-session', async () => {
        try {
            return { success: true, active: hasActiveBrowserSession() }
        } catch (err) {
            return { success: false, active: false, error: err.message }
        }
    })

    ipcMain.handle('capture-session', async (_, { masterPassword: pw }) => {
        try {
            const mp = pw || (activeMasterPasswordBuffer ? activeMasterPasswordBuffer.toString('utf-8') : null)
            if (!mp) return { success: false, error: 'No master password available' }

            const result = await captureSession()
            if (!result.success) return result

            // Save the captured URLs into the vault workspace
            // Phase 13: No longer saving cookies to vault.state.json —
            // persistent Chrome profile on USB handles all auth data
            const vaultPath = getVaultPath()
            if (existsSync(vaultPath)) {
                try { execSync(`attrib -H -R "${vaultPath}"`) } catch (_) { }
            }

            // Load existing vault and update webTabs with captured URLs
            let workspace = { webTabs: [], desktopApps: [] }
            try {
                const encryptedVault = JSON.parse(readFileSync(vaultPath, 'utf-8'))
                workspace = decrypt(encryptedVault, mp)
                if (workspace._honeyToken) delete workspace._honeyToken
            } catch (_) { }

            // Replace webTabs with captured URLs
            workspace.webTabs = result.urls.map(url => ({ url, enabled: true }))

            const payload = { ...workspace, _honeyToken: HONEY_TOKEN }

            // Re-encrypt and save the vault
            const driveInfo = await getDriveInfo()
            const encryptedVault = encrypt(payload, mp, driveInfo.driveType === 3)
            writeFileSync(vaultPath, JSON.stringify(encryptedVault, null, 2), 'utf-8')
            try { execSync(`attrib +H "${vaultPath}"`) } catch (_) { }

            return {
                success: true,
                tabCount: result.tabCount,
                urls: result.urls,
                skippedUrls: result.skippedUrls || [],
                skippedCount: result.skippedCount || 0
            }
        } catch (err) {
            console.error('Failed to capture session:', err)
            return { success: false, error: err.message }
        }
    })

    // ─── Session Edit (opens browser with saved tabs) ────────────────────
    ipcMain.handle('start-session-edit', async (event) => {
        try {
            beginDiagnosticsCycle('edit')
            await closeBrowser()
            await closeDesktopApps()

            const win = BrowserWindow.fromWebContents(event.sender)
            const mp = activeMasterPasswordBuffer ? activeMasterPasswordBuffer.toString('utf-8') : null
            if (!mp) return { success: false, error: 'No master password' }

            const vaultDir = getVaultDir()

            // Phase 13: No longer loading savedState (cookies) —
            // persistent Chrome profile handles auth. Only load URLs.
            let urls = []
            try {
                const vaultPath = getVaultPath()
                if (existsSync(vaultPath)) {
                    const encrypted = JSON.parse(readFileSync(vaultPath, 'utf-8'))
                    const workspace = decrypt(encrypted, mp)
                    urls = (workspace.webTabs || []).filter(t => t.enabled).map(t => t.url)
                }
            } catch (_) { }

            // Register disconnect callback
            onBrowserAllClosed(() => {
                if (win && !win.isDestroyed()) {
                    win.webContents.send('browser-disconnected')
                }
            })

            // Phase 13: Pass vaultDir for persistent profile, urls for tab restoration
            const result = await launchSessionSetup((statusMsg) => {
                if (win && !win.isDestroyed()) {
                    win.webContents.send('launch-status', statusMsg)
                }
            }, vaultDir, urls, { skipDiagnosticsCycle: true })

            return result
        } catch (err) {
            return { success: false, error: err.message }
        }
    })

    // ─── Save Current Session (without closing browser) ──────────────────
    ipcMain.handle('save-current-session', async () => {
        try {
            const mp = activeMasterPasswordBuffer ? activeMasterPasswordBuffer.toString('utf-8') : null
            if (!mp) return { success: false, error: 'No master password' }

            const result = await captureCurrentSession()
            if (!result.success) return result

            // Phase 13: Save URLs only — persistent Chrome profile handles auth
            const vaultPath = getVaultPath()
            if (existsSync(vaultPath)) {
                try { execSync(`attrib -H -R "${vaultPath}"`) } catch (_) { }
            }

            let workspace = { webTabs: [], desktopApps: [] }
            try {
                const encryptedVault = JSON.parse(readFileSync(vaultPath, 'utf-8'))
                workspace = decrypt(encryptedVault, mp)
                if (workspace._honeyToken) delete workspace._honeyToken
            } catch (_) { }

            workspace.webTabs = result.urls.map(url => ({ url, enabled: true }))

            const payload = { ...workspace, _honeyToken: HONEY_TOKEN }
            const driveInfo = await getDriveInfo()
            const encryptedVault = encrypt(payload, mp, driveInfo.driveType === 3)

            writeFileSync(vaultPath, JSON.stringify(encryptedVault, null, 2), 'utf-8')
            try { execSync(`attrib +H "${vaultPath}"`) } catch (_) { }

            return {
                success: true,
                tabCount: result.tabCount,
                urls: result.urls,
                skippedUrls: result.skippedUrls || [],
                skippedCount: result.skippedCount || 0
            }
        } catch (err) {
            return { success: false, error: err.message }
        }
    })

    // ─── Quit & Relaunch ─────────────────────────────────────────────────
    ipcMain.handle('quit-and-relaunch', async (_, { closeApps = false } = {}) => {
        try {
            await closeBrowser()
            if (closeApps) await closeDesktopApps()

            app.quit()

            return { success: true }
        } catch (err) {
            return { success: false, error: err.message }
        }
    })

    // ─── Close Desktop Apps ──────────────────────────────────────────────
    ipcMain.handle('close-desktop-apps', async () => {
        await closeDesktopApps()
        return { success: true }
    })

    // ─── Launch Workspace Engine ─────────────────────────────────────────
    ipcMain.handle('launch-workspace', (event, workspace) => {
        try {
            const win = BrowserWindow.fromWebContents(event.sender)

            // Phase 12: Dynamically resolve [USB] portable macros back into absolute paths
            const vaultDir = getVaultDir()
            if (workspace && workspace.desktopApps) {
                workspace.desktopApps = workspace.desktopApps.map(app => {
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
                    ...workspace,
                    desktopApps: (workspace.desktopApps || []).map((desktopApp) => {
                        try {
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
    ipcMain.handle('close-window', () => {
        const win = BrowserWindow.getFocusedWindow()
        if (win) win.close()
    })

    ipcMain.handle('minimize-window', () => {
        const win = BrowserWindow.getFocusedWindow()
        if (win) win.minimize()
    })

    // ─── Import Close Guard ─────────────────────────────────────────────
    ipcMain.on('import-started', (event) => {
        importInProgress = true
    })

    ipcMain.on('import-finished', (event) => {
        importInProgress = false
    })
}

// ─── Import Guard State ────────────────────────────────────────────────────────
let importInProgress = false

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
            sandbox: false,
            contextIsolation: true,
            nodeIntegration: false
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

    if (process.env['ELECTRON_RENDERER_URL']) {
        mainWindow.loadURL(process.env['ELECTRON_RENDERER_URL'])
    } else {
        mainWindow.loadFile(join(__dirname, '../renderer/index.html'))
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
    if (isQuitting) return
    e.preventDefault()

    try {
        // Sync Chrome profile back to USB + wipe local copy
        await closeBrowser()
    } catch (err) {
        console.error('[QuickPass] Profile sync during quit failed:', err)
        diagError('before-quit', err.message)
    } finally {
        // Cryptographic memory wipe
        setActiveMasterPassword(null)
        await closeDesktopApps()
        try { wipeAllRuntimeAppProfiles({ staleOnly: true }) } catch (_) { }
        try {
            const vd = getVaultDir()
            if (existsSync(vd)) {
                writeFileSync(join(vd, 'run-diagnostics.json'), JSON.stringify(runDiagnostics, null, 2), 'utf-8')
            }
        } catch (_) { }
        // Wipe Electron temp traces from local PC
        try { require('fs').rmSync(tmpPath, { recursive: true, force: true }) } catch (_) { }
        isQuitting = true
        app.quit()
    }
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

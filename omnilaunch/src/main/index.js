import { app, BrowserWindow, ipcMain, dialog } from 'electron'
import { join } from 'path'
import { existsSync, readFileSync, writeFileSync } from 'fs'
import { execSync } from 'child_process'
import crypto from 'crypto'
import { launchWorkspace, launchSessionSetup, captureSession, captureCurrentSession, closeBrowser, closeDesktopApps, onBrowserAllClosed } from './engine.js'

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
function getDriveInfo() {
    if (cachedDriveInfo) return cachedDriveInfo

    const vaultDir = getVaultDir()
    const driveLetter = vaultDir.split(':')[0] + ':'

    try {
        // We no longer rely on DriveType=2 because many USBs report as 3 (Local).
        // Since this is distributed as a portable USB app, we will assume it's portable.
        
        let serialNumber = 'UNKNOWN'
        
        // We still need a unique identifier for the PIN feature to detect hardware copies.
        // Doing this asynchronously isn't strictly necessary if it's fast, but WMI can be slow.
        // wmic logicaldisk takes ~1s. We use fs.statSync to get volume serial if possible, 
        // but Node doesn't expose it directly. We'll fallback to a fast cmd:
        const volOutput = execSync(`vol ${driveLetter}`, { encoding: 'utf-8' }).trim()
        const lines = volOutput.split('\n')
        const serialLine = lines.find(l => l.toLowerCase().includes('serial number'))
        if (serialLine) {
            serialNumber = serialLine.split(' ').pop().trim()
        }

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

    ipcMain.handle('get-drive-info', () => getDriveInfo())
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

    ipcMain.handle('save-workspace', (_, workspace) => {
        try {
            if (!activeMasterPasswordBuffer) throw new Error('Session is locked')

            const payload = { ...workspace, _honeyToken: HONEY_TOKEN }
            const encryptedVault = encrypt(payload, activeMasterPasswordBuffer.toString('utf-8'), getDriveInfo().driveType === 3)

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

    ipcMain.handle('save-vault', (_, { masterPassword, pin, fastBoot, workspace }) => {
        try {
            const driveInfo = getDriveInfo()

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
    ipcMain.handle('update-pin', (_, newPin) => {
        try {
            if (!activeMasterPasswordBuffer) throw new Error('Session locked')
            const driveInfo = getDriveInfo()
            if (!driveInfo.isRemovable) throw new Error('PIN only supported on removable drives')

            let meta = loadVaultMeta() || { version: '1.0.0', createdOn: driveInfo.serialNumber, isRemovable: true }

            if (newPin) {
                const pinKey = newPin + ':' + driveInfo.serialNumber
                meta.pinVault = encrypt({ masterPassword: activeMasterPasswordBuffer.toString('utf-8') }, pinKey)
                meta.hasPIN = true
            } else {
                delete meta.pinVault
                meta.hasPIN = false
            }
            saveVaultMeta(meta)
            return { success: true }
        } catch (e) {
            return { success: false, error: e.message }
        }
    })

    ipcMain.handle('update-fastboot', (_, enable) => {
        try {
            if (!activeMasterPasswordBuffer) throw new Error('Session locked')
            const driveInfo = getDriveInfo()
            if (!driveInfo.isRemovable) throw new Error('FastBoot only supported on removable drives')

            let meta = loadVaultMeta() || { version: '1.0.0', createdOn: driveInfo.serialNumber, isRemovable: true }

            if (enable) {
                const serialKey = 'FASTBOOT:' + driveInfo.serialNumber
                meta.fastBootVault = encrypt({ masterPassword: activeMasterPasswordBuffer.toString('utf-8') }, serialKey)
                meta.fastBoot = true
            } else {
                delete meta.fastBootVault
                meta.fastBoot = false
            }
            saveVaultMeta(meta)
            return { success: true }
        } catch (e) {
            return { success: false, error: e.message }
        }
    })

    ipcMain.handle('unlock-with-pin', (_, pin) => {
        try {
            const meta = loadVaultMeta()
            if (!meta || !meta.hasPIN || !meta.pinVault) {
                return { success: false, error: 'PIN not configured' }
            }

            const driveInfo = getDriveInfo()

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

    ipcMain.handle('try-fast-boot', () => {
        try {
            const meta = loadVaultMeta()
            if (!meta || !meta.fastBoot || !meta.fastBootVault) {
                return { success: false }
            }

            const driveInfo = getDriveInfo()
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

    // ─── Session State & Setup ─────────────────────────────────────────────

    ipcMain.handle('set-master-password', (_, password) => {
        setActiveMasterPassword(password)
        return { success: true }
    })

    ipcMain.handle('start-session-setup', async (event) => {
        try {
            await closeBrowser()
            closeDesktopApps()

            const win = BrowserWindow.fromWebContents(event.sender)

            // Register disconnect callback BEFORE launching
            // This fires when the user closes all Chrome windows
            onBrowserAllClosed(() => {
                if (win && !win.isDestroyed()) {
                    win.webContents.send('browser-disconnected')
                }
            })

            const result = await launchSessionSetup((statusMsg) => {
                if (win && !win.isDestroyed()) {
                    win.webContents.send('launch-status', statusMsg)
                }
            })

            return result
        } catch (err) {
            return { success: false, error: err.message }
        }
    })

    ipcMain.handle('capture-session', async (_, { masterPassword: pw }) => {
        try {
            const mp = pw || (activeMasterPasswordBuffer ? activeMasterPasswordBuffer.toString('utf-8') : null)
            if (!mp) return { success: false, error: 'No master password available' }

            const result = await captureSession()
            if (!result.success) return result

            // 1. Save the captured URLs into the vault workspace
            const vaultPath = getVaultPath()
            if (existsSync(vaultPath)) {
                try { execSync(`attrib -H -R "${vaultPath}"`) } catch (_) { }
            }

            // Load existing vault and update webTabs with captured URLs
            let workspace = { webTabs: [], desktopApps: [] }
            try {
                const encryptedVault = JSON.parse(readFileSync(vaultPath, 'utf-8'))
                workspace = decrypt(encryptedVault, mp)
                if (workspace._honeyToken) delete workspace._honeyToken // Remove honey token if present
            } catch (_) { }

            // Replace webTabs with captured URLs
            workspace.webTabs = result.urls.map(url => ({ url, enabled: true }))

            const payload = { ...workspace, _honeyToken: HONEY_TOKEN }

            // Re-encrypt and save the vault
            const encryptedVault = encrypt(payload, mp, getDriveInfo().driveType === 3)
            writeFileSync(vaultPath, JSON.stringify(encryptedVault, null, 2), 'utf-8')
            try { execSync(`attrib +H "${vaultPath}"`) } catch (_) { }

            // 2. Save the session state (cookies) to vault.state.json
            const statePath = getStatePath()
            if (existsSync(statePath)) {
                try { execSync(`attrib -H -R "${statePath}"`) } catch (_) { }
            }

            const encryptedState = encrypt(result.state, mp)
            writeFileSync(statePath, JSON.stringify(encryptedState, null, 2), 'utf-8')
            try { execSync(`attrib +H "${statePath}"`) } catch (_) { }

            return { success: true, tabCount: result.tabCount, urls: result.urls }
        } catch (err) {
            console.error('Failed to capture session:', err)
            return { success: false, error: err.message }
        }
    })

    // ─── Session Edit (opens browser with saved tabs) ────────────────────
    ipcMain.handle('start-session-edit', async (event) => {
        try {
            await closeBrowser()
            closeDesktopApps()

            const win = BrowserWindow.fromWebContents(event.sender)
            const mp = activeMasterPasswordBuffer ? activeMasterPasswordBuffer.toString('utf-8') : null
            if (!mp) return { success: false, error: 'No master password' }

            // Load saved state and URLs
            let savedState = null
            let urls = []

            try {
                const statePath = getStatePath()
                if (existsSync(statePath)) {
                    const encrypted = JSON.parse(readFileSync(statePath, 'utf-8'))
                    savedState = decrypt(encrypted, mp)
                }
            } catch (_) { }

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

            const result = await launchSessionSetup((statusMsg) => {
                if (win && !win.isDestroyed()) {
                    win.webContents.send('launch-status', statusMsg)
                }
            }, savedState, urls)

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

            // Save URLs to vault
            const vaultPath = getVaultPath()
            if (existsSync(vaultPath)) {
                try { execSync(`attrib -H -R "${vaultPath}"`) } catch (_) { }
            }

            let workspace = { webTabs: [], desktopApps: [] }
            try {
                const encryptedVault = JSON.parse(readFileSync(vaultPath, 'utf-8'))
                workspace = decrypt(encryptedVault, mp)
                if (workspace._honeyToken) delete workspace._honeyToken // Remove honey token if present
            } catch (_) { }

            workspace.webTabs = result.urls.map(url => ({ url, enabled: true }))

            const payload = { ...workspace, _honeyToken: HONEY_TOKEN }
            const encryptedVault = encrypt(payload, mp, getDriveInfo().driveType === 3)

            writeFileSync(vaultPath, JSON.stringify(encryptedVault, null, 2), 'utf-8')
            try { execSync(`attrib +H "${vaultPath}"`) } catch (_) { }

            // Save state (cookies) 
            const statePath = getStatePath()
            if (existsSync(statePath)) {
                try { execSync(`attrib -H -R "${statePath}"`) } catch (_) { }
            }
            const encryptedState = encrypt(result.state, mp)
            writeFileSync(statePath, JSON.stringify(encryptedState, null, 2), 'utf-8')
            try { execSync(`attrib +H "${statePath}"`) } catch (_) { }

            return { success: true, tabCount: result.tabCount, urls: result.urls }
        } catch (err) {
            return { success: false, error: err.message }
        }
    })

    // ─── Quit & Relaunch ─────────────────────────────────────────────────
    ipcMain.handle('quit-and-relaunch', async (_, { closeApps = false } = {}) => {
        try {
            await closeBrowser()
            if (closeApps) closeDesktopApps()

            app.quit()

            return { success: true }
        } catch (err) {
            return { success: false, error: err.message }
        }
    })

    // ─── Close Desktop Apps ──────────────────────────────────────────────
    ipcMain.handle('close-desktop-apps', () => {
        closeDesktopApps()
        return { success: true }
    })

    // ─── Launch Workspace Engine ─────────────────────────────────────────
    ipcMain.handle('launch-workspace', async (event, workspace) => {
        try {
            await closeBrowser()
            closeDesktopApps()

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

            // Attempt to load saved session state for cookie injection
            let savedState = null
            try {
                const statePath = getStatePath()
                if (existsSync(statePath) && activeMasterPasswordBuffer) {
                    const encrypted = JSON.parse(readFileSync(statePath, 'utf-8'))
                    savedState = decrypt(encrypted, activeMasterPasswordBuffer.toString('utf-8'))
                }
            } catch (_) {
                // No saved state or decryption failed
            }

            const results = await launchWorkspace(workspace, (statusMsg) => {
                if (win && !win.isDestroyed()) {
                    win.webContents.send('launch-status', statusMsg)
                }
            }, savedState)
            return { success: true, results }
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
            sandbox: false,
            contextIsolation: true,
            nodeIntegration: false
        }
    })

    mainWindow.once('ready-to-show', () => {
        mainWindow.show()
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
    const checkYank = () => {
        const driveInfo = getDriveInfo()
        if (driveInfo.isRemovable && !existsSync(getVaultDir())) {
            // Nuke it
            setActiveMasterPassword(null)
            closeDesktopApps()
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

// Phase 11: Zero Data Persistence - UserData & Temp redirection
const vaultDir = getVaultDir()
const tmpPath = join(vaultDir, '.tmp')
if (!existsSync(tmpPath)) {
    try { require('fs').mkdirSync(tmpPath, { recursive: true }) } catch (_) { }
}
app.setPath('userData', join(tmpPath, 'electron-user-data'))
app.setPath('temp', join(tmpPath, 'electron-temp'))

app.whenReady().then(() => {
    registerIpcHandlers()
    createWindow()
    setupKillCord()

    app.on('activate', () => {
        if (BrowserWindow.getAllWindows().length === 0) createWindow()
    })
})

app.on('will-quit', () => {
    // Phase 11: Cryptographic Memory Wiping
    setActiveMasterPassword(null)
    closeDesktopApps()

    // Phase 11: Cleanup hidden .tmp traces
    try {
        if (existsSync(tmpPath)) {
            const fs = require('fs')
            fs.rmSync(tmpPath, { recursive: true, force: true })
        }
    } catch (_) { }
})

app.on('window-all-closed', () => {
    app.quit()
})

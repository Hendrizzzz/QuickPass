import { app, BrowserWindow, ipcMain, dialog } from 'electron'
import { join } from 'path'
import { existsSync, readFileSync, writeFileSync } from 'fs'
import { execSync } from 'child_process'
import crypto from 'crypto'
import { launchWorkspace, launchSessionSetup, captureSession, captureCurrentSession, closeBrowser, closeDesktopApps, onBrowserAllClosed } from './engine.js'

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
function getDriveInfo() {
    const vaultDir = getVaultDir()
    const driveLetter = vaultDir.split(':')[0] + ':'

    try {
        const driveTypeOutput = execSync(
            `wmic logicaldisk where "DeviceID='${driveLetter}'" get DriveType /format:value`,
            { encoding: 'utf-8' }
        ).trim()

        const serialOutput = execSync(
            `wmic logicaldisk where "DeviceID='${driveLetter}'" get VolumeSerialNumber /format:value`,
            { encoding: 'utf-8' }
        ).trim()

        const driveType = parseInt(driveTypeOutput.split('=')[1]) || 3
        const serialNumber = serialOutput.split('=')[1]?.trim() || 'UNKNOWN'

        return {
            driveLetter,
            isRemovable: driveType === 2,
            serialNumber,
            driveType
        }
    } catch (e) {
        return { driveLetter, isRemovable: false, serialNumber: 'UNKNOWN', driveType: 3 }
    }
}

function getVaultPath() {
    return join(getVaultDir(), 'vault.json')
}

function getStatePath() {
    return join(getVaultDir(), 'vault.state.json')
}

// ─── AES-256-GCM Encryption ────────────────────────────────────────────────────
function deriveKey(password, salt) {
    return crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha512')
}

function encrypt(data, password) {
    const salt = crypto.randomBytes(16)
    const key = deriveKey(password, salt)
    const iv = crypto.randomBytes(12)
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv)

    let encrypted = cipher.update(JSON.stringify(data), 'utf-8', 'hex')
    encrypted += cipher.final('hex')
    const authTag = cipher.getAuthTag()

    return {
        salt: salt.toString('hex'),
        iv: iv.toString('hex'),
        authTag: authTag.toString('hex'),
        data: encrypted
    }
}

function decrypt(encryptedObj, password) {
    const salt = Buffer.from(encryptedObj.salt, 'hex')
    const iv = Buffer.from(encryptedObj.iv, 'hex')
    const authTag = Buffer.from(encryptedObj.authTag, 'hex')
    const key = deriveKey(password, salt)

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

// ─── IPC Handlers ──────────────────────────────────────────────────────────────
function registerIpcHandlers() {
    // Master password held in memory for session state encryption/decryption
    let activeMasterPassword = null

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
            if (!activeMasterPassword) throw new Error('Session is locked')
            const encryptedVault = encrypt(workspace, activeMasterPassword)

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
            const encryptedVault = encrypt(workspace, masterPassword)

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
            activeMasterPassword = masterPassword

            return { success: true }
        } catch (e) {
            return { success: false, error: e.message }
        }
    })

    // --- Isolated Security Handlers ---
    ipcMain.handle('update-pin', (_, newPin) => {
        try {
            if (!activeMasterPassword) throw new Error('Session locked')
            const driveInfo = getDriveInfo()
            if (!driveInfo.isRemovable) throw new Error('PIN only supported on removable drives')

            let meta = loadVaultMeta() || { version: '1.0.0', createdOn: driveInfo.serialNumber, isRemovable: true }

            if (newPin) {
                const pinKey = newPin + ':' + driveInfo.serialNumber
                meta.pinVault = encrypt({ masterPassword: activeMasterPassword }, pinKey)
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
            if (!activeMasterPassword) throw new Error('Session locked')
            const driveInfo = getDriveInfo()
            if (!driveInfo.isRemovable) throw new Error('FastBoot only supported on removable drives')

            let meta = loadVaultMeta() || { version: '1.0.0', createdOn: driveInfo.serialNumber, isRemovable: true }

            if (enable) {
                const serialKey = 'FASTBOOT:' + driveInfo.serialNumber
                meta.fastBootVault = encrypt({ masterPassword: activeMasterPassword }, serialKey)
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
            const workspace = decrypt(encryptedVault, masterPassword)

            // Cache the actual master password for future localized state saves / setting updates
            activeMasterPassword = masterPassword

            return { success: true, workspace }
        } catch (e) {
            return { success: false, error: 'Invalid PIN' }
        }
    })

    ipcMain.handle('unlock-with-password', (_, password) => {
        try {
            const encryptedVault = JSON.parse(readFileSync(getVaultPath(), 'utf-8'))
            const workspace = decrypt(encryptedVault, password)

            // Cache the actual master password for future localized state saves / setting updates
            activeMasterPassword = password

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
            const workspace = decrypt(encryptedVault, masterPassword)

            // Store the master password for session state encryption
            activeMasterPassword = masterPassword

            return { success: true, workspace }
        } catch (e) {
            return { success: false }
        }
    })

    ipcMain.handle('browse-exe', async () => {
        const result = await dialog.showOpenDialog({
            properties: ['openFile'],
            filters: [{ name: 'Executables', extensions: ['exe'] }]
        })
        if (result.canceled) return null
        return result.filePaths[0]
    })

    // ─── Session State & Setup ─────────────────────────────────────────────

    ipcMain.handle('set-master-password', (_, password) => {
        activeMasterPassword = password
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
            const mp = pw || activeMasterPassword
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
            } catch (_) { }

            // Replace webTabs with captured URLs
            workspace.webTabs = result.urls.map(url => ({ url, enabled: true }))

            // Re-encrypt and save the vault
            const encryptedVault = encrypt(workspace, mp)
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
            const mp = activeMasterPassword
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
            const mp = activeMasterPassword
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
            } catch (_) { }

            workspace.webTabs = result.urls.map(url => ({ url, enabled: true }))
            const encryptedVault = encrypt(workspace, mp)
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

            // Attempt to load saved session state for cookie injection
            let savedState = null
            try {
                const statePath = getStatePath()
                if (existsSync(statePath) && activeMasterPassword) {
                    const encrypted = JSON.parse(readFileSync(statePath, 'utf-8'))
                    savedState = decrypt(encrypted, activeMasterPassword)
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
app.whenReady().then(() => {
    registerIpcHandlers()
    createWindow()

    app.on('activate', () => {
        if (BrowserWindow.getAllWindows().length === 0) createWindow()
    })
})

app.on('window-all-closed', () => {
    app.quit()
})

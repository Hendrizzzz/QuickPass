import { app, BrowserWindow, ipcMain, dialog } from 'electron'
import { join } from 'path'
import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'fs'
import { execSync } from 'child_process'
import crypto from 'crypto'
import { launchWorkspace } from './engine.js'

// ─── Drive Detection ───────────────────────────────────────────────────────────
function getDriveInfo() {
    const appPath = app.isPackaged
        ? join(app.getPath('exe'), '..')
        : join(__dirname, '..', '..')
    const driveLetter = appPath.split(':')[0] + ':'

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

// ─── Vault Path Resolution ─────────────────────────────────────────────────────
function getVaultDir() {
    const exeDir = app.isPackaged
        ? join(app.getPath('exe'), '..')
        : join(__dirname, '..', '..')
    return exeDir
}

function getVaultPath() {
    return join(getVaultDir(), 'vault.json')
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
    try {
        writeFileSync(getMetaPath(), JSON.stringify(meta, null, 2), 'utf-8')
        try { execSync(`attrib +H "${getMetaPath()}"`) } catch (_) { }
    } catch (e) {
        console.error('Failed to save vault meta:', e)
    }
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
    ipcMain.handle('get-drive-info', () => getDriveInfo())
    ipcMain.handle('vault-exists', () => existsSync(getVaultPath()))
    ipcMain.handle('load-vault-meta', () => loadVaultMeta())

    ipcMain.handle('save-vault', (_, { masterPassword, pin, fastBoot, workspace }) => {
        try {
            const driveInfo = getDriveInfo()
            const vaultDir = getVaultDir()

            const appsDir = join(vaultDir, 'Apps')
            if (!existsSync(appsDir)) mkdirSync(appsDir, { recursive: true })

            const encryptedVault = encrypt(workspace, masterPassword)

            // Critical File System Fix: Windows blocks `fs.writeFileSync` on files that have the +H (Hidden) attribute.
            // We must temporarily remove the Hidden attribute before overwriting the vault JSON file, then reapply it.
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

            return { success: true, workspace }
        } catch (e) {
            return { success: false, error: 'Invalid PIN' }
        }
    })

    ipcMain.handle('unlock-with-password', (_, password) => {
        try {
            const encryptedVault = JSON.parse(readFileSync(getVaultPath(), 'utf-8'))
            const workspace = decrypt(encryptedVault, password)
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

    // ─── Launch Workspace Engine ─────────────────────────────────────────
    ipcMain.handle('launch-workspace', async (event, workspace) => {
        try {
            const win = BrowserWindow.fromWebContents(event.sender)
            const results = await launchWorkspace(workspace, (statusMsg) => {
                // Send real-time status updates to the renderer
                if (win && !win.isDestroyed()) {
                    win.webContents.send('launch-status', statusMsg)
                }
            })
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

    // Open DevTools in dev mode for debugging
    if (!app.isPackaged) {
        mainWindow.webContents.openDevTools({ mode: 'detach' })
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

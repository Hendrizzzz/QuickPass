import { contextBridge, ipcRenderer } from 'electron'

contextBridge.exposeInMainWorld('omnilaunch', {
    // Drive & Environment
    getDriveInfo: () => ipcRenderer.invoke('get-drive-info'),

    // Vault Operations
    vaultExists: () => ipcRenderer.invoke('vault-exists'),
    loadVaultMeta: () => ipcRenderer.invoke('load-vault-meta'),
    saveVault: (data) => ipcRenderer.invoke('save-vault', data),
    saveWorkspace: (workspace) => ipcRenderer.invoke('save-workspace', workspace),
    factoryReset: () => ipcRenderer.invoke('factory-reset'),

    // Security Modular Updates
    updatePin: (newPin) => ipcRenderer.invoke('update-pin', newPin),
    updateFastBoot: (enable) => ipcRenderer.invoke('update-fastboot', enable),

    // Unlock
    unlockWithPin: (pin) => ipcRenderer.invoke('unlock-with-pin', pin),
    unlockWithPassword: (pw) => ipcRenderer.invoke('unlock-with-password', pw),
    tryFastBoot: () => ipcRenderer.invoke('try-fast-boot'),

    // File Browser
    browseExe: () => ipcRenderer.invoke('browse-exe'),
    browseFolder: () => ipcRenderer.invoke('browse-folder'),

    // Session Setup & Capture
    setMasterPassword: (pw) => ipcRenderer.invoke('set-master-password', pw),
    startSessionSetup: () => ipcRenderer.invoke('start-session-setup'),
    startSessionEdit: () => ipcRenderer.invoke('start-session-edit'),
    captureSession: (data) => ipcRenderer.invoke('capture-session', data),

    // Live Session Management
    saveCurrentSession: () => ipcRenderer.invoke('save-current-session'),
    quitAndRelaunch: (opts) => ipcRenderer.invoke('quit-and-relaunch', opts),
    closeDesktopApps: () => ipcRenderer.invoke('close-desktop-apps'),

    // Automation Engine
    launchWorkspace: (workspace) => ipcRenderer.invoke('launch-workspace', workspace),
    onLaunchStatus: (callback) => {
        ipcRenderer.on('launch-status', (_, msg) => callback(msg))
        return () => ipcRenderer.removeAllListeners('launch-status')
    },
    onBrowserDisconnect: (callback) => {
        ipcRenderer.on('browser-disconnected', () => callback())
        return () => ipcRenderer.removeAllListeners('browser-disconnected')
    },

    // Window Controls
    minimize: () => ipcRenderer.invoke('minimize-window'),
    close: () => ipcRenderer.invoke('close-window')
})

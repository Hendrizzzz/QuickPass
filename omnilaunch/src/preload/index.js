import { contextBridge, ipcRenderer } from 'electron'

contextBridge.exposeInMainWorld('omnilaunch', {
    // Drive & Environment
    getDriveInfo: () => ipcRenderer.invoke('get-drive-info'),

    // Vault Operations
    vaultExists: () => ipcRenderer.invoke('vault-exists'),
    loadVaultMeta: () => ipcRenderer.invoke('load-vault-meta'),
    saveVault: (data) => ipcRenderer.invoke('save-vault', data),

    // Unlock
    unlockWithPin: (pin) => ipcRenderer.invoke('unlock-with-pin', pin),
    unlockWithPassword: (pw) => ipcRenderer.invoke('unlock-with-password', pw),
    tryFastBoot: () => ipcRenderer.invoke('try-fast-boot'),

    // File Browser
    browseExe: () => ipcRenderer.invoke('browse-exe'),

    // Automation Engine
    launchWorkspace: (workspace) => ipcRenderer.invoke('launch-workspace', workspace),
    onLaunchStatus: (callback) => {
        ipcRenderer.on('launch-status', (_, msg) => callback(msg))
        return () => ipcRenderer.removeAllListeners('launch-status')
    },

    // Window Controls
    close: () => ipcRenderer.invoke('close-window')
})

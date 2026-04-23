export const SUPPORT_TIERS = Object.freeze({
    VERIFIED: 'verified',
    BEST_EFFORT: 'best-effort',
    LAUNCH_ONLY: 'launch-only',
    NEEDS_ADAPTER: 'needs-adapter',
    UNSUPPORTED: 'unsupported'
})

export const APP_ADAPTER_IDS = Object.freeze({
    NONE: 'none',
    CHROMIUM_USER_DATA_DIR: 'chromium-user-data-dir',
    VSCODE_USER_DATA_DIR: 'vscode-user-data-dir',
    ELECTRON_USER_DATA_DIR: 'electron-user-data-dir',
    NATIVE_LAUNCH_ONLY: 'native-launch-only',
    OBS_PORTABLE: 'obs-portable'
})

export const APP_DATA_SUPPORT_LEVELS = Object.freeze({
    VERIFIED: 'verified',
    UNSUPPORTED: 'unsupported'
})

function normalizeText(value) {
    return String(value || '').trim().toLowerCase()
}

function normalizeDataMode(dataProfile) {
    return normalizeText(dataProfile?.mode || 'none') || 'none'
}

function inferLaunchProfile(appType, appName, launchProfile) {
    const normalizedLaunchProfile = normalizeText(launchProfile)
    if (normalizedLaunchProfile) return normalizedLaunchProfile

    const normalizedAppType = normalizeText(appType || 'native')
    const lowerName = normalizeText(appName)

    if (lowerName.includes('microsoft edge') || lowerName === 'edge') return 'chromium-browser'
    if (normalizedAppType === 'vscode-family' || lowerName.includes('cursor') || lowerName.includes('visual studio code')) return 'vscode-family'
    if (normalizedAppType === 'chromium') return 'chromium-browser'
    if (normalizedAppType === 'electron') return 'electron-standard'
    if (lowerName.includes('swi') || lowerName.includes('prolog')) return 'runtime-gui'
    return 'native-windowed'
}

function inferDataMode(appType, appName, launchProfile, dataProfile) {
    const explicitMode = normalizeDataMode(dataProfile)
    if (explicitMode && explicitMode !== 'none') return explicitMode

    const normalizedLaunchProfile = inferLaunchProfile(appType, appName, launchProfile)
    const normalizedAppType = normalizeText(appType || 'native')
    const lowerName = normalizeText(appName)

    if (normalizedLaunchProfile === 'chromium-browser' || normalizedAppType === 'chromium' || lowerName.includes('microsoft edge') || lowerName === 'edge') {
        return 'chromium-user-data'
    }
    if (normalizedLaunchProfile === 'vscode-family' || normalizedAppType === 'vscode-family' || lowerName.includes('cursor') || lowerName.includes('visual studio code')) {
        return 'vscode-user-data'
    }
    if (normalizedLaunchProfile === 'electron-standard' || normalizedAppType === 'electron') {
        return 'electron-user-data'
    }
    return 'none'
}

function isObsApp(appName) {
    const lowerName = normalizeText(appName)
    return lowerName === 'obs' || lowerName.includes('obs studio') || /\bobs\b/.test(lowerName)
}

function verifiedCapability({
    appType,
    appName,
    launchProfile,
    dataMode,
    adapterId,
    supportSummary,
    supportReason
}) {
    return {
        appType,
        appName,
        launchProfile,
        dataProfile: { mode: dataMode },
        dataMode,
        supportTier: SUPPORT_TIERS.VERIFIED,
        supportSummary,
        launchAdapter: adapterId,
        runtimeAdapter: adapterId,
        importedDataAdapterId: adapterId,
        importedDataSupported: true,
        importedDataSupportLevel: APP_DATA_SUPPORT_LEVELS.VERIFIED,
        importedDataSupportReason: supportReason,
        limitations: []
    }
}

export function resolveAppCapability({
    appType = 'native',
    appName = '',
    launchProfile,
    dataProfile
} = {}) {
    const normalizedAppType = normalizeText(appType || 'native')
    const normalizedLaunchProfile = inferLaunchProfile(normalizedAppType, appName, launchProfile)
    const dataMode = inferDataMode(normalizedAppType, appName, normalizedLaunchProfile, dataProfile)

    if (normalizedLaunchProfile === 'chromium-browser' || dataMode === 'chromium-user-data') {
        return verifiedCapability({
            appType: normalizedAppType,
            appName,
            launchProfile: normalizedLaunchProfile,
            dataMode,
            adapterId: APP_ADAPTER_IDS.CHROMIUM_USER_DATA_DIR,
            supportSummary: 'Verified Chromium/Edge profile adapter.',
            supportReason: 'Verified Chromium/Edge imported AppData adapter.'
        })
    }

    if (normalizedLaunchProfile === 'vscode-family' || dataMode === 'vscode-user-data') {
        return verifiedCapability({
            appType: normalizedAppType,
            appName,
            launchProfile: normalizedLaunchProfile,
            dataMode,
            adapterId: APP_ADAPTER_IDS.VSCODE_USER_DATA_DIR,
            supportSummary: 'Verified VS Code-family profile adapter.',
            supportReason: 'Verified VS Code-family imported AppData adapter.'
        })
    }

    if (isObsApp(appName)) {
        return {
            appType: normalizedAppType,
            appName,
            launchProfile: normalizedLaunchProfile,
            dataProfile: { mode: dataMode },
            dataMode,
            supportTier: SUPPORT_TIERS.NEEDS_ADAPTER,
            supportSummary: 'OBS needs an app-specific portable-mode adapter before data portability is claimed.',
            launchAdapter: APP_ADAPTER_IDS.OBS_PORTABLE,
            runtimeAdapter: APP_ADAPTER_IDS.NONE,
            importedDataAdapterId: APP_ADAPTER_IDS.NONE,
            importedDataSupported: false,
            importedDataSupportLevel: APP_DATA_SUPPORT_LEVELS.UNSUPPORTED,
            importedDataSupportReason: 'Imported AppData is supported only for Chromium/Edge and VS Code-family profiles.',
            limitations: [
                'OBS portable mode must sync configuration to and from the vault before support can be verified.',
                'OBS scene media paths are not automatically portable.'
            ]
        }
    }

    if (normalizedLaunchProfile === 'electron-standard' || dataMode === 'electron-user-data' || normalizedAppType === 'electron') {
        return {
            appType: normalizedAppType,
            appName,
            launchProfile: normalizedLaunchProfile,
            dataProfile: { mode: dataMode },
            dataMode,
            supportTier: SUPPORT_TIERS.BEST_EFFORT,
            supportSummary: 'Best-effort generic Electron launch support. Imported AppData is unsupported.',
            launchAdapter: APP_ADAPTER_IDS.ELECTRON_USER_DATA_DIR,
            runtimeAdapter: APP_ADAPTER_IDS.ELECTRON_USER_DATA_DIR,
            importedDataAdapterId: APP_ADAPTER_IDS.ELECTRON_USER_DATA_DIR,
            importedDataSupported: false,
            importedDataSupportLevel: APP_DATA_SUPPORT_LEVELS.UNSUPPORTED,
            importedDataSupportReason: 'Imported AppData is not verified for generic Electron apps. Launch-only isolation is best-effort.',
            limitations: [
                'Generic Electron apps can override user-data paths internally.',
                'Single-instance Electron apps may hand off to an existing host process.'
            ]
        }
    }

    return {
        appType: normalizedAppType,
        appName,
        launchProfile: normalizedLaunchProfile,
        dataProfile: { mode: dataMode },
        dataMode,
        supportTier: SUPPORT_TIERS.LAUNCH_ONLY,
        supportSummary: 'Launch-only native app support. Data is unmanaged unless a certified adapter is added.',
        launchAdapter: APP_ADAPTER_IDS.NATIVE_LAUNCH_ONLY,
        runtimeAdapter: APP_ADAPTER_IDS.NONE,
        importedDataAdapterId: APP_ADAPTER_IDS.NONE,
        importedDataSupported: false,
        importedDataSupportLevel: APP_DATA_SUPPORT_LEVELS.UNSUPPORTED,
        importedDataSupportReason: 'Imported AppData is supported only for Chromium/Edge and VS Code-family profiles.',
        limitations: [
            'No data portability is claimed for unknown native apps.'
        ]
    }
}

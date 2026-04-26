const LAUNCH_CAPABILITY_META_KEYS = [
    'launchCapabilityVault',
    'capabilityVault',
    'launchCapabilities',
    'launchCapabilityMigration',
    'launchCapabilitySummaries',
    'capabilitySummaries'
]

export function metaHasLaunchCapabilityMaterial(meta) {
    if (!meta || typeof meta !== 'object') return false
    return LAUNCH_CAPABILITY_META_KEYS.some(key => Object.prototype.hasOwnProperty.call(meta, key))
}

export function stripLaunchCapabilityMaterialFromMeta(meta) {
    const next = { ...(meta || { version: '1.0.0' }) }
    for (const key of LAUNCH_CAPABILITY_META_KEYS) {
        delete next[key]
    }
    return next
}

export function sanitizeVaultMetaForRenderer(meta, driveInfo) {
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

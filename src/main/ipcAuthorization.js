export function hasUnlockedSession(activeMasterPasswordBuffer) {
    return !!activeMasterPasswordBuffer
}

export function requireActiveSessionState(hasActiveSession, message = 'Session is locked') {
    if (!hasActiveSession) throw new Error(message)
}

export function requireUnlockedOrNoVaultState({ vaultExists, hasActiveSession }) {
    if (vaultExists) requireActiveSessionState(hasActiveSession)
}

export function requireSessionSetupAllowedState({ vaultExists, hasActiveSession }) {
    if (vaultExists) requireActiveSessionState(hasActiveSession)
}

export function requireConvenienceUnlockRequestSupported({
    requested,
    driveInfo,
    featureName = 'Convenience unlock'
}) {
    if (!requested) return
    if (!driveInfo?.isRemovable) throw new Error(`${featureName} only supported on removable drives`)
    if (!driveInfo?.serialKnown) throw new Error(`${featureName} unavailable because the drive serial could not be verified`)
}

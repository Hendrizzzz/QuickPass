import crypto from 'crypto'
import { existsSync, readFileSync } from 'fs'
import { validatePinInput } from './ipcValidation.js'
import { writeJsonFileDurable } from './vaultDurability.js'

export const PIN_LOCKOUT_STATE_KEY = 'pinLockout'
export const PIN_FAILURE_THRESHOLD = 5
export const PIN_BASE_LOCKOUT_MS = 60_000
export const PIN_MAX_LOCKOUT_MS = 30 * 60_000
export const PIN_LOCKOUT_RESET_METHODS = new Set(['master-password', 'fresh-pin'])

function isPlainObject(value) {
    return !!value && typeof value === 'object' && !Array.isArray(value)
}

function nowMs(now) {
    return typeof now === 'function' ? Number(now()) : Number(now)
}

function sha256(value) {
    return crypto.createHash('sha256').update(String(value), 'utf-8').digest('hex')
}

function lockoutError(message, code) {
    const err = new Error(message)
    err.code = code
    return err
}

function normalizeCounter(value) {
    const number = Number(value)
    return Number.isSafeInteger(number) && number > 0 ? number : 0
}

function normalizeLockedUntil(value) {
    const number = Number(value)
    return Number.isFinite(number) && number > 0 ? number : 0
}

function readVaultState(statePath) {
    if (!existsSync(statePath)) return {}
    const state = JSON.parse(readFileSync(statePath, 'utf-8'))
    if (!isPlainObject(state)) throw lockoutError('Vault state is malformed.', 'PIN_LOCKOUT_STATE_INVALID')
    return state
}

function writeVaultState(statePath, state) {
    writeJsonFileDurable(statePath, state)
}

function normalizePinLockoutState(state) {
    const lockout = state[PIN_LOCKOUT_STATE_KEY]
    if (lockout == null) {
        return {
            version: 1,
            buckets: {}
        }
    }
    if (!isPlainObject(lockout) || !isPlainObject(lockout.buckets)) {
        throw lockoutError('PIN lockout state is malformed.', 'PIN_LOCKOUT_STATE_INVALID')
    }
    return {
        version: 1,
        buckets: { ...lockout.buckets }
    }
}

function writePinLockoutState(statePath, state, lockout) {
    const nextState = { ...state }
    const buckets = Object.fromEntries(
        Object.entries(lockout.buckets || {}).filter(([, entry]) => entry !== undefined)
    )

    if (Object.keys(buckets).length === 0) {
        delete nextState[PIN_LOCKOUT_STATE_KEY]
    } else {
        nextState.version = nextState.version || 1
        nextState[PIN_LOCKOUT_STATE_KEY] = {
            version: 1,
            buckets
        }
    }

    writeVaultState(statePath, nextState)
}

export function ensureVaultId(meta, randomBytes = crypto.randomBytes) {
    if (typeof meta?.vaultId === 'string' && /^vault_[a-f0-9]{32}$/i.test(meta.vaultId)) {
        return meta.vaultId
    }
    const value = randomBytes(16)
    const hex = Buffer.isBuffer(value) ? value.toString('hex') : Buffer.from(value).toString('hex')
    return `vault_${hex}`
}

function vaultIdentitySource(meta) {
    if (typeof meta?.vaultId === 'string' && meta.vaultId) return `vault-id:${meta.vaultId}`
    if (typeof meta?.generationId === 'string' && meta.generationId) return `generation:${meta.generationId}`
    if (typeof meta?.createdOn === 'string' && meta.createdOn) return `legacy-created-on:${meta.createdOn}`
    return 'vault:unknown'
}

function driveFingerprintSource(driveInfo) {
    if (driveInfo?.serialKnown && driveInfo.serialNumber && driveInfo.serialNumber !== 'UNKNOWN') {
        return `serial:${driveInfo.serialNumber}`
    }
    if (driveInfo?.driveLetter) return `drive:${driveInfo.driveLetter}`
    return 'drive:unknown'
}

export function createPinLockoutBucketContext({ meta, driveInfo }) {
    const vaultIdentityHash = sha256(vaultIdentitySource(meta))
    const driveFingerprintHash = sha256(driveFingerprintSource(driveInfo))
    return {
        vaultIdentityHash,
        driveFingerprintHash,
        bucketId: sha256(`${vaultIdentityHash}:${driveFingerprintHash}`)
    }
}

function normalizeBucketEntry(entry, context) {
    return {
        vaultIdentityHash: entry?.vaultIdentityHash || context.vaultIdentityHash,
        driveFingerprintHash: entry?.driveFingerprintHash || context.driveFingerprintHash,
        failedAttempts: normalizeCounter(entry?.failedAttempts),
        lockoutCount: normalizeCounter(entry?.lockoutCount),
        lockedUntil: normalizeLockedUntil(entry?.lockedUntil),
        updatedAt: typeof entry?.updatedAt === 'string' ? entry.updatedAt : null
    }
}

function lockoutDuration(lockoutCount) {
    const multiplier = 2 ** Math.max(0, lockoutCount - 1)
    return Math.min(PIN_BASE_LOCKOUT_MS * multiplier, PIN_MAX_LOCKOUT_MS)
}

export function getPinLockoutEntry({ statePath, meta, driveInfo }) {
    const state = readVaultState(statePath)
    const lockout = normalizePinLockoutState(state)
    const context = createPinLockoutBucketContext({ meta, driveInfo })
    return normalizeBucketEntry(lockout.buckets[context.bucketId], context)
}

export function assertPinAttemptAllowed({ statePath, meta, driveInfo, now = Date.now }) {
    const currentTime = nowMs(now)
    const entry = getPinLockoutEntry({ statePath, meta, driveInfo })
    if (entry.lockedUntil > currentTime) {
        const err = lockoutError('PIN temporarily locked.', 'PIN_LOCKED')
        err.retryAfterMs = entry.lockedUntil - currentTime
        throw err
    }
    return entry
}

export function recordPinAttemptFailure({ statePath, meta, driveInfo, now = Date.now }) {
    const currentTime = nowMs(now)
    const state = readVaultState(statePath)
    const lockout = normalizePinLockoutState(state)
    const context = createPinLockoutBucketContext({ meta, driveInfo })
    const existing = normalizeBucketEntry(lockout.buckets[context.bucketId], context)
    const failedAttempts = existing.failedAttempts + 1
    let lockoutCount = existing.lockoutCount
    let lockedUntil = existing.lockedUntil

    if (failedAttempts > 0 && failedAttempts % PIN_FAILURE_THRESHOLD === 0) {
        lockoutCount += 1
        lockedUntil = currentTime + lockoutDuration(lockoutCount)
    }

    const entry = {
        vaultIdentityHash: context.vaultIdentityHash,
        driveFingerprintHash: context.driveFingerprintHash,
        failedAttempts,
        lockoutCount,
        lockedUntil,
        updatedAt: new Date(currentTime).toISOString()
    }
    lockout.buckets[context.bucketId] = entry
    writePinLockoutState(statePath, state, lockout)
    return {
        ...entry,
        retryAfterMs: lockedUntil > currentTime ? lockedUntil - currentTime : 0
    }
}

export function clearPinLockout({ statePath, meta, driveInfo, scope = 'exact' }) {
    const state = readVaultState(statePath)
    const lockout = normalizePinLockoutState(state)
    const context = createPinLockoutBucketContext({ meta, driveInfo })
    let changed = false

    for (const [bucketId, entry] of Object.entries(lockout.buckets)) {
        const normalized = normalizeBucketEntry(entry, context)
        const matches = scope === 'vault'
            ? normalized.vaultIdentityHash === context.vaultIdentityHash
            : bucketId === context.bucketId
        if (matches) {
            delete lockout.buckets[bucketId]
            changed = true
        }
    }

    if (!changed) return
    writePinLockoutState(statePath, state, lockout)
}

export function isApprovedPinLockoutResetMethod(method) {
    return PIN_LOCKOUT_RESET_METHODS.has(method)
}

export function isHiddenMasterVault(meta) {
    if (!meta || typeof meta !== 'object') return false
    if (meta.hiddenMaster === true) return true
    if (meta.hiddenMaster === false) return false
    return !!(meta.isRemovable && (meta.hasPIN || meta.fastBoot))
}

export function requireFreshPinProofForMediumRisk({
    statePath,
    meta,
    driveInfo,
    pin,
    activeMasterPassword,
    decryptVault,
    now = Date.now
}) {
    if (!isHiddenMasterVault(meta)) {
        return { required: false, approved: false }
    }
    if (!meta?.hasPIN || !meta?.pinVault) {
        throw lockoutError('Fresh PIN proof is unavailable for this hidden-master vault.', 'FRESH_PIN_UNAVAILABLE')
    }
    if (!driveInfo?.serialKnown || !driveInfo.serialNumber || driveInfo.serialNumber === 'UNKNOWN') {
        throw lockoutError('Fresh PIN proof requires the original drive fingerprint.', 'FRESH_PIN_DRIVE_UNAVAILABLE')
    }

    const safePin = validatePinInput(pin, { allowNull: false })
    assertPinAttemptAllowed({ statePath, meta, driveInfo, now })

    let proof
    try {
        proof = decryptVault(meta.pinVault, `${safePin}:${driveInfo.serialNumber}`)
    } catch (_) {
        recordPinAttemptFailure({ statePath, meta, driveInfo, now })
        throw lockoutError('Fresh PIN proof failed.', 'FRESH_PIN_INVALID')
    }

    if (!proof?.masterPassword || proof.masterPassword !== activeMasterPassword) {
        throw lockoutError('Fresh PIN proof does not match the active vault session.', 'FRESH_PIN_SESSION_MISMATCH')
    }

    clearPinLockout({ statePath, meta, driveInfo, scope: 'exact' })
    return {
        required: true,
        approved: true,
        masterPassword: proof.masterPassword
    }
}

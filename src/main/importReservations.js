import {
    closeSync,
    existsSync,
    fsyncSync,
    mkdirSync,
    openSync,
    readFileSync,
    readdirSync,
    statSync,
    unlinkSync,
    writeFileSync
} from 'fs'
import { basename, join } from 'path'
import crypto from 'crypto'
import {
    APP_MANIFEST_SUFFIX,
    LEGACY_APP_MANIFEST_SUFFIX,
    safeAppName
} from './appManifest.js'
import { createAvailableAppStorageId } from './ipcValidation.js'

export const IMPORT_RESERVATION_SCHEMA_VERSION = 1
export const DEFAULT_IMPORT_RESERVATION_STALE_MS = 6 * 60 * 60 * 1000

const RESERVATION_EXTENSION = '.lock'
const MANIFEST_SUFFIXES = [APP_MANIFEST_SUFFIX, LEGACY_APP_MANIFEST_SUFFIX]
const ARCHIVE_SUFFIX = '.tar.zst'
const STORAGE_ID_PATTERN = /^[a-zA-Z0-9_-]{1,160}$/

function nowMs(options = {}) {
    const candidate = typeof options.now === 'function' ? Number(options.now()) : Date.now()
    return Number.isFinite(candidate) ? candidate : Date.now()
}

function reservationStaleMs(options = {}) {
    const staleMs = Number(options.staleMs ?? DEFAULT_IMPORT_RESERVATION_STALE_MS)
    return Number.isFinite(staleMs) && staleMs > 0 ? staleMs : DEFAULT_IMPORT_RESERVATION_STALE_MS
}

function reservationsDir(vaultDir) {
    return join(vaultDir, 'Apps', '.reservations')
}

function reservationPath(vaultDir, storageId) {
    return join(reservationsDir(vaultDir), `${storageId}${RESERVATION_EXTENSION}`)
}

function isValidStorageId(value) {
    return typeof value === 'string' && STORAGE_ID_PATTERN.test(value)
}

function readJsonIfPresent(filePath) {
    try {
        return JSON.parse(readFileSync(filePath, 'utf-8'))
    } catch (_) {
        return null
    }
}

function fileAgeMs(filePath, options = {}) {
    try {
        return Math.max(0, nowMs(options) - statSync(filePath).mtimeMs)
    } catch (_) {
        return 0
    }
}

function reservationCreatedAtMs(lockPath, reservation, options = {}) {
    if (Number.isFinite(Number(reservation?.createdAtMs))) {
        return Number(reservation.createdAtMs)
    }
    if (reservation?.createdAt) {
        const parsed = Date.parse(reservation.createdAt)
        if (Number.isFinite(parsed)) return parsed
    }
    try {
        return statSync(lockPath).mtimeMs
    } catch (_) {
        return nowMs(options)
    }
}

function isReservationStale(lockPath, options = {}) {
    if (!existsSync(lockPath)) return false
    const reservation = readJsonIfPresent(lockPath)
    const age = reservation
        ? Math.max(0, nowMs(options) - reservationCreatedAtMs(lockPath, reservation, options))
        : fileAgeMs(lockPath, options)
    return age >= reservationStaleMs(options)
}

function removeStaleReservation(lockPath, options = {}) {
    if (!isReservationStale(lockPath, options)) return false
    try {
        unlinkSync(lockPath)
        return true
    } catch (_) {
        return false
    }
}

function reservationIsActive(vaultDir, storageId, options = {}) {
    const lockPath = reservationPath(vaultDir, storageId)
    if (!existsSync(lockPath)) return false
    if (removeStaleReservation(lockPath, options)) return false
    return existsSync(lockPath)
}

function writeReservationMetadata(fd, metadata) {
    writeFileSync(fd, `${JSON.stringify(metadata, null, 2)}\n`, 'utf-8')
    try { fsyncSync(fd) } catch (_) { }
}

function releaseReservation(lockPath, reservationId) {
    const current = readJsonIfPresent(lockPath)
    if (!current || current.reservationId !== reservationId) return false
    try {
        unlinkSync(lockPath)
        return true
    } catch (_) {
        return false
    }
}

function cleanStorageIdFromArchiveName(value) {
    const name = basename(String(value || ''))
    if (!name.toLowerCase().endsWith(ARCHIVE_SUFFIX)) return null
    return name.slice(0, -ARCHIVE_SUFFIX.length)
}

function cleanStorageIdFromManifestName(value) {
    const name = basename(String(value || ''))
    const suffix = MANIFEST_SUFFIXES.find(candidate => name.toLowerCase().endsWith(candidate))
    if (!suffix) return null
    return name.slice(0, -suffix.length)
}

function displayNameKey(value) {
    return String(value || '').trim().toLowerCase()
}

function allocatedBaseStorageId(value) {
    const storageId = String(value || '')
    const match = /^(.*)-([2-9][0-9]*)$/.exec(storageId)
    if (!match || !isValidStorageId(match[1])) return null
    return match[1]
}

function createImportedInventory() {
    return {
        displayNameKeys: new Set(),
        storageIds: new Set(),
        allocatedBaseStorageIds: new Set()
    }
}

function addStorageId(inventory, storageId, { inferAllocatedBase = true } = {}) {
    if (!isValidStorageId(storageId)) return
    inventory.storageIds.add(storageId)
    if (!inferAllocatedBase) return
    const allocatedBase = allocatedBaseStorageId(storageId)
    if (allocatedBase) inventory.allocatedBaseStorageIds.add(allocatedBase)
}

function addDisplayName(inventory, displayName) {
    const key = displayNameKey(displayName)
    if (key) inventory.displayNameKeys.add(key)
}

function addManifestToInventory(inventory, manifest, fallbackStorageId) {
    if (!manifest || typeof manifest !== 'object') {
        addStorageId(inventory, fallbackStorageId)
        return
    }

    const displayName = manifest.displayName || manifest.name
    addDisplayName(inventory, displayName)

    const manifestStorageIds = [
        fallbackStorageId,
        manifest.safeName,
        manifest.manifestId,
        cleanStorageIdFromArchiveName(manifest.archiveName)
    ].filter(Boolean)

    const canonicalDisplayStorageId = displayName ? safeAppName(displayName) : null
    for (const storageId of manifestStorageIds) {
        const couldBeLiteralHyphenName = canonicalDisplayStorageId === storageId
        addStorageId(inventory, storageId, { inferAllocatedBase: !couldBeLiteralHyphenName })
    }
}

export function cleanupStaleAppStorageReservations(vaultDir, options = {}) {
    const dir = reservationsDir(vaultDir)
    if (!existsSync(dir)) return []
    let entries = []
    try {
        entries = readdirSync(dir, { withFileTypes: true })
    } catch (_) {
        return []
    }

    const removed = []
    for (const entry of entries) {
        if (!entry.isFile() || !entry.name.endsWith(RESERVATION_EXTENSION)) continue
        const lockPath = join(dir, entry.name)
        if (removeStaleReservation(lockPath, options)) removed.push(lockPath)
    }
    return removed
}

export function scanImportedAppInventory(vaultDir) {
    const inventory = createImportedInventory()
    const appsDir = join(vaultDir, 'Apps')
    if (!existsSync(appsDir)) return inventory

    let entries = []
    try {
        entries = readdirSync(appsDir, { withFileTypes: true })
    } catch (_) {
        return inventory
    }

    for (const entry of entries) {
        if (entry.name === '.reservations') continue

        if (entry.isDirectory()) {
            addStorageId(inventory, entry.name)
            continue
        }

        if (!entry.isFile()) continue

        const archiveStorageId = cleanStorageIdFromArchiveName(entry.name)
        if (archiveStorageId) {
            addStorageId(inventory, archiveStorageId)
            continue
        }

        const manifestStorageId = cleanStorageIdFromManifestName(entry.name)
        if (!manifestStorageId) continue

        const manifestPath = join(appsDir, entry.name)
        addManifestToInventory(inventory, readJsonIfPresent(manifestPath), manifestStorageId)
    }

    return inventory
}

export function isImportedAppName(inventory, name) {
    const baseStorageId = safeAppName(name)
    return inventory.storageIds.has(baseStorageId) ||
        inventory.allocatedBaseStorageIds.has(baseStorageId) ||
        inventory.displayNameKeys.has(displayNameKey(name))
}

export function createImportedAppLookup(vaultDir) {
    const inventory = scanImportedAppInventory(vaultDir)
    return {
        inventory,
        alreadyImported(name) {
            return isImportedAppName(inventory, name)
        }
    }
}

export function isAppStorageIdTaken(vaultDir, candidate) {
    const inventory = scanImportedAppInventory(vaultDir)
    return inventory.storageIds.has(candidate) ||
        existsSync(join(vaultDir, 'Apps', candidate)) ||
        existsSync(join(vaultDir, 'Apps', `${candidate}${ARCHIVE_SUFFIX}`)) ||
        MANIFEST_SUFFIXES.some(suffix => existsSync(join(vaultDir, 'Apps', `${candidate}${suffix}`))) ||
        existsSync(join(vaultDir, 'AppData', candidate))
}

export function reserveAppStorageId(vaultDir, name, options = {}) {
    const dir = reservationsDir(vaultDir)
    mkdirSync(dir, { recursive: true })
    cleanupStaleAppStorageReservations(vaultDir, options)

    const rejected = new Set()
    const createdAtMs = nowMs(options)
    const createdAt = new Date(createdAtMs).toISOString()

    for (let attempt = 0; attempt < 1000; attempt += 1) {
        const storageId = createAvailableAppStorageId(name, candidate => (
            rejected.has(candidate) ||
            isAppStorageIdTaken(vaultDir, candidate) ||
            reservationIsActive(vaultDir, candidate, options)
        ))
        const lockPath = reservationPath(vaultDir, storageId)
        const reservationId = crypto.randomBytes(16).toString('hex')
        let fd = null

        try {
            fd = openSync(lockPath, 'wx', 0o600)
            writeReservationMetadata(fd, {
                schemaVersion: IMPORT_RESERVATION_SCHEMA_VERSION,
                reservationId,
                operation: options.operation || 'import-app',
                displayName: String(name || ''),
                storageId,
                pid: process.pid,
                createdAt,
                createdAtMs
            })
            closeSync(fd)
            fd = null
            return {
                storageId,
                lockPath,
                reservationId,
                release() {
                    return releaseReservation(lockPath, reservationId)
                }
            }
        } catch (err) {
            if (fd != null) {
                try { closeSync(fd) } catch (_) { }
            }
            if (err?.code !== 'EEXIST') throw err
            rejected.add(storageId)
        }
    }

    throw new Error('Could not reserve an app storage id.')
}

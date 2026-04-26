import { dirname } from 'path'
import {
    closeSync,
    existsSync,
    fsyncSync,
    mkdirSync,
    openSync,
    readFileSync,
    renameSync,
    unlinkSync,
    writeFileSync
} from 'fs'
import { execFileSync } from 'child_process'
import crypto from 'crypto'

export const VAULT_GENERATION_FIELD = 'generationId'
export const VAULT_STATE_VERSION = 1
export const VAULT_TRANSACTION_KEY = 'vaultTransaction'

function durabilityError(message, code = 'VAULT_DURABILITY_FAIL_CLOSED') {
    const err = new Error(message)
    err.code = code
    return err
}

function serializeJson(data) {
    return JSON.stringify(data, null, 2)
}

function hashSerialized(text) {
    return crypto.createHash('sha256').update(text, 'utf-8').digest('hex')
}

function hashJson(data) {
    return hashSerialized(serializeJson(data))
}

function randomHex(bytes, randomBytes = crypto.randomBytes) {
    const value = randomBytes(bytes)
    return Buffer.isBuffer(value) ? value.toString('hex') : Buffer.from(value).toString('hex')
}

function createGenerationId(randomBytes) {
    return `gen_${randomHex(16, randomBytes)}`
}

function createTransactionId(randomBytes) {
    return `txn_${randomHex(16, randomBytes)}`
}

function isPlainObject(value) {
    return !!value && typeof value === 'object' && !Array.isArray(value)
}

function generationIdOf(value) {
    return isPlainObject(value) && typeof value[VAULT_GENERATION_FIELD] === 'string' && value[VAULT_GENERATION_FIELD]
        ? value[VAULT_GENERATION_FIELD]
        : null
}

function withGeneration(value, generationId) {
    return {
        ...(isPlainObject(value) ? value : {}),
        [VAULT_GENERATION_FIELD]: generationId
    }
}

function clearHiddenReadOnly(filePath) {
    try { execFileSync('attrib', ['-H', '-R', filePath], { windowsHide: true }) } catch (_) { }
}

function setHidden(filePath) {
    try { execFileSync('attrib', ['+H', filePath], { windowsHide: true }) } catch (_) { }
}

function flushFile(filePath) {
    let fd = null
    try {
        fd = openSync(filePath, 'r')
        fsyncSync(fd)
    } catch (_) {
    } finally {
        if (fd != null) {
            try { closeSync(fd) } catch (_) { }
        }
    }
}

function flushDirectory(filePath) {
    let fd = null
    try {
        fd = openSync(dirname(filePath), 'r')
        fsyncSync(fd)
    } catch (_) {
    } finally {
        if (fd != null) {
            try { closeSync(fd) } catch (_) { }
        }
    }
}

export function writeJsonFileDurable(filePath, data, { hidden = true, randomBytes = crypto.randomBytes } = {}) {
    mkdirSync(dirname(filePath), { recursive: true })
    const tempPath = `${filePath}.${process.pid}.${Date.now()}.${randomHex(4, randomBytes)}.tmp`
    let fd = null

    try {
        if (existsSync(filePath)) clearHiddenReadOnly(filePath)
        fd = openSync(tempPath, 'w')
        writeFileSync(fd, serializeJson(data), 'utf-8')
        fsyncSync(fd)
        closeSync(fd)
        fd = null
        renameSync(tempPath, filePath)
        flushFile(filePath)
        flushDirectory(filePath)
        if (hidden) setHidden(filePath)
    } catch (err) {
        if (fd != null) {
            try { closeSync(fd) } catch (_) { }
        }
        try {
            if (existsSync(tempPath)) unlinkSync(tempPath)
        } catch (_) { }
        throw err
    }
}

function unlinkDurable(filePath) {
    if (!existsSync(filePath)) return
    clearHiddenReadOnly(filePath)
    unlinkSync(filePath)
    flushDirectory(filePath)
}

function readJsonIfExists(filePath, label) {
    if (!existsSync(filePath)) {
        return {
            exists: false,
            data: null,
            hash: null,
            generationId: null
        }
    }

    let text = ''
    try {
        text = readFileSync(filePath, 'utf-8')
        const data = JSON.parse(text)
        return {
            exists: true,
            data,
            hash: hashSerialized(text),
            generationId: generationIdOf(data)
        }
    } catch (err) {
        throw durabilityError(`${label} is unreadable or malformed.`, 'VAULT_DURABILITY_PARSE_ERROR')
    }
}

function readStateFile(statePath) {
    if (!existsSync(statePath)) return {}
    const state = readJsonIfExists(statePath, 'Vault state').data
    if (!isPlainObject(state)) {
        throw durabilityError('Vault state is malformed.', 'VAULT_DURABILITY_PARSE_ERROR')
    }
    return state
}

function writeStateFile(statePath, state, options = {}) {
    const keys = Object.keys(state).filter(key => state[key] !== undefined)
    if (keys.length === 0 || (keys.length === 1 && keys[0] === 'version')) {
        unlinkDurable(statePath)
        return
    }
    writeJsonFileDurable(statePath, state, options)
}

function readCurrent(paths) {
    return {
        vault: readJsonIfExists(paths.vaultPath, 'Vault'),
        meta: readJsonIfExists(paths.metaPath, 'Vault metadata')
    }
}

function assertCurrentGenerationsMatch(current) {
    if (!current.vault.exists || !current.meta.exists) return

    const vaultGeneration = current.vault.generationId
    const metaGeneration = current.meta.generationId
    if (!vaultGeneration && !metaGeneration) return

    if (!vaultGeneration || !metaGeneration || vaultGeneration !== metaGeneration) {
        throw durabilityError('Vault and metadata generations do not match.', 'VAULT_GENERATION_MISMATCH')
    }
}

function assertNoOpenTransaction(state) {
    if (state[VAULT_TRANSACTION_KEY]) {
        throw durabilityError('Vault transaction is already in progress.', 'VAULT_TRANSACTION_IN_PROGRESS')
    }
}

function validateTransaction(tx) {
    if (!isPlainObject(tx) || tx.schemaVersion !== 1 || tx.type !== 'vault-meta-transaction') {
        throw durabilityError('Vault transaction marker is malformed.', 'VAULT_TRANSACTION_MALFORMED')
    }
    if (tx.mode !== 'vault-meta' && tx.mode !== 'meta-only') {
        throw durabilityError('Vault transaction mode is malformed.', 'VAULT_TRANSACTION_MALFORMED')
    }
    if (typeof tx.transactionId !== 'string' || !tx.transactionId) {
        throw durabilityError('Vault transaction ID is missing.', 'VAULT_TRANSACTION_MALFORMED')
    }
    if (typeof tx.operation !== 'string' || !tx.operation) {
        throw durabilityError('Vault transaction operation is missing.', 'VAULT_TRANSACTION_MALFORMED')
    }
    if (typeof tx.nextGenerationId !== 'string' || !tx.nextGenerationId) {
        throw durabilityError('Vault transaction generation is missing.', 'VAULT_TRANSACTION_MALFORMED')
    }
    if (!isPlainObject(tx.meta) || hashJson(tx.meta) !== tx.metaSha256) {
        throw durabilityError('Vault transaction metadata payload is corrupted.', 'VAULT_TRANSACTION_MALFORMED')
    }
    if (generationIdOf(tx.meta) !== tx.nextGenerationId) {
        throw durabilityError('Vault transaction metadata generation is corrupted.', 'VAULT_TRANSACTION_MALFORMED')
    }
    if (tx.mode === 'vault-meta') {
        if (!isPlainObject(tx.vault) || hashJson(tx.vault) !== tx.vaultSha256) {
            throw durabilityError('Vault transaction payload is corrupted.', 'VAULT_TRANSACTION_MALFORMED')
        }
        if (generationIdOf(tx.vault) !== tx.nextGenerationId) {
            throw durabilityError('Vault transaction vault generation is corrupted.', 'VAULT_TRANSACTION_MALFORMED')
        }
    }
}

function assertCurrentSideIsRecoverable(side, previousHash, nextHash, label) {
    if (!side.exists) {
        if (previousHash == null) return
        throw durabilityError(`${label} disappeared during an incomplete vault transaction.`, 'VAULT_TRANSACTION_AMBIGUOUS')
    }
    if (side.hash === previousHash || side.hash === nextHash) return
    throw durabilityError(`${label} changed outside the incomplete vault transaction.`, 'VAULT_TRANSACTION_AMBIGUOUS')
}

function clearVaultTransaction(paths, state, options = {}) {
    const nextState = { ...state }
    delete nextState[VAULT_TRANSACTION_KEY]
    if (Object.keys(nextState).length > 1) {
        nextState.version = nextState.version || VAULT_STATE_VERSION
    }
    writeStateFile(paths.statePath, nextState, options)
}

function writeVaultTransaction(paths, tx, options = {}) {
    const state = readStateFile(paths.statePath)
    assertNoOpenTransaction(state)
    writeStateFile(paths.statePath, {
        ...state,
        version: VAULT_STATE_VERSION,
        [VAULT_TRANSACTION_KEY]: tx
    }, options)
}

function buildVaultMetaTransaction({
    mode,
    operation,
    current,
    vault,
    meta,
    generationId,
    transactionId,
    now = Date.now
}) {
    const tx = {
        schemaVersion: 1,
        type: 'vault-meta-transaction',
        mode,
        operation,
        transactionId,
        createdAt: new Date(now()).toISOString(),
        previousVaultGenerationId: current.vault.generationId,
        previousMetaGenerationId: current.meta.generationId,
        previousVaultSha256: current.vault.hash,
        previousMetaSha256: current.meta.hash,
        nextGenerationId: generationId,
        meta,
        metaSha256: hashJson(meta)
    }

    if (mode === 'vault-meta') {
        tx.vault = vault
        tx.vaultSha256 = hashJson(vault)
    } else {
        tx.vaultSha256 = current.vault.hash
        tx.vaultGenerationId = current.vault.generationId
    }

    return tx
}

function recoverTransaction(paths, state, tx, options = {}) {
    validateTransaction(tx)

    const current = readCurrent(paths)
    if (tx.mode === 'vault-meta') {
        assertCurrentSideIsRecoverable(current.vault, tx.previousVaultSha256, tx.vaultSha256, 'Vault')
        assertCurrentSideIsRecoverable(current.meta, tx.previousMetaSha256, tx.metaSha256, 'Vault metadata')
        writeJsonFileDurable(paths.vaultPath, tx.vault, options)
        writeJsonFileDurable(paths.metaPath, tx.meta, options)
    } else {
        if (tx.vaultSha256 && (!current.vault.exists || current.vault.hash !== tx.vaultSha256)) {
            throw durabilityError('Vault changed outside the incomplete metadata transaction.', 'VAULT_TRANSACTION_AMBIGUOUS')
        }
        assertCurrentSideIsRecoverable(current.meta, tx.previousMetaSha256, tx.metaSha256, 'Vault metadata')
        writeJsonFileDurable(paths.metaPath, tx.meta, options)
    }

    clearVaultTransaction(paths, state, options)
    assertCurrentGenerationsMatch(readCurrent(paths))
}

export function recoverVaultDurability(paths, options = {}) {
    try {
        const state = readStateFile(paths.statePath)
        const tx = state[VAULT_TRANSACTION_KEY]
        if (tx) {
            recoverTransaction(paths, state, tx, options)
            return {
                ok: true,
                recovered: true,
                status: 'recovered',
                transactionId: tx.transactionId,
                operation: tx.operation
            }
        }

        assertCurrentGenerationsMatch(readCurrent(paths))
        return { ok: true, recovered: false, status: 'ready' }
    } catch (err) {
        return {
            ok: false,
            recovered: false,
            status: 'fail-closed',
            code: err.code || 'VAULT_DURABILITY_FAIL_CLOSED',
            error: err.message
        }
    }
}

function requireOkStatus(status) {
    if (!status?.ok) {
        throw durabilityError(
            `Vault durability check failed: ${status?.error || 'inconsistent vault state'}`,
            status?.code || 'VAULT_DURABILITY_FAIL_CLOSED'
        )
    }
}

export function createVaultDurabilityController({
    getPaths,
    randomBytes,
    onStatus = () => { }
} = {}) {
    if (typeof getPaths !== 'function') {
        throw new Error('Vault durability controller requires a getPaths function.')
    }

    let status = { ok: true, recovered: false, status: 'not-started' }
    const options = () => randomBytes ? { randomBytes } : {}
    const setStatus = (nextStatus) => {
        status = nextStatus
        try { onStatus(status) } catch (_) { }
        return status
    }
    const recoverNow = () => setStatus(recoverVaultDurability(getPaths(), options()))
    const requireReady = () => requireOkStatus(status)
    const verifyReady = () => {
        const nextStatus = recoverNow()
        requireOkStatus(nextStatus)
        return nextStatus
    }
    const handleCommitFailure = (err, operation) => {
        const nextStatus = recoverNow()
        if (nextStatus.ok && nextStatus.recovered && nextStatus.operation === operation) {
            return {
                recoveredDuringCommit: true,
                operation,
                transactionId: nextStatus.transactionId
            }
        }
        requireOkStatus(nextStatus)
        throw err
    }

    return {
        getStatus: () => status,
        recover: recoverNow,
        requireReady,
        verifyReady,
        commitVaultMeta({ vault, meta, operation }) {
            requireReady()
            try {
                const result = commitVaultMetaTransaction({
                    ...getPaths(),
                    vault,
                    meta,
                    operation,
                    ...options()
                })
                setStatus({ ok: true, recovered: false, status: 'ready' })
                return result
            } catch (err) {
                return handleCommitFailure(err, operation)
            }
        },
        commitMetadata({ meta, operation }) {
            requireReady()
            try {
                const result = commitMetadataTransaction({
                    ...getPaths(),
                    meta,
                    operation,
                    ...options()
                })
                setStatus({ ok: true, recovered: false, status: 'ready' })
                return result
            } catch (err) {
                return handleCommitFailure(err, operation)
            }
        }
    }
}

export function commitVaultMetaTransaction({
    vaultPath,
    metaPath,
    statePath,
    vault,
    meta,
    operation = 'vault-meta-update',
    now = Date.now,
    randomBytes = crypto.randomBytes
}) {
    const recovery = recoverVaultDurability({ vaultPath, metaPath, statePath }, { randomBytes })
    if (!recovery.ok) throw durabilityError(recovery.error, recovery.code)

    const current = readCurrent({ vaultPath, metaPath })
    assertCurrentGenerationsMatch(current)

    const generationId = createGenerationId(randomBytes)
    const tx = buildVaultMetaTransaction({
        mode: 'vault-meta',
        operation,
        current,
        vault: withGeneration(vault, generationId),
        meta: withGeneration(meta, generationId),
        generationId,
        transactionId: createTransactionId(randomBytes),
        now
    })

    writeVaultTransaction({ vaultPath, metaPath, statePath }, tx, { randomBytes })
    writeJsonFileDurable(vaultPath, tx.vault, { randomBytes })
    writeJsonFileDurable(metaPath, tx.meta, { randomBytes })
    clearVaultTransaction({ vaultPath, metaPath, statePath }, readStateFile(statePath), { randomBytes })

    return {
        transactionId: tx.transactionId,
        generationId,
        operation
    }
}

export function commitMetadataTransaction({
    vaultPath,
    metaPath,
    statePath,
    meta,
    operation = 'vault-metadata-update',
    now = Date.now,
    randomBytes = crypto.randomBytes
}) {
    const recovery = recoverVaultDurability({ vaultPath, metaPath, statePath }, { randomBytes })
    if (!recovery.ok) throw durabilityError(recovery.error, recovery.code)

    const current = readCurrent({ vaultPath, metaPath })
    assertCurrentGenerationsMatch(current)

    const existingGeneration = current.vault.generationId || current.meta.generationId
    const generationId = existingGeneration || createGenerationId(randomBytes)
    const stagedMeta = withGeneration(meta, generationId)
    const needsVaultGenerationBootstrap = current.vault.exists && current.vault.generationId !== generationId

    const tx = buildVaultMetaTransaction({
        mode: needsVaultGenerationBootstrap ? 'vault-meta' : 'meta-only',
        operation,
        current,
        vault: needsVaultGenerationBootstrap ? withGeneration(current.vault.data, generationId) : null,
        meta: stagedMeta,
        generationId,
        transactionId: createTransactionId(randomBytes),
        now
    })

    writeVaultTransaction({ vaultPath, metaPath, statePath }, tx, { randomBytes })
    if (needsVaultGenerationBootstrap) {
        writeJsonFileDurable(vaultPath, tx.vault, { randomBytes })
    }
    writeJsonFileDurable(metaPath, tx.meta, { randomBytes })
    clearVaultTransaction({ vaultPath, metaPath, statePath }, readStateFile(statePath), { randomBytes })

    return {
        transactionId: tx.transactionId,
        generationId,
        operation
    }
}

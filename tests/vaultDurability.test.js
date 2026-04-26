import assert from 'assert/strict'
import { test } from 'node:test'
import { createHash } from 'crypto'
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import {
    VAULT_GENERATION_FIELD,
    VAULT_TRANSACTION_KEY,
    createVaultDurabilityController,
    commitMetadataTransaction,
    commitVaultMetaTransaction,
    recoverVaultDurability
} from '../src/main/vaultDurability.js'

function serializeJson(value) {
    return JSON.stringify(value, null, 2)
}

function hashJson(value) {
    return createHash('sha256').update(serializeJson(value), 'utf-8').digest('hex')
}

function writeJson(filePath, value) {
    writeFileSync(filePath, serializeJson(value), 'utf-8')
}

function readJson(filePath) {
    return JSON.parse(readFileSync(filePath, 'utf-8'))
}

function createHarness() {
    const vaultDir = mkdtempSync(join(tmpdir(), 'omnilaunch-vault-durability-'))
    return {
        vaultDir,
        paths: {
            vaultPath: join(vaultDir, 'vault.json'),
            metaPath: join(vaultDir, 'vault.meta.json'),
            statePath: join(vaultDir, 'vault.state.json')
        },
        cleanup: () => {
            if (existsSync(vaultDir)) rmSync(vaultDir, { recursive: true, force: true })
        }
    }
}

function vault(generationId, label = 'vault') {
    return {
        salt: `${label}-salt`,
        iv: `${label}-iv`,
        authTag: `${label}-tag`,
        data: `${label}-data`,
        isHardwareBound: false,
        [VAULT_GENERATION_FIELD]: generationId
    }
}

function meta(generationId, extra = {}) {
    return {
        version: '1.0.0',
        hasPIN: false,
        fastBoot: false,
        ...extra,
        [VAULT_GENERATION_FIELD]: generationId
    }
}

function writeTransaction(paths, tx) {
    writeJson(paths.statePath, {
        version: 1,
        [VAULT_TRANSACTION_KEY]: tx
    })
}

function pairTransaction({ previousVault, previousMeta, nextVault, nextMeta, operation = 'test-pair' }) {
    return {
        schemaVersion: 1,
        type: 'vault-meta-transaction',
        mode: 'vault-meta',
        operation,
        transactionId: `txn-${operation}`,
        createdAt: '2026-04-26T00:00:00.000Z',
        previousVaultGenerationId: previousVault?.[VAULT_GENERATION_FIELD] || null,
        previousMetaGenerationId: previousMeta?.[VAULT_GENERATION_FIELD] || null,
        previousVaultSha256: previousVault ? hashJson(previousVault) : null,
        previousMetaSha256: previousMeta ? hashJson(previousMeta) : null,
        nextGenerationId: nextVault[VAULT_GENERATION_FIELD],
        vault: nextVault,
        vaultSha256: hashJson(nextVault),
        meta: nextMeta,
        metaSha256: hashJson(nextMeta)
    }
}

function metaOnlyTransaction({ currentVault, previousMeta, nextMeta, operation = 'test-meta' }) {
    return {
        schemaVersion: 1,
        type: 'vault-meta-transaction',
        mode: 'meta-only',
        operation,
        transactionId: `txn-${operation}`,
        createdAt: '2026-04-26T00:00:00.000Z',
        previousVaultGenerationId: currentVault?.[VAULT_GENERATION_FIELD] || null,
        previousMetaGenerationId: previousMeta?.[VAULT_GENERATION_FIELD] || null,
        previousVaultSha256: currentVault ? hashJson(currentVault) : null,
        previousMetaSha256: previousMeta ? hashJson(previousMeta) : null,
        nextGenerationId: nextMeta[VAULT_GENERATION_FIELD],
        vaultSha256: currentVault ? hashJson(currentVault) : null,
        vaultGenerationId: currentVault?.[VAULT_GENERATION_FIELD] || null,
        meta: nextMeta,
        metaSha256: hashJson(nextMeta)
    }
}

test('interrupted vault write is detected and deterministically completed', () => {
    const harness = createHarness()
    try {
        const previousVault = vault('gen-old', 'old-vault')
        const previousMeta = meta('gen-old', { clearCacheOnExit: true })
        const nextVault = vault('gen-next', 'next-vault')
        const nextMeta = meta('gen-next', { clearCacheOnExit: false })

        writeJson(harness.paths.vaultPath, previousVault)
        writeJson(harness.paths.metaPath, nextMeta)
        writeTransaction(harness.paths, pairTransaction({ previousVault, previousMeta, nextVault, nextMeta }))

        const result = recoverVaultDurability(harness.paths)

        assert.equal(result.ok, true)
        assert.equal(result.recovered, true)
        assert.deepEqual(readJson(harness.paths.vaultPath), nextVault)
        assert.deepEqual(readJson(harness.paths.metaPath), nextMeta)
        assert.equal(existsSync(harness.paths.statePath), false)
    } finally {
        harness.cleanup()
    }
})

test('interrupted metadata write is detected and deterministically completed', () => {
    const harness = createHarness()
    try {
        const currentVault = vault('gen-current', 'vault')
        const previousMeta = meta('gen-current', { clearCacheOnExit: true })
        const nextMeta = meta('gen-current', { clearCacheOnExit: false })

        writeJson(harness.paths.vaultPath, currentVault)
        writeJson(harness.paths.metaPath, previousMeta)
        writeTransaction(harness.paths, metaOnlyTransaction({ currentVault, previousMeta, nextMeta }))

        const result = recoverVaultDurability(harness.paths)

        assert.equal(result.ok, true)
        assert.equal(result.recovered, true)
        assert.deepEqual(readJson(harness.paths.vaultPath), currentVault)
        assert.deepEqual(readJson(harness.paths.metaPath), nextMeta)
        assert.equal(existsSync(harness.paths.statePath), false)
    } finally {
        harness.cleanup()
    }
})

test('mismatched vault and metadata generation fails closed', () => {
    const harness = createHarness()
    try {
        writeJson(harness.paths.vaultPath, vault('gen-a'))
        writeJson(harness.paths.metaPath, meta('gen-b'))

        const result = recoverVaultDurability(harness.paths)

        assert.equal(result.ok, false)
        assert.equal(result.status, 'fail-closed')
        assert.equal(result.code, 'VAULT_GENERATION_MISMATCH')
        assert.match(result.error, /generations do not match/)
    } finally {
        harness.cleanup()
    }
})

test('successful vault transaction writes matching generation and clears marker', () => {
    const harness = createHarness()
    let counter = 1
    const randomBytes = (size) => Buffer.alloc(size, counter++)
    try {
        const result = commitVaultMetaTransaction({
            ...harness.paths,
            vault: vault('ignored', 'created-vault'),
            meta: meta('ignored', { hasPIN: true }),
            operation: 'save-vault-password-rotation',
            now: () => Date.parse('2026-04-26T00:00:00.000Z'),
            randomBytes
        })
        const storedVault = readJson(harness.paths.vaultPath)
        const storedMeta = readJson(harness.paths.metaPath)

        assert.equal(storedVault[VAULT_GENERATION_FIELD], result.generationId)
        assert.equal(storedMeta[VAULT_GENERATION_FIELD], result.generationId)
        assert.notEqual(result.generationId, 'ignored')
        assert.equal(existsSync(harness.paths.statePath), false)
    } finally {
        harness.cleanup()
    }
})

test('startup recovery is deterministic across repeated checks', () => {
    const harness = createHarness()
    try {
        const previousVault = vault('gen-old', 'old-vault')
        const previousMeta = meta('gen-old', { hasPIN: false })
        const nextVault = vault('gen-next', 'next-vault')
        const nextMeta = meta('gen-next', { hasPIN: true })

        writeJson(harness.paths.vaultPath, previousVault)
        writeJson(harness.paths.metaPath, previousMeta)
        writeTransaction(harness.paths, pairTransaction({
            previousVault,
            previousMeta,
            nextVault,
            nextMeta,
            operation: 'startup-recovery'
        }))

        const first = recoverVaultDurability(harness.paths)
        const afterFirstVaultHash = hashJson(readJson(harness.paths.vaultPath))
        const afterFirstMetaHash = hashJson(readJson(harness.paths.metaPath))
        const second = recoverVaultDurability(harness.paths)

        assert.equal(first.ok, true)
        assert.equal(first.recovered, true)
        assert.equal(second.ok, true)
        assert.equal(second.recovered, false)
        assert.equal(hashJson(readJson(harness.paths.vaultPath)), afterFirstVaultHash)
        assert.equal(hashJson(readJson(harness.paths.metaPath)), afterFirstMetaHash)
        assert.deepEqual(readJson(harness.paths.vaultPath), nextVault)
        assert.deepEqual(readJson(harness.paths.metaPath), nextMeta)
    } finally {
        harness.cleanup()
    }
})

test('metadata transaction bootstraps generation for legacy vaults', () => {
    const harness = createHarness()
    let counter = 10
    const randomBytes = (size) => Buffer.alloc(size, counter++)
    try {
        const legacyVault = {
            salt: 'legacy-salt',
            iv: 'legacy-iv',
            authTag: 'legacy-tag',
            data: 'legacy-data',
            isHardwareBound: false
        }
        writeJson(harness.paths.vaultPath, legacyVault)

        const result = commitMetadataTransaction({
            ...harness.paths,
            meta: { version: '1.0.0', clearCacheOnExit: false },
            operation: 'update-clear-cache',
            randomBytes
        })

        assert.equal(readJson(harness.paths.vaultPath)[VAULT_GENERATION_FIELD], result.generationId)
        assert.equal(readJson(harness.paths.metaPath)[VAULT_GENERATION_FIELD], result.generationId)
        assert.equal(existsSync(harness.paths.statePath), false)
    } finally {
        harness.cleanup()
    }
})

test('controller immediately recovers same-process transaction failure after marker write', () => {
    const harness = createHarness()
    let randomCall = 0
    const randomBytes = (size) => {
        randomCall += 1
        if (randomCall === 4) throw new Error('simulated crash after marker')
        return Buffer.alloc(size, randomCall)
    }
    const controller = createVaultDurabilityController({
        getPaths: () => harness.paths,
        randomBytes
    })

    try {
        const result = controller.commitVaultMeta({
            vault: vault('ignored', 'next-vault'),
            meta: meta('ignored', { clearCacheOnExit: false }),
            operation: 'same-process-recovery'
        })
        const storedVault = readJson(harness.paths.vaultPath)
        const storedMeta = readJson(harness.paths.metaPath)

        assert.equal(result.recoveredDuringCommit, true)
        assert.equal(controller.getStatus().ok, true)
        assert.equal(controller.getStatus().recovered, true)
        assert.equal(storedVault[VAULT_GENERATION_FIELD], storedMeta[VAULT_GENERATION_FIELD])
        assert.equal(existsSync(harness.paths.statePath), false)
        assert.equal(controller.verifyReady().ok, true)
    } finally {
        harness.cleanup()
    }
})

test('controller marks same-process transaction failure fail-closed when recovery cannot complete', () => {
    const harness = createHarness()
    let randomCall = 0
    const randomBytes = (size) => {
        randomCall += 1
        if (randomCall >= 4) throw new Error('storage unavailable after marker')
        return Buffer.alloc(size, randomCall)
    }
    const controller = createVaultDurabilityController({
        getPaths: () => harness.paths,
        randomBytes
    })

    try {
        assert.throws(() => controller.commitVaultMeta({
            vault: vault('ignored', 'next-vault'),
            meta: meta('ignored', { clearCacheOnExit: false }),
            operation: 'same-process-fail-closed'
        }), /Vault durability check failed/)

        assert.equal(controller.getStatus().ok, false)
        assert.equal(controller.getStatus().status, 'fail-closed')
        assert.equal(existsSync(harness.paths.statePath), true)
        assert.throws(() => controller.verifyReady(), /Vault durability check failed/)
    } finally {
        harness.cleanup()
    }
})

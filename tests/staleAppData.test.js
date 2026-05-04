import assert from 'assert/strict'
import { test } from 'node:test'
import { existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import {
    findStaleUnsupportedAppDataPayloads,
    isSafePayloadDirectory,
    sanitizeStaleAppDataCleanupResultForRenderer,
    sanitizeStaleAppDataPayloadsForRenderer,
    selectStaleAppDataPayloads
} from '../src/main/staleAppData.js'

function withVaultDir(fn) {
    const vaultDir = mkdtempSync(join(tmpdir(), 'wipesnap-stale-appdata-'))
    const cleanup = () => {
        if (existsSync(vaultDir)) rmSync(vaultDir, { recursive: true, force: true })
    }
    try {
        const result = fn(vaultDir)
        if (result && typeof result.then === 'function') {
            return result.finally(cleanup)
        }
        cleanup()
        return result
    } catch (err) {
        cleanup()
        throw err
    }
}

test('AppData payload safety rejects outside paths files and symlink or junction payloads', () => withVaultDir((vaultDir) => {
    const appDataRoot = join(vaultDir, 'AppData')
    const safePayload = join(appDataRoot, 'Safe_App')
    const filePayload = join(appDataRoot, 'Not_A_Directory')
    const outsidePayload = mkdtempSync(join(tmpdir(), 'wipesnap-outside-appdata-'))
    mkdirSync(safePayload, { recursive: true })
    writeFileSync(filePayload, 'not a directory', 'utf-8')

    try {
        assert.equal(isSafePayloadDirectory(appDataRoot, safePayload).safe, true)
        assert.equal(isSafePayloadDirectory(appDataRoot, outsidePayload).safe, false)
        assert.match(isSafePayloadDirectory(appDataRoot, filePayload).reason, /non-directory/i)
    } finally {
        if (existsSync(outsidePayload)) rmSync(outsidePayload, { recursive: true, force: true })
    }

    const target = join(vaultDir, 'Outside_Target')
    const link = join(appDataRoot, 'Linked_Payload')
    mkdirSync(target, { recursive: true })

    let linkCreated = false
    try {
        symlinkSync(target, link, process.platform === 'win32' ? 'junction' : 'dir')
        linkCreated = true
    } catch (_) {
        linkCreated = false
    }

    if (linkCreated) {
        const safety = isSafePayloadDirectory(appDataRoot, link)
        assert.equal(safety.safe, false)
        assert.match(safety.reason, /symbolic-link|junction/i)
    }
}))

test('stale AppData scan is read-only and renderer payloads omit cleanup paths', async () => withVaultDir(async (vaultDir) => {
    const payloadPath = join(vaultDir, 'AppData', 'Orphaned_App')
    mkdirSync(payloadPath, { recursive: true })
    writeFileSync(join(payloadPath, 'settings.json'), '{}', 'utf-8')

    const payloads = await findStaleUnsupportedAppDataPayloads({
        webTabs: [],
        desktopApps: []
    }, vaultDir)
    const rendererPayloads = sanitizeStaleAppDataPayloadsForRenderer(payloads)
    const serialized = JSON.stringify(rendererPayloads)

    assert.equal(payloads.length, 1)
    assert.equal(payloads[0].orphaned, true)
    assert.equal(payloads[0].cleanupBlocked, false)
    assert.equal('path' in payloads[0], true)
    assert.equal('path' in rendererPayloads[0], false)
    assert.equal(existsSync(payloadPath), true)
    assert.equal(serialized.includes(payloadPath), false)
    assert.equal(serialized.includes('settings.json'), false)
}))

test('stale AppData cleanup selection requires explicit valid payload ids', () => {
    const payloads = [
        { id: 'abcdef1234567890', name: 'One' },
        { id: '1234567890abcdef', name: 'Two' }
    ]

    assert.throws(() => selectStaleAppDataPayloads([], payloads), /Select at least one/)
    assert.throws(() => selectStaleAppDataPayloads(['ffffffffffffffff'], payloads), /no longer stale/)
    assert.throws(() => selectStaleAppDataPayloads(['abcdef1234567890', 'ffffffffffffffff'], payloads), /one or more/i)

    assert.deepEqual(selectStaleAppDataPayloads(['abcdef1234567890'], payloads), [payloads[0]])
})

test('stale AppData cleanup success response is metadata-only', () => withVaultDir((vaultDir) => {
    const payloadPath = join(vaultDir, 'AppData', 'Unused_App')
    const payload = {
        id: 'abcdef1234567890',
        name: 'Unused App',
        safeName: 'Unused_App',
        path: payloadPath,
        sizeBytes: 1024,
        sizeMB: 1,
        capabilityId: 'cap_0123456789abcdef0123456789abcdef',
        launchAuthority: { path: payloadPath },
        token: '0123456789abcdef0123456789abcdef01234567'
    }

    const response = sanitizeStaleAppDataCleanupResultForRenderer({
        removed: [payload],
        remainingPayloads: []
    })
    const removed = response.removed[0]
    const serialized = JSON.stringify(response)

    assert.equal(response.success, true)
    assert.equal(response.removedCount, 1)
    assert.equal(response.failedCount, 0)
    assert.equal(removed.status, 'removed')
    assert.equal(removed.reasonCode, 'removed')
    assert.equal(removed.metadataOnly, true)
    for (const forbiddenKey of ['path', 'capabilityId', 'launchAuthority', 'token', 'error']) {
        assert.equal(Object.hasOwn(removed, forbiddenKey), false)
    }
    assert.equal(serialized.includes(payloadPath), false)
    assert.equal(serialized.includes(vaultDir), false)
    assert.equal(serialized.includes('cap_0123456789abcdef0123456789abcdef'), false)
    assert.equal(serialized.includes('0123456789abcdef0123456789abcdef01234567'), false)
}))

test('stale AppData cleanup failure response uses sanitized reason codes', () => withVaultDir((vaultDir) => {
    const payloadPath = join(vaultDir, 'AppData', 'Locked_App')
    const rawError = `EPERM: operation not permitted, rmdir '${payloadPath}'`
    const response = sanitizeStaleAppDataCleanupResultForRenderer({
        failed: [{
            payload: {
                id: '1234567890abcdef',
                name: 'Locked App',
                safeName: 'Locked_App',
                path: payloadPath,
                sizeMB: 2
            },
            status: 'failed',
            reasonCode: 'cleanup-failed',
            error: rawError
        }],
        error: rawError,
        remainingPayloads: [{
            id: 'fedcba0987654321',
            name: 'Blocked App',
            safeName: 'Blocked_App',
            path: join(vaultDir, 'AppData', 'Blocked_App'),
            cleanupBlocked: true,
            cleanupBlockedReason: rawError,
            reason: `No saved app references ${payloadPath}.`
        }]
    })
    const failed = response.failed[0]
    const remaining = response.remainingPayloads[0]
    const serialized = JSON.stringify(response)

    assert.equal(response.success, false)
    assert.equal(response.removedCount, 0)
    assert.equal(response.failedCount, 1)
    assert.equal(response.error, 'Some stale AppData payloads could not be removed.')
    assert.equal(response.errorCode, 'cleanup-failed')
    assert.equal(failed.status, 'failed')
    assert.equal(failed.reasonCode, 'cleanup-failed')
    assert.equal(failed.metadataOnly, true)
    assert.equal(remaining.cleanupBlocked, true)
    assert.equal(remaining.cleanupBlockedReason, 'Cleanup blocked for safety.')
    for (const forbiddenKey of ['path', 'error']) {
        assert.equal(Object.hasOwn(failed, forbiddenKey), false)
        assert.equal(Object.hasOwn(remaining, forbiddenKey), false)
    }
    for (const forbiddenText of [rawError, payloadPath, vaultDir, 'EPERM: operation not permitted']) {
        assert.equal(serialized.includes(forbiddenText), false, `cleanup response leaked ${forbiddenText}`)
    }
}))

test('stale AppData cleanup response does not echo unsafe original payload material', () => {
    const unsafePath = 'C:\\VaultRoot\\AppData\\Unsafe_App'
    const unsafeToken = 'super-secret-token-0123456789abcdef0123456789abcdef'
    const response = sanitizeStaleAppDataCleanupResultForRenderer({
        removed: [{
            id: 'abcdefabcdef1234',
            name: `Unsafe token=${unsafeToken}`,
            safeName: 'Unsafe_App',
            path: unsafePath,
            processId: 4242,
            shellCommand: `Remove-Item ${unsafePath}`,
            vaultRecord: { path: unsafePath, token: unsafeToken },
            sizeMB: 3
        }],
        failed: [{
            payload: {
                id: '1234abcdefabcdef',
                name: 'Blocked Unsafe',
                path: unsafePath,
                capabilityRecord: { authority: unsafePath },
                credentials: unsafeToken,
                sizeMB: 4
            },
            status: 'blocked',
            reasonCode: 'cleanup-blocked',
            error: `Access denied at ${unsafePath} token=${unsafeToken}`
        }]
    })
    const serialized = JSON.stringify(response)

    assert.equal(response.success, false)
    assert.equal(response.removed[0].name.includes(unsafeToken), false)
    assert.equal(response.failed[0].status, 'blocked')
    assert.equal(response.failed[0].reasonCode, 'cleanup-blocked')
    for (const record of [...response.removed, ...response.failed]) {
        for (const forbiddenKey of ['path', 'processId', 'shellCommand', 'vaultRecord', 'capabilityRecord', 'credentials', 'error']) {
            assert.equal(Object.hasOwn(record, forbiddenKey), false)
        }
    }
    for (const forbiddenText of [unsafePath, 'C:\\VaultRoot', unsafeToken, 'Remove-Item', 'Access denied']) {
        assert.equal(serialized.includes(forbiddenText), false, `cleanup response leaked ${forbiddenText}`)
    }
})

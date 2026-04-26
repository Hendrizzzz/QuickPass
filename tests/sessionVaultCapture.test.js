import assert from 'assert/strict'
import { test } from 'node:test'
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import {
    resolveSessionCapturePassword,
    saveCapturedSessionToVault
} from '../src/main/sessionVaultCapture.js'

function createDeps(overrides = {}) {
    const calls = {
        captured: false,
        read: false,
        decryptedWith: null,
        encryptedWith: null,
        wrote: false,
        savedMeta: false
    }

    const deps = {
        input: {},
        vaultExists: true,
        activeMasterPassword: 'active-password',
        capture: async () => {
            calls.captured = true
            return {
                success: true,
                tabCount: 1,
                urls: ['https://example.com']
            }
        },
        readVault: () => {
            calls.read = true
            return { encrypted: true }
        },
        decryptVault: (_encrypted, password) => {
            calls.decryptedWith = password
            return {
                _honeyToken: true,
                webTabs: [{ url: 'https://old.example', enabled: true }],
                desktopApps: [{ name: 'USB App', path: '[USB]\\Apps\\USB_App\\app.exe', enabled: true }]
            }
        },
        encryptVault: (payload, password, driveInfo) => {
            calls.encryptedWith = password
            return { payload, password, driveType: driveInfo.driveType }
        },
        writeVault: () => {
            calls.wrote = true
        },
        getDriveInfo: async () => ({ driveType: 2 }),
        loadMeta: () => ({ version: '1.0.0' }),
        saveMeta: () => {
            calls.savedMeta = true
        },
        mergeMeta: (meta) => meta,
        authorizeWorkspaceLaunchCapabilities: (workspace) => ({ workspace, capabilities: {} }),
        honeyToken: { marker: true },
        validateWorkspace: (workspace) => workspace,
        ...overrides
    }

    return { deps, calls }
}

test('session capture rejects existing vault while locked before capture or write', async () => {
    const { deps, calls } = createDeps({
        activeMasterPassword: '',
        input: { masterPassword: 'renderer-password' }
    })

    await assert.rejects(() => saveCapturedSessionToVault(deps), /Session is locked/)

    assert.equal(calls.captured, false)
    assert.equal(calls.read, false)
    assert.equal(calls.wrote, false)
    assert.equal(calls.savedMeta, false)
})

test('session capture rejects existing vault decrypt failure before capture or write', async () => {
    const { deps, calls } = createDeps({
        decryptVault: () => {
            throw new Error('bad password')
        }
    })

    await assert.rejects(() => saveCapturedSessionToVault(deps), /could not be decrypted/)

    assert.equal(calls.captured, false)
    assert.equal(calls.read, true)
    assert.equal(calls.wrote, false)
    assert.equal(calls.savedMeta, false)
})

test('session capture leaves existing vault file unchanged on decrypt failure', async () => {
    const tempDir = mkdtempSync(join(tmpdir(), 'wipesnap-session-capture-'))
    const vaultPath = join(tempDir, 'vault.json')
    const originalVault = JSON.stringify({ encrypted: 'original' })
    writeFileSync(vaultPath, originalVault, 'utf-8')

    try {
        const { deps, calls } = createDeps({
            readVault: () => JSON.parse(readFileSync(vaultPath, 'utf-8')),
            decryptVault: () => {
                throw new Error('bad password')
            },
            writeVault: (encryptedVault) => {
                calls.wrote = true
                writeFileSync(vaultPath, JSON.stringify(encryptedVault), 'utf-8')
            }
        })

        await assert.rejects(() => saveCapturedSessionToVault(deps), /could not be decrypted/)

        assert.equal(calls.captured, false)
        assert.equal(calls.wrote, false)
        assert.equal(readFileSync(vaultPath, 'utf-8'), originalVault)
    } finally {
        if (existsSync(tempDir)) rmSync(tempDir, { recursive: true, force: true })
    }
})

test('session capture ignores renderer password for existing vault writes', async () => {
    const { deps, calls } = createDeps({
        input: { masterPassword: 'renderer-password' }
    })

    const result = await saveCapturedSessionToVault(deps)

    assert.equal(result.success, true)
    assert.equal(calls.captured, true)
    assert.equal(calls.decryptedWith, 'active-password')
    assert.equal(calls.encryptedWith, 'active-password')
    assert.equal(calls.wrote, true)
    assert.equal(calls.savedMeta, true)
})

test('session capture requires strong renderer password only for no-vault setup', async () => {
    const { deps, calls } = createDeps({
        vaultExists: false,
        activeMasterPassword: '',
        input: { masterPassword: 'short' }
    })

    await assert.rejects(() => saveCapturedSessionToVault(deps), /at least 8 characters/)

    assert.equal(calls.captured, false)
    assert.equal(calls.read, false)
    assert.equal(calls.wrote, false)
})

test('session capture can create a new vault with validated setup password', async () => {
    const { deps, calls } = createDeps({
        vaultExists: false,
        activeMasterPassword: '',
        input: { masterPassword: 'setup-password' },
        decryptVault: () => {
            throw new Error('decrypt should not run for new vault')
        }
    })

    const result = await saveCapturedSessionToVault(deps)

    assert.equal(result.success, true)
    assert.equal(calls.captured, true)
    assert.equal(calls.read, false)
    assert.equal(calls.decryptedWith, null)
    assert.equal(calls.encryptedWith, 'setup-password')
    assert.equal(calls.wrote, true)
})

test('save-current-session mode requires active session before capture', async () => {
    const { deps, calls } = createDeps({
        vaultExists: false,
        activeMasterPassword: '',
        requireActiveSession: true,
        allowNewVaultPassword: false
    })

    await assert.rejects(() => saveCapturedSessionToVault(deps), /Session is locked/)

    assert.equal(calls.captured, false)
    assert.equal(calls.wrote, false)
})

test('session capture password resolver uses active session for existing vaults', () => {
    assert.equal(resolveSessionCapturePassword({
        vaultExists: true,
        activeMasterPassword: 'active-password',
        suppliedMasterPassword: 'renderer-password'
    }), 'active-password')
})

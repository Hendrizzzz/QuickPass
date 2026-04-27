import assert from 'assert/strict'
import { test } from 'node:test'
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import {
    DIAGNOSTICS_FILE_NAME,
    MAX_DIAGNOSTICS_BYTES,
    loadDiagnosticsSummary,
    loadDiagnosticsSummaryHandlerCore
} from '../src/main/diagnosticsView.js'

function withVaultDir(fn) {
    const vaultDir = mkdtempSync(join(tmpdir(), 'wipesnap-diagnostics-view-'))
    try {
        return fn(vaultDir)
    } finally {
        if (existsSync(vaultDir)) rmSync(vaultDir, { recursive: true, force: true })
    }
}

function writeDiagnostics(vaultDir, payload) {
    writeFileSync(join(vaultDir, DIAGNOSTICS_FILE_NAME), JSON.stringify(payload, null, 2), 'utf-8')
}

test('missing diagnostics returns an empty safe state', () => withVaultDir((vaultDir) => {
    const summary = loadDiagnosticsSummary({ vaultDir })

    assert.equal(summary.success, true)
    assert.equal(summary.available, false)
    assert.equal(summary.state, 'missing')
    assert.equal(summary.status, 'missing')
    assert.deepEqual(summary.apps, [])
    assert.deepEqual(summary.warnings, [])
    assert.deepEqual(summary.failures, [])
    assert.equal(JSON.stringify(summary).includes(vaultDir), false)
}))

test('malformed diagnostics fail safely without raw content', () => withVaultDir((vaultDir) => {
    const secret = 'malformed-secret-token'
    writeFileSync(join(vaultDir, DIAGNOSTICS_FILE_NAME), `{ "token": "${secret}",`, 'utf-8')

    const summary = loadDiagnosticsSummary({ vaultDir })
    const serialized = JSON.stringify(summary)

    assert.equal(summary.success, false)
    assert.equal(summary.available, false)
    assert.equal(summary.state, 'malformed')
    assert.equal(serialized.includes(secret), false)
    assert.equal(serialized.includes(vaultDir), false)
}))

test('diagnostics with an invalid shape fail safely', () => withVaultDir((vaultDir) => {
    writeDiagnostics(vaultDir, {
        cycleType: 'launch',
        cycleStartTime: 1,
        phases: { name: 'not-an-array' }
    })

    const summary = loadDiagnosticsSummary({ vaultDir })

    assert.equal(summary.success, false)
    assert.equal(summary.state, 'malformed')
    assert.deepEqual(summary.apps, [])
    assert.deepEqual(summary.failures, [])
}))

test('oversized diagnostics are rejected before parsing', () => withVaultDir((vaultDir) => {
    const secret = 'oversized-secret-token'
    const content = `${secret}\n${'x'.repeat(MAX_DIAGNOSTICS_BYTES + 1)}`
    writeFileSync(join(vaultDir, DIAGNOSTICS_FILE_NAME), content, 'utf-8')

    const summary = loadDiagnosticsSummary({ vaultDir })
    const serialized = JSON.stringify(summary)

    assert.equal(summary.success, false)
    assert.equal(summary.state, 'oversized')
    assert.equal(summary.maxBytes, MAX_DIAGNOSTICS_BYTES)
    assert.equal(serialized.includes(secret), false)
}))

test('diagnostics summary sanitizes raw authority, paths, URLs, and secrets', () => withVaultDir((vaultDir) => {
    const secret = 'super-secret-token-1234567890abcdef1234567890abcdef'
    writeDiagnostics(vaultDir, {
        machineId: 'machine-id-not-needed',
        osVersion: '10.0.0',
        startTime: 111,
        cycleId: 'cycle-1',
        cycleType: 'launch',
        cycleStartTime: 222,
        phases: [
            {
                name: 'launch',
                status: 'ok',
                detail: `Opened C:\\Users\\Alice\\AppData\\vault.json token=${secret}`
            }
        ],
        appResults: [
            {
                name: 'Sensitive App',
                status: 'failed',
                launchStage: 'spawning',
                error: `Failed to spawn C:\\Users\\Alice\\vault.meta.json token=${secret}`,
                exePath: 'C:\\Users\\Alice\\secret.exe',
                attemptedPath: 'C:\\Users\\Alice\\secret.exe',
                resolvedPath: 'C:\\Users\\Alice\\secret.exe',
                archivePath: 'C:\\Vault\\Apps\\Sensitive.tar.zst',
                runtimeProfilePath: 'C:\\Users\\Alice\\AppData\\Local\\Temp\\Wipesnap-AppRuntime-Sensitive',
                spawnCwd: 'C:\\Users\\Alice',
                launchArgs: [`--token=${secret}`],
                rawLaunchAuthority: { path: 'C:\\Users\\Alice\\secret.exe', token: secret },
                capabilityVault: { data: secret },
                pinVault: { data: secret },
                fastBootVault: { data: secret },
                helperCiphertext: secret,
                supportTier: 'verified',
                launchSourceType: 'host-exe',
                launchMethod: 'spawn',
                availabilityStatus: 'available',
                readiness: {
                    status: 'failed',
                    failureReason: `cookie=${secret}`
                }
            }
        ],
        browserSync: {
            copyInMs: 12,
            copyOutMs: 34,
            migrated: true,
            helperCiphertext: secret
        },
        runtimeChecks: {
            extractor: {
                checked: true,
                tarAvailable: true,
                zstdSupported: false,
                detail: `secret=${secret}`
            }
        },
        webResults: [
            {
                tabIndex: 1,
                url: `https://example.com/callback?token=${secret}`,
                normalizedUrl: `https://example.com/callback?token=${secret}`,
                finalUrl: `https://example.com/callback?token=${secret}`,
                success: false,
                error: `cookie=${secret} C:\\Users\\Alice\\BrowserProfile`,
                errors: [{ message: `auth=${secret}` }]
            }
        ],
        errors: [
            {
                context: 'launch-workspace',
                message: `password=${secret} C:\\Users\\Alice\\vault.state.json`
            }
        ],
        vaultMeta: { pinVault: secret },
        launchCapabilities: { authority: secret }
    })

    const summary = loadDiagnosticsSummary({ vaultDir })
    const serialized = JSON.stringify(summary)

    assert.equal(summary.success, true)
    assert.equal(summary.available, true)
    assert.equal(summary.state, 'ready')
    assert.equal(summary.status, 'failed')
    assert.equal(summary.lastLaunch.type, 'launch')
    assert.equal(summary.browser.failed, 1)
    assert.equal(summary.apps[0].name, 'Sensitive App')

    for (const forbidden of [
        secret,
        'C:\\Users',
        'vault.json',
        'vault.meta.json',
        'vault.state.json',
        'BrowserProfile',
        'rawLaunchAuthority',
        'capabilityVault',
        'pinVault',
        'fastBootVault',
        'helperCiphertext',
        'launchArgs',
        'https://example.com/callback?token='
    ]) {
        assert.equal(serialized.includes(forbidden), false, `summary leaked ${forbidden}`)
    }

    for (const forbiddenKey of ['exePath', 'attemptedPath', 'resolvedPath', 'archivePath', 'runtimeProfilePath', 'spawnCwd']) {
        assert.equal(Object.hasOwn(summary.apps[0], forbiddenKey), false)
    }
}))

test('diagnostics summary allowlists status-like fields before returning them', () => withVaultDir((vaultDir) => {
    const secret = '0123456789abcdef0123456789abcdef01234567'
    writeDiagnostics(vaultDir, {
        cycleType: secret,
        cycleStartTime: 333,
        phases: [
            {
                name: 'status probe',
                status: secret,
                detail: `status detail ${secret}`
            }
        ],
        appResults: [
            {
                name: 'Status Probe App',
                diagnosticRole: secret,
                status: secret,
                launchStage: secret,
                supportTier: secret,
                launchSourceType: secret,
                launchMethod: secret,
                availabilityStatus: secret,
                closeMethod: secret,
                launchVerifiedBy: secret,
                importedDataSupportLevel: secret,
                archivePolicyStatus: secret,
                readiness: {
                    status: secret,
                    failureReason: `readiness ${secret}`
                },
                error: `app ${secret}`
            }
        ],
        webResults: [
            {
                tabIndex: 1,
                success: false,
                skipped: true,
                reason: secret,
                error: `browser ${secret}`
            }
        ],
        errors: [
            {
                context: `context ${secret}`,
                message: `message ${secret}`
            }
        ]
    })

    const summary = loadDiagnosticsSummary({ vaultDir })
    const serialized = JSON.stringify(summary)
    const app = summary.apps[0]
    const tab = summary.browser.tabs[0]

    assert.equal(summary.success, true)
    assert.equal(serialized.includes(secret), false)
    assert.equal(summary.lastRun.type, 'run')
    assert.equal(summary.lastLaunch, null)
    assert.equal(summary.phases[0].status, 'unknown')
    assert.equal(app.role, 'launch')
    assert.equal(app.status, 'unknown')
    assert.equal(app.stage, 'unknown')
    assert.equal(app.readinessStatus, 'unknown')
    assert.equal(app.supportTier, 'unknown')
    assert.equal(app.launchSourceType, 'unknown')
    assert.equal(app.launchMethod, 'unknown')
    assert.equal(app.availabilityStatus, 'unknown')
    assert.equal(app.closeMethod, 'none')
    assert.equal(app.launchVerifiedBy, 'unknown')
    assert.equal(app.importedDataSupportLevel, 'unknown')
    assert.equal(app.archivePolicyStatus, 'unknown')
    assert.equal(tab.reason, '')
    assert.equal(summary.failures.some(item => JSON.stringify(item).includes(secret)), false)
    assert.equal(summary.warnings.some(item => JSON.stringify(item).includes(secret)), false)
}))

test('diagnostics handler rejects locked state before reading diagnostics', () => {
    let getVaultDirCalled = false
    const summary = loadDiagnosticsSummaryHandlerCore({
        input: undefined,
        deps: {
            requireActiveSession: () => {
                throw new Error('Session is locked')
            },
            getVaultDir: () => {
                getVaultDirCalled = true
                return 'C:\\ShouldNotRead'
            }
        }
    })

    assert.equal(summary.success, false)
    assert.equal(summary.state, 'locked')
    assert.equal(getVaultDirCalled, false)
})

test('diagnostics handler rejects renderer-supplied paths', () => withVaultDir((vaultDir) => {
    const attackerDir = mkdtempSync(join(tmpdir(), 'wipesnap-diagnostics-attacker-'))
    try {
        writeDiagnostics(attackerDir, {
            cycleType: 'launch',
            cycleStartTime: 1,
            errors: [{ context: 'attacker', message: 'attacker-secret' }]
        })

        let getVaultDirCalled = false
        const summary = loadDiagnosticsSummaryHandlerCore({
            input: { path: join(attackerDir, DIAGNOSTICS_FILE_NAME) },
            deps: {
                requireActiveSession: () => {},
                getVaultDir: () => {
                    getVaultDirCalled = true
                    return vaultDir
                }
            }
        })

        const serialized = JSON.stringify(summary)
        assert.equal(summary.success, false)
        assert.equal(summary.state, 'invalid-request')
        assert.equal(getVaultDirCalled, false)
        assert.equal(serialized.includes('attacker-secret'), false)
        assert.equal(serialized.includes(attackerDir), false)
    } finally {
        if (existsSync(attackerDir)) rmSync(attackerDir, { recursive: true, force: true })
    }
}))

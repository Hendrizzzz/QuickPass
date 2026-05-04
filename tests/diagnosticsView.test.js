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

test('diagnostics lifecycle reports sync-back failure and cleanup blocked with safe guidance', () => withVaultDir((vaultDir) => {
    const secretPath = 'C:\\Users\\Alice\\AppData\\Local\\Wipesnap'
    writeDiagnostics(vaultDir, {
        cycleType: 'launch',
        cycleStartTime: 444,
        phases: [
            { name: 'launch-started', status: 'ok' },
            { name: 'workspace-running', status: 'ok' },
            { name: 'quit-requested', status: 'ok' },
            { name: 'browser-copy-out', status: 'ok' },
            { name: 'workspace-cleanup', status: 'warning', detail: `blocked ${secretPath}` }
        ],
        browserSync: {
            copyInMs: 10,
            copyOutMs: 20
        },
        appResults: [{
            name: 'Portable App',
            diagnosticRole: 'cleanup',
            status: 'ok',
            launchStage: 'ok',
            runtimeProfileSynced: true,
            appSessionSyncBackStatus: 'failed',
            appSessionSyncBackError: `Copy failed at ${secretPath}`,
            cleanupSkippedForSafety: true,
            cleanupSafetyReason: `Live process still references ${secretPath}`
        }]
    })

    const summary = loadDiagnosticsSummary({ vaultDir })
    const serialized = JSON.stringify(summary)

    assert.equal(summary.success, true)
    assert.equal(summary.lifecycle.launchStarted, true)
    assert.equal(summary.lifecycle.workspaceRunning, true)
    assert.equal(summary.lifecycle.quitRequested, true)
    assert.equal(summary.lifecycle.browserSyncBack.status, 'completed')
    assert.equal(summary.lifecycle.appSessionSyncBack.status, 'failed')
    assert.equal(summary.lifecycle.cleanup.status, 'blocked')
    assert.equal(summary.lifecycle.finalState, 'action-needed')
    assert.match(summary.lifecycle.recoveryGuidance, /review diagnostics before unplugging/i)
    assert.equal(summary.failures.some(item => item.scope === 'sync-back'), true)
    assert.equal(serialized.includes(secretPath), false)
    assert.equal(serialized.includes('AppData'), false)
}))

test('diagnostics lifecycle reports cleanup deferred without implying safe unplug', () => withVaultDir((vaultDir) => {
    writeDiagnostics(vaultDir, {
        cycleType: 'launch',
        cycleStartTime: 555,
        phases: [
            { name: 'launch-started', status: 'ok' },
            { name: 'workspace-running', status: 'ok' },
            { name: 'quit-requested', status: 'ok' },
            { name: 'browser-copy-out', status: 'ok' },
            { name: 'workspace-cleanup', status: 'warning' }
        ],
        browserSync: {
            copyInMs: 5,
            copyOutMs: 15
        },
        appResults: [{
            name: 'Runtime Only App',
            diagnosticRole: 'cleanup',
            status: 'ok',
            launchStage: 'ok',
            runtimeProfileSynced: false,
            runtimeProfileWipeSkippedForSafety: true,
            runtimeProfileWipeSafetyReason: 'Known owned processes are still alive after shutdown.'
        }]
    })

    const summary = loadDiagnosticsSummary({ vaultDir })

    assert.equal(summary.lifecycle.browserSyncBack.status, 'completed')
    assert.equal(summary.lifecycle.appSessionSyncBack.status, 'not-run')
    assert.equal(summary.lifecycle.cleanup.status, 'deferred')
    assert.equal(summary.lifecycle.finalState, 'cleanup-deferred')
    assert.match(summary.lifecycle.recoveryGuidance, /before unplugging/i)
}))

test('diagnostics lifecycle keeps null and missing browser copy-out unknown after quit', () => {
    for (const browserSync of [
        { copyInMs: 5, copyOutMs: null },
        { copyInMs: 5 }
    ]) {
        withVaultDir((vaultDir) => {
            writeDiagnostics(vaultDir, {
                cycleType: 'launch',
                cycleStartTime: 600,
                phases: [
                    { name: 'launch-started', status: 'ok' },
                    { name: 'workspace-running', status: 'ok' },
                    { name: 'quit-requested', status: 'ok' },
                    { name: 'workspace-cleanup', status: 'ok' }
                ],
                browserSync,
                webResults: [{
                    tabIndex: 1,
                    success: true
                }],
                appResults: [{
                    name: 'Closed App',
                    diagnosticRole: 'cleanup',
                    status: 'ok',
                    launchStage: 'ok',
                    closeMethod: 'graceful'
                }]
            })

            const summary = loadDiagnosticsSummary({ vaultDir })

            assert.equal(summary.browser.copyOutMs, null)
            assert.equal(summary.lifecycle.browserSyncBack.status, 'unknown')
            assert.equal(summary.lifecycle.cleanup.status, 'completed')
            assert.equal(summary.lifecycle.finalState, 'action-needed')
            assert.notEqual(summary.lifecycle.finalState, 'synced')
            assert.equal(/Last diagnostics show sync-back and cleanup completed/i.test(summary.lifecycle.recoveryGuidance), false)
        })
    }
})

test('diagnostics lifecycle does not mark mixed completed and unknown sync channels as synced', () => withVaultDir((vaultDir) => {
    writeDiagnostics(vaultDir, {
        cycleType: 'launch',
        cycleStartTime: 610,
        phases: [
            { name: 'launch-started', status: 'ok' },
            { name: 'workspace-running', status: 'ok' },
            { name: 'quit-requested', status: 'ok' },
            { name: 'workspace-cleanup', status: 'ok' }
        ],
        browserSync: {
            copyInMs: 7
        },
        webResults: [{
            tabIndex: 1,
            success: true
        }],
        appResults: [{
            name: 'Synced App',
            diagnosticRole: 'cleanup',
            status: 'ok',
            launchStage: 'ok',
            closeMethod: 'graceful',
            runtimeProfileSynced: true,
            appSessionSyncBackStatus: 'completed'
        }]
    })

    const summary = loadDiagnosticsSummary({ vaultDir })

    assert.equal(summary.lifecycle.browserSyncBack.status, 'unknown')
    assert.equal(summary.lifecycle.appSessionSyncBack.status, 'completed')
    assert.equal(summary.lifecycle.cleanup.status, 'completed')
    assert.equal(summary.lifecycle.finalState, 'action-needed')
    assert.notEqual(summary.lifecycle.finalState, 'synced')
    assert.match(summary.lifecycle.recoveryGuidance, /needs attention/i)
}))

test('just-launched diagnostics without quit or copy-out do not report synced or cleanup completed', () => withVaultDir((vaultDir) => {
    writeDiagnostics(vaultDir, {
        cycleType: 'launch',
        cycleStartTime: 620,
        phases: [
            { name: 'launch-started', status: 'ok' },
            { name: 'workspace-running', status: 'ok' }
        ],
        browserSync: {
            copyInMs: 8,
            copyOutMs: null
        },
        webResults: [{
            tabIndex: 1,
            success: true
        }]
    })

    const summary = loadDiagnosticsSummary({ vaultDir })

    assert.equal(summary.lifecycle.quitRequested, false)
    assert.equal(summary.lifecycle.browserSyncBack.status, 'not-run')
    assert.equal(summary.lifecycle.cleanup.status, 'not-run')
    assert.equal(summary.lifecycle.finalState, 'unknown')
    assert.notEqual(summary.lifecycle.finalState, 'synced')
    assert.notEqual(summary.lifecycle.finalState, 'cleanup-completed')
    assert.equal(/Last diagnostics show sync-back and cleanup completed|Cleanup completed/i.test(summary.lifecycle.recoveryGuidance), false)
}))

test('unknown sync-back guidance does not use completed guidance', () => withVaultDir((vaultDir) => {
    writeDiagnostics(vaultDir, {
        cycleType: 'launch',
        cycleStartTime: 630,
        phases: [
            { name: 'launch-started', status: 'ok' },
            { name: 'workspace-running', status: 'ok' },
            { name: 'quit-requested', status: 'ok' },
            { name: 'workspace-cleanup', status: 'ok' }
        ],
        browserSync: {
            copyInMs: 9
        },
        webResults: [{
            tabIndex: 1,
            success: true
        }],
        appResults: [{
            name: 'Cleanup App',
            diagnosticRole: 'cleanup',
            status: 'ok',
            launchStage: 'ok',
            closeMethod: 'graceful'
        }]
    })

    const summary = loadDiagnosticsSummary({ vaultDir })

    assert.equal(summary.lifecycle.browserSyncBack.status, 'unknown')
    assert.equal(summary.lifecycle.finalState, 'action-needed')
    assert.match(summary.lifecycle.recoveryGuidance, /needs attention/i)
    assert.equal(/Last diagnostics show sync-back and cleanup completed|Cleanup completed/i.test(summary.lifecycle.recoveryGuidance), false)
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

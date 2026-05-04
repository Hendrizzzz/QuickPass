import assert from 'assert/strict'
import { test } from 'node:test'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import {
    beginDiagnosticsCycle,
    closeBrowser,
    launchChromeForTests,
    resetBrowserLifecycleStateForTests,
    runDiagnostics
} from '../src/main/engine.js'
import {
    DIAGNOSTICS_FILE_NAME,
    loadDiagnosticsSummary
} from '../src/main/diagnosticsView.js'

async function withVaultDir(fn) {
    const vaultDir = mkdtempSync(join(tmpdir(), 'wipesnap-engine-browser-'))
    try {
        return await fn(vaultDir)
    } finally {
        rmSync(vaultDir, { recursive: true, force: true })
    }
}

test('browser profile copy-in failure blocks launch and cannot copy partial local data back', async () => {
    await withVaultDir(async (vaultDir) => {
        resetBrowserLifecycleStateForTests()
        beginDiagnosticsCycle('launch')

        const usbProfile = join(vaultDir, 'BrowserProfile')
        const usbDefault = join(usbProfile, 'Default')
        mkdirSync(usbDefault, { recursive: true })
        writeFileSync(join(usbDefault, 'portable.txt'), 'portable-profile', 'utf-8')

        const secretToken = '0123456789abcdef0123456789abcdef01234567'
        const statuses = []
        const copyCalls = []
        let localProfile = ''
        let launchCalls = 0
        const ops = {
            mkdirSync,
            rmSync,
            robocopyAsync: async (src, dest) => {
                copyCalls.push({ src, dest })
                localProfile = dest
                mkdirSync(join(dest, 'Default'), { recursive: true })
                writeFileSync(join(dest, 'Default', 'partial-stale.txt'), 'partial-local-profile', 'utf-8')
                throw new Error(`robocopy failed at ${join(src, 'Default')} token=${secretToken}`)
            },
            launchPersistentContext: async () => {
                launchCalls += 1
                return {
                    browser: () => ({ close: async () => {} }),
                    close: async () => {},
                    pages: () => []
                }
            }
        }

        try {
            await assert.rejects(
                () => launchChromeForTests(vaultDir, (status) => statuses.push(status), ops),
                /Browser profile copy-in failed/
            )
            await closeBrowser(ops)

            assert.equal(launchCalls, 0)
            assert.equal(copyCalls.length, 1)
            assert.equal(readFileSync(join(usbDefault, 'portable.txt'), 'utf-8'), 'portable-profile')
            assert.equal(existsSync(join(usbDefault, 'partial-stale.txt')), false)
            assert.equal(localProfile ? existsSync(localProfile) : false, false)
            assert.equal(runDiagnostics.browserSync.copyOutMs, null)
            assert.equal(runDiagnostics.phases.some(phase => phase.name === 'browser-copy-out'), false)
            assert.equal(statuses.some(status => /blocked to protect the portable profile/i.test(status)), true)

            const copyInPhase = runDiagnostics.phases.find(phase => phase.name === 'browser-copy-in')
            assert.equal(copyInPhase?.status, 'failed')
            assert.match(copyInPhase?.detail || '', /blocked to protect the portable profile/i)
            assert.equal((copyInPhase?.detail || '').includes(usbProfile), false)
            assert.equal((copyInPhase?.detail || '').includes(secretToken), false)

            writeFileSync(join(vaultDir, DIAGNOSTICS_FILE_NAME), JSON.stringify(runDiagnostics), 'utf-8')
            const summary = loadDiagnosticsSummary({ vaultDir })
            const serialized = JSON.stringify(summary)

            assert.equal(summary.status, 'failed')
            assert.equal(summary.failures.some(item => item.scope === 'phase' && item.name === 'browser-copy-in'), true)
            assert.equal(serialized.includes(usbProfile), false)
            assert.equal(serialized.includes(localProfile), false)
            assert.equal(serialized.includes('BrowserProfile'), false)
            assert.equal(serialized.includes(secretToken), false)
        } finally {
            resetBrowserLifecycleStateForTests()
        }
    })
})

test('browser launch failure after successful copy-in does not authorize copy-out', async () => {
    await withVaultDir(async (vaultDir) => {
        resetBrowserLifecycleStateForTests()
        beginDiagnosticsCycle('launch')

        const usbProfile = join(vaultDir, 'BrowserProfile')
        const usbDefault = join(usbProfile, 'Default')
        mkdirSync(usbDefault, { recursive: true })
        writeFileSync(join(usbDefault, 'portable.txt'), 'portable-profile', 'utf-8')

        const secretToken = 'abcdef0123456789abcdef0123456789abcdef01'
        const secretPath = join(usbProfile, 'Default')
        const copyCalls = []
        let localProfile = ''
        let launchCalls = 0
        const ops = {
            mkdirSync,
            rmSync,
            cleanProfileLocks: () => {},
            handleProfileMigration: () => false,
            patchProfileLocale: () => {},
            robocopyAsync: async (src, dest) => {
                copyCalls.push({ src, dest })
                if (copyCalls.length === 1) {
                    localProfile = dest
                    mkdirSync(join(dest, 'Default'), { recursive: true })
                    writeFileSync(join(dest, 'Default', 'copied-local.txt'), 'copied-local-profile', 'utf-8')
                    return
                }
                mkdirSync(join(dest, 'Default'), { recursive: true })
                writeFileSync(join(dest, 'Default', 'local-overwrite.txt'), 'unsafe-copy-out', 'utf-8')
            },
            launchPersistentContext: async () => {
                launchCalls += 1
                throw new Error(`Chrome failed at ${secretPath} token=${secretToken}`)
            }
        }

        try {
            await assert.rejects(
                () => launchChromeForTests(vaultDir, () => {}, ops),
                /Browser launch failed/
            )
            await closeBrowser(ops)

            assert.equal(launchCalls, 2)
            assert.equal(copyCalls.length, 1)
            assert.equal(readFileSync(join(usbDefault, 'portable.txt'), 'utf-8'), 'portable-profile')
            assert.equal(existsSync(join(usbDefault, 'local-overwrite.txt')), false)
            assert.equal(localProfile ? existsSync(localProfile) : false, false)
            assert.equal(runDiagnostics.browserSync.copyOutMs, null)
            assert.equal(runDiagnostics.phases.some(phase => phase.name === 'browser-copy-out'), false)

            const launchPhase = runDiagnostics.phases.find(phase => phase.name === 'browser-launch')
            assert.equal(launchPhase?.status, 'failed')
            assert.equal((launchPhase?.detail || '').includes(secretPath), false)
            assert.equal((launchPhase?.detail || '').includes(secretToken), false)

            writeFileSync(join(vaultDir, DIAGNOSTICS_FILE_NAME), JSON.stringify(runDiagnostics), 'utf-8')
            const summary = loadDiagnosticsSummary({ vaultDir })
            const serialized = JSON.stringify(summary)

            assert.equal(summary.status, 'failed')
            assert.equal(summary.failures.some(item => item.scope === 'phase' && item.name === 'browser-launch'), true)
            assert.equal(serialized.includes(secretPath), false)
            assert.equal(serialized.includes(localProfile), false)
            assert.equal(serialized.includes('BrowserProfile'), false)
            assert.equal(serialized.includes(secretToken), false)
        } finally {
            resetBrowserLifecycleStateForTests()
        }
    })
})

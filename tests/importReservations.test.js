import assert from 'assert/strict'
import { spawn } from 'child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import { test } from 'node:test'
import { pathToFileURL } from 'url'
import {
    IMPORT_RESERVATION_SCHEMA_VERSION,
    createImportedAppLookup,
    reserveAppStorageId
} from '../src/main/importReservations.js'
import { APP_MANIFEST_SUFFIX, LEGACY_APP_MANIFEST_SUFFIX } from '../src/main/appManifest.js'

function createTempVault() {
    const vaultDir = mkdtempSync(join(tmpdir(), 'wipesnap-import-reservations-'))
    mkdirSync(join(vaultDir, 'Apps'), { recursive: true })
    return vaultDir
}

function removeTempVault(vaultDir) {
    rmSync(vaultDir, { recursive: true, force: true })
}

function readJson(filePath) {
    return JSON.parse(readFileSync(filePath, 'utf-8'))
}

function writeReservation(vaultDir, storageId, payload) {
    const reservationsDir = join(vaultDir, 'Apps', '.reservations')
    mkdirSync(reservationsDir, { recursive: true })
    const lockPath = join(reservationsDir, `${storageId}.lock`)
    writeFileSync(lockPath, `${JSON.stringify({
        schemaVersion: IMPORT_RESERVATION_SCHEMA_VERSION,
        reservationId: `${storageId}-reservation`,
        operation: 'test-import',
        displayName: storageId,
        storageId,
        pid: process.pid,
        createdAt: new Date(payload.createdAtMs).toISOString(),
        ...payload
    }, null, 2)}\n`, 'utf-8')
    return lockPath
}

function startReservationWorker(vaultDir, workerId) {
    const moduleUrl = pathToFileURL(join(process.cwd(), 'src/main/importReservations.js')).href
    const script = `
const { reserveAppStorageId } = await import(${JSON.stringify(moduleUrl)});
try {
    const reservation = reserveAppStorageId(process.env.TEST_VAULT_DIR, 'Concurrent App', {
        operation: 'test-concurrent-import',
        staleMs: 60000
    });
    process.stdout.write(JSON.stringify({
        workerId: process.env.TEST_WORKER_ID,
        storageId: reservation.storageId
    }) + '\\n');
    let released = false;
    const releaseAndExit = () => {
        if (released) return;
        released = true;
        reservation.release();
        process.exit(0);
    };
    process.stdin.resume();
    process.stdin.on('data', releaseAndExit);
    process.stdin.on('end', releaseAndExit);
    setTimeout(() => {
        process.stderr.write('timed out waiting for parent release');
        reservation.release();
        process.exit(2);
    }, 10000);
} catch (err) {
    process.stderr.write(err?.stack || err?.message || String(err));
    process.exitCode = 1;
}
`

    const child = spawn(process.execPath, ['--input-type=module', '-e', script], {
        env: {
            ...process.env,
            TEST_VAULT_DIR: vaultDir,
            TEST_WORKER_ID: String(workerId)
        },
        stdio: ['pipe', 'pipe', 'pipe']
    })
    let stdout = ''
    let stderr = ''
    let reported = false
    let rejectReport = null
    const timeout = setTimeout(() => {
        child.kill()
        if (!reported && rejectReport) {
            rejectReport(new Error(`reservation worker ${workerId} timed out`))
        }
    }, 15000)

    const report = new Promise((resolve, reject) => {
        rejectReport = reject
        child.stdout.on('data', chunk => {
            stdout += chunk.toString()
            const line = stdout.trim().split(/\r?\n/).filter(Boolean).at(-1)
            if (!line || reported) return
            try {
                const payload = JSON.parse(line)
                reported = true
                resolve(payload)
            } catch (err) {
                reject(err)
            }
        })
        child.on('error', reject)
    })

    const close = new Promise((resolve, reject) => {
        child.stderr.on('data', chunk => {
            stderr += chunk.toString()
        })
        child.on('error', err => {
            clearTimeout(timeout)
            reject(err)
        })
        child.on('close', code => {
            clearTimeout(timeout)
            if (code !== 0) {
                const err = new Error(`reservation worker ${workerId} exited ${code}: ${stderr}`)
                if (!reported && rejectReport) rejectReport(err)
                reject(err)
                return
            }
            if (!reported && rejectReport) {
                rejectReport(new Error(`reservation worker ${workerId} did not report a storage id`))
            }
            resolve()
        })
    })

    return {
        report,
        close,
        release() {
            if (!child.killed && child.stdin.writable) {
                child.stdin.end('release\n')
            }
        }
    }
}

test('concurrent reservation simulation cannot allocate duplicate storage ids', async () => {
    const vaultDir = createTempVault()
    const workers = Array.from({ length: 8 }, (_, index) => startReservationWorker(vaultDir, index))
    try {
        const results = await Promise.all(workers.map(worker => worker.report))
        const storageIds = results.map(result => result.storageId)
        const uniqueStorageIds = new Set(storageIds)

        assert.equal(uniqueStorageIds.size, storageIds.length)
        assert.equal(uniqueStorageIds.has('Concurrent_App'), true)
        for (let suffix = 2; suffix <= 8; suffix += 1) {
            assert.equal(uniqueStorageIds.has(`Concurrent_App-${suffix}`), true)
        }
    } finally {
        for (const worker of workers) worker.release()
        await Promise.allSettled(workers.map(worker => worker.close))
        removeTempVault(vaultDir)
    }
})

test('stale reservation is cleaned after threshold and replaced with fresh metadata', () => {
    const vaultDir = createTempVault()
    try {
        const oldCreatedAtMs = 1000
        const lockPath = writeReservation(vaultDir, 'Stale_App', {
            reservationId: 'old-reservation',
            operation: 'old-import',
            displayName: 'Stale App',
            createdAtMs: oldCreatedAtMs
        })

        const reservation = reserveAppStorageId(vaultDir, 'Stale App', {
            staleMs: 5000,
            now: () => oldCreatedAtMs + 6000
        })
        const metadata = readJson(lockPath)

        assert.equal(reservation.storageId, 'Stale_App')
        assert.equal(metadata.schemaVersion, IMPORT_RESERVATION_SCHEMA_VERSION)
        assert.equal(metadata.operation, 'import-app')
        assert.equal(metadata.displayName, 'Stale App')
        assert.equal(metadata.storageId, 'Stale_App')
        assert.notEqual(metadata.reservationId, 'old-reservation')
        assert.equal(typeof metadata.createdAtMs, 'number')
        assert.equal(reservation.release(), true)
        assert.equal(existsSync(lockPath), false)
    } finally {
        removeTempVault(vaultDir)
    }
})

test('active reservation is not stolen before stale threshold', () => {
    const vaultDir = createTempVault()
    try {
        const createdAtMs = 10000
        const activeLockPath = writeReservation(vaultDir, 'Active_App', {
            reservationId: 'active-reservation',
            operation: 'active-import',
            displayName: 'Active App',
            createdAtMs
        })

        const reservation = reserveAppStorageId(vaultDir, 'Active App', {
            staleMs: 60000,
            now: () => createdAtMs + 1000
        })

        assert.equal(reservation.storageId, 'Active_App-2')
        assert.equal(readJson(activeLockPath).reservationId, 'active-reservation')
        assert.equal(existsSync(activeLockPath), true)
        assert.equal(reservation.release(), true)
        assert.equal(existsSync(activeLockPath), true)
    } finally {
        removeTempVault(vaultDir)
    }
})

test('reservation release does not remove a replacement lock without matching ownership', () => {
    const vaultDir = createTempVault()
    try {
        const reservation = reserveAppStorageId(vaultDir, 'Replacement Guarded App')
        writeFileSync(reservation.lockPath, `${JSON.stringify({
            schemaVersion: IMPORT_RESERVATION_SCHEMA_VERSION,
            operation: 'replacement-import',
            displayName: 'Replacement Guarded App',
            storageId: reservation.storageId,
            pid: process.pid,
            createdAt: new Date().toISOString(),
            createdAtMs: Date.now()
        }, null, 2)}\n`, 'utf-8')

        assert.equal(reservation.release(), false)
        assert.equal(existsSync(reservation.lockPath), true)
    } finally {
        removeTempVault(vaultDir)
    }
})

test('suffixed imported app is reported already imported from current and legacy manifests', () => {
    const vaultDir = createTempVault()
    try {
        writeFileSync(join(vaultDir, 'Apps', `Suffixed_App-2${APP_MANIFEST_SUFFIX}`), `${JSON.stringify({
            schemaVersion: 2,
            manifestId: 'Suffixed_App-2',
            safeName: 'Suffixed_App-2',
            displayName: 'Suffixed App',
            archiveName: 'Suffixed_App-2.tar.zst',
            selectedExecutable: { relativePath: 'app.exe' }
        }, null, 2)}\n`, 'utf-8')
        writeFileSync(join(vaultDir, 'Apps', `Legacy_App-2${LEGACY_APP_MANIFEST_SUFFIX}`), `${JSON.stringify({
            schemaVersion: 2,
            manifestId: 'Legacy_App-2',
            safeName: 'Legacy_App-2',
            displayName: 'Legacy App',
            archiveName: 'Legacy_App-2.tar.zst',
            selectedExecutable: { relativePath: 'legacy.exe' }
        }, null, 2)}\n`, 'utf-8')
        mkdirSync(join(vaultDir, 'Apps', 'Storage_Only_App-2'), { recursive: true })

        const importedApps = createImportedAppLookup(vaultDir)

        assert.equal(importedApps.alreadyImported('Suffixed App'), true)
        assert.equal(importedApps.alreadyImported('Legacy App'), true)
        assert.equal(importedApps.alreadyImported('Storage Only App'), true)
        assert.equal(importedApps.alreadyImported('Not Imported App'), false)
    } finally {
        removeTempVault(vaultDir)
    }
})

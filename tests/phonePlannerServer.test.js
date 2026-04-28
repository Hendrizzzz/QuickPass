import assert from 'assert/strict'
import http from 'http'
import { createRequire } from 'module'
import { test } from 'node:test'
import path from 'path'

const require = createRequire(import.meta.url)
const packageJson = require('../package.json')
const {
    PHONE_PLANNER_STATIC_ROOT,
    parseArgs,
    resolvePhonePlannerRequest,
    startPhonePlannerServer
} = require('../scripts/phone-planner-server.cjs')

function request(url, { method = 'GET' } = {}) {
    return new Promise((resolve, reject) => {
        const req = http.request(url, { method }, res => {
            const chunks = []
            res.on('data', chunk => chunks.push(chunk))
            res.on('end', () => {
                resolve({
                    statusCode: res.statusCode,
                    headers: res.headers,
                    body: Buffer.concat(chunks).toString('utf8')
                })
            })
        })
        req.on('error', reject)
        req.end()
    })
}

async function closeServer(server) {
    await new Promise((resolve, reject) => {
        server.close(error => error ? reject(error) : resolve())
    })
}

test('phone planner server defaults to loopback and rejects non-loopback binds', () => {
    assert.equal(packageJson.scripts['phone-planner'], 'node scripts/phone-planner-server.cjs')
    assert.deepEqual(parseArgs([], {}), {
        help: false,
        host: '127.0.0.1',
        port: 4176
    })
    assert.deepEqual(parseArgs(['--port', '0'], {}), {
        help: false,
        host: '127.0.0.1',
        port: 0
    })
    assert.throws(() => parseArgs(['--host', '0.0.0.0'], {}), /only binds/)
    assert.throws(() => parseArgs(['--host', '192.168.1.5'], {}), /only binds/)
})

test('phone planner static resolver confines requests to src/phone-planner', () => {
    const index = resolvePhonePlannerRequest('/')
    const app = resolvePhonePlannerRequest('/app.js')
    const traversal = resolvePhonePlannerRequest('/..%2Fpackage.json')
    const encodedTraversal = resolvePhonePlannerRequest('/%2e%2e/vault.json')
    const backslashTraversal = resolvePhonePlannerRequest('/..%5Cpackage.json')

    assert.equal(index.ok, true)
    assert.equal(path.resolve(index.filePath), path.join(PHONE_PLANNER_STATIC_ROOT, 'index.html'))
    assert.equal(app.ok, true)
    assert.equal(path.resolve(app.filePath), path.join(PHONE_PLANNER_STATIC_ROOT, 'app.js'))
    assert.equal(traversal.ok, false)
    assert.equal(traversal.statusCode, 403)
    assert.equal(encodedTraversal.ok, false)
    assert.equal(encodedTraversal.statusCode, 403)
    assert.equal(backslashTraversal.ok, false)
    assert.equal(backslashTraversal.statusCode, 403)
})

test('phone planner static server serves planner files and not repo root files', async () => {
    const started = await startPhonePlannerServer({ port: 0 })
    try {
        const index = await request(started.url)
        const app = await request(new URL('/app.js', started.url))
        const missingVault = await request(new URL('/vault.json', started.url))
        const packageTraversal = await request(new URL('/..%2Fpackage.json', started.url))
        const packageAtRoot = await request(new URL('/package.json', started.url))

        assert.equal(index.statusCode, 200)
        assert.match(index.body, /<div id="app"><\/div>/)
        assert.match(index.body, /type="module" src="\.\/app\.js"/)
        assert.equal(app.statusCode, 200)
        assert.match(app.body, /Local Draft Planner/)
        assert.equal(missingVault.statusCode, 404)
        assert.equal(packageTraversal.statusCode, 403)
        assert.equal(packageAtRoot.statusCode, 404)
    } finally {
        await closeServer(started.server)
    }
})

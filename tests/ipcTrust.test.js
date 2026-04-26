import assert from 'assert/strict'
import { test } from 'node:test'
import { configureTrustedIpcRenderer, isTrustedIpcSender } from '../src/main/ipcTrust.js'
import { PACKAGED_RENDERER_URL } from '../src/main/electronShellHardening.js'

function fakeEvent(url, parent = null, senderId = 7) {
    return {
        sender: {
            id: senderId
        },
        senderFrame: {
            url,
            parent
        }
    }
}

test('IPC trust accepts only the configured development renderer URL', () => {
    assert.equal(
        isTrustedIpcSender(fakeEvent('http://localhost:5173/'), {
            allowedRendererUrls: ['http://localhost:5173/'],
            webContentsId: 7
        }),
        true
    )

    assert.equal(
        isTrustedIpcSender(fakeEvent('http://localhost:5173/evil.html'), {
            allowedRendererUrls: ['http://localhost:5173/'],
            webContentsId: 7
        }),
        false
    )
})

test('IPC trust rejects unexpected origins and subframes', () => {
    assert.equal(
        isTrustedIpcSender(fakeEvent('https://evil.example/index.html'), {
            allowedRendererUrls: ['http://localhost:5173/'],
            webContentsId: 7
        }),
        false
    )

    assert.equal(
        isTrustedIpcSender(fakeEvent('http://localhost:5173/frame.html', {}), {
            allowedRendererUrls: ['http://localhost:5173/'],
            webContentsId: 7
        }),
        false
    )

    assert.equal(
        isTrustedIpcSender(fakeEvent('http://localhost:5173/', null, 8), {
            allowedRendererUrls: ['http://localhost:5173/'],
            webContentsId: 7
        }),
        false
    )
})

test('IPC trust accepts only the exact packaged custom protocol renderer URL', () => {
    assert.equal(
        isTrustedIpcSender(fakeEvent(PACKAGED_RENDERER_URL), {
            allowedRendererUrls: [PACKAGED_RENDERER_URL],
            webContentsId: 7
        }),
        true
    )

    assert.equal(
        isTrustedIpcSender(fakeEvent(`${PACKAGED_RENDERER_URL}?evil=1`), {
            allowedRendererUrls: [PACKAGED_RENDERER_URL],
            webContentsId: 7
        }),
        false
    )

    assert.equal(
        isTrustedIpcSender(fakeEvent(`${PACKAGED_RENDERER_URL}#evil`), {
            allowedRendererUrls: [PACKAGED_RENDERER_URL],
            webContentsId: 7
        }),
        false
    )
})

test('IPC trust can use configured process-wide renderer state', () => {
    configureTrustedIpcRenderer({
        urls: [PACKAGED_RENDERER_URL],
        webContentsId: 42
    })

    assert.equal(isTrustedIpcSender(fakeEvent(PACKAGED_RENDERER_URL, null, 42)), true)
    assert.equal(isTrustedIpcSender(fakeEvent(PACKAGED_RENDERER_URL, null, 7)), false)
})

test('IPC trust fails closed without explicit renderer configuration', () => {
    configureTrustedIpcRenderer({ urls: [], webContentsId: null })
    process.env.ELECTRON_RENDERER_URL = 'http://localhost:5173/'

    assert.equal(isTrustedIpcSender(fakeEvent('http://localhost:5173/', null, 7)), false)

    delete process.env.ELECTRON_RENDERER_URL
})

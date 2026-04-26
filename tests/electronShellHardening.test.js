import assert from 'assert/strict'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'fs'
import { join, resolve } from 'path'
import { test } from 'node:test'
import { pathToFileURL } from 'url'
import {
    PACKAGED_RENDERER_PROTOCOL,
    PACKAGED_RENDERER_URL,
    createPackagedRendererProtocolHandler,
    installGlobalWebContentsGuards,
    installWebContentsGuards,
    isAllowedRendererNavigationUrl,
    registerPackagedRendererProtocolScheme,
    resolvePackagedRendererAssetPath
} from '../src/main/electronShellHardening.js'

function fakeEvent() {
    return {
        defaultPrevented: false,
        preventDefault() {
            this.defaultPrevented = true
        }
    }
}

function fakeContents() {
    const handlers = new Map()
    return {
        handlers,
        windowOpenHandler: null,
        setWindowOpenHandler(handler) {
            this.windowOpenHandler = handler
        },
        on(name, handler) {
            handlers.set(name, handler)
        }
    }
}

test('packaged renderer protocol scheme registers as a privileged custom scheme', () => {
    const calls = []
    const registered = registerPackagedRendererProtocolScheme({
        registerSchemesAsPrivileged(schemes) {
            calls.push(schemes)
        }
    })

    assert.equal(registered, true)
    assert.equal(calls.length, 1)
    assert.equal(calls[0][0].scheme, PACKAGED_RENDERER_PROTOCOL)
    assert.equal(calls[0][0].privileges.standard, true)
    assert.equal(calls[0][0].privileges.secure, true)
    assert.equal(calls[0][0].privileges.supportFetchAPI, true)
})

test('packaged renderer protocol resolves only bundled renderer assets', () => {
    const rendererRoot = join(process.cwd(), 'out', 'renderer')

    assert.equal(
        resolvePackagedRendererAssetPath(PACKAGED_RENDERER_URL, rendererRoot),
        join(resolve(rendererRoot), 'index.html')
    )

    assert.equal(
        resolvePackagedRendererAssetPath(`${PACKAGED_RENDERER_URL.replace('/index.html', '')}/assets/app.js`, rendererRoot),
        join(resolve(rendererRoot), 'assets', 'app.js')
    )

    assert.throws(
        () => resolvePackagedRendererAssetPath('wipesnap-app://unexpected/index.html', rendererRoot),
        /not trusted/
    )
    assert.throws(
        () => resolvePackagedRendererAssetPath('https://renderer/index.html', rendererRoot),
        /not trusted/
    )
    assert.throws(
        () => resolvePackagedRendererAssetPath('wipesnap-app://renderer/%5c..%5cmain%5cindex.js', rendererRoot),
        /escapes/
    )
})

test('packaged renderer protocol handler fetches confined files and denies invalid requests', async () => {
    const tempRoot = mkdtempSync(join(process.cwd(), '.tmp-shell-hardening-'))
    try {
        const rendererRoot = join(tempRoot, 'renderer')
        mkdirSync(join(rendererRoot, 'assets'), { recursive: true })
        writeFileSync(join(rendererRoot, 'index.html'), '<!doctype html>')
        writeFileSync(join(rendererRoot, 'assets', 'app.js'), 'console.log("ok")')

        const fetched = []
        const handler = createPackagedRendererProtocolHandler({
            rendererRoot,
            fetchFile: async (fileUrl) => {
                fetched.push(fileUrl)
                return new Response('ok', { status: 200 })
            }
        })

        const response = await handler({ url: PACKAGED_RENDERER_URL })
        assert.equal(response.status, 200)
        assert.equal(fetched[0], pathToFileURL(join(rendererRoot, 'index.html')).toString())

        const denied = await handler({ url: 'wipesnap-app://unexpected/index.html' })
        assert.equal(denied.status, 404)
        assert.equal(fetched.length, 1)

        const missing = await handler({ url: 'wipesnap-app://renderer/missing.js' })
        assert.equal(missing.status, 404)
        assert.equal(fetched.length, 1)
    } finally {
        rmSync(tempRoot, { recursive: true, force: true })
    }
})

test('renderer navigation allowlist is exact', () => {
    assert.equal(isAllowedRendererNavigationUrl(PACKAGED_RENDERER_URL, [PACKAGED_RENDERER_URL]), true)
    assert.equal(isAllowedRendererNavigationUrl(`${PACKAGED_RENDERER_URL}?x=1`, [PACKAGED_RENDERER_URL]), false)
    assert.equal(isAllowedRendererNavigationUrl(`${PACKAGED_RENDERER_URL}#x`, [PACKAGED_RENDERER_URL]), false)
    assert.equal(isAllowedRendererNavigationUrl('wipesnap-app://renderer/other.html', [PACKAGED_RENDERER_URL]), false)
})

test('webContents guards deny window.open, webviews, unexpected navigation, and subframes', () => {
    const contents = fakeContents()
    installWebContentsGuards(contents, {
        getAllowedRendererUrls: () => [PACKAGED_RENDERER_URL]
    })

    assert.deepEqual(contents.windowOpenHandler(), { action: 'deny' })

    const allowedTopLevel = fakeEvent()
    contents.handlers.get('will-navigate')(allowedTopLevel, PACKAGED_RENDERER_URL)
    assert.equal(allowedTopLevel.defaultPrevented, false)

    const wrongTopLevel = fakeEvent()
    contents.handlers.get('will-navigate')(wrongTopLevel, 'https://example.test/')
    assert.equal(wrongTopLevel.defaultPrevented, true)

    const allowedMainFrame = fakeEvent()
    contents.handlers.get('will-frame-navigate')(allowedMainFrame, PACKAGED_RENDERER_URL, false, true)
    assert.equal(allowedMainFrame.defaultPrevented, false)

    const subframe = fakeEvent()
    contents.handlers.get('will-frame-navigate')(subframe, PACKAGED_RENDERER_URL, false, false)
    assert.equal(subframe.defaultPrevented, true)

    const webview = fakeEvent()
    contents.handlers.get('will-attach-webview')(webview)
    assert.equal(webview.defaultPrevented, true)
})

test('global webContents guards default-deny permissions and attach to new contents', () => {
    let permissionHandler = null
    const appHandlers = new Map()
    const fakeSession = {
        setPermissionRequestHandler(handler) {
            permissionHandler = handler
        }
    }
    const fakeApp = {
        on(name, handler) {
            appHandlers.set(name, handler)
        }
    }

    installGlobalWebContentsGuards({
        electronApp: fakeApp,
        defaultSession: fakeSession,
        getAllowedRendererUrls: () => [PACKAGED_RENDERER_URL]
    })

    let permissionResult = true
    permissionHandler({}, 'media', (allowed) => {
        permissionResult = allowed
    })
    assert.equal(permissionResult, false)

    const contents = fakeContents()
    appHandlers.get('web-contents-created')({}, contents)
    assert.deepEqual(contents.windowOpenHandler(), { action: 'deny' })
})

import { existsSync, statSync } from 'fs'
import { isAbsolute, relative, resolve } from 'path'
import { pathToFileURL } from 'url'

export const PACKAGED_RENDERER_PROTOCOL = 'wipesnap-app'
export const PACKAGED_RENDERER_HOST = 'renderer'
export const PACKAGED_RENDERER_URL = `${PACKAGED_RENDERER_PROTOCOL}://${PACKAGED_RENDERER_HOST}/index.html`

const PACKAGED_RENDERER_PROTOCOL_PRIVILEGES = Object.freeze({
    standard: true,
    secure: true,
    supportFetchAPI: true
})

let packagedRendererProtocolSchemeRegistered = false

function normalizeExactUrl(value) {
    const url = String(value || '')
    if (!url) return ''
    try {
        const parsed = new URL(url)
        if ((parsed.protocol === 'http:' || parsed.protocol === 'https:') && parsed.pathname === '') {
            parsed.pathname = '/'
        }
        return parsed.toString()
    } catch (_) {
        return ''
    }
}

function readAllowedRendererUrls(getAllowedRendererUrls) {
    try {
        const urls = getAllowedRendererUrls()
        return (Array.isArray(urls) ? urls : [urls])
            .map(normalizeExactUrl)
            .filter(Boolean)
    } catch (_) {
        return []
    }
}

function prevent(event) {
    if (event && typeof event.preventDefault === 'function') {
        event.preventDefault()
    }
}

function notFoundResponse() {
    return new Response('Not found', { status: 404 })
}

export function registerPackagedRendererProtocolScheme(protocolApi) {
    if (packagedRendererProtocolSchemeRegistered) return false
    if (!protocolApi || typeof protocolApi.registerSchemesAsPrivileged !== 'function') {
        throw new Error('Electron protocol API is required to register the renderer scheme.')
    }
    protocolApi.registerSchemesAsPrivileged([{
        scheme: PACKAGED_RENDERER_PROTOCOL,
        privileges: PACKAGED_RENDERER_PROTOCOL_PRIVILEGES
    }])
    packagedRendererProtocolSchemeRegistered = true
    return true
}

export function resolvePackagedRendererAssetPath(requestUrl, rendererRoot) {
    if (!rendererRoot) throw new Error('Renderer root is required.')
    const root = resolve(String(rendererRoot || ''))

    let parsed
    try {
        parsed = new URL(String(requestUrl || ''))
    } catch (_) {
        throw new Error('Renderer protocol URL is invalid.')
    }

    if (parsed.protocol !== `${PACKAGED_RENDERER_PROTOCOL}:` || parsed.hostname !== PACKAGED_RENDERER_HOST) {
        throw new Error('Renderer protocol URL is not trusted.')
    }

    let pathname
    try {
        pathname = decodeURIComponent(parsed.pathname || '/')
    } catch (_) {
        throw new Error('Renderer protocol URL path is invalid.')
    }

    const segments = pathname.split(/[\\/]+/).filter(Boolean)
    if (segments.includes('..')) {
        throw new Error('Renderer protocol URL path escapes the renderer root.')
    }

    const relativePath = segments.length === 0 ? 'index.html' : segments.join('/')
    const assetPath = resolve(root, relativePath)
    const rootRelativePath = relative(root, assetPath)

    if (!rootRelativePath || rootRelativePath.startsWith('..') || isAbsolute(rootRelativePath)) {
        throw new Error('Renderer protocol URL path escapes the renderer root.')
    }

    return assetPath
}

export function createPackagedRendererProtocolHandler({ rendererRoot, fetchFile }) {
    if (typeof fetchFile !== 'function') {
        throw new Error('A file fetch function is required for the renderer protocol handler.')
    }

    return async (request) => {
        try {
            const assetPath = resolvePackagedRendererAssetPath(request?.url, rendererRoot)
            if (!existsSync(assetPath) || !statSync(assetPath).isFile()) {
                return notFoundResponse()
            }
            return fetchFile(pathToFileURL(assetPath).toString())
        } catch (_) {
            return notFoundResponse()
        }
    }
}

export function registerPackagedRendererProtocolHandler({ protocolApi, netApi, rendererRoot }) {
    if (!protocolApi || typeof protocolApi.handle !== 'function') {
        throw new Error('Electron protocol API is required to handle the renderer scheme.')
    }
    if (!netApi || typeof netApi.fetch !== 'function') {
        throw new Error('Electron net API is required to serve renderer assets.')
    }

    protocolApi.handle(PACKAGED_RENDERER_PROTOCOL, createPackagedRendererProtocolHandler({
        rendererRoot,
        fetchFile: (fileUrl) => netApi.fetch(fileUrl)
    }))
}

export function isAllowedRendererNavigationUrl(navigationUrl, allowedRendererUrls) {
    const expected = (Array.isArray(allowedRendererUrls) ? allowedRendererUrls : [allowedRendererUrls])
        .map(normalizeExactUrl)
        .filter(Boolean)
    if (expected.length === 0) return false
    return expected.includes(normalizeExactUrl(navigationUrl))
}

export function installWebContentsGuards(contents, { getAllowedRendererUrls = () => [] } = {}) {
    if (!contents) return

    if (typeof contents.setWindowOpenHandler === 'function') {
        contents.setWindowOpenHandler(() => ({ action: 'deny' }))
    }

    if (typeof contents.on !== 'function') return

    contents.on('will-attach-webview', (event) => {
        prevent(event)
    })

    contents.on('will-navigate', (event, navigationUrl) => {
        if (!isAllowedRendererNavigationUrl(navigationUrl, readAllowedRendererUrls(getAllowedRendererUrls))) {
            prevent(event)
        }
    })

    contents.on('will-frame-navigate', (event, navigationUrl, _isInPlace, isMainFrame) => {
        if (isMainFrame !== true ||
            !isAllowedRendererNavigationUrl(navigationUrl, readAllowedRendererUrls(getAllowedRendererUrls))) {
            prevent(event)
        }
    })
}

export function installGlobalWebContentsGuards({ electronApp, defaultSession, getAllowedRendererUrls = () => [] }) {
    if (defaultSession && typeof defaultSession.setPermissionRequestHandler === 'function') {
        defaultSession.setPermissionRequestHandler((_webContents, _permission, callback) => callback(false))
    }

    if (!electronApp || typeof electronApp.on !== 'function') return

    electronApp.on('web-contents-created', (_event, contents) => {
        installWebContentsGuards(contents, { getAllowedRendererUrls })
    })
}

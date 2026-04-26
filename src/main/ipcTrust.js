const BLOCKED_IPC_ERROR = 'Blocked untrusted IPC sender.'

let trustedRendererConfig = {
    urls: [],
    webContentsId: null
}

function normalizeFilePathname(pathname) {
    return decodeURIComponent(String(pathname || '')).replace(/\\/g, '/').toLowerCase()
}

function normalizeUrlForTrust(value) {
    const url = String(value || '')
    if (!url) return ''
    try {
        const parsed = new URL(url)
        if ((parsed.protocol === 'http:' || parsed.protocol === 'https:') && parsed.pathname === '') {
            parsed.pathname = '/'
        }
        if (parsed.protocol === 'file:') {
            parsed.pathname = normalizeFilePathname(parsed.pathname)
        }
        return parsed.toString()
    } catch (_) {
        return ''
    }
}

function normalizeTrustedUrls(urls) {
    return (Array.isArray(urls) ? urls : [urls])
        .map(normalizeUrlForTrust)
        .filter(Boolean)
}

export function configureTrustedIpcRenderer({ urls = [], webContentsId = null } = {}) {
    trustedRendererConfig = {
        urls: normalizeTrustedUrls(urls),
        webContentsId: webContentsId == null ? null : Number(webContentsId)
    }
}

export function isTrustedIpcSender(event, {
    allowedRendererUrls = trustedRendererConfig.urls,
    webContentsId = trustedRendererConfig.webContentsId
} = {}) {
    const frame = event?.senderFrame
    if (!frame) return false
    if (frame.parent) return false
    if (webContentsId != null && event?.sender?.id !== webContentsId) return false

    const frameUrl = String(frame.url || '')
    if (!frameUrl) return false

    const trustedUrls = normalizeTrustedUrls(allowedRendererUrls)
    if (trustedUrls.length === 0) return false

    return trustedUrls.includes(normalizeUrlForTrust(frameUrl))
}

export function assertTrustedIpcSender(event, options) {
    if (!isTrustedIpcSender(event, options)) throw new Error(BLOCKED_IPC_ERROR)
}

export function blockedIpcResponse(error = BLOCKED_IPC_ERROR) {
    return { success: false, error }
}

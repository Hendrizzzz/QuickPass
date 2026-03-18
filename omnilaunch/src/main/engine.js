/**
 * OmniLaunch Automation Engine — Phase 7: Multi-Context & App Management
 * 
 * Capabilities:
 * - launchSessionSetup(onStatus, savedState?, urls?)  — Open browser for setup/editing
 * - captureSession()                                   — Extract URLs + cookies from ALL contexts, close browser
 * - captureCurrentSession()                            — Extract URLs + cookies from ALL contexts, keep browser open
 * - closeBrowser()                                     — Force close the browser
 * - closeDesktopApps()                                 — Kill tracked desktop app processes
 * - launchWorkspace(workspace, onStatus, savedState)   — Daily authenticated launch
 * - onBrowserAllClosed(cb)                             — Register disconnect callback
 */
import { chromium } from 'playwright-core'
import { spawn, execSync } from 'child_process'

// Active browser/context references
let activeBrowser = null
let activeContext = null
let onDisconnectCallback = null

// Track launched desktop app PIDs so we can close them
let launchedAppPids = []

// ─── Disconnect Detection ───────────────────────────────────────────────────────

export function onBrowserAllClosed(cb) {
    onDisconnectCallback = cb
}

function attachPageTracking(context) {
    const checkAllClosed = () => {
        try {
            const remaining = context?.pages() || []
            if (remaining.length === 0) {
                if (onDisconnectCallback) onDisconnectCallback()
                activeBrowser?.close().catch(() => { })
                activeBrowser = null
                activeContext = null
            }
        } catch (_) {
            if (onDisconnectCallback) onDisconnectCallback()
            activeBrowser = null
            activeContext = null
        }
    }
    const trackPage = (page) => page.on('close', checkAllClosed)
    for (const p of context.pages()) trackPage(p)
    context.on('page', (p) => trackPage(p))
}

// ─── Browser Launch Helper ──────────────────────────────────────────────────────

async function launchChrome() {
    return chromium.launch({
        headless: false,
        channel: 'chrome',
        ignoreDefaultArgs: ['--enable-automation'],
        args: [
            '--no-first-run',
            '--no-default-browser-check',
            '--disable-infobars',
            '--disable-blink-features=AutomationControlled',
            '--start-maximized',
            // Phase 11: RAM-Only Execution Flags
            '--disk-cache-size=1',
            '--media-cache-size=1',
            '--disable-gpu-shader-disk-cache'
        ]
    })
}

// ─── Multi-Context URL + Cookie Extraction ──────────────────────────────────────

/**
 * Collects URLs from ALL browser contexts (catches Ctrl+N windows).
 * Merges cookies from all contexts.
 */
async function extractAllPages() {
    if (!activeBrowser) return { urls: [], state: null }

    const allUrls = []
    let mergedState = { cookies: [], origins: [] }

    for (const ctx of activeBrowser.contexts()) {
        // Collect URLs from this context
        const pages = ctx.pages()
        for (const p of pages) {
            try {
                const url = p.url()
                if (url && url !== 'about:blank' && !url.startsWith('chrome://')) {
                    allUrls.push(url)
                }
            } catch (_) { }
        }

        // Collect cookies/storage from this context
        try {
            const ctxState = await ctx.storageState()
            mergedState.cookies.push(...(ctxState.cookies || []))
            mergedState.origins.push(...(ctxState.origins || []))
        } catch (_) { }
    }

    return { urls: allUrls, state: mergedState }
}

// ─── Session Setup / Edit ───────────────────────────────────────────────────────

export async function launchSessionSetup(onStatus, savedState = null, urls = []) {
    onStatus('Opening browser...')

    activeBrowser = await launchChrome()

    const contextOptions = { 
        viewport: null, 
        ignoreHTTPSErrors: true,
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36'
    }
    if (savedState && savedState.cookies && savedState.cookies.length > 0) {
        contextOptions.storageState = savedState
        onStatus('Restoring your session...')
    }

    activeContext = await activeBrowser.newContext(contextOptions)

    // Phase 11: Bot Mitigation Script Injection
    await activeContext.addInitScript(() => {
        Object.defineProperty(navigator, 'webdriver', { get: () => undefined })
        window.chrome = { runtime: {} }
    })

    attachPageTracking(activeContext)

    if (urls.length > 0) {
        for (let i = 0; i < urls.length; i++) {
            const url = urls[i].startsWith('http') ? urls[i] : `https://${urls[i]}`
            const page = await activeContext.newPage()
            onStatus(`Loading tab ${i + 1}/${urls.length}...`)
            await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 }).catch(() => { })
        }
        onStatus('All tabs loaded. Edit your workspace, then save.')
    } else {
        const page = await activeContext.newPage()
        await page.goto('https://www.google.com', { waitUntil: 'domcontentloaded', timeout: 15000 }).catch(() => { })
        onStatus('Browser is ready. Navigate to your sites and log in.')
    }

    return { success: true }
}

// ─── Session Capture ────────────────────────────────────────────────────────────

/**
 * Captures URLs + cookies from ALL browser contexts and CLOSES the browser.
 */
export async function captureSession() {
    const result = await captureCurrentSession()

    // Always close browser during a full capture, regardless of result
    await closeBrowser()

    // Provide friendly error message if they tried to save zero tabs
    if (!result.success && result.error === 'No tabs are open') {
        return { success: false, error: 'No tabs are open. Please open at least one website.' }
    }

    return result
}

/**
 * Captures URLs + cookies from ALL browser contexts WITHOUT closing.
 */
export async function captureCurrentSession() {
    if (!activeBrowser) {
        return { success: false, error: 'No active browser session' }
    }

    try {
        const { urls, state } = await extractAllPages()

        if (urls.length === 0) {
            return { success: false, error: 'No tabs are open' }
        }

        return { success: true, urls, state, tabCount: urls.length }
    } catch (err) {
        return { success: false, error: err.message }
    }
}

// ─── Browser & App Control ──────────────────────────────────────────────────────

export async function closeBrowser() {
    onDisconnectCallback = null
    if (activeBrowser) {
        await activeBrowser.close().catch(() => { })
        activeBrowser = null
        activeContext = null
    }
}


/**
 * Kill all tracked desktop app processes.
 */
export function closeDesktopApps() {
    for (const pid of launchedAppPids) {
        try {
            if (process.platform === 'win32') {
                // Phase 12: Graceful Process Teardown
                // Remove /F so apps receive WM_CLOSE and save state cleanly
                execSync(`taskkill /pid ${pid} /T`, { stdio: 'ignore' })
            } else {
                process.kill(-pid) // Kill process group on Unix
            }
        } catch (_) { }
    }
    launchedAppPids = []
}

// ─── Desktop App Launcher ───────────────────────────────────────────────────────

function launchDesktopApp(appConfig, onStatus) {
    return new Promise((resolve) => {
        try {
            onStatus(`Launching ${appConfig.name}...`)
            const args = appConfig.args ? appConfig.args.split(' ').filter(Boolean) : []
            let child;

            // Phase 12: File Explorer Context Support
            // If path ends in a common executable extension, spawn normally.
            // If it's a directory, spawn it using explorer.exe
            const isExe = appConfig.path.toLowerCase().endsWith('.exe') || appConfig.path.toLowerCase().endsWith('.bat') || appConfig.path.toLowerCase().endsWith('.cmd')

            if (isExe) {
                child = spawn(appConfig.path, args, {
                    detached: true,
                    stdio: 'ignore'
                })
            } else {
                child = spawn('explorer.exe', [appConfig.path, ...args], {
                    detached: true,
                    stdio: 'ignore'
                })
            }

            // Track the PID so we can close it later
            if (child.pid) launchedAppPids.push(child.pid)

            child.unref()
            child.on('error', (err) => {
                onStatus(`[WARN] ${appConfig.name} — ${err.message}`)
            })

            setTimeout(() => {
                onStatus(`[OK] ${appConfig.name} — launched`)
                resolve({ success: true, name: appConfig.name })
            }, 1000)
        } catch (err) {
            onStatus(`[WARN] ${appConfig.name} — ${err.message}`)
            resolve({ success: false, name: appConfig.name, error: err.message })
        }
    })
}

// ─── Daily Workspace Launch ─────────────────────────────────────────────────────

export async function launchWorkspace(workspace, onStatus, savedState) {
    const savedUrls = (workspace.webTabs || []).filter(t => t.enabled).map(t => t.url)
    const enabledApps = (workspace.desktopApps || []).filter(a => a.enabled)
    const total = savedUrls.length + enabledApps.length

    if (total === 0) {
        onStatus('No items configured')
        return { webResults: [], appResults: [] }
    }

    onStatus(`Launching ${total} items...`)

    const webResults = []

    if (savedUrls.length > 0) {
        activeBrowser = await launchChrome()

        const contextOptions = { 
            viewport: null, 
            ignoreHTTPSErrors: true,
            userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36'
        }
        if (savedState && savedState.cookies && savedState.cookies.length > 0) {
            onStatus('Restoring saved session...')
            contextOptions.storageState = savedState
        }

        activeContext = await activeBrowser.newContext(contextOptions)

        // Phase 11: Bot Mitigation Script Injection
        await activeContext.addInitScript(() => {
            Object.defineProperty(navigator, 'webdriver', { get: () => undefined })
            window.chrome = { runtime: {} }
        })

        const tabPromises = savedUrls.map((url, i) => {
            const fullUrl = url.startsWith('http') ? url : `https://${url}`
            return (async () => {
                const page = await activeContext.newPage()
                try {
                    onStatus(`[Tab ${i + 1}] Loading ${url}...`)
                    await page.goto(fullUrl, { waitUntil: 'domcontentloaded', timeout: 30000 })
                    onStatus(`[Tab ${i + 1}] [OK] ${url} — ready`)
                    return { type: 'web', url, success: true }
                } catch (err) {
                    onStatus(`[Tab ${i + 1}] [WARN] ${url} — ${err.message}`)
                    return { type: 'web', url, success: false }
                }
            })()
        })

        const results = await Promise.all(tabPromises)
        webResults.push(...results)

        try {
            for (const p of activeContext.pages()) {
                if (p.url() !== 'about:blank') {
                    await p.bringToFront().catch(() => { })
                    break
                }
            }
        } catch (_) { }
    }

    const appPromises = enabledApps.map((appConfig, i) =>
        launchDesktopApp(appConfig, (msg) => onStatus(`[App ${i + 1}] ${msg}`))
            .then(result => ({ type: 'app', ...result }))
    )
    const appResults = await Promise.all(appPromises)

    onStatus('LAUNCH_COMPLETE')
    return { webResults, appResults }
}

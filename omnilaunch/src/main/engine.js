/**
 * OmniLaunch Automation Engine
 * 
 * Premium UX: Browser logs in OFF-SCREEN, then appears already logged in.
 * Uses Promise.all() for concurrent execution of all workspace items.
 */
import { chromium } from 'playwright'
import { spawn } from 'child_process'
import crypto from 'crypto'

// Store active browser instances (not returned via IPC)
const activeBrowsers = []

// ─── TOTP Generator (Offline Google Authenticator) ──────────────────────────────

function generateTOTP(secret) {
    const base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
    const cleanSecret = secret.replace(/[\s=-]/g, '').toUpperCase()
    let bits = ''
    for (const char of cleanSecret) {
        const val = base32Chars.indexOf(char)
        if (val === -1) continue
        bits += val.toString(2).padStart(5, '0')
    }
    const keyBytes = []
    for (let i = 0; i + 8 <= bits.length; i += 8) {
        keyBytes.push(parseInt(bits.substring(i, i + 8), 2))
    }
    const key = Buffer.from(keyBytes)

    const epoch = Math.floor(Date.now() / 1000)
    const timeStep = Math.floor(epoch / 30)
    const timeBuffer = Buffer.alloc(8)
    timeBuffer.writeUInt32BE(0, 0)
    timeBuffer.writeUInt32BE(timeStep, 4)

    const hmac = crypto.createHmac('sha1', key)
    hmac.update(timeBuffer)
    const hash = hmac.digest()

    const offset = hash[hash.length - 1] & 0x0f
    const code = (
        ((hash[offset] & 0x7f) << 24) |
        ((hash[offset + 1] & 0xff) << 16) |
        ((hash[offset + 2] & 0xff) << 8) |
        (hash[offset + 3] & 0xff)
    ) % 1000000

    return code.toString().padStart(6, '0')
}

// ─── Google Service Detection ───────────────────────────────────────────────────

const GOOGLE_DOMAINS = [
    'classroom.google.com', 'drive.google.com', 'docs.google.com',
    'sheets.google.com', 'slides.google.com', 'mail.google.com',
    'calendar.google.com', 'meet.google.com', 'chat.google.com',
    'sites.google.com', 'groups.google.com', 'keep.google.com',
    'youtube.com', 'photos.google.com', 'myaccount.google.com'
]

function isGoogleService(url) {
    return GOOGLE_DOMAINS.some(domain => url.includes(domain))
}

// ─── Browser Automation Engine ──────────────────────────────────────────────────

async function launchWebTab(tab, onStatus) {
    const url = tab.url.startsWith('http') ? tab.url : `https://${tab.url}`
    const needsLogin = tab.email && tab.password
    const isGoogle = isGoogleService(url)

    // Launch browser MINIMIZED during login (stays in taskbar, can be alt-tabbed)
    const browser = await chromium.launch({
        headless: false,
        channel: 'chrome', // Use system Google Chrome instead of bundled Chromium
        args: [
            '--no-first-run',
            '--no-default-browser-check',
            '--disable-infobars',
            '--window-position=-32000,-32000',
            '--window-size=1280,800'
        ]
    })

    const context = await browser.newContext({
        viewport: null, // Allow native scaling with window bounds
        ignoreHTTPSErrors: true
    })

    // Block Images, Fonts, and Media exclusively on Google Login pages for ultra-fast text-only rendering
    await context.route('**/*', (route) => {
        const req = route.request()
        const url = req.url()
        const type = req.resourceType()

        if (url.includes('accounts.google.com') || url.includes('gstatic.com') || url.includes('play.google.com')) {
            // ONLY block media/images. DO NOT block stylesheets or fonts because Google's SPA relies on CSS for 2FA dropdown menus!
            if (['image', 'media'].includes(type)) {
                return route.abort()
            }
        }
        route.continue()
    })

    const page = await context.newPage()

    try {
        if (isGoogle && needsLogin) {
            // ─── Google Service: Route through ServiceLogin ───────────────
            const continueUrl = encodeURIComponent(url)
            const loginUrl = `https://accounts.google.com/ServiceLogin?continue=${continueUrl}`
            onStatus(`Authenticating for ${tab.url}...`)
            await page.goto(loginUrl, { waitUntil: 'domcontentloaded', timeout: 30000 })
            await page.waitForLoadState('domcontentloaded')

            await googleLogin(page, tab, onStatus)

            // Wait for redirect to the actual service
            onStatus(`Waiting for ${tab.url} to load...`)
            try {
                const targetDomain = new URL(tab.url).hostname.replace('www.', '')
                await page.waitForURL('**/*' + targetDomain + '*/**', { timeout: 60000 })
            } catch (_) {
                await page.waitForTimeout(5000)
            }
        } else {
            // ─── Non-Google URL ──────────────────────────────────────────
            onStatus(`Loading ${tab.url}...`)
            await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 })
            await page.waitForLoadState('domcontentloaded')

            const currentUrl = page.url()

            if (currentUrl.includes('accounts.google.com') && needsLogin) {
                onStatus('Google login redirect detected...')
                await googleLogin(page, tab, onStatus)
                try {
                    const targetDomain = new URL(tab.url).hostname.replace('www.', '')
                    await page.waitForURL('**/*' + targetDomain + '*/**', { timeout: 60000 })
                } catch (_) {
                    await page.waitForTimeout(5000)
                }
            } else if (needsLogin) {
                await genericLogin(page, tab, onStatus)
            }
        }

        // ─── REVEAL BROWSER (Post-Login Finalization) ────────────────────
        try {
            const context = page.context()
            const pages = context.pages()
            if (pages.length > 0) {
                const cdp = await context.newCDPSession(pages[0])
                const { windowId } = await cdp.send('Browser.getWindowForTarget')
                // First teleport it back to the primary screen
                await cdp.send('Browser.setWindowBounds', {
                    windowId,
                    bounds: { windowState: 'normal', left: 0, top: 0, width: 1280, height: 800 }
                })
                // Then maximize
                await cdp.send('Browser.setWindowBounds', {
                    windowId,
                    bounds: { windowState: 'maximized' }
                })
            }
        } catch (_) {
            await page.bringToFront().catch(() => { })
        }

        onStatus(`[OK] ${tab.url} — ready`)
    } catch (err) {
        onStatus(`[WARN] ${tab.url} — ${err.message}`)
        // Browser remains hidden on failure to prevent jarring popups
    }

    activeBrowsers.push(browser)
    return { url: tab.url, success: true }
}

// ─── Google Login Flow ──────────────────────────────────────────────────────────

async function googleLogin(page, tab, onStatus) {
    try {
        // Step 1: Email ──────────────────────────────────────────────────
        onStatus('Entering email...')
        const emailInput = await page.waitForSelector('input[type="email"]', { timeout: 10000 })
        await emailInput.fill(tab.email)

        // Click Next — use keyboard Enter (most reliable on Google's SPA)
        await page.keyboard.press('Enter')
        onStatus('Email submitted...')

        // Step 2: Password ───────────────────────────────────────────────
        // Wait for the password page to transition
        const pwdInput = await page.waitForSelector('input[type="password"]:visible', { timeout: 15000 })
        onStatus('Entering password...')
        await pwdInput.fill(tab.password)

        // Click Next
        await page.keyboard.press('Enter')
        onStatus('Password submitted...')

        // Step 3: Handle 2FA ─────────────────────────────────────────────
        // Wait for SPA transition to 2FA screen or success
        await page.waitForURL(/challenge|signin\/v2|myaccount/, { timeout: 10000 }).catch(() => { })
        await page.waitForTimeout(2000)
        const currentUrl = page.url()

        if (currentUrl.includes('challenge') || currentUrl.includes('signin/v2')) {
            if (tab.totpSecret) {
                onStatus('2FA challenge detected, generating code...')
                const totpCode = generateTOTP(tab.totpSecret)

                // ─── Navigate the 2FA method selection page ──────────────
                // Google's 2FA page shows multiple options. The TOTP/Authenticator
                // option is often hidden behind "Try another way". Strategy:
                // 1. Check if TOTP input already exists (direct path)
                // 2. If not, click "Try another way" to see all methods
                // 3. Then click the Google Authenticator / TOTP option specifically

                // Fast path: check if TOTP input is already on the page
                let totpInputVisible = false
                try {
                    const quickCheck = page.locator('input[type="tel"], input#totpPin, input[name="totpPin"]').first()
                    totpInputVisible = await quickCheck.isVisible({ timeout: 2000 })
                } catch (_) { }

                if (!totpInputVisible) {
                    // Google sometimes shows the full list immediately. We should try to click Authenticator FIRST.
                    let clickedAuth = false

                    const tryClickAuthenticator = async (timeoutMs) => {
                        try {
                            // Try exact match by text first
                            const authMatch = page.getByText(/authenticator/i, { exact: false }).first()
                            await authMatch.click({ timeout: timeoutMs })
                            return true
                        } catch (_) { }

                        try {
                            // Fallback to data attribute if text fails
                            const fallbackMatch = page.locator('[data-challengetype="6"]').first()
                            await fallbackMatch.click({ timeout: timeoutMs })
                            return true
                        } catch (_) { }

                        return false
                    }

                    // Attempt 1: Is it already on the screen?
                    onStatus('Looking for authenticator option...')
                    clickedAuth = await tryClickAuthenticator(3000)

                    if (!clickedAuth) {
                        // Attempt 2: It's hidden behind "Try another way"
                        try {
                            const tryAnother = page.getByText(/Try another way/i).first()
                            await tryAnother.click({ timeout: 2000 })
                            onStatus('Expanding 2FA options...')
                            await page.waitForTimeout(1000) // Deep buffer for React CSS slide animation

                            clickedAuth = await tryClickAuthenticator(5000)
                        } catch (_) { }
                    }
                }

                // ─── Now find and fill the TOTP input ────────────────────
                // Look for any text/tel input on the current page
                const inputSelectors = [
                    'input[type="tel"]',
                    'input[name="totpPin"]',
                    'input#totpPin',
                    'input[name="pin"]',
                    'input[type="text"][autocomplete="one-time-code"]',
                    'input[aria-label*="code"]',
                    'input[aria-label*="Enter"]'
                ]

                let totpFilled = false
                for (const sel of inputSelectors) {
                    try {
                        const input = page.locator(sel).first()
                        await input.waitFor({ state: 'visible', timeout: 2000 })
                        await input.fill(totpCode)
                        await page.keyboard.press('Enter')
                        totpFilled = true
                        onStatus('2FA code submitted...')
                        break
                    } catch (_) { continue }
                }

                if (!totpFilled) {
                    onStatus('[WARN] Could not find TOTP input field')
                }

                await page.waitForURL(/myaccount|classroom|mail/, { timeout: 10000 }).catch(() => { })
                await page.waitForTimeout(2000)
            } else {
                onStatus('[WARN] 2FA required — no secret key configured')
            }
        }

        onStatus('Login complete')
    } catch (err) {
        onStatus(`[WARN] Login step failed: ${err.message}`)
    }
}

// ─── Generic Login ──────────────────────────────────────────────────────────────

async function genericLogin(page, tab, onStatus) {
    try {
        onStatus('Attempting auto-login...')
        const emailSelectors = [
            'input[type="email"]', 'input[name="email"]', 'input[name="username"]',
            'input[name="login"]', 'input[id="email"]', 'input[id="username"]',
            'input[autocomplete="email"]', 'input[autocomplete="username"]'
        ]

        let filled = false
        for (const sel of emailSelectors) {
            try {
                const el = page.locator(sel).first()
                if (await el.isVisible({ timeout: 2000 })) {
                    await el.fill(tab.email)
                    filled = true
                    break
                }
            } catch (_) { continue }
        }

        if (!filled) {
            onStatus('[WARN] Could not find login form')
            return
        }

        // Password
        try {
            const passInput = page.locator('input[type="password"]').first()
            if (await passInput.isVisible({ timeout: 2000 })) {
                await passInput.fill(tab.password)
            }
        } catch (_) { }

        // Submit
        try {
            const submitBtn = page.locator('button[type="submit"], input[type="submit"]').first()
            if (await submitBtn.isVisible({ timeout: 2000 })) {
                await submitBtn.click()
            } else {
                await page.keyboard.press('Enter')
            }
        } catch (_) {
            await page.keyboard.press('Enter')
        }

        // Wait for redirect to the actual service
        try {
            const targetDomain = new URL(tab.url).hostname.replace('www.', '')
            await page.waitForURL('**/*' + targetDomain + '*/**', { timeout: 60000 })
        } catch (_) {
            await page.waitForTimeout(5000)
        }
        onStatus('Login attempt completed')
    } catch (err) {
        onStatus(`[WARN] Login failed: ${err.message}`)
    }
}

// ─── Desktop App Launcher ───────────────────────────────────────────────────────

function launchDesktopApp(appConfig, onStatus) {
    return new Promise((resolve) => {
        try {
            onStatus(`Launching ${appConfig.name}...`)
            const args = appConfig.args ? appConfig.args.split(' ').filter(Boolean) : []

            const child = spawn(appConfig.path, args, {
                detached: true,
                stdio: 'ignore'
            })

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

// ─── Main Orchestrator ──────────────────────────────────────────────────────────

export async function launchWorkspace(workspace, onStatus) {
    const enabledTabs = (workspace.webTabs || []).filter(t => t.enabled)
    const enabledApps = (workspace.desktopApps || []).filter(a => a.enabled)
    const total = enabledTabs.length + enabledApps.length

    if (total === 0) {
        onStatus('No items configured')
        return { webResults: [], appResults: [] }
    }

    onStatus(`Launching ${total} items...`)

    // Fire ALL web tabs and desktop apps simultaneously
    const webPromises = enabledTabs.map((tab, i) =>
        launchWebTab(tab, (msg) => onStatus(`[Web ${i + 1}] ${msg}`))
            .then(result => ({ type: 'web', ...result }))
            .catch(err => ({ type: 'web', url: tab.url, success: false, error: err.message }))
    )

    const appPromises = enabledApps.map((appConfig, i) =>
        launchDesktopApp(appConfig, (msg) => onStatus(`[App ${i + 1}] ${msg}`))
            .then(result => ({ type: 'app', ...result }))
    )

    const allResults = await Promise.all([...webPromises, ...appPromises])
    const webResults = allResults.filter(r => r.type === 'web')
    const appResults = allResults.filter(r => r.type === 'app')

    onStatus(`[OK] All done (${webResults.length} tabs, ${appResults.length} apps)`)
    return { webResults, appResults }
}

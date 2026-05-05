import assert from 'assert/strict'
import { test } from 'node:test'
import {
    sanitizeRendererLaunchError,
    sanitizeRendererLaunchStatusMessage,
    summarizeTrustedAutoLaunchResults
} from '../src/main/launchRendererStatus.js'

const FORBIDDEN = [
    'C:/Users/Alice/BrowserProfile/Default',
    'C:\\Users\\Alice\\AppData\\Local',
    '//SERVER/Share/Secret',
    'HKEY_CURRENT_USER\\Software\\Alice',
    'HKLM:\\Software\\Alice',
    'failed/dev..example:3000/path?code=abc#frag',
    '例子.测试/path?code=abc#frag',
    'Authorization: Bearer raw-launch-token',
    'Proxy-Authorization: Bearer proxy-launch-token',
    'Bearer raw-launch-token',
    'ghp_1234567890ABCDEFGHIJ',
    'github_pat_1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    'xoxb-123456789012-abcdefghijkl',
    'AKIAABCDEFGHIJKLMNOP',
    'eyJaaaaaaaaaaa.bbbbbbbbbbbbb.ccccccccccccc',
    '--password=hunter2',
    'pid=9999',
    'cap_aaaaaaaaaaaaaaaa'
]

function assertNoRendererLaunchLeaks(value) {
    const text = String(value)
    for (const forbidden of [
        'C:/Users/Alice',
        'C:\\Users\\Alice',
        'BrowserProfile',
        'AppData',
        'SERVER/Share',
        'HKEY_CURRENT_USER',
        'HKLM',
        'dev..example',
        'code=abc',
        '例子.测试',
        'raw-launch-token',
        'proxy-launch-token',
        'ghp_',
        'github_pat_',
        'xoxb-',
        'AKIAABCDEFGHIJKLMNOP',
        'eyJaaaaaaaaaaa.',
        '--password',
        'hunter2',
        'pid=9999',
        'cap_aaaaaaaaaaaaaaaa'
    ]) {
        assert.equal(text.includes(forbidden), false, `renderer launch payload leaked ${forbidden}`)
    }
}

test('trusted auto-launch status uses hardened renderer launch sanitizer', () => {
    const corpus = FORBIDDEN.join(' ')
    const statuses = [
        `[Tab 1] [WARN] Saved - ${corpus}`,
        `[App 1] Launching ${corpus}...`,
        `[App 1] [WARN] Desktop - ${corpus}`,
        `Workspace failed ${corpus}`
    ]

    for (const status of statuses) {
        const safe = sanitizeRendererLaunchStatusMessage(status)
        assertNoRendererLaunchLeaks(safe)
        assert.match(safe, /Saved browser tab|Desktop item|Workspace launch status updated|Browser tab|Desktop/)
    }
})

test('trusted auto-launch completion errors use hardened renderer launch sanitizer', () => {
    const safe = sanitizeRendererLaunchError(
        new Error(`trusted auto-launch failed ${FORBIDDEN.join(' ')}`),
        'Trusted auto-launch failed.'
    )

    assert.equal(safe, 'Trusted auto-launch failed.')
    assertNoRendererLaunchLeaks(safe)
})

test('trusted auto-launch success results are metadata-only summaries', () => {
    const results = summarizeTrustedAutoLaunchResults({
        webResults: [{
            type: 'web',
            url: FORBIDDEN.join(' '),
            normalizedUrl: FORBIDDEN[4],
            finalUrl: FORBIDDEN[5],
            success: false,
            error: FORBIDDEN[6]
        }, {
            type: 'web',
            success: true
        }],
        appResults: [{
            type: 'app',
            name: FORBIDDEN.join(' '),
            success: false,
            error: FORBIDDEN[8]
        }, {
            type: 'app',
            skipped: true
        }]
    })
    const serialized = JSON.stringify(results)

    assert.deepEqual(results.webResults, [])
    assert.deepEqual(results.appResults, [])
    assert.equal(results.metadataOnly, true)
    assert.equal(results.summary.metadataOnly, true)
    assert.deepEqual(results.summary.browserTabs, {
        total: 2,
        succeeded: 1,
        failed: 1,
        skipped: 0
    })
    assert.deepEqual(results.summary.desktopApps, {
        total: 2,
        succeeded: 0,
        failed: 1,
        skipped: 1
    })
    assertNoRendererLaunchLeaks(serialized)
})

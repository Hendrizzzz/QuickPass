import {
    sanitizeManualLaunchError,
    sanitizeManualLaunchStatusMessage
} from './workspaceCapabilityHandlers.js'

export function sanitizeRendererLaunchStatusMessage(message) {
    return sanitizeManualLaunchStatusMessage(message)
}

export function sanitizeRendererLaunchError(err, fallback = 'Workspace launch failed. Review diagnostics before retrying.') {
    return sanitizeManualLaunchError(err, fallback)
}

export function summarizeTrustedAutoLaunchResults(results) {
    const webResults = Array.isArray(results?.webResults) ? results.webResults : []
    const appResults = Array.isArray(results?.appResults) ? results.appResults : []
    const summarize = (items) => ({
        total: items.length,
        succeeded: items.filter(item => item?.success === true).length,
        failed: items.filter(item => item && item.success === false && item.skipped !== true).length,
        skipped: items.filter(item => item?.skipped === true).length
    })
    return {
        metadataOnly: true,
        webResults: [],
        appResults: [],
        summary: {
            browserTabs: summarize(webResults),
            desktopApps: summarize(appResults),
            metadataOnly: true
        }
    }
}

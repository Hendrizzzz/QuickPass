import { validateCloudDraft } from './cloudDraftSchema.js'

export const CLOUD_DRAFT_IMPORT_PLAN_VERSION = 1

function sortTabsForPlan(tabs) {
    return tabs
        .map((tab, index) => ({ tab, index }))
        .sort((a, b) => a.tab.order - b.tab.order || a.index - b.index)
        .map(({ tab }) => tab)
}

function createAccountIntentions(draft) {
    return draft.accountSlots.map(slot => ({
        id: slot.id,
        provider: slot.provider,
        label: slot.label,
        identifierHint: slot.identifierHint,
        profileIntentionId: slot.profileSlotId || '',
        cloudState: slot.state,
        desktopState: slot.desktopState,
        metadataOnly: true,
        requiresDesktopVerification: true
    }))
}

function createProfileIntentions(draft) {
    return draft.browserProfileSlots.map(slot => ({
        id: slot.id,
        provider: slot.provider,
        label: slot.label,
        metadataOnly: true,
        createsDesktopProfile: false
    }))
}

function createSafeBrowserTabs(draft) {
    return sortTabsForPlan(draft.browserTabs).map(tab => ({
        id: tab.id,
        url: tab.url,
        order: tab.order,
        label: tab.label,
        notes: tab.notes,
        enabled: tab.enabled,
        accountIntentionId: tab.accountSlotId || '',
        profileIntentionId: tab.profileSlotId || ''
    }))
}

function createDesiredAppPlaceholders(draft) {
    return draft.desiredApps.map(app => ({
        id: app.id,
        name: app.name,
        label: app.label,
        notes: app.notes,
        enabled: app.enabled,
        status: 'unresolved',
        resolution: 'desktop-required',
        launchable: false,
        createsCapability: false,
        metadataOnly: true
    }))
}

function createWarnings(placeholders) {
    return placeholders
        .filter(app => app.enabled)
        .map(app => `Desired app ${app.label} must be resolved on desktop before it can launch.`)
}

export function planCloudDraftImport(input) {
    const draft = validateCloudDraft(input)
    const accountIntentions = createAccountIntentions(draft)
    const browserProfileIntentions = createProfileIntentions(draft)
    const safeBrowserTabs = createSafeBrowserTabs(draft)
    const desiredAppPlaceholders = createDesiredAppPlaceholders(draft)

    return {
        success: true,
        importPlanVersion: CLOUD_DRAFT_IMPORT_PLAN_VERSION,
        source: 'cloud-draft',
        schemaVersion: draft.schemaVersion,
        draftId: draft.draftId,
        revisionId: draft.revisionId,
        baseRevisionId: draft.baseRevisionId,
        authorDeviceId: draft.authorDeviceId,
        name: draft.name,
        notes: draft.notes,
        isDefault: draft.isDefault,
        createdAt: draft.createdAt,
        updatedAt: draft.updatedAt,
        safeBrowserTabs,
        accountIntentions,
        browserProfileIntentions,
        desiredAppPlaceholders,
        workspaceIntentMetadata: {
            source: 'cloud-draft',
            draftId: draft.draftId,
            revisionId: draft.revisionId,
            accountIntentions,
            browserProfileIntentions,
            tabIntentions: safeBrowserTabs.map(tab => ({
                tabId: tab.id,
                accountIntentionId: tab.accountIntentionId,
                profileIntentionId: tab.profileIntentionId
            }))
        },
        imported: {
            browserTabs: safeBrowserTabs.length,
            accountIntentions: accountIntentions.length,
            profileIntentions: browserProfileIntentions.length,
            desiredAppPlaceholders: desiredAppPlaceholders.length
        },
        warnings: createWarnings(desiredAppPlaceholders)
    }
}

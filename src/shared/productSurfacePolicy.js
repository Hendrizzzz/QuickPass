const DEFAULT_PRODUCT_SURFACE_POLICY = Object.freeze({
    metadataOnly: true,
    policyVersion: 1,
    source: 'default',
    configState: 'absent',
    currentPhase: 'desktop-mvp-hardening',
    cloudPhoneExpansionFrozen: true,
    desktopOwnsLaunch: true,
    phoneRole: 'safe-preset-editor',
    productionReady: {
        desktopMvp: true,
        cloudSync: false,
        phonePlanner: false
    },
    surfaces: {
        productionMvp: true,
        advancedLocal: true,
        stagingCloudSync: false,
        stagingPhoneEnrollment: false,
        stagingProviderControls: false,
        trustedAutoImportStatus: false,
        trustedAutoLaunchConfig: false
    }
})

const FORBIDDEN_POLICY_TEXT = /deviceSessionToken|bearer\s+|syncRootKey|rootKeyMaterial|privateKey|vault\.json|vault\.meta\.json|vault\.state\.json|BrowserProfile|AppData[\\/]|cap_[A-Za-z0-9_-]{4,128}|[A-Za-z]:[\\/]|\\\\|HKEY_|HKLM|HKCU|powershell|taskkill|cmd\s|ciphertext|cloudEnvelope|encryptedEnvelope|patchPayload|vaultData|devicePrivateKey|credential|browserSession|launchAuthority|firebase[-_\s]*(api[-_\s]*)?key|firebaseSecret/i

function clone(value) {
    return JSON.parse(JSON.stringify(value))
}

function isPlainObject(value) {
    return !!value && typeof value === 'object' && !Array.isArray(value)
}

function bool(value, fallback = false) {
    return typeof value === 'boolean' ? value : fallback
}

function objectAt(value, key) {
    return isPlainObject(value?.[key]) ? value[key] : {}
}

function explicitTrue(...values) {
    return values.some(value => value === true)
}

function sanitizeSource(value) {
    return value === 'ignored-local-config' ? value : 'default'
}

function sanitizeConfigState(value) {
    if (value === 'loaded' || value === 'invalid' || value === 'absent') return value
    return 'absent'
}

export function defaultProductSurfacePolicy(overrides = {}) {
    return {
        ...clone(DEFAULT_PRODUCT_SURFACE_POLICY),
        ...overrides,
        productionReady: {
            ...clone(DEFAULT_PRODUCT_SURFACE_POLICY.productionReady),
            ...(isPlainObject(overrides.productionReady) ? overrides.productionReady : {})
        },
        surfaces: {
            ...clone(DEFAULT_PRODUCT_SURFACE_POLICY.surfaces),
            ...(isPlainObject(overrides.surfaces) ? overrides.surfaces : {})
        }
    }
}

export function normalizeProductSurfacePolicyConfig(config = {}, options = {}) {
    const root = isPlainObject(config) ? config : {}
    const productSurface = objectAt(root, 'productSurface')
    const surface = isPlainObject(root.surface) ? root.surface : productSurface
    const staging = {
        ...objectAt(root, 'staging'),
        ...objectAt(productSurface, 'staging'),
        ...objectAt(surface, 'staging')
    }
    const advanced = {
        ...objectAt(root, 'advanced'),
        ...objectAt(productSurface, 'advanced'),
        ...objectAt(surface, 'advanced')
    }
    const stagingEnabled = explicitTrue(
        staging.enabled,
        surface.stagingEnabled,
        surface.showStaging,
        root.showStaging
    )
    const trustedAutomationEnabled = explicitTrue(
        advanced.enabled,
        advanced.trustedAutomation,
        surface.advancedEnabled
    )
    const cloudSync = explicitTrue(
        stagingEnabled,
        staging.cloudSync,
        staging.showCloudSync,
        surface.showStagingCloudSync,
        root.showStagingCloudSync
    )
    const phoneEnrollment = explicitTrue(
        stagingEnabled,
        staging.phoneEnrollment,
        staging.showPhoneEnrollment,
        surface.showPhoneEnrollment,
        root.showPhoneEnrollment
    )
    const providerControls = explicitTrue(
        stagingEnabled,
        staging.providerControls,
        staging.showProviderControls,
        surface.showProviderControls,
        root.showProviderControls
    )
    const trustedAutoImportStatus = explicitTrue(
        trustedAutomationEnabled,
        advanced.trustedAutoImportStatus,
        surface.showTrustedAutoImportStatus,
        root.showTrustedAutoImportStatus
    )
    const trustedAutoLaunchConfig = explicitTrue(
        trustedAutomationEnabled,
        advanced.trustedAutoLaunchConfig,
        surface.showTrustedAutoLaunchConfig,
        root.showTrustedAutoLaunchConfig
    )

    return defaultProductSurfacePolicy({
        source: options.source || 'ignored-local-config',
        configState: options.configState || 'loaded',
        surfaces: {
            stagingCloudSync: cloudSync,
            stagingPhoneEnrollment: phoneEnrollment,
            stagingProviderControls: providerControls,
            trustedAutoImportStatus,
            trustedAutoLaunchConfig
        }
    })
}

export function normalizeProductSurfacePolicyForRenderer(value) {
    if (!isPlainObject(value)) return defaultProductSurfacePolicy()
    const surfaces = isPlainObject(value.surfaces) ? value.surfaces : {}
    const productionReady = isPlainObject(value.productionReady) ? value.productionReady : {}
    return defaultProductSurfacePolicy({
        source: sanitizeSource(value.source),
        configState: sanitizeConfigState(value.configState),
        currentPhase: value.currentPhase === 'desktop-mvp-hardening' ? value.currentPhase : 'desktop-mvp-hardening',
        cloudPhoneExpansionFrozen: value.cloudPhoneExpansionFrozen !== false,
        desktopOwnsLaunch: value.desktopOwnsLaunch !== false,
        phoneRole: value.phoneRole === 'safe-preset-editor' ? value.phoneRole : 'safe-preset-editor',
        productionReady: {
            desktopMvp: productionReady.desktopMvp !== false,
            cloudSync: bool(productionReady.cloudSync, false),
            phonePlanner: bool(productionReady.phonePlanner, false)
        },
        surfaces: {
            productionMvp: surfaces.productionMvp !== false,
            advancedLocal: surfaces.advancedLocal !== false,
            stagingCloudSync: bool(surfaces.stagingCloudSync, false),
            stagingPhoneEnrollment: bool(surfaces.stagingPhoneEnrollment, false),
            stagingProviderControls: bool(surfaces.stagingProviderControls, false),
            trustedAutoImportStatus: bool(surfaces.trustedAutoImportStatus, false),
            trustedAutoLaunchConfig: bool(surfaces.trustedAutoLaunchConfig, false)
        }
    })
}

export function shouldShowCloudSyncControls(policy) {
    return normalizeProductSurfacePolicyForRenderer(policy).surfaces.stagingCloudSync === true
}

export function shouldShowPhoneEnrollmentControls(policy) {
    return normalizeProductSurfacePolicyForRenderer(policy).surfaces.stagingPhoneEnrollment === true
}

export function shouldShowProviderControls(policy) {
    return normalizeProductSurfacePolicyForRenderer(policy).surfaces.stagingProviderControls === true
}

export function shouldShowTrustedAutoImportStatus(policy) {
    return normalizeProductSurfacePolicyForRenderer(policy).surfaces.trustedAutoImportStatus === true
}

export function shouldShowTrustedAutoLaunchConfig(policy) {
    return normalizeProductSurfacePolicyForRenderer(policy).surfaces.trustedAutoLaunchConfig === true
}

export function productSurfacePolicyContainsForbiddenMaterial(value) {
    return FORBIDDEN_POLICY_TEXT.test(JSON.stringify(value || {}))
}

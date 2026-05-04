import assert from 'assert/strict'
import { test } from 'node:test'
import { join } from 'path'
import {
    loadProductSurfacePolicy,
    PRODUCT_SURFACE_CONFIG_FILE
} from '../src/main/productSurfacePolicy.js'
import {
    defaultProductSurfacePolicy,
    normalizeProductSurfacePolicyForRenderer,
    productSurfacePolicyContainsForbiddenMaterial,
    shouldShowCloudSyncControls,
    shouldShowPhoneEnrollmentControls,
    shouldShowProviderControls,
    shouldShowTrustedAutoImportStatus,
    shouldShowTrustedAutoLaunchConfig
} from '../src/shared/productSurfacePolicy.js'

function fsHarness(configText = null) {
    const configPath = join('C:\\Vault', PRODUCT_SURFACE_CONFIG_FILE)
    return {
        configPath,
        fsApi: {
            existsSync: pathValue => pathValue === configPath && configText != null,
            readFileSync: pathValue => {
                assert.equal(pathValue, configPath)
                return configText
            }
        }
    }
}

test('default product surface hides staging cloud, phone, provider, and trusted automation config controls', () => {
    const policy = defaultProductSurfacePolicy()

    assert.equal(policy.productionReady.desktopMvp, true)
    assert.equal(policy.productionReady.cloudSync, false)
    assert.equal(policy.productionReady.phonePlanner, false)
    assert.equal(shouldShowCloudSyncControls(policy), false)
    assert.equal(shouldShowPhoneEnrollmentControls(policy), false)
    assert.equal(shouldShowProviderControls(policy), false)
    assert.equal(shouldShowTrustedAutoImportStatus(policy), false)
    assert.equal(shouldShowTrustedAutoLaunchConfig(policy), false)
    assert.equal(policy.desktopOwnsLaunch, true)
    assert.equal(policy.phoneRole, 'safe-preset-editor')
})

test('absent ignored local config fails closed to the default dashboard surface', () => {
    const { fsApi } = fsHarness(null)
    const policy = loadProductSurfacePolicy({ vaultDir: 'C:\\Vault', fsApi })

    assert.equal(policy.source, 'default')
    assert.equal(policy.configState, 'absent')
    assert.equal(shouldShowCloudSyncControls(policy), false)
    assert.equal(shouldShowPhoneEnrollmentControls(policy), false)
    assert.equal(shouldShowProviderControls(policy), false)
    assert.equal(productSurfacePolicyContainsForbiddenMaterial(policy), false)
})

test('explicit ignored local staging config reveals staging controls without exposing config paths', () => {
    const { fsApi, configPath } = fsHarness(JSON.stringify({
        productSurface: {
            staging: {
                enabled: true
            },
            advanced: {
                trustedAutoImportStatus: true,
                trustedAutoLaunchConfig: true
            }
        }
    }))
    const policy = loadProductSurfacePolicy({ vaultDir: 'C:\\Vault', fsApi })
    const rendererPolicy = normalizeProductSurfacePolicyForRenderer(policy)
    const serialized = JSON.stringify(rendererPolicy)

    assert.equal(rendererPolicy.source, 'ignored-local-config')
    assert.equal(rendererPolicy.configState, 'loaded')
    assert.equal(shouldShowCloudSyncControls(rendererPolicy), true)
    assert.equal(shouldShowPhoneEnrollmentControls(rendererPolicy), true)
    assert.equal(shouldShowProviderControls(rendererPolicy), true)
    assert.equal(shouldShowTrustedAutoImportStatus(rendererPolicy), true)
    assert.equal(shouldShowTrustedAutoLaunchConfig(rendererPolicy), true)
    assert.equal(serialized.includes(configPath), false)
    assert.equal(serialized.includes('wipesnap.local.json'), false)
    assert.equal(productSurfacePolicyContainsForbiddenMaterial(rendererPolicy), false)
})

test('malformed ignored local config fails closed instead of revealing staging surfaces', () => {
    const { fsApi } = fsHarness('{ not json')
    const policy = loadProductSurfacePolicy({ vaultDir: 'C:\\Vault', fsApi })

    assert.equal(policy.source, 'default')
    assert.equal(policy.configState, 'invalid')
    assert.equal(shouldShowCloudSyncControls(policy), false)
    assert.equal(shouldShowPhoneEnrollmentControls(policy), false)
    assert.equal(shouldShowProviderControls(policy), false)
})

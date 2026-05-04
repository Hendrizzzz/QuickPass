import { existsSync, readFileSync } from 'fs'
import { join } from 'path'
import {
    defaultProductSurfacePolicy,
    normalizeProductSurfacePolicyConfig,
    productSurfacePolicyContainsForbiddenMaterial
} from '../shared/productSurfacePolicy.js'

export const PRODUCT_SURFACE_CONFIG_FILE = 'wipesnap.local.json'

function safeDefault(configState = 'absent') {
    return defaultProductSurfacePolicy({
        configState,
        source: 'default'
    })
}

export function loadProductSurfacePolicy({ vaultDir, fsApi = null } = {}) {
    const fs = fsApi || { existsSync, readFileSync }
    if (!vaultDir || typeof vaultDir !== 'string') return safeDefault('absent')

    const configPath = join(vaultDir, PRODUCT_SURFACE_CONFIG_FILE)
    try {
        if (!fs.existsSync(configPath)) return safeDefault('absent')
        const parsed = JSON.parse(fs.readFileSync(configPath, 'utf-8'))
        const policy = normalizeProductSurfacePolicyConfig(parsed, {
            source: 'ignored-local-config',
            configState: 'loaded'
        })
        if (productSurfacePolicyContainsForbiddenMaterial(policy)) return safeDefault('invalid')
        return policy
    } catch (_) {
        return safeDefault('invalid')
    }
}

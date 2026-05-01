import { validatePhonePlannerCloudflareConfig } from './phonePlannerCloudflareConfig.js'
import { validatePhonePlannerFirebaseConfig } from './phonePlannerFirebaseConfig.js'

export const PHONE_PLANNER_CLOUD_PROVIDER_IDS = Object.freeze({
    firebase: 'firebase-staging',
    cloudflare: 'cloudflare-d1-spike'
})

export function validatePhonePlannerCloudProviderConfig(input) {
    if (!input || typeof input !== 'object' || Array.isArray(input)) {
        throw new Error('Hosted phone planner cloud provider config must be an object.')
    }
    const provider = input.provider || (input.projectId ? PHONE_PLANNER_CLOUD_PROVIDER_IDS.firebase : '')
    if (provider === PHONE_PLANNER_CLOUD_PROVIDER_IDS.firebase) {
        const { provider: _provider, ...firebaseConfig } = input
        return {
            provider: PHONE_PLANNER_CLOUD_PROVIDER_IDS.firebase,
            config: validatePhonePlannerFirebaseConfig(firebaseConfig)
        }
    }
    if (provider === PHONE_PLANNER_CLOUD_PROVIDER_IDS.cloudflare) {
        return {
            provider: PHONE_PLANNER_CLOUD_PROVIDER_IDS.cloudflare,
            config: validatePhonePlannerCloudflareConfig(input)
        }
    }
    throw new Error('Hosted phone planner cloud provider is not supported.')
}

export function createPhonePlannerCloudProviderPlan(provider) {
    const providerId = typeof provider === 'string' ? provider : provider?.provider
    if (providerId === PHONE_PLANNER_CLOUD_PROVIDER_IDS.firebase) {
        return {
            provider: providerId,
            auth: 'firebase-auth-custom-claims',
            transport: 'callable-functions-firestore',
            migrationStatus: 'kept-for-phase31.1'
        }
    }
    if (providerId === PHONE_PLANNER_CLOUD_PROVIDER_IDS.cloudflare) {
        return {
            provider: providerId,
            auth: 'device-signed-canonical-requests',
            transport: 'workers-d1',
            migrationStatus: 'phase31.2-spike'
        }
    }
    throw new Error('Hosted phone planner cloud provider plan is not supported.')
}

export const CLOUD_SYNC_PROVIDER_IDS = Object.freeze({
    firebase: 'firebase-staging',
    cloudflare: 'cloudflare-d1-spike'
})

export const CLOUD_SYNC_PROVIDER_PLANS = Object.freeze({
    [CLOUD_SYNC_PROVIDER_IDS.firebase]: Object.freeze({
        providerId: CLOUD_SYNC_PROVIDER_IDS.firebase,
        status: 'implemented-staging',
        hostedStatic: 'firebase-hosting',
        api: 'firebase-callable-functions',
        authoritativeStore: 'firestore',
        authModel: 'firebase-auth-custom-claims',
        canCoexist: true
    }),
    [CLOUD_SYNC_PROVIDER_IDS.cloudflare]: Object.freeze({
        providerId: CLOUD_SYNC_PROVIDER_IDS.cloudflare,
        status: 'phase31.2-spike',
        hostedStatic: 'cloudflare-pages',
        api: 'cloudflare-workers',
        authoritativeStore: 'd1',
        authModel: 'wipesnap-device-signed-canonical-requests',
        rejectKvAsAuthoritative: true,
        durableObjectsRequiredNow: false,
        canCoexist: true
    })
})

export function validateCloudSyncProviderId(providerId, { allowSpike = true } = {}) {
    if (typeof providerId !== 'string') throw new Error('cloud sync provider id must be a string.')
    const normalized = providerId.trim()
    const plan = CLOUD_SYNC_PROVIDER_PLANS[normalized]
    if (!plan) throw new Error('cloud sync provider id is not supported.')
    if (!allowSpike && plan.status.includes('spike')) {
        throw new Error('cloud sync spike providers are not enabled for production.')
    }
    return normalized
}

export function getCloudSyncProviderPlan(providerId) {
    return CLOUD_SYNC_PROVIDER_PLANS[validateCloudSyncProviderId(providerId)]
}

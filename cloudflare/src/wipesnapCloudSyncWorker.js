import { createCloudflareD1Store } from '../../src/cloudflare-sync/cloudflareD1Store.js'
import { createCloudflareSyncWorkerCore } from '../../src/cloudflare-sync/cloudflareSyncWorkerCore.js'

function responseJson(body, status = 500) {
    return new Response(JSON.stringify({ ...body, metadataOnly: true }), {
        status,
        headers: {
            'Content-Type': 'application/json; charset=utf-8',
            'Cache-Control': 'no-store'
        }
    })
}

export default {
    async fetch(request, env) {
        if (!env?.WIPESNAP_D1) {
            return responseJson({
                status: 'rejected',
                error: 'missing-d1-binding',
                message: 'Cloudflare sync D1 binding is not configured.'
            })
        }
        const worker = createCloudflareSyncWorkerCore({
            store: createCloudflareD1Store({ db: env.WIPESNAP_D1 }),
            cryptoApi: globalThis.crypto,
            now: Date.now
        })
        return worker.handle(request)
    }
}

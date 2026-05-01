const CACHE_NAME = 'wipesnap-phone-planner-v1'
const ASSETS = [
    './',
    './index.html',
    './styles.css',
    './app.js',
    './phonePlannerCloudCrypto.js',
    './phonePlannerCloudStorage.js',
    './phonePlannerCloudWorkflow.js',
    './phonePlannerCore.js',
    './phonePlannerFirebaseConfig.js',
    './phonePlannerFirebaseRest.js',
    './phonePlannerStorage.js',
    './manifest.webmanifest'
]

self.addEventListener('install', event => {
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then(cache => cache.addAll(ASSETS))
            .then(() => self.skipWaiting())
    )
})

self.addEventListener('activate', event => {
    event.waitUntil(
        caches.keys()
            .then(names => Promise.all(
                names
                    .filter(name => name !== CACHE_NAME)
                    .map(name => caches.delete(name))
            ))
            .then(() => self.clients.claim())
    )
})

self.addEventListener('fetch', event => {
    const requestUrl = new URL(event.request.url)
    if (requestUrl.origin !== self.location.origin) return

    event.respondWith(
        caches.match(event.request)
            .then(cached => cached || fetch(event.request))
    )
})

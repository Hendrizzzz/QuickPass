import { validatePhonePlannerFirebaseConfig } from './phonePlannerFirebaseConfig.js'

function fail(message) {
    throw new Error(message)
}

function isPlainObject(value) {
    return !!value && typeof value === 'object' && !Array.isArray(value)
}

function encodePath(path) {
    return String(path || '')
        .split('/')
        .filter(Boolean)
        .map(segment => encodeURIComponent(segment))
        .join('/')
}

function authBaseUrl(config) {
    return config.useEmulators && config.emulators?.auth
        ? `http://${config.emulators.auth}/identitytoolkit.googleapis.com/v1`
        : 'https://identitytoolkit.googleapis.com/v1'
}

function secureTokenBaseUrl(config) {
    return config.useEmulators && config.emulators?.auth
        ? `http://${config.emulators.auth}/securetoken.googleapis.com/v1`
        : 'https://securetoken.googleapis.com/v1'
}

function firestoreBaseUrl(config) {
    return config.useEmulators && config.emulators?.firestore
        ? `http://${config.emulators.firestore}/v1/projects/${config.projectId}/databases/(default)/documents`
        : `https://firestore.googleapis.com/v1/projects/${config.projectId}/databases/(default)/documents`
}

function functionsUrl(config, name) {
    if (config.useEmulators && config.emulators?.functions) {
        return `http://${config.emulators.functions}/${config.projectId}/${config.functionsRegion}/${name}`
    }
    return `https://${config.functionsRegion}-${config.projectId}.cloudfunctions.net/${name}`
}

async function parseJsonResponse(response, fallbackMessage) {
    const body = await response.json().catch(() => null)
    if (!response.ok || body?.error) {
        const message = body?.error?.message || body?.error?.status || fallbackMessage
        fail(String(message || fallbackMessage))
    }
    return body
}

async function postJson(fetchImpl, url, body, headers = {}) {
    const response = await fetchImpl(url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            ...headers
        },
        body: JSON.stringify(body)
    })
    return parseJsonResponse(response, 'Firebase request failed.')
}

async function getJson(fetchImpl, url, headers = {}) {
    const response = await fetchImpl(url, {
        method: 'GET',
        headers
    })
    if (response.status === 404) return null
    return parseJsonResponse(response, 'Firebase read failed.')
}

function normalizeAuthResponse(body, now) {
    if (!body || typeof body.idToken !== 'string' || typeof body.localId !== 'string') {
        fail('Firebase Auth did not return a signed-in user.')
    }
    const expiresInSeconds = Number(body.expiresIn || 3600)
    return {
        uid: body.localId,
        email: typeof body.email === 'string' ? body.email : '',
        idToken: body.idToken,
        refreshToken: typeof body.refreshToken === 'string' ? body.refreshToken : '',
        expiresAt: now() + Math.max(60, expiresInSeconds - 30) * 1000
    }
}

function safeAuthState(state) {
    return state
        ? {
            signedIn: true,
            uid: state.uid,
            email: state.email || '',
            metadataOnly: true
        }
        : {
            signedIn: false,
            uid: '',
            email: '',
            metadataOnly: true
        }
}

function decodeFirestoreValue(value) {
    if (!value || typeof value !== 'object') return null
    if ('stringValue' in value) return value.stringValue
    if ('integerValue' in value) return Number(value.integerValue)
    if ('doubleValue' in value) return Number(value.doubleValue)
    if ('booleanValue' in value) return Boolean(value.booleanValue)
    if ('nullValue' in value) return null
    if ('arrayValue' in value) return (value.arrayValue.values || []).map(decodeFirestoreValue)
    if ('mapValue' in value) return decodeFirestoreFields(value.mapValue.fields || {})
    return null
}

function decodeFirestoreFields(fields) {
    const decoded = {}
    for (const [key, value] of Object.entries(fields || {})) decoded[key] = decodeFirestoreValue(value)
    return decoded
}

function decodeFirestoreDocument(document) {
    if (!document || !isPlainObject(document)) return null
    return decodeFirestoreFields(document.fields || {})
}

export function createFirebaseRestAuthClient({
    config,
    fetchImpl = globalThis.fetch?.bind(globalThis),
    now = Date.now
} = {}) {
    const safeConfig = validatePhonePlannerFirebaseConfig(config)
    if (typeof fetchImpl !== 'function') fail('Firebase Auth requires fetch.')
    let state = null

    async function signInWithEndpoint(endpoint, payload) {
        const body = await postJson(
            fetchImpl,
            `${authBaseUrl(safeConfig)}/${endpoint}?key=${encodeURIComponent(safeConfig.apiKey)}`,
            payload
        )
        state = normalizeAuthResponse(body, now)
        return { user: safeAuthState(state) }
    }

    async function refreshIdToken() {
        if (!state?.refreshToken) fail('Firebase Auth session has expired.')
        const body = await postJson(
            fetchImpl,
            `${secureTokenBaseUrl(safeConfig)}/token?key=${encodeURIComponent(safeConfig.apiKey)}`,
            {
                grant_type: 'refresh_token',
                refresh_token: state.refreshToken
            }
        )
        state = normalizeAuthResponse({
            idToken: body.id_token,
            refreshToken: body.refresh_token,
            expiresIn: body.expires_in,
            localId: body.user_id,
            email: state.email
        }, now)
        return state.idToken
    }

    return {
        getSafeAuthState() {
            return safeAuthState(state)
        },
        async getIdToken() {
            if (!state) fail('Sign in to Firebase staging first.')
            if (now() >= state.expiresAt) return refreshIdToken()
            return state.idToken
        },
        async signInWithEmailAndPassword(email, password) {
            return signInWithEndpoint('accounts:signInWithPassword', {
                email,
                password,
                returnSecureToken: true
            })
        },
        async createUserWithEmailAndPassword(email, password) {
            return signInWithEndpoint('accounts:signUp', {
                email,
                password,
                returnSecureToken: true
            })
        },
        async signInAnonymously() {
            if (!safeConfig.allowAnonymousAuth) fail('Anonymous staging auth is disabled by config.')
            return signInWithEndpoint('accounts:signUp', { returnSecureToken: true })
        },
        async signInWithCustomToken(deviceSessionToken) {
            if (typeof deviceSessionToken !== 'string' || !deviceSessionToken) {
                fail('A device session token is required.')
            }
            let rawToken = deviceSessionToken
            try {
                return await signInWithEndpoint('accounts:signInWithCustomToken', {
                    token: rawToken,
                    returnSecureToken: true
                })
            } finally {
                rawToken = null
            }
        },
        signOut() {
            state = null
            return { signedIn: false, metadataOnly: true }
        }
    }
}

export function createFirebaseRestFunctionsClient({
    config,
    authClient,
    fetchImpl = globalThis.fetch?.bind(globalThis)
} = {}) {
    const safeConfig = validatePhonePlannerFirebaseConfig(config)
    if (!authClient || typeof authClient.getIdToken !== 'function') fail('Functions client requires Firebase Auth.')
    if (typeof fetchImpl !== 'function') fail('Functions client requires fetch.')
    return {
        async callCloudSyncFunction(name, data) {
            const idToken = await authClient.getIdToken()
            const body = await postJson(
                fetchImpl,
                functionsUrl(safeConfig, name),
                { data },
                { Authorization: `Bearer ${idToken}` }
            )
            return body.result
        }
    }
}

export function createFirebaseRestFirestoreClient({
    config,
    authClient,
    fetchImpl = globalThis.fetch?.bind(globalThis)
} = {}) {
    const safeConfig = validatePhonePlannerFirebaseConfig(config)
    if (!authClient || typeof authClient.getIdToken !== 'function') fail('Firestore client requires Firebase Auth.')
    if (typeof fetchImpl !== 'function') fail('Firestore client requires fetch.')

    async function authHeaders() {
        return { Authorization: `Bearer ${await authClient.getIdToken()}` }
    }

    return {
        async getDocument(path) {
            const body = await getJson(
                fetchImpl,
                `${firestoreBaseUrl(safeConfig)}/${encodePath(path)}`,
                await authHeaders()
            )
            return decodeFirestoreDocument(body)
        },
        async listDocuments(path) {
            const body = await getJson(
                fetchImpl,
                `${firestoreBaseUrl(safeConfig)}/${encodePath(path)}`,
                await authHeaders()
            )
            return Array.isArray(body?.documents)
                ? body.documents.map(decodeFirestoreDocument).filter(Boolean)
                : []
        },
        async getTrustedDeviceRecord({ ownerUid, deviceId } = {}) {
            if (typeof ownerUid !== 'string' || typeof deviceId !== 'string') return null
            return this.getDocument(`users/${ownerUid}/devices/${deviceId}`)
        }
    }
}

export function createPhonePlannerFirebaseRestApp(options = {}) {
    const config = validatePhonePlannerFirebaseConfig(options.config)
    const fetchImpl = options.fetchImpl || globalThis.fetch?.bind(globalThis)
    const authClient = createFirebaseRestAuthClient({ config, fetchImpl, now: options.now || Date.now })
    return {
        config,
        authClient,
        functionsClient: createFirebaseRestFunctionsClient({ config, authClient, fetchImpl }),
        firestoreClient: createFirebaseRestFirestoreClient({ config, authClient, fetchImpl })
    }
}

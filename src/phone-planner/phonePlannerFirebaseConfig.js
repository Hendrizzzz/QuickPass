export const PHONE_PLANNER_FIREBASE_CONFIG_URL = './firebase-staging-config.json'

const ALLOWED_CONFIG_KEYS = new Set([
    'environment',
    'projectId',
    'apiKey',
    'appId',
    'authDomain',
    'messagingSenderId',
    'storageBucket',
    'measurementId',
    'functionsRegion',
    'allowAnonymousAuth',
    'useEmulators',
    'emulators'
])
const ALLOWED_EMULATOR_KEYS = new Set(['auth', 'firestore', 'functions'])
const PROJECT_ID_PATTERN = /^[a-z][a-z0-9-]{4,80}$/i
const API_KEY_PATTERN = /^[A-Za-z0-9_-]{16,128}$/
const APP_ID_PATTERN = /^[A-Za-z0-9:_-]{8,160}$/
const HOST_PATTERN = /^(?:[a-z0-9-]+\.)+[a-z]{2,}(?::\d{1,5})?$/i
const LOCAL_EMULATOR_PATTERN = /^(?:127\.0\.0\.1|localhost|\[?::1\]?):\d{1,5}$/i

function fail(message) {
    throw new Error(message)
}

function isPlainObject(value) {
    return !!value && typeof value === 'object' && !Array.isArray(value)
}

function normalizedKey(value) {
    return String(value || '').toLowerCase().replace(/[^a-z0-9]/g, '')
}

function looksLikeForbiddenConfigKey(key) {
    const normalized = normalizedKey(key)
    return [
        'serviceaccount',
        'privatekey',
        'clientsecret',
        'refreshtoken',
        'deploymenttoken',
        'firebasetoken',
        'synckey',
        'syncrootkey',
        'rootkeymaterial',
        'deviceprivatekey',
        'vault',
        'password',
        'cookie',
        'credential'
    ].some(marker => normalized.includes(marker))
}

function looksLikeForbiddenConfigString(value) {
    return /-----BEGIN [A-Z ]*PRIVATE KEY-----/i.test(value) ||
        /\b(?:refresh|access|id|deployment|firebase)[_\s-]*token\s*[:=]/i.test(value) ||
        /\b(?:sync[_\s-]*root[_\s-]*key|root[_\s-]*key[_\s-]*material|device[_\s-]*private[_\s-]*key)\s*[:=]/i.test(value) ||
        /\b(?:vault\.json|vault\.meta\.json|vault\.state\.json|BrowserProfile|AppData[\\/])\b/i.test(value) ||
        /\bcap_[a-f0-9]{32,64}\b/i.test(value)
}

function assertNoForbiddenConfigMaterial(value, path = 'phone planner Firebase config') {
    if (Array.isArray(value)) {
        value.forEach((item, index) => assertNoForbiddenConfigMaterial(item, `${path}[${index}]`))
        return
    }
    if (isPlainObject(value)) {
        for (const [key, nested] of Object.entries(value)) {
            if (looksLikeForbiddenConfigKey(key)) {
                fail(`${path}.${key} cannot be present in hosted planner config.`)
            }
            assertNoForbiddenConfigMaterial(nested, `${path}.${key}`)
        }
        return
    }
    if (typeof value === 'string' && looksLikeForbiddenConfigString(value)) {
        fail(`${path} contains forbidden secret or authority material.`)
    }
}

function requireString(value, fieldName, pattern, max = 160) {
    if (typeof value !== 'string') fail(`${fieldName} must be a string.`)
    const text = value.trim()
    if (!text || text.length > max) fail(`${fieldName} is required.`)
    if (pattern && !pattern.test(text)) fail(`${fieldName} is not a safe staging Firebase value.`)
    return text
}

function normalizeBoolean(value, fieldName, fallback = false) {
    if (value == null) return fallback
    if (typeof value !== 'boolean') fail(`${fieldName} must be a boolean.`)
    return value
}

function normalizeHost(value, fieldName, { emulator = false } = {}) {
    const text = requireString(value, fieldName, emulator ? LOCAL_EMULATOR_PATTERN : HOST_PATTERN, 120)
    const port = text.match(/:(\d{1,5})$/)?.[1]
    if (port) {
        const number = Number(port)
        if (!Number.isSafeInteger(number) || number < 1 || number > 65535) {
            fail(`${fieldName} has an invalid port.`)
        }
    }
    return text
}

function normalizeEmulators(value) {
    if (value == null) return null
    if (!isPlainObject(value)) fail('phone planner Firebase config.emulators must be an object.')
    for (const key of Object.keys(value)) {
        if (!ALLOWED_EMULATOR_KEYS.has(key)) fail(`phone planner Firebase config.emulators.${key} is not supported.`)
    }
    const normalized = {}
    for (const key of ALLOWED_EMULATOR_KEYS) {
        if (value[key] != null && value[key] !== '') {
            normalized[key] = normalizeHost(value[key], `phone planner Firebase config.emulators.${key}`, { emulator: true })
        }
    }
    return Object.keys(normalized).length ? normalized : null
}

export function validatePhonePlannerFirebaseConfig(input) {
    if (!isPlainObject(input)) fail('Hosted phone planner Firebase config must be a JSON object.')
    assertNoForbiddenConfigMaterial(input)
    for (const key of Object.keys(input)) {
        if (!ALLOWED_CONFIG_KEYS.has(key)) {
            if (looksLikeForbiddenConfigKey(key)) fail(`phone planner Firebase config.${key} is forbidden.`)
            fail(`phone planner Firebase config.${key} is not supported.`)
        }
    }

    const environment = requireString(input.environment, 'phone planner Firebase config.environment', /^[a-z][a-z0-9-]{1,40}$/i, 40).toLowerCase()
    if (environment !== 'staging') fail('Hosted phone planner must use staging Firebase config.')

    const projectId = requireString(input.projectId, 'phone planner Firebase config.projectId', PROJECT_ID_PATTERN, 80).toLowerCase()
    if (/(^|-)prod(uction)?($|-)|^wipesnap$/i.test(projectId)) {
        fail('Hosted phone planner refuses production-looking Firebase project ids.')
    }

    const functionsRegion = requireString(
        input.functionsRegion || 'us-central1',
        'phone planner Firebase config.functionsRegion',
        /^[a-z]+-[a-z]+[0-9]$/,
        40
    )
    const useEmulators = normalizeBoolean(input.useEmulators, 'phone planner Firebase config.useEmulators', false)
    const emulators = normalizeEmulators(input.emulators)
    if (useEmulators && !emulators) fail('Hosted phone planner emulator config requires emulator hosts.')

    return {
        environment,
        projectId,
        apiKey: requireString(input.apiKey, 'phone planner Firebase config.apiKey', API_KEY_PATTERN, 128),
        appId: requireString(input.appId, 'phone planner Firebase config.appId', APP_ID_PATTERN, 160),
        authDomain: normalizeHost(input.authDomain, 'phone planner Firebase config.authDomain'),
        messagingSenderId: input.messagingSenderId
            ? requireString(input.messagingSenderId, 'phone planner Firebase config.messagingSenderId', /^[0-9]{4,32}$/, 32)
            : '',
        storageBucket: input.storageBucket
            ? normalizeHost(input.storageBucket, 'phone planner Firebase config.storageBucket')
            : '',
        measurementId: input.measurementId
            ? requireString(input.measurementId, 'phone planner Firebase config.measurementId', /^[A-Za-z0-9-]{4,40}$/, 40)
            : '',
        functionsRegion,
        allowAnonymousAuth: normalizeBoolean(input.allowAnonymousAuth, 'phone planner Firebase config.allowAnonymousAuth', false),
        useEmulators,
        emulators
    }
}

export async function loadPhonePlannerFirebaseConfig({
    fetchImpl = globalThis.fetch?.bind(globalThis),
    configUrl = PHONE_PLANNER_FIREBASE_CONFIG_URL
} = {}) {
    if (typeof fetchImpl !== 'function') fail('Hosted phone planner cannot load Firebase config without fetch.')
    let response
    try {
        response = await fetchImpl(configUrl, { cache: 'no-store' })
    } catch (_) {
        fail('Hosted phone planner staging Firebase config is not available.')
    }
    if (!response || response.ok !== true) {
        fail('Hosted phone planner staging Firebase config is missing or unavailable.')
    }
    let json
    try {
        json = await response.json()
    } catch (_) {
        fail('Hosted phone planner staging Firebase config must be valid JSON.')
    }
    return validatePhonePlannerFirebaseConfig(json)
}

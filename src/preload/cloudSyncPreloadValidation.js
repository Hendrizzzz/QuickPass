const MAX_CLOUD_SYNC_PATCH_REVISION_IDS = 50
const CLOUD_SYNC_PATCH_REVISION_ID_PATTERN = /^patchrev_[A-Za-z0-9_-]{1,120}$/
const CLOUD_SYNC_ENROLLMENT_REQUEST_ID_PATTERN = /^dev_[A-Za-z0-9_-]{1,92}$/
const ALLOWED_KEYS = new Set(['patchRevisionIds'])
const ENROLLMENT_APPROVAL_KEYS = new Set(['requestId'])

function fail(message) {
    throw new Error(message)
}

function isPlainObject(value) {
    return !!value && typeof value === 'object' && !Array.isArray(value)
}

function normalizedKey(value) {
    return String(value || '').toLowerCase().replace(/[^a-z0-9]/g, '')
}

function looksLikeForbiddenField(key) {
    const normalized = normalizedKey(key)
    return [
        'vault',
        'capability',
        'rawpath',
        'path',
        'appdata',
        'browserprofile',
        'browsersession',
        'process',
        'pid',
        'shell',
        'command',
        'registry',
        'token',
        'credential',
        'password',
        'passcode',
        'pin',
        'cookie',
        'oauth',
        'secret',
        'syncrootkey',
        'rootkeymaterial',
        'privatekey',
        'recovery',
        'fastboot',
        'hiddenmaster'
    ].some(marker => normalized.includes(marker))
}

function looksLikeForbiddenString(value) {
    return /\bdeviceSessionToken\b/i.test(value) ||
        /\bbearer\s+[A-Za-z0-9._~+/-]{16,}/i.test(value) ||
        /\b(?:refresh|access|id|custom|device[_\s-]*session)[_\s-]*token\s*[:=]/i.test(value) ||
        /\b(?:sync[_\s-]*root[_\s-]*key|root[_\s-]*key[_\s-]*material|private[_\s-]*key|recovery[_\s-]*material)\s*[:=]/i.test(value) ||
        /\b(?:password|passcode|backup\s*code|cookie|oauth|credential|pin|fastboot|hidden[_\s-]*master)\b\s*[:=]/i.test(value) ||
        /\b(?:vault\.json|vault\.meta\.json|vault\.state\.json|BrowserProfile|AppData[\\/])\b/i.test(value) ||
        /\bcap_[a-f0-9]{32,64}\b/i.test(value) ||
        /(?:^|[\s"'([{])(?:[A-Za-z]:[\\/]|\\\\|\[USB\][\\/])/i.test(value) ||
        /\b(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU|cmd|powershell|taskkill)\b/i.test(value)
}

function assertNoForbiddenMaterial(value, path = 'cloud sync invocation payload') {
    if (Array.isArray(value)) {
        value.forEach((item, index) => assertNoForbiddenMaterial(item, `${path}[${index}]`))
        return true
    }
    if (isPlainObject(value)) {
        for (const [key, nested] of Object.entries(value)) {
            if (looksLikeForbiddenField(key)) fail(`${path}.${key} is not accepted for cloud sync invocation.`)
            assertNoForbiddenMaterial(nested, `${path}.${key}`)
        }
        return true
    }
    if (typeof value === 'string' && looksLikeForbiddenString(value)) {
        fail(`${path} contains forbidden cloud sync invocation material.`)
    }
    return true
}

function normalizePatchRevisionIds(value) {
    if (value == null) return undefined
    if (!Array.isArray(value)) fail('cloud sync invocation patchRevisionIds must be an array.')
    if (value.length > MAX_CLOUD_SYNC_PATCH_REVISION_IDS) {
        fail(`cloud sync invocation cannot request more than ${MAX_CLOUD_SYNC_PATCH_REVISION_IDS} patch revisions.`)
    }
    const seen = new Set()
    return value.map((id, index) => {
        if (typeof id !== 'string') fail(`cloud sync invocation patchRevisionIds[${index}] must be a string.`)
        if (id.includes('\0')) fail(`cloud sync invocation patchRevisionIds[${index}] contains an invalid null byte.`)
        const normalized = id.trim()
        if (!CLOUD_SYNC_PATCH_REVISION_ID_PATTERN.test(normalized)) {
            fail(`cloud sync invocation patchRevisionIds[${index}] must be a safe patch revision id.`)
        }
        if (seen.has(normalized)) fail('cloud sync invocation patchRevisionIds contains a duplicate id.')
        seen.add(normalized)
        return normalized
    })
}

export function validateCloudSyncInvocationPayload(value = {}) {
    const payload = value == null ? {} : value
    if (!isPlainObject(payload)) fail('cloud sync invocation payload must be an object.')
    assertNoForbiddenMaterial(payload)
    for (const key of Object.keys(payload)) {
        if (!ALLOWED_KEYS.has(key)) fail(`cloud sync invocation payload.${key} is not accepted.`)
    }
    const patchRevisionIds = normalizePatchRevisionIds(payload.patchRevisionIds)
    return patchRevisionIds ? { patchRevisionIds } : {}
}

export function validateCloudSyncEnrollmentApprovalPayload(value = {}) {
    const payload = value == null ? {} : value
    if (!isPlainObject(payload)) fail('cloud sync enrollment approval payload must be an object.')
    assertNoForbiddenMaterial(payload)
    for (const key of Object.keys(payload)) {
        if (!ENROLLMENT_APPROVAL_KEYS.has(key)) {
            fail(`cloud sync enrollment approval payload.${key} is not accepted.`)
        }
    }
    if (typeof payload.requestId !== 'string') {
        fail('cloud sync enrollment approval requestId must be a string.')
    }
    const requestId = payload.requestId.trim()
    if (!CLOUD_SYNC_ENROLLMENT_REQUEST_ID_PATTERN.test(requestId)) {
        fail('cloud sync enrollment approval requestId must be a safe enrollment request id.')
    }
    return { requestId }
}

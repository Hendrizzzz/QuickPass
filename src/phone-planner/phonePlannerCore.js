export const PHONE_PLANNER_STORAGE_VERSION = 1
export const PHONE_DRAFT_SCHEMA_VERSION = 1

export const PHONE_DRAFT_LIMITS = Object.freeze({
    maxActiveDraftsPerUser: 25,
    maxDraftJsonBytes: 256 * 1024,
    maxBrowserTabs: 64,
    maxAccountIntentions: 16,
    maxBrowserProfileSlots: 8,
    maxDesiredApps: 32,
    maxDraftNameLength: 80,
    maxDraftNotesLength: 2000,
    maxBrowserTabUrlLength: 2048,
    maxBrowserTabLabelLength: 80,
    maxBrowserTabNotesLength: 500,
    maxAccountIntentionLabelLength: 80,
    maxAccountIdentifierHintLength: 160,
    maxBrowserProfileSlotLabelLength: 80,
    maxDesiredAppNameLength: 80,
    maxDesiredAppLabelLength: 80,
    maxDesiredAppNotesLength: 500,
    maxIdLength: 96
})

export const PHONE_ACCOUNT_STATES = Object.freeze([
    'unknown',
    'needs-check',
    'signed-in',
    'needs-auth',
    'needs-phone-approval',
    'blocked'
])

const PROVIDERS = new Set(['google'])
const PHONE_ACCOUNT_STATE_SET = new Set(PHONE_ACCOUNT_STATES)
const MAX_TIMESTAMP = 8_640_000_000_000_000
const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_-]{0,95}$/
const CAPABILITY_ID_PATTERN = /^cap_[a-f0-9]{32,64}$/i

const TOP_LEVEL_DRAFT_KEYS = new Set([
    'product',
    'schemaVersion',
    'draftId',
    'revisionId',
    'baseRevisionId',
    'authorDeviceId',
    'name',
    'notes',
    'isDefault',
    'accountSlots',
    'browserProfileSlots',
    'browserTabs',
    'desiredApps',
    'createdAt',
    'updatedAt'
])
const ACCOUNT_INTENTION_KEYS = new Set(['id', 'provider', 'label', 'identifierHint', 'profileSlotId', 'state'])
const PROFILE_SLOT_KEYS = new Set(['id', 'label', 'provider'])
const BROWSER_TAB_KEYS = new Set(['id', 'url', 'order', 'label', 'notes', 'enabled', 'accountSlotId', 'profileSlotId'])
const DESIRED_APP_KEYS = new Set(['id', 'name', 'label', 'notes', 'enabled'])

const COLLECTION_LIMITS = Object.freeze({
    accountSlots: PHONE_DRAFT_LIMITS.maxAccountIntentions,
    browserProfileSlots: PHONE_DRAFT_LIMITS.maxBrowserProfileSlots,
    browserTabs: PHONE_DRAFT_LIMITS.maxBrowserTabs,
    desiredApps: PHONE_DRAFT_LIMITS.maxDesiredApps
})

const SECRET_FIELD_MARKERS = [
    'password',
    'passcode',
    'backupcode',
    'cookie',
    'oauth',
    'refreshtoken',
    'accesstoken',
    'idtoken',
    'token',
    'credential',
    'secret',
    'pin',
    'fastboot',
    'hiddenmaster'
]

const AUTHORITY_FIELD_MARKERS = [
    'vault',
    'capability',
    'executable',
    'exepath',
    'sourcepath',
    'importpath',
    'datapath',
    'apppath',
    'appdata',
    'path',
    'command',
    'script',
    'registry',
    'process',
    'pid',
    'shell',
    'session',
    'browserprofiledata',
    'rawbrowser'
]

function fail(message) {
    throw new Error(message)
}

function isPlainObject(value) {
    return !!value && typeof value === 'object' && !Array.isArray(value)
}

function requireObject(value, fieldName) {
    if (!isPlainObject(value)) fail(`${fieldName} must be an object.`)
    return value
}

function clone(value) {
    return JSON.parse(JSON.stringify(value))
}

function nowMs(now = Date.now) {
    const value = typeof now === 'function' ? now() : now
    if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) return Date.now()
    return Math.floor(value)
}

function normalizedKey(value) {
    return String(value || '').toLowerCase().replace(/[^a-z0-9]/g, '')
}

function looksLikeForbiddenField(key) {
    const normalized = normalizedKey(key)
    return SECRET_FIELD_MARKERS.some(marker => normalized.includes(marker)) ||
        AUTHORITY_FIELD_MARKERS.some(marker => normalized.includes(marker))
}

function rejectUnknownKeys(value, allowedKeys, fieldName) {
    for (const key of Object.keys(value || {})) {
        if (allowedKeys.has(key)) continue
        if (looksLikeForbiddenField(key)) {
            fail(`${fieldName}.${key} is not accepted because phone drafts cannot carry secrets, paths, commands, registry, process, vault, browser session, or launch capability material.`)
        }
        fail(`${fieldName}.${key} is not accepted.`)
    }
}

function getRandomBytes(length) {
    const cryptoApi = globalThis.crypto
    if (cryptoApi?.getRandomValues) {
        const bytes = new Uint8Array(length)
        cryptoApi.getRandomValues(bytes)
        return bytes
    }

    const bytes = new Uint8Array(length)
    for (let index = 0; index < length; index += 1) {
        bytes[index] = Math.floor(Math.random() * 256)
    }
    return bytes
}

function bytesToHex(bytes) {
    return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('')
}

export function createLocalId(prefix = 'id') {
    const safePrefix = String(prefix || 'id').replace(/[^A-Za-z0-9_-]/g, '').slice(0, 24) || 'id'
    return `${safePrefix}_${bytesToHex(getRandomBytes(12))}`
}

function idFromFactory(idFactory, prefix) {
    const id = typeof idFactory === 'function' ? idFactory(prefix) : createLocalId(prefix)
    return normalizeId(id, `${prefix} id`)
}

function normalizeString(value, fieldName, {
    required = false,
    max,
    multiline = false,
    rejectDangerous = true
} = {}) {
    if (value == null) {
        if (required) fail(`${fieldName} is required.`)
        return ''
    }
    if (typeof value !== 'string') fail(`${fieldName} must be a string.`)
    if (value.includes('\0')) fail(`${fieldName} contains an invalid null byte.`)

    let text = value.normalize('NFC').replace(/\r\n?/g, '\n')
    const controlPattern = multiline
        ? /[\u0000-\u0009\u000B\u000C\u000E-\u001F\u007F]/
        : /[\u0000-\u001F\u007F]/
    if (controlPattern.test(text)) fail(`${fieldName} contains unsupported control characters.`)

    text = text.trim()
    if (required && !text) fail(`${fieldName} is required.`)
    if (!required && !text) return ''
    if (text.length > max) fail(`${fieldName} is too long.`)
    if (rejectDangerous) assertNoDangerousString(text, fieldName)
    return text
}

function normalizeOptionalString(value, fieldName, options = {}) {
    if (value == null || value === '') return ''
    return normalizeString(value, fieldName, options)
}

function normalizeBoolean(value, fieldName, defaultValue = false) {
    if (value == null) return defaultValue
    if (typeof value !== 'boolean') fail(`${fieldName} must be a boolean.`)
    return value
}

function normalizeTimestamp(value, fieldName) {
    if (typeof value !== 'number' || !Number.isFinite(value) || value < 0 || value > MAX_TIMESTAMP) {
        fail(`${fieldName} must be a non-negative timestamp.`)
    }
    return Math.floor(value)
}

function normalizeInteger(value, fieldName) {
    if (!Number.isSafeInteger(value) || value < 0) fail(`${fieldName} must be a non-negative integer.`)
    return value
}

function normalizeId(value, fieldName, { required = true, nullable = false } = {}) {
    if (value == null || value === '') {
        if (nullable) return null
        if (required) fail(`${fieldName} is required.`)
        return ''
    }
    const id = normalizeString(value, fieldName, {
        required,
        max: PHONE_DRAFT_LIMITS.maxIdLength,
        rejectDangerous: false
    })
    if (!ID_PATTERN.test(id)) fail(`${fieldName} must be a safe draft id.`)
    if (CAPABILITY_ID_PATTERN.test(id)) fail(`${fieldName} cannot use a launch capability id shape.`)
    return id
}

function normalizeProvider(value, fieldName) {
    const provider = normalizeString(value, fieldName, {
        required: true,
        max: 40,
        rejectDangerous: false
    }).toLowerCase()
    if (!PROVIDERS.has(provider)) fail(`${fieldName} is not supported.`)
    return provider
}

function normalizeAccountState(value, fieldName) {
    if (value == null || value === '') return 'unknown'
    const state = normalizeString(value, fieldName, {
        required: true,
        max: 80,
        rejectDangerous: false
    }).toLowerCase()
    if (!PHONE_ACCOUNT_STATE_SET.has(state)) fail(`${fieldName} is not supported.`)
    return state
}

function normalizeArray(value, fieldName, max) {
    if (value == null) return []
    if (!Array.isArray(value)) fail(`${fieldName} must be an array.`)
    if (value.length > max) fail(`${fieldName} cannot contain more than ${max} items.`)
    return value
}

function assertUniqueIds(items, fieldName) {
    const seen = new Set()
    for (const item of items) {
        if (seen.has(item.id)) fail(`${fieldName} contains a duplicate id.`)
        seen.add(item.id)
    }
}

function looksLikeSecretString(value) {
    return /\b(?:password|passcode|backup\s*code|cookie|oauth|refresh[_\s-]*token|access[_\s-]*token|id[_\s-]*token|token|credential|secret|pin|fastboot|hidden[_\s-]*master)\b\s*[:=]/i.test(value) ||
        /\bbearer\s+[A-Za-z0-9._~+/-]{16,}/i.test(value) ||
        /\b(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{16,}\b/i.test(value) ||
        /\bAIza[A-Za-z0-9_-]{20,}\b/.test(value) ||
        /\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/.test(value) ||
        /(?:^|[^a-f0-9])[a-f0-9]{40,}(?:$|[^a-f0-9])/i.test(value)
}

function looksLikeWindowsPathString(value) {
    return /(?:^|[\s"'([{])(?:[A-Za-z]:[\\/]|\\\\|\[USB\][\\/])/i.test(value) ||
        /\b(?:vault\.json|vault\.meta\.json|vault\.state\.json|BrowserProfile)\b/i.test(value) ||
        /\bAppData[\\/]/i.test(value)
}

function looksLikeRegistryString(value) {
    return /\b(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG)\b/i.test(value) ||
        /\b(?:HKLM|HKCU|HKCR|HKU|HKCC)[\\:]/i.test(value)
}

function looksLikeProcessSelector(value) {
    return /\b(?:pid|process\s*id)\s*[:=]?\s*\d{2,}\b/i.test(value)
}

function looksLikeCapabilityIdString(value) {
    return /\bcap_[a-f0-9]{32,64}\b/i.test(value)
}

function looksLikeShellCommand(value) {
    return /(?:^|[\s"'([{])(?:cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regedit|reg|schtasks|taskkill|start)\s+(?:\/|-\w|&|\||<|>)/i.test(value) ||
        /[;&|`><]\s*(?:cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|reg|taskkill)\b/i.test(value)
}

function looksLikeExecutableReference(value, { includeJs = false } = {}) {
    const extensions = includeJs
        ? 'exe|bat|cmd|ps1|vbs|js|lnk|scr|msi'
        : 'exe|bat|cmd|ps1|vbs|lnk|scr|msi'
    const fileReference = String.raw`(?:^|[\s"'([{\\/])[^\\/\s"'([{@:]+\.(?:${extensions})(?=$|[\s"'\])},.;:!?])`
    if (new RegExp(fileReference, 'i').test(value)) return true

    const comReference = /(?:^|[\s"'([{\\/])[^\\/\s"'([{@:]+\.com(?=$|[\s"'\])},.;:!?])/i
    return comReference.test(value)
}

function assertNoDangerousString(value, fieldName) {
    if (!value) return
    if (looksLikeSecretString(value)) fail(`${fieldName} cannot contain secret-looking material.`)
    if (looksLikeCapabilityIdString(value)) fail(`${fieldName} cannot contain launch capability material.`)
    if (looksLikeWindowsPathString(value)) fail(`${fieldName} cannot contain filesystem, vault, AppData, or browser profile paths.`)
    if (looksLikeRegistryString(value)) fail(`${fieldName} cannot contain registry paths.`)
    if (looksLikeProcessSelector(value)) fail(`${fieldName} cannot contain process selectors.`)
    if (looksLikeShellCommand(value)) fail(`${fieldName} cannot contain shell commands.`)
    if (looksLikeExecutableReference(value)) fail(`${fieldName} cannot contain executable, shortcut, or script references.`)
}

function assertSafeDesiredAppText(value, fieldName) {
    assertNoDangerousString(value, fieldName)
    if (/[\\/:*?"<>|&;`$%]/.test(value)) fail(`${fieldName} cannot contain path separators or shell metacharacters.`)
    if (looksLikeExecutableReference(value, { includeJs: true })) fail(`${fieldName} cannot contain executable, shortcut, or script references.`)
    if (/\s--?\w/.test(value)) fail(`${fieldName} cannot contain command-line arguments.`)
}

function decodeUrlComponentText(value) {
    let text = String(value || '')
    for (let attempt = 0; attempt < 2; attempt += 1) {
        try {
            const decoded = decodeURIComponent(text)
            if (decoded === text) break
            text = decoded
        } catch (_) {
            break
        }
    }
    return text
}

function assertNoDangerousUrlComponent(value, fieldName) {
    const text = decodeUrlComponentText(value)
    if (!text) return
    assertNoDangerousString(text, fieldName)
}

function parseIpv4(hostname) {
    if (!/^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname)) return null
    const octets = hostname.split('.').map(part => Number(part))
    if (octets.some(octet => !Number.isInteger(octet) || octet < 0 || octet > 255)) return null
    return octets
}

function isNonPublicIpv4(octets) {
    const [a, b] = octets
    return a === 0 ||
        a === 10 ||
        a === 127 ||
        a === 169 && b === 254 ||
        a === 172 && b >= 16 && b <= 31 ||
        a === 192 && b === 168 ||
        a === 100 && b >= 64 && b <= 127 ||
        a === 198 && (b === 18 || b === 19) ||
        a >= 224
}

function isNonPublicIpv6(hostname) {
    const host = hostname.replace(/^\[|\]$/g, '').toLowerCase()
    return host === '::1' ||
        host === '::' ||
        host.startsWith('fe80:') ||
        host.startsWith('fc') ||
        host.startsWith('fd')
}

function validateBrowserUrl(value, fieldName) {
    const raw = normalizeString(value, fieldName, {
        required: true,
        max: PHONE_DRAFT_LIMITS.maxBrowserTabUrlLength,
        rejectDangerous: false
    })
    if (/\s/.test(raw)) fail(`${fieldName} cannot contain whitespace.`)
    if (looksLikeSecretString(raw)) fail(`${fieldName} cannot contain secret-looking material.`)

    const looksLikeHostPort = /^[^:/?#]+:\d{1,5}(?:[/?#].*)?$/i.test(raw)
    const explicitScheme = raw.match(/^([a-z][a-z0-9+.-]*):/i)
    if (explicitScheme && !/^https?:\/\//i.test(raw) && !looksLikeHostPort) {
        fail(`${fieldName} must use http or https.`)
    }

    const candidate = /^https?:\/\//i.test(raw) ? raw : `https://${raw}`
    let parsed
    try {
        parsed = new URL(candidate)
    } catch (_) {
        fail(`${fieldName} must be a valid web URL.`)
    }

    if (!['http:', 'https:'].includes(parsed.protocol)) fail(`${fieldName} must use http or https.`)
    if (parsed.username || parsed.password) fail(`${fieldName} cannot include username or password credentials.`)

    const hostname = parsed.hostname.toLowerCase()
    const ipv4 = parseIpv4(hostname)
    const isIpv6 = hostname.includes(':')
    if (!hostname || (!ipv4 && !isIpv6 && hostname !== 'localhost' && !hostname.includes('.'))) {
        fail(`${fieldName} must include a valid host name.`)
    }
    if (hostname === 'localhost') fail(`${fieldName} cannot target localhost.`)
    if (ipv4 && isNonPublicIpv4(ipv4)) fail(`${fieldName} cannot target local or private network addresses.`)
    if (isIpv6 && isNonPublicIpv6(hostname)) fail(`${fieldName} cannot target local or private network addresses.`)

    for (const [key, queryValue] of parsed.searchParams.entries()) {
        if (looksLikeForbiddenField(key)) fail(`${fieldName} cannot include secret-looking query parameters.`)
        assertNoDangerousUrlComponent(key, `${fieldName} query parameter`)
        assertNoDangerousUrlComponent(queryValue, `${fieldName} query parameter`)
    }
    if (parsed.hash) assertNoDangerousUrlComponent(parsed.hash.slice(1), `${fieldName} fragment`)
    return parsed.href
}

function validateAccountIntention(value, index) {
    const fieldName = `phone draft.accountSlots[${index}]`
    const slot = requireObject(value, fieldName)
    rejectUnknownKeys(slot, ACCOUNT_INTENTION_KEYS, fieldName)
    return {
        id: normalizeId(slot.id, `${fieldName}.id`),
        provider: normalizeProvider(slot.provider, `${fieldName}.provider`),
        label: normalizeString(slot.label, `${fieldName}.label`, {
            required: true,
            max: PHONE_DRAFT_LIMITS.maxAccountIntentionLabelLength
        }),
        identifierHint: normalizeOptionalString(slot.identifierHint, `${fieldName}.identifierHint`, {
            max: PHONE_DRAFT_LIMITS.maxAccountIdentifierHintLength
        }),
        profileSlotId: normalizeId(slot.profileSlotId, `${fieldName}.profileSlotId`, { required: false }),
        state: normalizeAccountState(slot.state, `${fieldName}.state`)
    }
}

function validateProfileSlot(value, index) {
    const fieldName = `phone draft.browserProfileSlots[${index}]`
    const slot = requireObject(value, fieldName)
    rejectUnknownKeys(slot, PROFILE_SLOT_KEYS, fieldName)
    return {
        id: normalizeId(slot.id, `${fieldName}.id`),
        label: normalizeString(slot.label, `${fieldName}.label`, {
            required: true,
            max: PHONE_DRAFT_LIMITS.maxBrowserProfileSlotLabelLength
        }),
        provider: normalizeProvider(slot.provider, `${fieldName}.provider`)
    }
}

function validateBrowserTab(value, index) {
    const fieldName = `phone draft.browserTabs[${index}]`
    const tab = requireObject(value, fieldName)
    rejectUnknownKeys(tab, BROWSER_TAB_KEYS, fieldName)
    return {
        id: normalizeId(tab.id, `${fieldName}.id`),
        url: validateBrowserUrl(tab.url, `${fieldName}.url`),
        order: normalizeInteger(tab.order, `${fieldName}.order`),
        label: normalizeOptionalString(tab.label, `${fieldName}.label`, {
            max: PHONE_DRAFT_LIMITS.maxBrowserTabLabelLength
        }),
        notes: normalizeOptionalString(tab.notes, `${fieldName}.notes`, {
            max: PHONE_DRAFT_LIMITS.maxBrowserTabNotesLength,
            multiline: true
        }),
        enabled: normalizeBoolean(tab.enabled, `${fieldName}.enabled`, true),
        accountSlotId: normalizeId(tab.accountSlotId, `${fieldName}.accountSlotId`, { required: false }),
        profileSlotId: normalizeId(tab.profileSlotId, `${fieldName}.profileSlotId`, { required: false })
    }
}

function validateDesiredApp(value, index) {
    const fieldName = `phone draft.desiredApps[${index}]`
    const app = requireObject(value, fieldName)
    rejectUnknownKeys(app, DESIRED_APP_KEYS, fieldName)
    const name = normalizeString(app.name, `${fieldName}.name`, {
        required: true,
        max: PHONE_DRAFT_LIMITS.maxDesiredAppNameLength
    })
    assertSafeDesiredAppText(name, `${fieldName}.name`)
    const label = normalizeOptionalString(app.label, `${fieldName}.label`, {
        max: PHONE_DRAFT_LIMITS.maxDesiredAppLabelLength
    }) || name
    assertSafeDesiredAppText(label, `${fieldName}.label`)
    const notes = normalizeOptionalString(app.notes, `${fieldName}.notes`, {
        max: PHONE_DRAFT_LIMITS.maxDesiredAppNotesLength,
        multiline: true
    })
    return {
        id: normalizeId(app.id, `${fieldName}.id`),
        name,
        label,
        notes,
        enabled: normalizeBoolean(app.enabled, `${fieldName}.enabled`, true)
    }
}

function assertReferencesExist(draft) {
    const accountIds = new Set(draft.accountSlots.map(slot => slot.id))
    const profileIds = new Set(draft.browserProfileSlots.map(slot => slot.id))

    for (const account of draft.accountSlots) {
        if (account.profileSlotId && !profileIds.has(account.profileSlotId)) {
            fail('phone draft.accountSlots references an unknown browser profile slot.')
        }
    }

    for (const tab of draft.browserTabs) {
        if (tab.accountSlotId && !accountIds.has(tab.accountSlotId)) {
            fail('phone draft.browserTabs references an unknown account slot.')
        }
        if (tab.profileSlotId && !profileIds.has(tab.profileSlotId)) {
            fail('phone draft.browserTabs references an unknown browser profile slot.')
        }
    }
}

function jsonByteLength(value) {
    const json = typeof value === 'string' ? value : JSON.stringify(value)
    if (globalThis.TextEncoder) return new TextEncoder().encode(json).length
    return unescape(encodeURIComponent(json)).length
}

export function buildCloudDraft(draftInput) {
    const draft = requireObject(draftInput, 'phone draft')
    rejectUnknownKeys(draft, TOP_LEVEL_DRAFT_KEYS, 'phone draft')
    if (draft.schemaVersion !== PHONE_DRAFT_SCHEMA_VERSION) fail('phone draft.schemaVersion is not supported.')

    const accountSlots = normalizeArray(
        draft.accountSlots,
        'phone draft.accountSlots',
        PHONE_DRAFT_LIMITS.maxAccountIntentions
    ).map(validateAccountIntention)
    const browserProfileSlots = normalizeArray(
        draft.browserProfileSlots,
        'phone draft.browserProfileSlots',
        PHONE_DRAFT_LIMITS.maxBrowserProfileSlots
    ).map(validateProfileSlot)
    const browserTabs = normalizeArray(
        draft.browserTabs,
        'phone draft.browserTabs',
        PHONE_DRAFT_LIMITS.maxBrowserTabs
    ).map(validateBrowserTab)
    const desiredApps = normalizeArray(
        draft.desiredApps,
        'phone draft.desiredApps',
        PHONE_DRAFT_LIMITS.maxDesiredApps
    ).map(validateDesiredApp)

    assertUniqueIds(accountSlots, 'phone draft.accountSlots')
    assertUniqueIds(browserProfileSlots, 'phone draft.browserProfileSlots')
    assertUniqueIds(browserTabs, 'phone draft.browserTabs')
    assertUniqueIds(desiredApps, 'phone draft.desiredApps')

    const product = normalizeString(draft.product, 'phone draft.product', {
        required: true,
        max: 40,
        rejectDangerous: false
    }).toLowerCase()
    if (product !== 'wipesnap') fail('phone draft.product is not supported.')

    const normalized = {
        product,
        schemaVersion: PHONE_DRAFT_SCHEMA_VERSION,
        draftId: normalizeId(draft.draftId, 'phone draft.draftId'),
        revisionId: normalizeId(draft.revisionId, 'phone draft.revisionId'),
        baseRevisionId: normalizeId(draft.baseRevisionId, 'phone draft.baseRevisionId', { nullable: true, required: false }),
        authorDeviceId: normalizeId(draft.authorDeviceId, 'phone draft.authorDeviceId', { required: false }),
        name: normalizeString(draft.name, 'phone draft.name', {
            required: true,
            max: PHONE_DRAFT_LIMITS.maxDraftNameLength
        }),
        notes: normalizeOptionalString(draft.notes, 'phone draft.notes', {
            max: PHONE_DRAFT_LIMITS.maxDraftNotesLength,
            multiline: true
        }),
        isDefault: normalizeBoolean(draft.isDefault, 'phone draft.isDefault', false),
        accountSlots,
        browserProfileSlots,
        browserTabs,
        desiredApps,
        createdAt: normalizeTimestamp(draft.createdAt, 'phone draft.createdAt'),
        updatedAt: normalizeTimestamp(draft.updatedAt, 'phone draft.updatedAt')
    }

    assertReferencesExist(normalized)
    if (jsonByteLength(normalized) > PHONE_DRAFT_LIMITS.maxDraftJsonBytes) {
        fail(`phone draft JSON exceeds the ${PHONE_DRAFT_LIMITS.maxDraftJsonBytes} byte limit.`)
    }
    return normalized
}

export function exportCloudDraftJson(draftInput) {
    return JSON.stringify(buildCloudDraft(draftInput), null, 2)
}

export function validateDraftForExport(draftInput) {
    try {
        const draft = buildCloudDraft(draftInput)
        return { valid: true, draft, errors: [] }
    } catch (err) {
        return { valid: false, draft: null, errors: [err?.message || 'Draft is not valid.'] }
    }
}

export function createPhoneDraft({
    name = 'Untitled Draft',
    now = Date.now,
    idFactory = createLocalId,
    authorDeviceId = ''
} = {}) {
    const timestamp = nowMs(now)
    const draftId = idFromFactory(idFactory, 'draft')
    const revisionId = idFromFactory(idFactory, 'rev')
    return {
        product: 'wipesnap',
        schemaVersion: PHONE_DRAFT_SCHEMA_VERSION,
        draftId,
        revisionId,
        baseRevisionId: null,
        authorDeviceId: authorDeviceId ? normalizeId(authorDeviceId, 'authorDeviceId') : idFromFactory(idFactory, 'dev'),
        name: String(name || 'Untitled Draft').slice(0, PHONE_DRAFT_LIMITS.maxDraftNameLength),
        notes: '',
        isDefault: false,
        accountSlots: [],
        browserProfileSlots: [],
        browserTabs: [],
        desiredApps: [],
        createdAt: timestamp,
        updatedAt: timestamp
    }
}

export function createPhonePlannerState(options = {}) {
    const draft = createPhoneDraft(options)
    const timestamp = nowMs(options.now)
    return {
        storageVersion: PHONE_PLANNER_STORAGE_VERSION,
        selectedDraftId: draft.draftId,
        drafts: [draft],
        lastSavedAt: timestamp
    }
}

function uniqueCopyName(name) {
    const suffix = ' Copy'
    const base = String(name || 'Untitled Draft').trim() || 'Untitled Draft'
    if (base.length + suffix.length <= PHONE_DRAFT_LIMITS.maxDraftNameLength) return `${base}${suffix}`
    return `${base.slice(0, PHONE_DRAFT_LIMITS.maxDraftNameLength - suffix.length)}${suffix}`
}

function assertDraftCapacity(drafts) {
    if (drafts.length >= PHONE_DRAFT_LIMITS.maxActiveDraftsPerUser) {
        fail(`Phone planner cannot store more than ${PHONE_DRAFT_LIMITS.maxActiveDraftsPerUser} active drafts.`)
    }
}

function findDraftIndex(state, draftId) {
    const index = (state.drafts || []).findIndex(draft => draft.draftId === draftId)
    if (index < 0) fail('Draft was not found.')
    return index
}

function touchDraft(draft, { now = Date.now, idFactory = createLocalId } = {}) {
    const next = { ...draft }
    next.baseRevisionId = draft.revisionId || null
    next.revisionId = idFromFactory(idFactory, 'rev')
    next.updatedAt = nowMs(now)
    return next
}

export function createDraftInState(stateInput, options = {}) {
    const state = clone(normalizeStoredPlannerState(stateInput, options))
    assertDraftCapacity(state.drafts)
    const draft = createPhoneDraft(options)
    return {
        ...state,
        selectedDraftId: draft.draftId,
        drafts: [...state.drafts, draft],
        lastSavedAt: nowMs(options.now)
    }
}

export function duplicateDraftInState(stateInput, draftId, options = {}) {
    const state = clone(normalizeStoredPlannerState(stateInput, options))
    assertDraftCapacity(state.drafts)
    const sourceIndex = findDraftIndex(state, draftId)
    const source = state.drafts[sourceIndex]
    const timestamp = nowMs(options.now)
    const idFactory = options.idFactory || createLocalId
    const profileMap = new Map()
    const accountMap = new Map()

    const browserProfileSlots = source.browserProfileSlots.map(slot => {
        const id = idFromFactory(idFactory, 'profile')
        profileMap.set(slot.id, id)
        return { ...slot, id }
    })
    const accountSlots = source.accountSlots.map(slot => {
        const id = idFromFactory(idFactory, 'intent')
        accountMap.set(slot.id, id)
        return {
            ...slot,
            id,
            profileSlotId: profileMap.get(slot.profileSlotId) || ''
        }
    })
    const browserTabs = source.browserTabs.map(tab => ({
        ...tab,
        id: idFromFactory(idFactory, 'tab'),
        accountSlotId: accountMap.get(tab.accountSlotId) || '',
        profileSlotId: profileMap.get(tab.profileSlotId) || ''
    }))
    const desiredApps = source.desiredApps.map(app => ({
        ...app,
        id: idFromFactory(idFactory, 'wish')
    }))

    const copyDraft = {
        ...source,
        draftId: idFromFactory(idFactory, 'draft'),
        revisionId: idFromFactory(idFactory, 'rev'),
        baseRevisionId: null,
        name: uniqueCopyName(source.name),
        accountSlots,
        browserProfileSlots,
        browserTabs,
        desiredApps,
        createdAt: timestamp,
        updatedAt: timestamp
    }

    return {
        ...state,
        selectedDraftId: copyDraft.draftId,
        drafts: [...state.drafts, copyDraft],
        lastSavedAt: timestamp
    }
}

export function deleteDraftFromState(stateInput, draftId, options = {}) {
    const state = clone(normalizeStoredPlannerState(stateInput, options))
    const drafts = state.drafts.filter(draft => draft.draftId !== draftId)
    const selectedDraftId = state.selectedDraftId === draftId
        ? drafts[0]?.draftId || ''
        : state.selectedDraftId
    return {
        ...state,
        selectedDraftId,
        drafts,
        lastSavedAt: nowMs(options.now)
    }
}

export function updateDraftFields(stateInput, draftId, patch, options = {}) {
    const state = clone(normalizeStoredPlannerState(stateInput, options))
    const index = findDraftIndex(state, draftId)
    const allowed = new Set(['name', 'notes', 'isDefault'])
    for (const key of Object.keys(patch || {})) {
        if (!allowed.has(key)) fail(`Draft field ${key} is not editable by the phone planner.`)
    }
    state.drafts[index] = touchDraft({ ...state.drafts[index], ...patch }, options)
    state.lastSavedAt = nowMs(options.now)
    return state
}

export function addDraftItem(stateInput, draftId, collectionName, item, options = {}) {
    if (!Object.hasOwn(COLLECTION_LIMITS, collectionName)) fail('Unknown draft collection.')
    const state = clone(normalizeStoredPlannerState(stateInput, options))
    const index = findDraftIndex(state, draftId)
    const draft = state.drafts[index]
    if (draft[collectionName].length >= COLLECTION_LIMITS[collectionName]) {
        fail(`${collectionName} cannot contain more than ${COLLECTION_LIMITS[collectionName]} items.`)
    }
    const nextDraft = touchDraft({
        ...draft,
        [collectionName]: [...draft[collectionName], item]
    }, options)
    state.drafts[index] = nextDraft
    state.lastSavedAt = nowMs(options.now)
    return state
}

export function updateDraftItem(stateInput, draftId, collectionName, itemId, patch, options = {}) {
    if (!Object.hasOwn(COLLECTION_LIMITS, collectionName)) fail('Unknown draft collection.')
    const state = clone(normalizeStoredPlannerState(stateInput, options))
    const draftIndex = findDraftIndex(state, draftId)
    const draft = state.drafts[draftIndex]
    const itemIndex = draft[collectionName].findIndex(item => item.id === itemId)
    if (itemIndex < 0) fail('Draft item was not found.')
    const nextItems = draft[collectionName].map((item, index) => index === itemIndex ? { ...item, ...patch } : item)
    state.drafts[draftIndex] = touchDraft({ ...draft, [collectionName]: nextItems }, options)
    state.lastSavedAt = nowMs(options.now)
    return state
}

export function deleteDraftItem(stateInput, draftId, collectionName, itemId, options = {}) {
    if (!Object.hasOwn(COLLECTION_LIMITS, collectionName)) fail('Unknown draft collection.')
    const state = clone(normalizeStoredPlannerState(stateInput, options))
    const draftIndex = findDraftIndex(state, draftId)
    const draft = state.drafts[draftIndex]
    const nextItems = draft[collectionName].filter(item => item.id !== itemId)
    state.drafts[draftIndex] = touchDraft({ ...draft, [collectionName]: nextItems }, options)
    state.lastSavedAt = nowMs(options.now)
    return state
}

export function createBrowserProfileSlot({
    label = 'Personal',
    provider = 'google',
    idFactory = createLocalId
} = {}) {
    return {
        id: idFromFactory(idFactory, 'profile'),
        label,
        provider
    }
}

export function createAccountIntention({
    label = 'Personal Google',
    identifierHint = '',
    profileSlotId = '',
    state = 'needs-check',
    provider = 'google',
    idFactory = createLocalId
} = {}) {
    return {
        id: idFromFactory(idFactory, 'intent'),
        provider,
        label,
        identifierHint,
        profileSlotId,
        state
    }
}

export function createBrowserTab({
    url = 'https://aistudio.google.com/',
    order = 0,
    label = 'AI Studio',
    notes = '',
    enabled = true,
    accountSlotId = '',
    profileSlotId = '',
    idFactory = createLocalId
} = {}) {
    return {
        id: idFromFactory(idFactory, 'tab'),
        url,
        order,
        label,
        notes,
        enabled,
        accountSlotId,
        profileSlotId
    }
}

export function createDesiredAppPlaceholder({
    name = 'Cursor',
    label = '',
    notes = '',
    enabled = true,
    idFactory = createLocalId
} = {}) {
    return {
        id: idFromFactory(idFactory, 'wish'),
        name,
        label: label || name,
        notes,
        enabled
    }
}

function pickAllowedObject(value, keys) {
    const next = {}
    if (!isPlainObject(value)) return next
    for (const key of keys) {
        if (key in value) next[key] = value[key]
    }
    return next
}

function coerceStoredString(value, fallback = '') {
    if (typeof value !== 'string') return fallback
    return value
}

function coerceStoredBoolean(value, fallback = false) {
    return typeof value === 'boolean' ? value : fallback
}

function coerceStoredTimestamp(value, fallback) {
    return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? Math.floor(value) : fallback
}

function normalizeStoredDraft(value, options = {}) {
    const timestamp = nowMs(options.now)
    const draft = pickAllowedObject(value, TOP_LEVEL_DRAFT_KEYS)
    return {
        product: 'wipesnap',
        schemaVersion: PHONE_DRAFT_SCHEMA_VERSION,
        draftId: coerceStoredString(draft.draftId, idFromFactory(options.idFactory || createLocalId, 'draft')),
        revisionId: coerceStoredString(draft.revisionId, idFromFactory(options.idFactory || createLocalId, 'rev')),
        baseRevisionId: draft.baseRevisionId == null ? null : coerceStoredString(draft.baseRevisionId, ''),
        authorDeviceId: coerceStoredString(draft.authorDeviceId, idFromFactory(options.idFactory || createLocalId, 'dev')),
        name: coerceStoredString(draft.name, 'Untitled Draft'),
        notes: coerceStoredString(draft.notes, ''),
        isDefault: coerceStoredBoolean(draft.isDefault, false),
        accountSlots: Array.isArray(draft.accountSlots)
            ? draft.accountSlots.slice(0, PHONE_DRAFT_LIMITS.maxAccountIntentions).map(item => pickAllowedObject(item, ACCOUNT_INTENTION_KEYS))
            : [],
        browserProfileSlots: Array.isArray(draft.browserProfileSlots)
            ? draft.browserProfileSlots.slice(0, PHONE_DRAFT_LIMITS.maxBrowserProfileSlots).map(item => pickAllowedObject(item, PROFILE_SLOT_KEYS))
            : [],
        browserTabs: Array.isArray(draft.browserTabs)
            ? draft.browserTabs.slice(0, PHONE_DRAFT_LIMITS.maxBrowserTabs).map(item => pickAllowedObject(item, BROWSER_TAB_KEYS))
            : [],
        desiredApps: Array.isArray(draft.desiredApps)
            ? draft.desiredApps.slice(0, PHONE_DRAFT_LIMITS.maxDesiredApps).map(item => pickAllowedObject(item, DESIRED_APP_KEYS))
            : [],
        createdAt: coerceStoredTimestamp(draft.createdAt, timestamp),
        updatedAt: coerceStoredTimestamp(draft.updatedAt, timestamp)
    }
}

export function normalizeStoredPlannerState(input, options = {}) {
    const raw = isPlainObject(input) ? input : {}
    let drafts = Array.isArray(raw.drafts) ? raw.drafts.slice(0, PHONE_DRAFT_LIMITS.maxActiveDraftsPerUser) : []
    drafts = drafts.map(draft => normalizeStoredDraft(draft, options))
    if (drafts.length === 0 && options.createIfEmpty !== false) {
        drafts = [createPhoneDraft(options)]
    }
    const selectedDraftId = drafts.some(draft => draft.draftId === raw.selectedDraftId)
        ? raw.selectedDraftId
        : drafts[0]?.draftId || ''
    return {
        storageVersion: PHONE_PLANNER_STORAGE_VERSION,
        selectedDraftId,
        drafts,
        lastSavedAt: coerceStoredTimestamp(raw.lastSavedAt, nowMs(options.now))
    }
}

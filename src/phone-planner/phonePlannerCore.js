export const PHONE_PLANNER_STORAGE_VERSION = 1
export const PHONE_DRAFT_SCHEMA_VERSION = 1
export const SANITIZED_PRESET_SNAPSHOT_SCHEMA_VERSION = 1
export const SANITIZED_PRESET_SNAPSHOT_KIND = 'sanitized-preset-snapshot'
export const SAFE_PRESET_PATCH_SCHEMA_VERSION = 1
export const SAFE_PRESET_PATCH_KIND = 'safe-preset-patch'

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

export const SANITIZED_PRESET_SNAPSHOT_LIMITS = Object.freeze({
    maxSnapshotJsonBytes: 256 * 1024,
    maxPresets: 25,
    maxPresetItemRefs: 256,
    maxAvailableItems: 256,
    maxBrowserItems: 64,
    maxDesktopItems: 64,
    maxAccountIntentions: 16,
    maxProfileIntentions: 8,
    maxPresetNameLength: 80,
    maxItemLabelLength: 80,
    maxAccountIdentifierHintLength: 160,
    maxIdLength: 64
})

export const SAFE_PRESET_PATCH_LIMITS = Object.freeze({
    maxPatchJsonBytes: 256 * 1024,
    maxPresets: SANITIZED_PRESET_SNAPSHOT_LIMITS.maxPresets,
    maxPresetItemRefs: SANITIZED_PRESET_SNAPSHOT_LIMITS.maxPresetItemRefs,
    maxNewBrowserItems: SANITIZED_PRESET_SNAPSHOT_LIMITS.maxBrowserItems,
    maxPresetNameLength: SANITIZED_PRESET_SNAPSHOT_LIMITS.maxPresetNameLength,
    maxBrowserTabUrlLength: PHONE_DRAFT_LIMITS.maxBrowserTabUrlLength,
    maxBrowserTabLabelLength: PHONE_DRAFT_LIMITS.maxBrowserTabLabelLength,
    maxBrowserTabNotesLength: PHONE_DRAFT_LIMITS.maxBrowserTabNotesLength,
    maxIdLength: SANITIZED_PRESET_SNAPSHOT_LIMITS.maxIdLength
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
const CAPABILITY_ID_TEXT_PATTERN = /\bcap_[a-f0-9]{32,64}\b/i
const RAW_ACCOUNT_SLOT_ID_PATTERN = /\bacct_[a-f0-9]{32,64}\b/i
const SAFE_ID_PATTERN = /^[A-Za-z][A-Za-z0-9_-]+$/

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

const SNAPSHOT_TOP_LEVEL_KEYS = new Set([
    'product',
    'kind',
    'schemaVersion',
    'snapshotId',
    'revisionId',
    'baseRevisionId',
    'sourceDeviceId',
    'timestamp',
    'limits',
    'selection',
    'presets',
    'availableItems'
])
const SNAPSHOT_SELECTION_KEYS = new Set(['defaultPresetId', 'nextPresetId', 'metadataOnly', 'selectionKind'])
const SNAPSHOT_PRESET_KEYS = new Set(['id', 'name', 'order', 'enabled', 'itemRefs'])
const SNAPSHOT_ITEM_REF_KEYS = new Set([
    'id',
    'itemId',
    'order',
    'enabled',
    'accountIntentionId',
    'profileIntentionId',
    'metadataOnly'
])
const SNAPSHOT_AVAILABLE_ITEM_KEYS = new Set([
    'id',
    'type',
    'label',
    'status',
    'source',
    'url',
    'provider',
    'identifierHint',
    'state',
    'metadataOnly'
])
const SNAPSHOT_LIMIT_KEYS = new Set(Object.keys(SANITIZED_PRESET_SNAPSHOT_LIMITS))

const SNAPSHOT_EDITOR_KEYS = new Set([
    'mode',
    'snapshot',
    'selectedPresetId',
    'authorDeviceId',
    'patchId',
    'patchRevisionId',
    'createdAt',
    'updatedAt',
    'selection',
    'presets',
    'newBrowserItems',
    'lastExportJson'
])
const SNAPSHOT_EDITOR_SELECTION_KEYS = new Set(['defaultPresetId', 'nextPresetId', 'metadataOnly', 'selectionKind'])
const SNAPSHOT_EDITOR_PRESET_KEYS = new Set(['id', 'name', 'order', 'enabled', 'itemRefs', 'metadataOnly'])
const SNAPSHOT_EDITOR_ITEM_REF_KEYS = new Set([
    'itemId',
    'order',
    'enabled',
    'accountIntentionId',
    'profileIntentionId',
    'metadataOnly'
])
const SNAPSHOT_EDITOR_NEW_BROWSER_ITEM_KEYS = new Set([
    'id',
    'url',
    'label',
    'notes',
    'enabled',
    'accountIntentionId',
    'profileIntentionId',
    'metadataOnly'
])

const PATCH_TOP_LEVEL_KEYS = new Set([
    'product',
    'kind',
    'schemaVersion',
    'patchId',
    'patchRevisionId',
    'baseSnapshotRevisionId',
    'authorDeviceId',
    'createdAt',
    'updatedAt',
    'selection',
    'presets',
    'newBrowserItems'
])
const PATCH_SELECTION_KEYS = new Set(['defaultPresetId', 'nextPresetId', 'metadataOnly', 'selectionKind'])
const PATCH_PRESET_KEYS = SNAPSHOT_EDITOR_PRESET_KEYS
const PATCH_ITEM_REF_KEYS = SNAPSHOT_EDITOR_ITEM_REF_KEYS
const PATCH_NEW_BROWSER_ITEM_KEYS = SNAPSHOT_EDITOR_NEW_BROWSER_ITEM_KEYS

const SNAPSHOT_ITEM_TYPES = new Set([
    'browser-tab',
    'desktop-app',
    'host-folder',
    'account-intention',
    'profile-intention'
])
const SNAPSHOT_ITEM_STATUSES = new Set(['available', 'disabled', 'redacted', 'broken'])
const SNAPSHOT_ITEM_SOURCES = new Set(['browser', 'desktop', 'account', 'profile'])
const SNAPSHOT_ACCOUNT_STATES = new Set([
    'unknown',
    'signed-in',
    'needs-recheck',
    'needs-auth',
    'needs-phone-approval',
    'needs-passkey',
    'blocked-or-suspicious',
    'user-action-required'
])

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
    'browserprofile',
    'path',
    'command',
    'script',
    'registry',
    'process',
    'pid',
    'shell',
    'session',
    'browserprofiledata',
    'rawbrowser',
    'launch',
    'args',
    'userargs',
    'manifest',
    'storage',
    'shortcut'
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

function rejectUnknownKeysFor(value, allowedKeys, fieldName, reason) {
    for (const key of Object.keys(value || {})) {
        if (allowedKeys.has(key)) continue
        if (looksLikeForbiddenField(key)) {
            fail(`${fieldName}.${key} is not accepted because ${reason}.`)
        }
        fail(`${fieldName}.${key} is not accepted.`)
    }
}

function rejectUnknownKeys(value, allowedKeys, fieldName) {
    rejectUnknownKeysFor(
        value,
        allowedKeys,
        fieldName,
        'phone drafts cannot carry secrets, paths, commands, registry, process, vault, browser session, or launch capability material'
    )
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
    return CAPABILITY_ID_TEXT_PATTERN.test(value)
}

function looksLikeRawAccountSlotIdString(value) {
    return RAW_ACCOUNT_SLOT_ID_PATTERN.test(value)
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

function looksLikeManifestOrStorageReference(value) {
    return /\b(?:manifest|storage)\s*(?:id)?\s*[:=]/i.test(value) ||
        /\b(?:manifestId|storageId)\b/i.test(value)
}

function assertNoDangerousString(value, fieldName) {
    if (!value) return
    if (looksLikeSecretString(value)) fail(`${fieldName} cannot contain secret-looking material.`)
    if (looksLikeCapabilityIdString(value)) fail(`${fieldName} cannot contain launch capability material.`)
    if (looksLikeRawAccountSlotIdString(value)) fail(`${fieldName} cannot contain raw account slot ids.`)
    if (looksLikeWindowsPathString(value)) fail(`${fieldName} cannot contain filesystem, vault, AppData, or browser profile paths.`)
    if (looksLikeRegistryString(value)) fail(`${fieldName} cannot contain registry paths.`)
    if (looksLikeProcessSelector(value)) fail(`${fieldName} cannot contain process selectors.`)
    if (looksLikeShellCommand(value)) fail(`${fieldName} cannot contain shell commands.`)
    if (looksLikeExecutableReference(value)) fail(`${fieldName} cannot contain executable, shortcut, or script references.`)
    if (looksLikeManifestOrStorageReference(value)) fail(`${fieldName} cannot contain manifest or storage identifiers.`)
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

function jsonByteLengthForInput(input, fieldName) {
    if (typeof input === 'string') return jsonByteLength(input)
    if (typeof Buffer !== 'undefined' && Buffer.isBuffer?.(input)) return input.length
    if (ArrayBuffer.isView(input)) return input.byteLength
    try {
        const json = JSON.stringify(input)
        if (typeof json !== 'string') fail(`${fieldName} must be JSON data.`)
        return jsonByteLength(json)
    } catch (_) {
        fail(`${fieldName} must be JSON-serializable.`)
    }
}

function parseJsonInput(input, fieldName, maxBytes) {
    const bytes = jsonByteLengthForInput(input, fieldName)
    if (bytes > maxBytes) fail(`${fieldName} exceeds the ${maxBytes} byte limit.`)

    const isBuffer = typeof Buffer !== 'undefined' && Buffer.isBuffer?.(input)
    if (typeof input === 'string' || isBuffer || ArrayBuffer.isView(input)) {
        const text = typeof input === 'string'
            ? input
            : typeof Buffer !== 'undefined' && Buffer.from
                ? Buffer.from(input).toString('utf8')
                : new TextDecoder().decode(input)
        try {
            return JSON.parse(text)
        } catch (_) {
            fail(`${fieldName} must be valid JSON.`)
        }
    }

    return input
}

function assertNoForbiddenPlannerMaterial(value, path = 'phone planner data') {
    if (Array.isArray(value)) {
        value.forEach((item, index) => assertNoForbiddenPlannerMaterial(item, `${path}[${index}]`))
        return
    }
    if (isPlainObject(value)) {
        for (const [key, nested] of Object.entries(value)) {
            if (looksLikeForbiddenField(key)) fail(`${path}.${key} is forbidden.`)
            assertNoForbiddenPlannerMaterial(nested, `${path}.${key}`)
        }
        return
    }
    if (typeof value === 'string' && path.endsWith('.url')) {
        validateBrowserUrl(value, path)
        return
    }
    if (typeof value === 'string') assertNoDangerousString(value, path)
}

function normalizeRequiredBoolean(value, fieldName) {
    if (typeof value !== 'boolean') fail(`${fieldName} must be a boolean.`)
    return value
}

function normalizeRequiredArray(value, fieldName, max) {
    if (!Array.isArray(value)) fail(`${fieldName} must be an array.`)
    if (value.length > max) fail(`${fieldName} cannot contain more than ${max} items.`)
    return value
}

function assertUniqueValues(values, fieldName) {
    const seen = new Set()
    for (const value of values) {
        if (seen.has(value)) fail(`${fieldName} contains a duplicate id.`)
        seen.add(value)
    }
}

function normalizeSafePatchId(value, fieldName, prefixes, { nullable = false, required = true } = {}) {
    if (value == null || value === '') {
        if (nullable) return null
        if (required) fail(`${fieldName} is required.`)
        return ''
    }
    const id = normalizeString(value, fieldName, {
        required: true,
        max: SAFE_PRESET_PATCH_LIMITS.maxIdLength,
        rejectDangerous: false
    })
    if (!SAFE_ID_PATTERN.test(id)) fail(`${fieldName} must be a safe id.`)
    if (CAPABILITY_ID_TEXT_PATTERN.test(id)) fail(`${fieldName} cannot use a launch capability id shape.`)
    if (RAW_ACCOUNT_SLOT_ID_PATTERN.test(id)) fail(`${fieldName} cannot use a raw account slot id shape.`)
    if (prefixes && !prefixes.some(prefix => id.startsWith(prefix))) {
        fail(`${fieldName} must use an allowed safe id prefix.`)
    }
    return id
}

function normalizeOptionalIntentionId(value, fieldName, prefix) {
    if (value == null || value === '') return ''
    return normalizeSafePatchId(value, fieldName, [prefix], { required: false })
}

function validateMetadataOnly(value, fieldName) {
    if (value == null) return true
    if (value !== true) fail(`${fieldName} must be true because phone preset edits are metadata only.`)
    return true
}

function expectedSnapshotSourceForType(type) {
    if (type === 'browser-tab') return 'browser'
    if (type === 'desktop-app' || type === 'host-folder') return 'desktop'
    if (type === 'account-intention') return 'account'
    if (type === 'profile-intention') return 'profile'
    return ''
}

function expectedSnapshotIdPrefixesForType(type) {
    if (type === 'account-intention') return ['accti_']
    if (type === 'profile-intention') return ['profi_']
    return ['item_']
}

function validateSnapshotLimits(value) {
    const limits = requireObject(value, 'sanitized snapshot.limits')
    rejectUnknownKeysFor(
        limits,
        SNAPSHOT_LIMIT_KEYS,
        'sanitized snapshot.limits',
        'sanitized snapshots cannot carry secrets, paths, commands, registry, process, vault, browser session, or launch capability material'
    )
    for (const [key, expected] of Object.entries(SANITIZED_PRESET_SNAPSHOT_LIMITS)) {
        if (limits[key] !== expected) fail(`sanitized snapshot.limits.${key} is invalid.`)
    }
    return { ...SANITIZED_PRESET_SNAPSHOT_LIMITS }
}

function validateSnapshotSelection(value) {
    const selection = requireObject(value, 'sanitized snapshot.selection')
    rejectUnknownKeysFor(
        selection,
        SNAPSHOT_SELECTION_KEYS,
        'sanitized snapshot.selection',
        'sanitized snapshots cannot carry secrets, paths, commands, registry, process, vault, browser session, or launch capability material'
    )
    if (selection.metadataOnly !== true) fail('sanitized snapshot.selection.metadataOnly must be true.')
    if (selection.selectionKind !== 'metadata-only') fail('sanitized snapshot.selection.selectionKind must be metadata-only.')
    return {
        defaultPresetId: normalizeSafePatchId(selection.defaultPresetId, 'sanitized snapshot.selection.defaultPresetId', ['preset_'], {
            nullable: true,
            required: false
        }),
        nextPresetId: normalizeSafePatchId(selection.nextPresetId, 'sanitized snapshot.selection.nextPresetId', ['preset_'], {
            nullable: true,
            required: false
        }),
        metadataOnly: true,
        selectionKind: 'metadata-only'
    }
}

function validateSnapshotAvailableItem(value, index) {
    const fieldName = `sanitized snapshot.availableItems[${index}]`
    const item = requireObject(value, fieldName)
    rejectUnknownKeysFor(
        item,
        SNAPSHOT_AVAILABLE_ITEM_KEYS,
        fieldName,
        'sanitized snapshots cannot carry secrets, paths, commands, registry, process, vault, browser session, or launch capability material'
    )
    const type = normalizeString(item.type, `${fieldName}.type`, {
        required: true,
        max: 40,
        rejectDangerous: false
    })
    if (!SNAPSHOT_ITEM_TYPES.has(type)) fail(`${fieldName}.type is invalid.`)
    const source = normalizeString(item.source, `${fieldName}.source`, {
        required: true,
        max: 40,
        rejectDangerous: false
    })
    if (!SNAPSHOT_ITEM_SOURCES.has(source)) fail(`${fieldName}.source is invalid.`)
    if (source !== expectedSnapshotSourceForType(type)) fail(`${fieldName}.source does not match its type.`)
    const status = normalizeString(item.status, `${fieldName}.status`, {
        required: true,
        max: 40,
        rejectDangerous: false
    })
    if (!SNAPSHOT_ITEM_STATUSES.has(status)) fail(`${fieldName}.status is invalid.`)
    if (item.metadataOnly != null && item.metadataOnly !== true) fail(`${fieldName}.metadataOnly must be true when present.`)
    if ((type === 'account-intention' || type === 'profile-intention') && item.metadataOnly !== true) {
        fail(`${fieldName}.metadataOnly must be true for account/profile intentions.`)
    }

    const next = {
        id: normalizeSafePatchId(item.id, `${fieldName}.id`, expectedSnapshotIdPrefixesForType(type)),
        type,
        label: normalizeString(item.label, `${fieldName}.label`, {
            required: true,
            max: SANITIZED_PRESET_SNAPSHOT_LIMITS.maxItemLabelLength
        }),
        status,
        source
    }
    if (item.url != null) {
        if (type !== 'browser-tab') fail(`${fieldName}.url is only allowed on browser-tab items.`)
        next.url = validateBrowserUrl(item.url, `${fieldName}.url`)
        if (next.url !== item.url) fail(`${fieldName}.url must already be normalized.`)
    }
    if (item.provider != null) {
        next.provider = normalizeProvider(item.provider, `${fieldName}.provider`)
    }
    if (item.identifierHint != null) {
        next.identifierHint = normalizeOptionalString(item.identifierHint, `${fieldName}.identifierHint`, {
            max: SANITIZED_PRESET_SNAPSHOT_LIMITS.maxAccountIdentifierHintLength
        })
    }
    if (item.state != null) {
        const state = normalizeString(item.state, `${fieldName}.state`, {
            required: true,
            max: 80,
            rejectDangerous: false
        })
        if (!SNAPSHOT_ACCOUNT_STATES.has(state)) fail(`${fieldName}.state is not supported.`)
        next.state = state
    }
    if (item.metadataOnly === true) next.metadataOnly = true
    return next
}

function validateSnapshotItemRef(value, index, presetIndex) {
    const fieldName = `sanitized snapshot.presets[${presetIndex}].itemRefs[${index}]`
    const ref = requireObject(value, fieldName)
    rejectUnknownKeysFor(
        ref,
        SNAPSHOT_ITEM_REF_KEYS,
        fieldName,
        'sanitized snapshots cannot carry secrets, paths, commands, registry, process, vault, browser session, or launch capability material'
    )
    if (ref.metadataOnly !== true) fail(`${fieldName}.metadataOnly must be true.`)
    const next = {
        id: normalizeSafePatchId(ref.id, `${fieldName}.id`, ['pref_']),
        itemId: normalizeSafePatchId(ref.itemId, `${fieldName}.itemId`, ['item_', 'accti_', 'profi_']),
        order: normalizeInteger(ref.order, `${fieldName}.order`),
        enabled: normalizeRequiredBoolean(ref.enabled, `${fieldName}.enabled`),
        metadataOnly: true
    }
    if (ref.accountIntentionId != null) {
        next.accountIntentionId = normalizeOptionalIntentionId(ref.accountIntentionId, `${fieldName}.accountIntentionId`, 'accti_')
    }
    if (ref.profileIntentionId != null) {
        next.profileIntentionId = normalizeOptionalIntentionId(ref.profileIntentionId, `${fieldName}.profileIntentionId`, 'profi_')
    }
    return next
}

function validateSnapshotPreset(value, index) {
    const fieldName = `sanitized snapshot.presets[${index}]`
    const preset = requireObject(value, fieldName)
    rejectUnknownKeysFor(
        preset,
        SNAPSHOT_PRESET_KEYS,
        fieldName,
        'sanitized snapshots cannot carry secrets, paths, commands, registry, process, vault, browser session, or launch capability material'
    )
    const itemRefs = normalizeRequiredArray(
        preset.itemRefs,
        `${fieldName}.itemRefs`,
        SANITIZED_PRESET_SNAPSHOT_LIMITS.maxPresetItemRefs
    ).map((ref, refIndex) => validateSnapshotItemRef(ref, refIndex, index))
    assertUniqueValues(itemRefs.map(ref => ref.id), `${fieldName}.itemRefs`)
    assertUniqueValues(itemRefs.map(ref => ref.itemId), `${fieldName}.itemRefs`)
    return {
        id: normalizeSafePatchId(preset.id, `${fieldName}.id`, ['preset_']),
        name: normalizeString(preset.name, `${fieldName}.name`, {
            required: true,
            max: SANITIZED_PRESET_SNAPSHOT_LIMITS.maxPresetNameLength
        }),
        order: normalizeInteger(preset.order, `${fieldName}.order`),
        enabled: normalizeRequiredBoolean(preset.enabled, `${fieldName}.enabled`),
        itemRefs
    }
}

export function validateSanitizedPresetSnapshotForPhone(input) {
    const rawSnapshot = parseJsonInput(
        input,
        'sanitized snapshot JSON',
        SANITIZED_PRESET_SNAPSHOT_LIMITS.maxSnapshotJsonBytes
    )
    const snapshot = requireObject(rawSnapshot, 'sanitized snapshot')
    assertNoForbiddenPlannerMaterial(snapshot, 'sanitized snapshot')
    rejectUnknownKeysFor(
        snapshot,
        SNAPSHOT_TOP_LEVEL_KEYS,
        'sanitized snapshot',
        'sanitized snapshots cannot carry secrets, paths, commands, registry, process, vault, browser session, or launch capability material'
    )

    const product = normalizeString(snapshot.product, 'sanitized snapshot.product', {
        required: true,
        max: 40,
        rejectDangerous: false
    }).toLowerCase()
    if (product !== 'wipesnap') fail('sanitized snapshot.product is not supported.')
    if (snapshot.kind !== SANITIZED_PRESET_SNAPSHOT_KIND) fail('sanitized snapshot.kind is not supported.')
    if (snapshot.schemaVersion !== SANITIZED_PRESET_SNAPSHOT_SCHEMA_VERSION) {
        fail('sanitized snapshot.schemaVersion is not supported.')
    }

    const availableItems = normalizeRequiredArray(
        snapshot.availableItems,
        'sanitized snapshot.availableItems',
        SANITIZED_PRESET_SNAPSHOT_LIMITS.maxAvailableItems
    ).map(validateSnapshotAvailableItem)
    assertUniqueValues(availableItems.map(item => item.id), 'sanitized snapshot.availableItems')

    const presets = normalizeRequiredArray(
        snapshot.presets,
        'sanitized snapshot.presets',
        SANITIZED_PRESET_SNAPSHOT_LIMITS.maxPresets
    ).map(validateSnapshotPreset)
    assertUniqueValues(presets.map(preset => preset.id), 'sanitized snapshot.presets')

    const itemIds = new Set(availableItems.map(item => item.id))
    const accountIds = new Set(availableItems.filter(item => item.type === 'account-intention').map(item => item.id))
    const profileIds = new Set(availableItems.filter(item => item.type === 'profile-intention').map(item => item.id))
    for (const preset of presets) {
        for (const ref of preset.itemRefs) {
            if (!itemIds.has(ref.itemId)) fail('sanitized snapshot preset item reference points at an unknown safe item.')
            if (ref.accountIntentionId && !accountIds.has(ref.accountIntentionId)) {
                fail('sanitized snapshot preset item reference points at an unknown account intention.')
            }
            if (ref.profileIntentionId && !profileIds.has(ref.profileIntentionId)) {
                fail('sanitized snapshot preset item reference points at an unknown profile intention.')
            }
        }
    }

    const presetIds = new Set(presets.map(preset => preset.id))
    const selection = validateSnapshotSelection(snapshot.selection)
    if (selection.defaultPresetId && !presetIds.has(selection.defaultPresetId)) {
        fail('sanitized snapshot.selection.defaultPresetId references an unknown preset id.')
    }
    if (selection.nextPresetId && !presetIds.has(selection.nextPresetId)) {
        fail('sanitized snapshot.selection.nextPresetId references an unknown preset id.')
    }

    const normalized = {
        product,
        kind: SANITIZED_PRESET_SNAPSHOT_KIND,
        schemaVersion: SANITIZED_PRESET_SNAPSHOT_SCHEMA_VERSION,
        snapshotId: normalizeSafePatchId(snapshot.snapshotId, 'sanitized snapshot.snapshotId', ['snap_']),
        revisionId: normalizeSafePatchId(snapshot.revisionId, 'sanitized snapshot.revisionId', ['srev_']),
        baseRevisionId: normalizeSafePatchId(snapshot.baseRevisionId, 'sanitized snapshot.baseRevisionId', ['srev_'], {
            nullable: true,
            required: false
        }),
        sourceDeviceId: normalizeSafePatchId(snapshot.sourceDeviceId, 'sanitized snapshot.sourceDeviceId', ['dev_']),
        timestamp: normalizeTimestamp(snapshot.timestamp, 'sanitized snapshot.timestamp'),
        limits: validateSnapshotLimits(snapshot.limits),
        selection,
        presets,
        availableItems
    }
    if (jsonByteLength(normalized) > SANITIZED_PRESET_SNAPSHOT_LIMITS.maxSnapshotJsonBytes) {
        fail('sanitized snapshot JSON exceeds the byte limit.')
    }
    return normalized
}

function indexById(items) {
    const map = new Map()
    for (const item of items || []) map.set(item.id, item)
    return map
}

function orderedByOrder(items) {
    return [...items].map((item, index) => ({ item, index }))
        .sort((a, b) => Number(a.item.order || 0) - Number(b.item.order || 0) || a.index - b.index)
        .map(({ item }) => item)
}

function snapshotPatchRefFromRef(ref) {
    return {
        itemId: ref.itemId,
        order: ref.order,
        enabled: ref.enabled,
        ...(ref.accountIntentionId ? { accountIntentionId: ref.accountIntentionId } : {}),
        ...(ref.profileIntentionId ? { profileIntentionId: ref.profileIntentionId } : {}),
        metadataOnly: true
    }
}

function snapshotPatchPresetFromPreset(preset) {
    return {
        id: preset.id,
        name: preset.name,
        order: preset.order,
        enabled: preset.enabled,
        itemRefs: orderedByOrder(preset.itemRefs).map(snapshotPatchRefFromRef),
        metadataOnly: true
    }
}

function createEditorSelectionFromSnapshot(snapshot) {
    return {
        defaultPresetId: snapshot.selection.defaultPresetId,
        nextPresetId: snapshot.selection.nextPresetId,
        metadataOnly: true,
        selectionKind: 'metadata-only'
    }
}

export function createSnapshotEditorFromSnapshot(snapshotInput, options = {}) {
    const snapshot = validateSanitizedPresetSnapshotForPhone(snapshotInput)
    const timestamp = nowMs(options.now)
    const selectedPresetId = orderedByOrder(snapshot.presets)[0]?.id || ''
    const authorDeviceId = options.authorDeviceId
        ? normalizeSafePatchId(options.authorDeviceId, 'snapshot editor.authorDeviceId', ['dev_'])
        : idFromFactory(options.idFactory || createLocalId, 'dev')
    return {
        mode: 'snapshot-editor',
        snapshot,
        selectedPresetId,
        authorDeviceId,
        patchId: options.patchId
            ? normalizeSafePatchId(options.patchId, 'snapshot editor.patchId', ['patch_'])
            : idFromFactory(options.idFactory || createLocalId, 'patch'),
        patchRevisionId: options.patchRevisionId
            ? normalizeSafePatchId(options.patchRevisionId, 'snapshot editor.patchRevisionId', ['patchrev_'])
            : idFromFactory(options.idFactory || createLocalId, 'patchrev'),
        createdAt: timestamp,
        updatedAt: timestamp,
        selection: createEditorSelectionFromSnapshot(snapshot),
        presets: orderedByOrder(snapshot.presets).map(snapshotPatchPresetFromPreset),
        newBrowserItems: [],
        lastExportJson: ''
    }
}

function normalizeEditorSelection(value, snapshotIndexes, fieldName = 'snapshot editor.selection') {
    const selection = value == null
        ? { defaultPresetId: null, nextPresetId: null, metadataOnly: true, selectionKind: 'metadata-only' }
        : requireObject(value, fieldName)
    rejectUnknownKeysFor(
        selection,
        SNAPSHOT_EDITOR_SELECTION_KEYS,
        fieldName,
        'phone preset edits cannot carry secrets, paths, commands, registry, process, vault, browser session, or launch capability material'
    )
    validateMetadataOnly(selection.metadataOnly, `${fieldName}.metadataOnly`)
    if (selection.selectionKind != null && selection.selectionKind !== 'metadata-only') {
        fail(`${fieldName}.selectionKind must be metadata-only.`)
    }
    const next = {
        defaultPresetId: normalizeSafePatchId(selection.defaultPresetId, `${fieldName}.defaultPresetId`, ['preset_'], {
            nullable: true,
            required: false
        }),
        nextPresetId: normalizeSafePatchId(selection.nextPresetId, `${fieldName}.nextPresetId`, ['preset_'], {
            nullable: true,
            required: false
        }),
        metadataOnly: true,
        selectionKind: 'metadata-only'
    }
    if (snapshotIndexes && next.defaultPresetId && !snapshotIndexes.presets.has(next.defaultPresetId)) {
        fail(`${fieldName}.defaultPresetId references an unknown preset id.`)
    }
    if (snapshotIndexes && next.nextPresetId && !snapshotIndexes.presets.has(next.nextPresetId)) {
        fail(`${fieldName}.nextPresetId references an unknown preset id.`)
    }
    return next
}

function normalizeEditorNewBrowserItem(value, index) {
    const fieldName = `snapshot editor.newBrowserItems[${index}]`
    const item = requireObject(value, fieldName)
    rejectUnknownKeysFor(
        item,
        SNAPSHOT_EDITOR_NEW_BROWSER_ITEM_KEYS,
        fieldName,
        'phone preset edits cannot carry secrets, paths, commands, registry, process, vault, browser session, or launch capability material'
    )
    validateMetadataOnly(item.metadataOnly, `${fieldName}.metadataOnly`)
    const next = {
        id: normalizeSafePatchId(item.id, `${fieldName}.id`, ['patch_item_']),
        url: validateBrowserUrl(item.url, `${fieldName}.url`),
        label: normalizeOptionalString(item.label, `${fieldName}.label`, {
            max: SAFE_PRESET_PATCH_LIMITS.maxBrowserTabLabelLength
        }),
        notes: normalizeOptionalString(item.notes, `${fieldName}.notes`, {
            max: SAFE_PRESET_PATCH_LIMITS.maxBrowserTabNotesLength,
            multiline: true
        }),
        enabled: normalizeBoolean(item.enabled, `${fieldName}.enabled`, true),
        metadataOnly: true
    }
    if (Object.hasOwn(item, 'accountIntentionId')) {
        next.accountIntentionId = normalizeOptionalIntentionId(item.accountIntentionId, `${fieldName}.accountIntentionId`, 'accti_')
    }
    if (Object.hasOwn(item, 'profileIntentionId')) {
        next.profileIntentionId = normalizeOptionalIntentionId(item.profileIntentionId, `${fieldName}.profileIntentionId`, 'profi_')
    }
    return next
}

function normalizeEditorItemRef(value, index, presetIndex) {
    const fieldName = `snapshot editor.presets[${presetIndex}].itemRefs[${index}]`
    const ref = requireObject(value, fieldName)
    rejectUnknownKeysFor(
        ref,
        SNAPSHOT_EDITOR_ITEM_REF_KEYS,
        fieldName,
        'phone preset edits cannot carry secrets, paths, commands, registry, process, vault, browser session, or launch capability material'
    )
    validateMetadataOnly(ref.metadataOnly, `${fieldName}.metadataOnly`)
    const next = {
        itemId: normalizeSafePatchId(ref.itemId, `${fieldName}.itemId`, ['item_', 'accti_', 'profi_', 'patch_item_']),
        order: normalizeInteger(ref.order, `${fieldName}.order`),
        enabled: normalizeRequiredBoolean(ref.enabled, `${fieldName}.enabled`),
        metadataOnly: true
    }
    if (Object.hasOwn(ref, 'accountIntentionId')) {
        next.accountIntentionId = normalizeOptionalIntentionId(ref.accountIntentionId, `${fieldName}.accountIntentionId`, 'accti_')
    }
    if (Object.hasOwn(ref, 'profileIntentionId')) {
        next.profileIntentionId = normalizeOptionalIntentionId(ref.profileIntentionId, `${fieldName}.profileIntentionId`, 'profi_')
    }
    return next
}

function normalizeEditorPreset(value, index) {
    const fieldName = `snapshot editor.presets[${index}]`
    const preset = requireObject(value, fieldName)
    rejectUnknownKeysFor(
        preset,
        SNAPSHOT_EDITOR_PRESET_KEYS,
        fieldName,
        'phone preset edits cannot carry secrets, paths, commands, registry, process, vault, browser session, or launch capability material'
    )
    validateMetadataOnly(preset.metadataOnly, `${fieldName}.metadataOnly`)
    const itemRefs = normalizeRequiredArray(
        preset.itemRefs,
        `${fieldName}.itemRefs`,
        SAFE_PRESET_PATCH_LIMITS.maxPresetItemRefs
    ).map((ref, refIndex) => normalizeEditorItemRef(ref, refIndex, index))
    assertUniqueValues(itemRefs.map(ref => ref.itemId), `${fieldName}.itemRefs`)
    return {
        id: normalizeSafePatchId(preset.id, `${fieldName}.id`, ['preset_']),
        name: normalizeString(preset.name, `${fieldName}.name`, {
            required: true,
            max: SAFE_PRESET_PATCH_LIMITS.maxPresetNameLength
        }),
        order: normalizeInteger(preset.order, `${fieldName}.order`),
        enabled: normalizeRequiredBoolean(preset.enabled, `${fieldName}.enabled`),
        itemRefs,
        metadataOnly: true
    }
}

function itemTypeForEditorItem(item) {
    return item?.type || 'browser-tab'
}

function assertIntentionMappingAllowedForEditor({ item, accountIntentionId, profileIntentionId, accountIds, profileIds }) {
    if (accountIntentionId && !accountIds.has(accountIntentionId)) {
        fail('phone preset edit references an unknown account intention id.')
    }
    if (profileIntentionId && !profileIds.has(profileIntentionId)) {
        fail('phone preset edit references an unknown profile intention id.')
    }
    if ((accountIntentionId || profileIntentionId) && itemTypeForEditorItem(item) !== 'browser-tab') {
        fail('phone preset account/profile mappings are only allowed on browser tabs.')
    }
}

function assertEditorReferencesSnapshot(editor, snapshot) {
    const snapshotIndexes = createSnapshotIndexes(snapshot)
    const presetIds = new Set(editor.presets.map(preset => preset.id))
    const newBrowserItems = indexById(editor.newBrowserItems)
    const usedNewBrowserItemIds = new Set()

    for (const preset of editor.presets) {
        if (!snapshotIndexes.presets.has(preset.id)) fail('phone preset edit references an unknown preset id.')
        for (const ref of preset.itemRefs) {
            const newBrowserItem = newBrowserItems.get(ref.itemId) || null
            const item = newBrowserItem
                ? { id: newBrowserItem.id, type: 'browser-tab', source: 'phone-patch', label: newBrowserItem.label || '' }
                : snapshotIndexes.availableItems.get(ref.itemId)
            if (!item) fail('phone preset edit references an unknown safe item id.')
            if (newBrowserItem) {
                if (usedNewBrowserItemIds.has(ref.itemId)) fail('phone preset edit contains a duplicate new browser item reference.')
                usedNewBrowserItemIds.add(ref.itemId)
            }
            assertIntentionMappingAllowedForEditor({
                item,
                accountIntentionId: ref.accountIntentionId || newBrowserItem?.accountIntentionId || '',
                profileIntentionId: ref.profileIntentionId || newBrowserItem?.profileIntentionId || '',
                accountIds: snapshotIndexes.accountIntentions,
                profileIds: snapshotIndexes.profileIntentions
            })
        }
    }
    for (const item of editor.newBrowserItems) {
        if (!usedNewBrowserItemIds.has(item.id)) fail('phone preset edit new browser items must be referenced by exactly one preset item ref.')
        assertIntentionMappingAllowedForEditor({
            item: { ...item, type: 'browser-tab' },
            accountIntentionId: item.accountIntentionId || '',
            profileIntentionId: item.profileIntentionId || '',
            accountIds: snapshotIndexes.accountIntentions,
            profileIds: snapshotIndexes.profileIntentions
        })
    }
    for (const selected of [editor.selectedPresetId, editor.selection.defaultPresetId, editor.selection.nextPresetId]) {
        if (selected && !presetIds.has(selected)) fail('phone preset edit selection references an unknown preset id.')
    }
}

function createSnapshotIndexes(snapshot) {
    return {
        availableItems: indexById(snapshot.availableItems),
        presets: indexById(snapshot.presets),
        accountIntentions: new Set(snapshot.availableItems.filter(item => item.type === 'account-intention').map(item => item.id)),
        profileIntentions: new Set(snapshot.availableItems.filter(item => item.type === 'profile-intention').map(item => item.id))
    }
}

export function normalizeSnapshotEditorForExport(input) {
    const editor = requireObject(input, 'snapshot editor')
    assertNoForbiddenPlannerMaterial(editor, 'snapshot editor')
    rejectUnknownKeysFor(
        editor,
        SNAPSHOT_EDITOR_KEYS,
        'snapshot editor',
        'phone preset edits cannot carry secrets, paths, commands, registry, process, vault, browser session, or launch capability material'
    )
    const snapshot = validateSanitizedPresetSnapshotForPhone(editor.snapshot)
    const snapshotIndexes = createSnapshotIndexes(snapshot)
    const selectedPresetId = normalizeSafePatchId(editor.selectedPresetId, 'snapshot editor.selectedPresetId', ['preset_'], {
        required: false
    })
    if (selectedPresetId && !snapshotIndexes.presets.has(selectedPresetId)) {
        fail('snapshot editor.selectedPresetId references an unknown preset id.')
    }
    const newBrowserItems = normalizeArray(
        editor.newBrowserItems,
        'snapshot editor.newBrowserItems',
        SAFE_PRESET_PATCH_LIMITS.maxNewBrowserItems
    ).map(normalizeEditorNewBrowserItem)
    assertUniqueValues(newBrowserItems.map(item => item.id), 'snapshot editor.newBrowserItems')
    const normalized = {
        mode: editor.mode === 'snapshot-editor' ? 'snapshot-editor' : 'snapshot-editor',
        snapshot,
        selectedPresetId,
        authorDeviceId: normalizeSafePatchId(editor.authorDeviceId, 'snapshot editor.authorDeviceId', ['dev_']),
        patchId: normalizeSafePatchId(editor.patchId, 'snapshot editor.patchId', ['patch_']),
        patchRevisionId: normalizeSafePatchId(editor.patchRevisionId, 'snapshot editor.patchRevisionId', ['patchrev_']),
        createdAt: normalizeTimestamp(editor.createdAt, 'snapshot editor.createdAt'),
        updatedAt: normalizeTimestamp(editor.updatedAt, 'snapshot editor.updatedAt'),
        selection: normalizeEditorSelection(editor.selection, snapshotIndexes),
        presets: normalizeRequiredArray(
            editor.presets,
            'snapshot editor.presets',
            SAFE_PRESET_PATCH_LIMITS.maxPresets
        ).map(normalizeEditorPreset),
        newBrowserItems,
        lastExportJson: normalizeOptionalString(editor.lastExportJson, 'snapshot editor.lastExportJson', {
            max: SAFE_PRESET_PATCH_LIMITS.maxPatchJsonBytes,
            multiline: true,
            rejectDangerous: false
        })
    }
    assertUniqueValues(normalized.presets.map(preset => preset.id), 'snapshot editor.presets')
    assertEditorReferencesSnapshot(normalized, snapshot)
    return normalized
}

function normalizePatchSelection(value, snapshotIndexes) {
    if (value == null) return null
    return normalizeEditorSelection(value, snapshotIndexes, 'safe preset patch.selection')
}

function validatePatchNewBrowserItem(value, index) {
    return normalizeEditorNewBrowserItem(value, index)
}

function validatePatchItemRef(value, index, presetIndex) {
    return normalizeEditorItemRef(value, index, presetIndex)
}

function validatePatchPreset(value, index) {
    const fieldName = `safe preset patch.presets[${index}]`
    const preset = requireObject(value, fieldName)
    rejectUnknownKeysFor(
        preset,
        PATCH_PRESET_KEYS,
        fieldName,
        'safe preset patches cannot carry secrets, paths, commands, registry, process, vault, browser session, or launch capability material'
    )
    validateMetadataOnly(preset.metadataOnly, `${fieldName}.metadataOnly`)
    const next = {
        id: normalizeSafePatchId(preset.id, `${fieldName}.id`, ['preset_']),
        metadataOnly: true
    }
    if (Object.hasOwn(preset, 'name')) {
        next.name = normalizeString(preset.name, `${fieldName}.name`, {
            required: true,
            max: SAFE_PRESET_PATCH_LIMITS.maxPresetNameLength
        })
    }
    if (Object.hasOwn(preset, 'order')) next.order = normalizeInteger(preset.order, `${fieldName}.order`)
    if (Object.hasOwn(preset, 'enabled')) next.enabled = normalizeRequiredBoolean(preset.enabled, `${fieldName}.enabled`)
    if (Object.hasOwn(preset, 'itemRefs')) {
        next.itemRefs = normalizeRequiredArray(
            preset.itemRefs,
            `${fieldName}.itemRefs`,
            SAFE_PRESET_PATCH_LIMITS.maxPresetItemRefs
        ).map((ref, refIndex) => validatePatchItemRef(ref, refIndex, index))
        assertUniqueValues(next.itemRefs.map(ref => ref.itemId), `${fieldName}.itemRefs`)
    }
    return next
}

function assertPatchReferencesSnapshot(patch, snapshot) {
    const snapshotIndexes = createSnapshotIndexes(snapshot)
    const newBrowserItems = indexById(patch.newBrowserItems)
    if (patch.baseSnapshotRevisionId !== snapshot.revisionId) {
        fail('safe preset patch.baseSnapshotRevisionId does not match the sanitized snapshot revision.')
    }
    if (snapshot.availableItems.length + patch.newBrowserItems.length > SANITIZED_PRESET_SNAPSHOT_LIMITS.maxAvailableItems) {
        fail('safe preset patch would exceed the sanitized snapshot available item limit.')
    }
    if (patch.selection?.defaultPresetId && !snapshotIndexes.presets.has(patch.selection.defaultPresetId)) {
        fail('safe preset patch.selection.defaultPresetId references an unknown preset id.')
    }
    if (patch.selection?.nextPresetId && !snapshotIndexes.presets.has(patch.selection.nextPresetId)) {
        fail('safe preset patch.selection.nextPresetId references an unknown preset id.')
    }

    const usedNewBrowserItemIds = new Set()
    for (const preset of patch.presets) {
        if (!snapshotIndexes.presets.has(preset.id)) fail('safe preset patch references an unknown preset id.')
        if (!Object.hasOwn(preset, 'itemRefs')) continue
        for (const ref of preset.itemRefs) {
            const newBrowserItem = newBrowserItems.get(ref.itemId) || null
            const item = newBrowserItem
                ? { id: newBrowserItem.id, type: 'browser-tab', source: 'phone-patch', label: newBrowserItem.label || '' }
                : snapshotIndexes.availableItems.get(ref.itemId)
            if (!item) fail('safe preset patch references an unknown safe item id.')
            if (newBrowserItem) {
                if (usedNewBrowserItemIds.has(ref.itemId)) fail('safe preset patch contains a duplicate new browser item reference.')
                usedNewBrowserItemIds.add(ref.itemId)
            }
            assertIntentionMappingAllowedForEditor({
                item,
                accountIntentionId: ref.accountIntentionId || newBrowserItem?.accountIntentionId || '',
                profileIntentionId: ref.profileIntentionId || newBrowserItem?.profileIntentionId || '',
                accountIds: snapshotIndexes.accountIntentions,
                profileIds: snapshotIndexes.profileIntentions
            })
        }
    }
    for (const item of patch.newBrowserItems) {
        if (!usedNewBrowserItemIds.has(item.id)) fail('safe preset patch new browser items must be referenced by exactly one preset item ref.')
    }
}

export function validateSafePresetPatchForPhone(input, sanitizedSnapshotInput) {
    const rawPatch = parseJsonInput(input, 'safe preset patch JSON', SAFE_PRESET_PATCH_LIMITS.maxPatchJsonBytes)
    const patch = requireObject(rawPatch, 'safe preset patch')
    assertNoForbiddenPlannerMaterial(patch, 'safe preset patch')
    rejectUnknownKeysFor(
        patch,
        PATCH_TOP_LEVEL_KEYS,
        'safe preset patch',
        'safe preset patches cannot carry secrets, paths, commands, registry, process, vault, browser session, or launch capability material'
    )
    const product = normalizeString(patch.product, 'safe preset patch.product', {
        required: true,
        max: 40,
        rejectDangerous: false
    }).toLowerCase()
    if (product !== 'wipesnap') fail('safe preset patch.product is not supported.')
    if (patch.kind !== SAFE_PRESET_PATCH_KIND) fail('safe preset patch.kind is not supported.')
    if (patch.schemaVersion !== SAFE_PRESET_PATCH_SCHEMA_VERSION) fail('safe preset patch.schemaVersion is not supported.')

    const snapshot = sanitizedSnapshotInput
        ? validateSanitizedPresetSnapshotForPhone(sanitizedSnapshotInput)
        : null
    const snapshotIndexes = snapshot ? createSnapshotIndexes(snapshot) : null
    const normalized = {
        product,
        kind: SAFE_PRESET_PATCH_KIND,
        schemaVersion: SAFE_PRESET_PATCH_SCHEMA_VERSION,
        patchId: normalizeSafePatchId(patch.patchId, 'safe preset patch.patchId', ['patch_']),
        patchRevisionId: normalizeSafePatchId(patch.patchRevisionId, 'safe preset patch.patchRevisionId', ['patchrev_']),
        baseSnapshotRevisionId: normalizeSafePatchId(patch.baseSnapshotRevisionId, 'safe preset patch.baseSnapshotRevisionId', ['srev_']),
        authorDeviceId: normalizeSafePatchId(patch.authorDeviceId, 'safe preset patch.authorDeviceId', ['dev_']),
        createdAt: normalizeTimestamp(patch.createdAt, 'safe preset patch.createdAt'),
        updatedAt: normalizeTimestamp(patch.updatedAt, 'safe preset patch.updatedAt'),
        selection: normalizePatchSelection(patch.selection, snapshotIndexes),
        presets: normalizeArray(
            patch.presets,
            'safe preset patch.presets',
            SAFE_PRESET_PATCH_LIMITS.maxPresets
        ).map(validatePatchPreset),
        newBrowserItems: normalizeArray(
            patch.newBrowserItems,
            'safe preset patch.newBrowserItems',
            SAFE_PRESET_PATCH_LIMITS.maxNewBrowserItems
        ).map(validatePatchNewBrowserItem)
    }
    assertUniqueValues(normalized.presets.map(preset => preset.id), 'safe preset patch.presets')
    assertUniqueValues(normalized.newBrowserItems.map(item => item.id), 'safe preset patch.newBrowserItems')
    if (snapshot) assertPatchReferencesSnapshot(normalized, snapshot)
    if (jsonByteLength(normalized) > SAFE_PRESET_PATCH_LIMITS.maxPatchJsonBytes) {
        fail(`safe preset patch JSON exceeds the ${SAFE_PRESET_PATCH_LIMITS.maxPatchJsonBytes} byte limit.`)
    }
    return normalized
}

function cleanPatchRefForExport(ref) {
    return {
        itemId: ref.itemId,
        order: ref.order,
        enabled: ref.enabled,
        ...(ref.accountIntentionId ? { accountIntentionId: ref.accountIntentionId } : {}),
        ...(ref.profileIntentionId ? { profileIntentionId: ref.profileIntentionId } : {}),
        metadataOnly: true
    }
}

function cleanNewBrowserItemForExport(item) {
    return {
        id: item.id,
        url: item.url,
        label: item.label,
        notes: item.notes,
        enabled: item.enabled,
        ...(item.accountIntentionId ? { accountIntentionId: item.accountIntentionId } : {}),
        ...(item.profileIntentionId ? { profileIntentionId: item.profileIntentionId } : {}),
        metadataOnly: true
    }
}

export function buildSafePresetPatch(editorInput) {
    const editor = normalizeSnapshotEditorForExport(editorInput)
    const patch = {
        product: 'wipesnap',
        kind: SAFE_PRESET_PATCH_KIND,
        schemaVersion: SAFE_PRESET_PATCH_SCHEMA_VERSION,
        patchId: editor.patchId,
        patchRevisionId: editor.patchRevisionId,
        baseSnapshotRevisionId: editor.snapshot.revisionId,
        authorDeviceId: editor.authorDeviceId,
        createdAt: editor.createdAt,
        updatedAt: editor.updatedAt,
        selection: {
            defaultPresetId: editor.selection.defaultPresetId,
            nextPresetId: editor.selection.nextPresetId,
            metadataOnly: true,
            selectionKind: 'metadata-only'
        },
        presets: orderedByOrder(editor.presets).map(preset => ({
            id: preset.id,
            name: preset.name,
            order: preset.order,
            enabled: preset.enabled,
            itemRefs: orderedByOrder(preset.itemRefs).map(cleanPatchRefForExport),
            metadataOnly: true
        })),
        newBrowserItems: editor.newBrowserItems.map(cleanNewBrowserItemForExport)
    }
    return validateSafePresetPatchForPhone(patch, editor.snapshot)
}

export function exportSafePresetPatchJson(editorInput) {
    return JSON.stringify(buildSafePresetPatch(editorInput), null, 2)
}

export function validateSafePresetPatchForExport(editorInput) {
    try {
        const patch = buildSafePresetPatch(editorInput)
        return { valid: true, patch, errors: [] }
    } catch (err) {
        return { valid: false, patch: null, errors: [err?.message || 'Safe preset patch is not valid.'] }
    }
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
        snapshotEditor: null,
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

function snapshotEditorOrFail(state) {
    if (!state.snapshotEditor) fail('No sanitized snapshot is loaded.')
    return state.snapshotEditor
}

function touchSnapshotEditor(editor, { now = Date.now, idFactory = createLocalId } = {}) {
    editor.patchRevisionId = idFromFactory(idFactory, 'patchrev')
    editor.updatedAt = nowMs(now)
    editor.lastExportJson = ''
    return editor
}

function selectedSnapshotPreset(editor, presetId) {
    const index = editor.presets.findIndex(preset => preset.id === presetId)
    if (index < 0) fail('Preset was not found.')
    return { preset: editor.presets[index], index }
}

function nextOrder(items) {
    return items.reduce((max, item) => Math.max(max, Number(item.order || 0)), -1) + 1
}

function renumberOrders(items) {
    items.forEach((item, index) => { item.order = index })
    return items
}

function findEditorItem(editor, itemId) {
    const snapshotItem = editor.snapshot.availableItems.find(item => item.id === itemId)
    if (snapshotItem) return { item: snapshotItem, newBrowserItem: null }
    const newBrowserItem = editor.newBrowserItems.find(item => item.id === itemId)
    if (newBrowserItem) {
        return {
            item: {
                id: newBrowserItem.id,
                type: 'browser-tab',
                source: 'phone-patch',
                label: newBrowserItem.label || newBrowserItem.url,
                status: newBrowserItem.enabled === false ? 'disabled' : 'available',
                url: newBrowserItem.url
            },
            newBrowserItem
        }
    }
    return { item: null, newBrowserItem: null }
}

function validateIntentionIdsForEditor(editor, { item, accountIntentionId = '', profileIntentionId = '' }) {
    const indexes = createSnapshotIndexes(editor.snapshot)
    assertIntentionMappingAllowedForEditor({
        item,
        accountIntentionId,
        profileIntentionId,
        accountIds: indexes.accountIntentions,
        profileIds: indexes.profileIntentions
    })
}

export function importSnapshotIntoPlannerState(stateInput, snapshotInput, options = {}) {
    const state = clone(normalizeStoredPlannerState(stateInput, options))
    state.snapshotEditor = createSnapshotEditorFromSnapshot(snapshotInput, options)
    state.lastSavedAt = nowMs(options.now)
    return state
}

export function clearSnapshotEditorFromState(stateInput, options = {}) {
    const state = clone(normalizeStoredPlannerState(stateInput, options))
    state.snapshotEditor = null
    state.lastSavedAt = nowMs(options.now)
    return state
}

export function updateSnapshotEditorSelection(stateInput, selectionPatch, options = {}) {
    const state = clone(normalizeStoredPlannerState(stateInput, options))
    const editor = snapshotEditorOrFail(state)
    const allowed = new Set(['defaultPresetId', 'nextPresetId'])
    rejectUnknownKeysFor(
        selectionPatch || {},
        allowed,
        'snapshot editor.selection edit',
        'phone preset edits cannot carry secrets, paths, commands, registry, process, vault, browser session, or launch capability material'
    )
    const indexes = createSnapshotIndexes(editor.snapshot)
    if (Object.hasOwn(selectionPatch || {}, 'defaultPresetId')) {
        const value = normalizeSafePatchId(selectionPatch.defaultPresetId, 'snapshot editor.selection.defaultPresetId', ['preset_'], {
            nullable: true,
            required: false
        })
        if (value && !indexes.presets.has(value)) fail('Default preset selection references an unknown preset id.')
        editor.selection.defaultPresetId = value
    }
    if (Object.hasOwn(selectionPatch || {}, 'nextPresetId')) {
        const value = normalizeSafePatchId(selectionPatch.nextPresetId, 'snapshot editor.selection.nextPresetId', ['preset_'], {
            nullable: true,
            required: false
        })
        if (value && !indexes.presets.has(value)) fail('Next preset selection references an unknown preset id.')
        editor.selection.nextPresetId = value
    }
    touchSnapshotEditor(editor, options)
    state.lastSavedAt = nowMs(options.now)
    return state
}

export function selectSnapshotPresetInState(stateInput, presetId, options = {}) {
    const state = clone(normalizeStoredPlannerState(stateInput, options))
    const editor = snapshotEditorOrFail(state)
    const id = normalizeSafePatchId(presetId, 'snapshot editor.selectedPresetId', ['preset_'])
    selectedSnapshotPreset(editor, id)
    editor.selectedPresetId = id
    state.lastSavedAt = nowMs(options.now)
    return state
}

export function updateSnapshotPresetFields(stateInput, presetId, patch, options = {}) {
    const state = clone(normalizeStoredPlannerState(stateInput, options))
    const editor = snapshotEditorOrFail(state)
    const { preset } = selectedSnapshotPreset(editor, presetId)
    const allowed = new Set(['name', 'enabled', 'order'])
    rejectUnknownKeysFor(
        patch || {},
        allowed,
        'snapshot preset edit',
        'phone preset edits cannot carry secrets, paths, commands, registry, process, vault, browser session, or launch capability material'
    )
    if (Object.hasOwn(patch || {}, 'name')) {
        preset.name = normalizeString(patch.name, 'snapshot preset edit.name', {
            required: true,
            max: SAFE_PRESET_PATCH_LIMITS.maxPresetNameLength
        })
    }
    if (Object.hasOwn(patch || {}, 'enabled')) {
        preset.enabled = normalizeRequiredBoolean(patch.enabled, 'snapshot preset edit.enabled')
    }
    if (Object.hasOwn(patch || {}, 'order')) {
        preset.order = normalizeInteger(patch.order, 'snapshot preset edit.order')
    }
    touchSnapshotEditor(editor, options)
    state.lastSavedAt = nowMs(options.now)
    return state
}

export function moveSnapshotPresetInState(stateInput, presetId, direction, options = {}) {
    const state = clone(normalizeStoredPlannerState(stateInput, options))
    const editor = snapshotEditorOrFail(state)
    const ordered = orderedByOrder(editor.presets)
    const index = ordered.findIndex(preset => preset.id === presetId)
    if (index < 0) fail('Preset was not found.')
    const nextIndex = index + direction
    if (nextIndex < 0 || nextIndex >= ordered.length) return state
    const [item] = ordered.splice(index, 1)
    ordered.splice(nextIndex, 0, item)
    editor.presets = renumberOrders(ordered)
    editor.selectedPresetId = presetId
    touchSnapshotEditor(editor, options)
    state.lastSavedAt = nowMs(options.now)
    return state
}

export function addExistingSnapshotItemToPreset(stateInput, presetId, itemId, options = {}) {
    const state = clone(normalizeStoredPlannerState(stateInput, options))
    const editor = snapshotEditorOrFail(state)
    const { preset } = selectedSnapshotPreset(editor, presetId)
    if (preset.itemRefs.length >= SAFE_PRESET_PATCH_LIMITS.maxPresetItemRefs) fail('Preset item limit reached.')
    const id = normalizeSafePatchId(itemId, 'snapshot preset item.itemId', ['item_', 'accti_', 'profi_'])
    const { item } = findEditorItem(editor, id)
    if (!item || item.id.startsWith('patch_item_')) fail('Existing safe item id was not found in the sanitized snapshot.')
    if (preset.itemRefs.some(ref => ref.itemId === id)) fail('Preset already contains that safe item id.')
    preset.itemRefs.push({
        itemId: id,
        order: nextOrder(preset.itemRefs),
        enabled: true,
        metadataOnly: true
    })
    touchSnapshotEditor(editor, options)
    state.lastSavedAt = nowMs(options.now)
    return state
}

export function removeSnapshotItemFromPreset(stateInput, presetId, itemId, options = {}) {
    const state = clone(normalizeStoredPlannerState(stateInput, options))
    const editor = snapshotEditorOrFail(state)
    const { preset } = selectedSnapshotPreset(editor, presetId)
    const beforeLength = preset.itemRefs.length
    preset.itemRefs = renumberOrders(orderedByOrder(preset.itemRefs).filter(ref => ref.itemId !== itemId))
    if (preset.itemRefs.length === beforeLength) fail('Preset item was not found.')
    if (String(itemId || '').startsWith('patch_item_')) {
        const stillReferenced = editor.presets.some(candidate => candidate.itemRefs.some(ref => ref.itemId === itemId))
        if (!stillReferenced) editor.newBrowserItems = editor.newBrowserItems.filter(item => item.id !== itemId)
    }
    touchSnapshotEditor(editor, options)
    state.lastSavedAt = nowMs(options.now)
    return state
}

export function moveSnapshotPresetItemInState(stateInput, presetId, itemId, direction, options = {}) {
    const state = clone(normalizeStoredPlannerState(stateInput, options))
    const editor = snapshotEditorOrFail(state)
    const { preset } = selectedSnapshotPreset(editor, presetId)
    const ordered = orderedByOrder(preset.itemRefs)
    const index = ordered.findIndex(ref => ref.itemId === itemId)
    if (index < 0) fail('Preset item was not found.')
    const nextIndex = index + direction
    if (nextIndex < 0 || nextIndex >= ordered.length) return state
    const [item] = ordered.splice(index, 1)
    ordered.splice(nextIndex, 0, item)
    preset.itemRefs = renumberOrders(ordered)
    touchSnapshotEditor(editor, options)
    state.lastSavedAt = nowMs(options.now)
    return state
}

export function updateSnapshotPresetItem(stateInput, presetId, itemId, patch, options = {}) {
    const state = clone(normalizeStoredPlannerState(stateInput, options))
    const editor = snapshotEditorOrFail(state)
    const { preset } = selectedSnapshotPreset(editor, presetId)
    const ref = preset.itemRefs.find(item => item.itemId === itemId)
    if (!ref) fail('Preset item was not found.')
    const { item, newBrowserItem } = findEditorItem(editor, itemId)
    if (!item) fail('Preset item references an unknown safe item id.')
    const allowed = new Set(['enabled', 'accountIntentionId', 'profileIntentionId'])
    rejectUnknownKeysFor(
        patch || {},
        allowed,
        'snapshot preset item edit',
        'phone preset edits cannot carry secrets, paths, commands, registry, process, vault, browser session, or launch capability material'
    )
    if (Object.hasOwn(patch || {}, 'enabled')) {
        ref.enabled = normalizeRequiredBoolean(patch.enabled, 'snapshot preset item edit.enabled')
        if (newBrowserItem) newBrowserItem.enabled = ref.enabled
    }
    if (Object.hasOwn(patch || {}, 'accountIntentionId')) {
        const accountIntentionId = normalizeOptionalIntentionId(patch.accountIntentionId, 'snapshot preset item edit.accountIntentionId', 'accti_')
        validateIntentionIdsForEditor(editor, {
            item,
            accountIntentionId,
            profileIntentionId: ref.profileIntentionId || newBrowserItem?.profileIntentionId || ''
        })
        if (accountIntentionId) ref.accountIntentionId = accountIntentionId
        else delete ref.accountIntentionId
        if (newBrowserItem) {
            if (accountIntentionId) newBrowserItem.accountIntentionId = accountIntentionId
            else delete newBrowserItem.accountIntentionId
        }
    }
    if (Object.hasOwn(patch || {}, 'profileIntentionId')) {
        const profileIntentionId = normalizeOptionalIntentionId(patch.profileIntentionId, 'snapshot preset item edit.profileIntentionId', 'profi_')
        validateIntentionIdsForEditor(editor, {
            item,
            accountIntentionId: ref.accountIntentionId || newBrowserItem?.accountIntentionId || '',
            profileIntentionId
        })
        if (profileIntentionId) ref.profileIntentionId = profileIntentionId
        else delete ref.profileIntentionId
        if (newBrowserItem) {
            if (profileIntentionId) newBrowserItem.profileIntentionId = profileIntentionId
            else delete newBrowserItem.profileIntentionId
        }
    }
    touchSnapshotEditor(editor, options)
    state.lastSavedAt = nowMs(options.now)
    return state
}

export function addSnapshotBrowserTabToPreset(stateInput, presetId, tabInput = {}, options = {}) {
    const state = clone(normalizeStoredPlannerState(stateInput, options))
    const editor = snapshotEditorOrFail(state)
    const { preset } = selectedSnapshotPreset(editor, presetId)
    if (preset.itemRefs.length >= SAFE_PRESET_PATCH_LIMITS.maxPresetItemRefs) fail('Preset item limit reached.')
    if (editor.newBrowserItems.length >= SAFE_PRESET_PATCH_LIMITS.maxNewBrowserItems) fail('New browser item limit reached.')
    const itemId = options.itemId
        ? normalizeSafePatchId(options.itemId, 'snapshot new browser item.id', ['patch_item_'])
        : idFromFactory(options.idFactory || createLocalId, 'patch_item')
    if (findEditorItem(editor, itemId).item) fail('New browser item id already exists.')
    const item = normalizeEditorNewBrowserItem({
        id: itemId,
        url: tabInput.url,
        label: tabInput.label || '',
        notes: tabInput.notes || '',
        enabled: tabInput.enabled ?? true,
        ...(tabInput.accountIntentionId ? { accountIntentionId: tabInput.accountIntentionId } : {}),
        ...(tabInput.profileIntentionId ? { profileIntentionId: tabInput.profileIntentionId } : {}),
        metadataOnly: true
    }, editor.newBrowserItems.length)
    validateIntentionIdsForEditor(editor, {
        item: { ...item, type: 'browser-tab' },
        accountIntentionId: item.accountIntentionId || '',
        profileIntentionId: item.profileIntentionId || ''
    })
    editor.newBrowserItems.push(item)
    preset.itemRefs.push({
        itemId: item.id,
        order: nextOrder(preset.itemRefs),
        enabled: item.enabled,
        ...(item.accountIntentionId ? { accountIntentionId: item.accountIntentionId } : {}),
        ...(item.profileIntentionId ? { profileIntentionId: item.profileIntentionId } : {}),
        metadataOnly: true
    })
    touchSnapshotEditor(editor, options)
    state.lastSavedAt = nowMs(options.now)
    return state
}

export function updateSnapshotNewBrowserItem(stateInput, itemId, patch, options = {}) {
    const state = clone(normalizeStoredPlannerState(stateInput, options))
    const editor = snapshotEditorOrFail(state)
    const item = editor.newBrowserItems.find(candidate => candidate.id === itemId)
    if (!item) fail('New browser item was not found.')
    const allowed = new Set(['url', 'label', 'notes', 'enabled', 'accountIntentionId', 'profileIntentionId'])
    rejectUnknownKeysFor(
        patch || {},
        allowed,
        'snapshot new browser item edit',
        'phone preset edits cannot carry secrets, paths, commands, registry, process, vault, browser session, or launch capability material'
    )
    if (Object.hasOwn(patch || {}, 'url')) item.url = validateBrowserUrl(patch.url, 'snapshot new browser item edit.url')
    if (Object.hasOwn(patch || {}, 'label')) {
        item.label = normalizeOptionalString(patch.label, 'snapshot new browser item edit.label', {
            max: SAFE_PRESET_PATCH_LIMITS.maxBrowserTabLabelLength
        })
    }
    if (Object.hasOwn(patch || {}, 'notes')) {
        item.notes = normalizeOptionalString(patch.notes, 'snapshot new browser item edit.notes', {
            max: SAFE_PRESET_PATCH_LIMITS.maxBrowserTabNotesLength,
            multiline: true
        })
    }
    if (Object.hasOwn(patch || {}, 'enabled')) {
        item.enabled = normalizeRequiredBoolean(patch.enabled, 'snapshot new browser item edit.enabled')
    }
    if (Object.hasOwn(patch || {}, 'accountIntentionId')) {
        const accountIntentionId = normalizeOptionalIntentionId(patch.accountIntentionId, 'snapshot new browser item edit.accountIntentionId', 'accti_')
        validateIntentionIdsForEditor(editor, {
            item: { ...item, type: 'browser-tab' },
            accountIntentionId,
            profileIntentionId: item.profileIntentionId || ''
        })
        if (accountIntentionId) item.accountIntentionId = accountIntentionId
        else delete item.accountIntentionId
    }
    if (Object.hasOwn(patch || {}, 'profileIntentionId')) {
        const profileIntentionId = normalizeOptionalIntentionId(patch.profileIntentionId, 'snapshot new browser item edit.profileIntentionId', 'profi_')
        validateIntentionIdsForEditor(editor, {
            item: { ...item, type: 'browser-tab' },
            accountIntentionId: item.accountIntentionId || '',
            profileIntentionId
        })
        if (profileIntentionId) item.profileIntentionId = profileIntentionId
        else delete item.profileIntentionId
    }
    for (const preset of editor.presets) {
        const ref = preset.itemRefs.find(candidate => candidate.itemId === item.id)
        if (!ref) continue
        ref.enabled = item.enabled
        if (item.accountIntentionId) ref.accountIntentionId = item.accountIntentionId
        else delete ref.accountIntentionId
        if (item.profileIntentionId) ref.profileIntentionId = item.profileIntentionId
        else delete ref.profileIntentionId
    }
    touchSnapshotEditor(editor, options)
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

function normalizeStoredSnapshotEditor(value) {
    if (value == null) return null
    return normalizeSnapshotEditorForExport(value)
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
        snapshotEditor: normalizeStoredSnapshotEditor(raw.snapshotEditor),
        lastSavedAt: coerceStoredTimestamp(raw.lastSavedAt, nowMs(options.now))
    }
}

import { ACCOUNT_SLOT_PROVIDERS, ACCOUNT_SLOT_STATES } from './accountSlots.js'
import { validateBrowserUrl } from './ipcValidation.js'

export const CLOUD_DRAFT_SCHEMA_VERSION = 1

export const CLOUD_DRAFT_LIMITS = Object.freeze({
    maxActiveDraftsPerUser: 25,
    maxDraftJsonBytes: 256 * 1024,
    maxCloudEnvelopeBytes: 512 * 1024,
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

export const CLOUD_ACCOUNT_STATES = Object.freeze([
    'unknown',
    'needs-check',
    'signed-in',
    'needs-auth',
    'needs-phone-approval',
    'blocked'
])

const PROVIDERS = new Set(ACCOUNT_SLOT_PROVIDERS)
const DESKTOP_ACCOUNT_STATES = new Set(ACCOUNT_SLOT_STATES)
const CLOUD_ACCOUNT_STATE_SET = new Set(CLOUD_ACCOUNT_STATES)
const MAX_TIMESTAMP = 8_640_000_000_000_000
const DRAFT_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_-]{0,95}$/
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
const ENVELOPE_KEYS = new Set([
    'ownerUid',
    'draftId',
    'schemaVersion',
    'revisionId',
    'baseRevisionId',
    'authorDeviceId',
    'updatedAt',
    'createdAt',
    'deletedAt',
    'isDefault',
    'encrypted',
    'encryption',
    'blobHash',
    'blobCiphertext'
])
const ENVELOPE_ENCRYPTION_KEYS = new Set(['alg', 'keyId', 'nonce'])

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

const CLOUD_TO_DESKTOP_STATE = Object.freeze({
    unknown: 'unknown',
    'needs-check': 'needs-recheck',
    'signed-in': 'signed-in',
    'needs-auth': 'needs-auth',
    'needs-phone-approval': 'needs-phone-approval',
    blocked: 'blocked-or-suspicious'
})

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
            fail(`${fieldName}.${key} is not accepted because cloud drafts cannot carry secrets, paths, commands, registry, process, vault, or launch capability material.`)
        }
        fail(`${fieldName}.${key} is not accepted.`)
    }
}

function jsonByteLengthForInput(input, fieldName) {
    if (typeof input === 'string') return Buffer.byteLength(input, 'utf8')
    if (Buffer.isBuffer(input)) return input.length
    try {
        const json = JSON.stringify(input)
        if (typeof json !== 'string') fail(`${fieldName} must be JSON data.`)
        return Buffer.byteLength(json, 'utf8')
    } catch (err) {
        fail(`${fieldName} must be JSON-serializable.`)
    }
}

function parseJsonInput(input, fieldName, maxBytes) {
    const bytes = jsonByteLengthForInput(input, fieldName)
    if (bytes > maxBytes) fail(`${fieldName} exceeds the ${maxBytes} byte limit.`)

    if (typeof input === 'string' || Buffer.isBuffer(input)) {
        const text = Buffer.isBuffer(input) ? input.toString('utf8') : input
        try {
            return JSON.parse(text)
        } catch (_) {
            fail(`${fieldName} must be valid JSON.`)
        }
    }

    return input
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

function normalizeTimestamp(value, fieldName, { required = true, allowNull = false } = {}) {
    if (value == null || value === '') {
        if (allowNull) return null
        if (required) fail(`${fieldName} is required.`)
        return 0
    }
    if (typeof value !== 'number' || !Number.isFinite(value) || value < 0 || value > MAX_TIMESTAMP) {
        fail(`${fieldName} must be a non-negative timestamp.`)
    }
    return Math.floor(value)
}

function normalizeInteger(value, fieldName, { required = true } = {}) {
    if (value == null || value === '') {
        if (required) fail(`${fieldName} is required.`)
        return 0
    }
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
        max: CLOUD_DRAFT_LIMITS.maxIdLength,
        rejectDangerous: false
    })
    if (!DRAFT_ID_PATTERN.test(id)) fail(`${fieldName} must be a safe draft id.`)
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

function normalizeCloudAccountState(value, fieldName) {
    if (value == null || value === '') return 'unknown'
    const state = normalizeString(value, fieldName, {
        required: true,
        max: 80,
        rejectDangerous: false
    }).toLowerCase()
    if (!CLOUD_ACCOUNT_STATE_SET.has(state)) fail(`${fieldName} is not supported.`)
    return state
}

export function mapCloudAccountStateToDesktopState(value) {
    const cloudState = normalizeCloudAccountState(value, 'account state')
    const desktopState = CLOUD_TO_DESKTOP_STATE[cloudState]
    if (!DESKTOP_ACCOUNT_STATES.has(desktopState)) fail('Mapped account state is not supported by desktop account slots.')
    return desktopState
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

function assertRemoteWebUrl(url, fieldName) {
    const parsed = new URL(url)
    const hostname = parsed.hostname.toLowerCase()
    if (hostname === 'localhost') fail(`${fieldName} cannot target localhost.`)

    const ipv4 = parseIpv4(hostname)
    if (ipv4 && isNonPublicIpv4(ipv4)) fail(`${fieldName} cannot target local or private network addresses.`)
    if (hostname.includes(':') && isNonPublicIpv6(hostname)) fail(`${fieldName} cannot target local or private network addresses.`)

    const params = parsed.searchParams
    for (const [key, value] of params.entries()) {
        if (looksLikeForbiddenField(key)) fail(`${fieldName} cannot include secret-looking query parameters.`)
        assertNoDangerousUrlComponent(key, `${fieldName} query parameter`)
        assertNoDangerousUrlComponent(value, `${fieldName} query parameter`)
    }

    if (parsed.hash) {
        assertNoDangerousUrlComponent(parsed.hash.slice(1), `${fieldName} fragment`)
    }
}

function normalizeDraftBrowserUrl(value, fieldName) {
    const raw = normalizeString(value, fieldName, {
        required: true,
        max: CLOUD_DRAFT_LIMITS.maxBrowserTabUrlLength,
        rejectDangerous: false
    })
    if (looksLikeSecretString(raw)) fail(`${fieldName} cannot contain secret-looking material.`)
    const url = validateBrowserUrl(raw, fieldName)
    if (looksLikeSecretString(url)) fail(`${fieldName} cannot contain secret-looking material.`)
    assertRemoteWebUrl(url, fieldName)
    return url
}

function validateAccountIntention(value, index) {
    const fieldName = `cloud draft.accountSlots[${index}]`
    const slot = requireObject(value, fieldName)
    rejectUnknownKeys(slot, ACCOUNT_INTENTION_KEYS, fieldName)
    const cloudState = normalizeCloudAccountState(slot.state, `${fieldName}.state`)

    return {
        id: normalizeId(slot.id, `${fieldName}.id`),
        provider: normalizeProvider(slot.provider, `${fieldName}.provider`),
        label: normalizeString(slot.label, `${fieldName}.label`, {
            required: true,
            max: CLOUD_DRAFT_LIMITS.maxAccountIntentionLabelLength
        }),
        identifierHint: normalizeOptionalString(slot.identifierHint, `${fieldName}.identifierHint`, {
            max: CLOUD_DRAFT_LIMITS.maxAccountIdentifierHintLength
        }),
        profileSlotId: normalizeId(slot.profileSlotId, `${fieldName}.profileSlotId`, { required: false }),
        state: cloudState,
        desktopState: mapCloudAccountStateToDesktopState(cloudState)
    }
}

function validateProfileSlot(value, index) {
    const fieldName = `cloud draft.browserProfileSlots[${index}]`
    const slot = requireObject(value, fieldName)
    rejectUnknownKeys(slot, PROFILE_SLOT_KEYS, fieldName)
    return {
        id: normalizeId(slot.id, `${fieldName}.id`),
        label: normalizeString(slot.label, `${fieldName}.label`, {
            required: true,
            max: CLOUD_DRAFT_LIMITS.maxBrowserProfileSlotLabelLength
        }),
        provider: normalizeProvider(slot.provider, `${fieldName}.provider`)
    }
}

function validateBrowserTab(value, index) {
    const fieldName = `cloud draft.browserTabs[${index}]`
    const tab = requireObject(value, fieldName)
    rejectUnknownKeys(tab, BROWSER_TAB_KEYS, fieldName)
    return {
        id: normalizeId(tab.id, `${fieldName}.id`),
        url: normalizeDraftBrowserUrl(tab.url, `${fieldName}.url`),
        order: normalizeInteger(tab.order, `${fieldName}.order`),
        label: normalizeOptionalString(tab.label, `${fieldName}.label`, {
            max: CLOUD_DRAFT_LIMITS.maxBrowserTabLabelLength
        }),
        notes: normalizeOptionalString(tab.notes, `${fieldName}.notes`, {
            max: CLOUD_DRAFT_LIMITS.maxBrowserTabNotesLength,
            multiline: true
        }),
        enabled: normalizeBoolean(tab.enabled, `${fieldName}.enabled`, true),
        accountSlotId: normalizeId(tab.accountSlotId, `${fieldName}.accountSlotId`, { required: false }),
        profileSlotId: normalizeId(tab.profileSlotId, `${fieldName}.profileSlotId`, { required: false })
    }
}

function validateDesiredApp(value, index) {
    const fieldName = `cloud draft.desiredApps[${index}]`
    const app = requireObject(value, fieldName)
    rejectUnknownKeys(app, DESIRED_APP_KEYS, fieldName)
    const name = normalizeString(app.name, `${fieldName}.name`, {
        required: true,
        max: CLOUD_DRAFT_LIMITS.maxDesiredAppNameLength
    })
    assertSafeDesiredAppText(name, `${fieldName}.name`)
    const label = normalizeOptionalString(app.label, `${fieldName}.label`, {
        max: CLOUD_DRAFT_LIMITS.maxDesiredAppLabelLength
    }) || name
    assertSafeDesiredAppText(label, `${fieldName}.label`)
    const notes = normalizeOptionalString(app.notes, `${fieldName}.notes`, {
        max: CLOUD_DRAFT_LIMITS.maxDesiredAppNotesLength,
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
            fail('cloud draft.accountSlots references an unknown browser profile slot.')
        }
    }

    for (const tab of draft.browserTabs) {
        if (tab.accountSlotId && !accountIds.has(tab.accountSlotId)) {
            fail('cloud draft.browserTabs references an unknown account slot.')
        }
        if (tab.profileSlotId && !profileIds.has(tab.profileSlotId)) {
            fail('cloud draft.browserTabs references an unknown browser profile slot.')
        }
    }
}

export function validateCloudDraft(input) {
    const rawDraft = parseJsonInput(input, 'cloud draft JSON', CLOUD_DRAFT_LIMITS.maxDraftJsonBytes)
    const draft = requireObject(rawDraft, 'cloud draft')
    rejectUnknownKeys(draft, TOP_LEVEL_DRAFT_KEYS, 'cloud draft')

    const product = normalizeString(draft.product, 'cloud draft.product', {
        required: true,
        max: 40,
        rejectDangerous: false
    }).toLowerCase()
    if (product !== 'wipesnap') fail('cloud draft.product is not supported.')
    if (draft.schemaVersion !== CLOUD_DRAFT_SCHEMA_VERSION) fail('cloud draft.schemaVersion is not supported.')

    const accountSlots = normalizeArray(
        draft.accountSlots,
        'cloud draft.accountSlots',
        CLOUD_DRAFT_LIMITS.maxAccountIntentions
    ).map(validateAccountIntention)
    const browserProfileSlots = normalizeArray(
        draft.browserProfileSlots,
        'cloud draft.browserProfileSlots',
        CLOUD_DRAFT_LIMITS.maxBrowserProfileSlots
    ).map(validateProfileSlot)
    const browserTabs = normalizeArray(
        draft.browserTabs,
        'cloud draft.browserTabs',
        CLOUD_DRAFT_LIMITS.maxBrowserTabs
    ).map(validateBrowserTab)
    const desiredApps = normalizeArray(
        draft.desiredApps,
        'cloud draft.desiredApps',
        CLOUD_DRAFT_LIMITS.maxDesiredApps
    ).map(validateDesiredApp)

    assertUniqueIds(accountSlots, 'cloud draft.accountSlots')
    assertUniqueIds(browserProfileSlots, 'cloud draft.browserProfileSlots')
    assertUniqueIds(browserTabs, 'cloud draft.browserTabs')
    assertUniqueIds(desiredApps, 'cloud draft.desiredApps')

    const normalized = {
        product,
        schemaVersion: CLOUD_DRAFT_SCHEMA_VERSION,
        draftId: normalizeId(draft.draftId, 'cloud draft.draftId'),
        revisionId: normalizeId(draft.revisionId, 'cloud draft.revisionId'),
        baseRevisionId: normalizeId(draft.baseRevisionId, 'cloud draft.baseRevisionId', { nullable: true, required: false }),
        authorDeviceId: normalizeId(draft.authorDeviceId, 'cloud draft.authorDeviceId', { required: false }),
        name: normalizeString(draft.name, 'cloud draft.name', {
            required: true,
            max: CLOUD_DRAFT_LIMITS.maxDraftNameLength
        }),
        notes: normalizeOptionalString(draft.notes, 'cloud draft.notes', {
            max: CLOUD_DRAFT_LIMITS.maxDraftNotesLength,
            multiline: true
        }),
        isDefault: normalizeBoolean(draft.isDefault, 'cloud draft.isDefault', false),
        accountSlots,
        browserProfileSlots,
        browserTabs,
        desiredApps,
        createdAt: normalizeTimestamp(draft.createdAt, 'cloud draft.createdAt'),
        updatedAt: normalizeTimestamp(draft.updatedAt, 'cloud draft.updatedAt')
    }

    assertReferencesExist(normalized)
    return normalized
}

export function validateCloudDraftEnvelope(input) {
    const rawEnvelope = parseJsonInput(input, 'cloud draft envelope JSON', CLOUD_DRAFT_LIMITS.maxCloudEnvelopeBytes)
    const envelope = requireObject(rawEnvelope, 'cloud draft envelope')
    rejectUnknownKeys(envelope, ENVELOPE_KEYS, 'cloud draft envelope')
    if (envelope.schemaVersion !== CLOUD_DRAFT_SCHEMA_VERSION) fail('cloud draft envelope.schemaVersion is not supported.')

    const encryption = requireObject(envelope.encryption, 'cloud draft envelope.encryption')
    rejectUnknownKeys(encryption, ENVELOPE_ENCRYPTION_KEYS, 'cloud draft envelope.encryption')
    const alg = normalizeString(encryption.alg, 'cloud draft envelope.encryption.alg', {
        required: true,
        max: 40,
        rejectDangerous: false
    })
    if (alg !== 'AES-GCM') fail('cloud draft envelope.encryption.alg is not supported.')

    const deletedAt = normalizeTimestamp(envelope.deletedAt, 'cloud draft envelope.deletedAt', {
        required: false,
        allowNull: true
    })
    if (envelope.encrypted !== true) fail('cloud draft envelope.encrypted must be true.')

    return {
        ownerUid: normalizeString(envelope.ownerUid, 'cloud draft envelope.ownerUid', {
            required: true,
            max: CLOUD_DRAFT_LIMITS.maxIdLength,
            rejectDangerous: false
        }),
        draftId: normalizeId(envelope.draftId, 'cloud draft envelope.draftId'),
        schemaVersion: CLOUD_DRAFT_SCHEMA_VERSION,
        revisionId: normalizeId(envelope.revisionId, 'cloud draft envelope.revisionId'),
        baseRevisionId: normalizeId(envelope.baseRevisionId, 'cloud draft envelope.baseRevisionId', { nullable: true, required: false }),
        authorDeviceId: normalizeId(envelope.authorDeviceId, 'cloud draft envelope.authorDeviceId'),
        updatedAt: normalizeTimestamp(envelope.updatedAt, 'cloud draft envelope.updatedAt'),
        createdAt: normalizeTimestamp(envelope.createdAt, 'cloud draft envelope.createdAt'),
        deletedAt,
        isDefault: normalizeBoolean(envelope.isDefault, 'cloud draft envelope.isDefault', false),
        encrypted: true,
        encryption: {
            alg,
            keyId: normalizeId(encryption.keyId, 'cloud draft envelope.encryption.keyId'),
            nonce: normalizeString(encryption.nonce, 'cloud draft envelope.encryption.nonce', {
                required: true,
                max: CLOUD_DRAFT_LIMITS.maxIdLength,
                rejectDangerous: false
            })
        },
        blobHash: normalizeString(envelope.blobHash, 'cloud draft envelope.blobHash', {
            required: true,
            max: 160,
            rejectDangerous: false
        }),
        blobCiphertext: normalizeString(envelope.blobCiphertext, 'cloud draft envelope.blobCiphertext', {
            required: true,
            max: CLOUD_DRAFT_LIMITS.maxCloudEnvelopeBytes,
            rejectDangerous: false
        })
    }
}

export function validateActiveCloudDraftLimit(records) {
    if (!Array.isArray(records)) fail('cloud draft records must be an array.')
    let activeDrafts = 0
    for (const record of records) {
        const value = requireObject(record, 'cloud draft record')
        if (value.deletedAt == null) activeDrafts += 1
    }
    if (activeDrafts > CLOUD_DRAFT_LIMITS.maxActiveDraftsPerUser) {
        fail(`cloud draft records cannot contain more than ${CLOUD_DRAFT_LIMITS.maxActiveDraftsPerUser} active drafts.`)
    }
    return {
        activeDrafts,
        maxActiveDrafts: CLOUD_DRAFT_LIMITS.maxActiveDraftsPerUser
    }
}

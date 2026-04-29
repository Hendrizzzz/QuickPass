import {
    createCipheriv,
    createDecipheriv,
    createHash,
    createSign,
    createVerify,
    hkdfSync,
    randomBytes as nodeRandomBytes
} from 'crypto'
import {
    SANITIZED_PRESET_SNAPSHOT_KIND,
    SANITIZED_PRESET_SNAPSHOT_LIMITS,
    SANITIZED_PRESET_SNAPSHOT_SCHEMA_VERSION
} from './sanitizedPresetSnapshot.js'
import { validateCloudDraft } from './cloudDraftSchema.js'
import {
    SAFE_PRESET_PATCH_KIND,
    SAFE_PRESET_PATCH_LIMITS,
    SAFE_PRESET_PATCH_SCHEMA_VERSION,
    validateSafePresetPatch
} from './safePresetPatch.js'

export const CLOUD_SYNC_SCHEMA_VERSION = 1
export const CLOUD_SYNC_ENVELOPE_VERSION = 1
export const CLOUD_SYNC_ENVELOPE_RECORD_TYPE = 'cloud-sync-envelope'
export const CLOUD_SYNC_DEVICE_RECORD_TYPE = 'cloud-sync-device'
export const CLOUD_SYNC_KEY_GRANT_RECORD_TYPE = 'cloud-sync-key-grant'
export const CLOUD_SYNC_SNAPSHOT_DOC_TYPE = 'sanitized-snapshot'
export const CLOUD_SYNC_PATCH_DOC_TYPE = 'safe-preset-patch'
export const CLOUD_SYNC_CONTENT_ENCRYPTION = 'AES-256-GCM'
export const CLOUD_SYNC_KEY_DERIVATION = 'HKDF-SHA256'
export const CLOUD_SYNC_SIGNING_ALGORITHM = 'ECDSA-P256-SHA256-P1363'
export const CLOUD_SYNC_SIGNING_ALGORITHM_DETAILS =
    'ECDSA over NIST P-256 with SHA-256 and 64-byte IEEE P1363 signatures; supported by Node crypto and browser WebCrypto P-256 ECDSA.'

export const CLOUD_SYNC_LIMITS = Object.freeze({
    maxEnvelopeJsonBytes: 768 * 1024,
    maxCiphertextBytes: 512 * 1024,
    maxWrappedKeyBytes: 2048,
    maxUidLength: 128,
    maxIdLength: 96,
    maxDeviceSequence: 9_007_199_254_740_991,
    maxKeyVersion: 1_000_000_000,
    maxPublicKeyBytes: 2048,
    maxHashLength: 96
})

const MAX_TIMESTAMP = 8_640_000_000_000_000
const AES_KEY_BYTES = 32
const AES_GCM_IV_BYTES = 12
const AES_GCM_TAG_BYTES = 16
const HKDF_SALT_BYTES = 32
const OWNER_UID_PATTERN = /^[A-Za-z0-9:_-]{1,128}$/
const SAFE_ID_PATTERN = /^[A-Za-z][A-Za-z0-9_-]+$/
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/
const HEX_PATTERN = /^[a-f0-9]+$/i
const CAPABILITY_ID_PATTERN = /\bcap_[a-f0-9]{32,64}\b/i
const RAW_ACCOUNT_SLOT_ID_PATTERN = /\bacct_[a-f0-9]{32,64}\b/i

const DOC_TYPES = new Set([CLOUD_SYNC_SNAPSHOT_DOC_TYPE, CLOUD_SYNC_PATCH_DOC_TYPE])
const DEVICE_ROLES = new Set(['desktop', 'phone', 'web-planner'])
const DEVICE_STATUSES = new Set(['pending', 'active', 'revoked'])
const DEVICE_PLATFORMS = new Set(['windows-electron', 'web-pwa', 'unknown'])
const SYNC_SCOPES = new Set(['read', 'snapshot-upload', 'patch-upload'])
const TOMBSTONE_REASONS = new Set([
    'superseded',
    'acknowledged',
    'revoked-device',
    'expired',
    'user-deleted'
])
const CONFLICT_REASONS = new Set([
    'stale-base',
    'parallel-patch',
    'revoked-device',
    'invalid-envelope',
    'unknown-safe-id',
    'schema-rejected'
])
const WRAPPING_ALGORITHMS = new Set(['RSA-OAEP-256'])

const ENVELOPE_KEYS = new Set([
    'product',
    'recordType',
    'schemaVersion',
    'envelopeVersion',
    'docType',
    'ownerUid',
    'snapshotId',
    'patchId',
    'revisionId',
    'baseRevisionId',
    'deviceId',
    'deviceSequence',
    'keyVersion',
    'createdAt',
    'updatedAt',
    'encryption',
    'ciphertext',
    'ciphertextHash',
    'signature',
    'tombstone',
    'conflict'
])
const ENCRYPTION_KEYS = new Set(['alg', 'kdf', 'salt', 'iv', 'tag'])
const SIGNATURE_KEYS = new Set(['alg', 'keyId', 'value'])
const DEVICE_RECORD_KEYS = new Set([
    'product',
    'recordType',
    'schemaVersion',
    'ownerUid',
    'deviceId',
    'role',
    'status',
    'platform',
    'syncScopes',
    'signingPublicKey',
    'wrapPublicKey',
    'enrollmentEpoch',
    'keyVersion',
    'deviceSequence',
    'createdAt',
    'updatedAt',
    'revokedAt',
    'revokedByDeviceId'
])
const PUBLIC_KEY_KEYS = new Set(['alg', 'spki', 'fingerprint'])
const KEY_GRANT_KEYS = new Set([
    'product',
    'recordType',
    'schemaVersion',
    'ownerUid',
    'grantId',
    'recipientDeviceId',
    'createdByDeviceId',
    'keyVersion',
    'wrapAlg',
    'wrappedKeyCiphertext',
    'wrappedKeyHash',
    'createdAt',
    'revokedAt',
    'revokedByDeviceId'
])
const TOMBSTONE_KEYS = new Set([
    'status',
    'reason',
    'tombstonedAt',
    'tombstonedByDeviceId',
    'supersededByRevisionId'
])
const CONFLICT_KEYS = new Set([
    'status',
    'reason',
    'detectedAt',
    'detectedByDeviceId',
    'baseRevisionId',
    'currentRevisionId',
    'conflictingRevisionId'
])

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
const SNAPSHOT_ITEM_TYPES = new Set([
    'browser-tab',
    'desktop-app',
    'host-folder',
    'account-intention',
    'profile-intention'
])
const SNAPSHOT_ITEM_STATUSES = new Set(['available', 'disabled', 'redacted', 'broken'])
const SNAPSHOT_ITEM_SOURCES = new Set(['browser', 'desktop', 'account', 'profile'])

const BACKEND_PLAINTEXT_FIELD_NAMES = new Set([
    'accountintentionid',
    'availableitems',
    'browsertabs',
    'desktopapps',
    'desiredapps',
    'identifierhint',
    'itemrefs',
    'label',
    'name',
    'newbrowseritems',
    'notes',
    'presets',
    'profileintentionid',
    'selection',
    'url'
])
const SECRET_FIELD_MARKERS = [
    'password',
    'passcode',
    'backupcode',
    'cookie',
    'oauth',
    'refreshtoken',
    'accesstoken',
    'idtoken',
    'credential',
    'secret',
    'privatekey',
    'syncrootkey',
    'rootkeymaterial',
    'recoveryphrase',
    'seedphrase',
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
    'rawbrowser',
    'launch',
    'args',
    'userargs',
    'manifest',
    'storage',
    'shortcut'
]
const BACKEND_OPAQUE_VALUE_KEYS = new Set([
    'ciphertext',
    'ciphertexthash',
    'fingerprint',
    'iv',
    'salt',
    'spki',
    'tag',
    'value',
    'wrappedkeyciphertext',
    'wrappedkeyhash'
])

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

function jsonByteLength(value) {
    return Buffer.byteLength(JSON.stringify(value), 'utf8')
}

function jsonByteLengthForInput(input, fieldName) {
    if (typeof input === 'string') return Buffer.byteLength(input, 'utf8')
    if (Buffer.isBuffer(input)) return input.length
    try {
        const json = JSON.stringify(input)
        if (typeof json !== 'string') fail(`${fieldName} must be JSON data.`)
        return Buffer.byteLength(json, 'utf8')
    } catch (_) {
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

function normalizedKey(value) {
    return String(value || '').toLowerCase().replace(/[^a-z0-9]/g, '')
}

function rejectUnknownKeys(value, allowedKeys, fieldName) {
    for (const key of Object.keys(value || {})) {
        if (allowedKeys.has(key)) continue
        if (looksLikeBackendPlaintextField(key)) {
            fail(`${fieldName}.${key} is not accepted because cloud sync documents cannot store plaintext snapshot or patch content.`)
        }
        if (looksLikeForbiddenField(key)) {
            fail(`${fieldName}.${key} is not accepted because cloud sync documents cannot carry secrets, paths, commands, registry, process, vault, browser session, or launch authority material.`)
        }
        fail(`${fieldName}.${key} is not accepted.`)
    }
}

function normalizeString(value, fieldName, {
    required = false,
    max = 256,
    rejectDangerous = true,
    allowEmpty = false
} = {}) {
    if (value == null) {
        if (required) fail(`${fieldName} is required.`)
        return ''
    }
    if (typeof value !== 'string') fail(`${fieldName} must be a string.`)
    if (value.includes('\0') || /[\u0000-\u001F\u007F]/.test(value)) {
        fail(`${fieldName} contains unsupported control characters.`)
    }
    const text = value.trim()
    if (required && !text) fail(`${fieldName} is required.`)
    if (!required && !text && !allowEmpty) return ''
    if (text.length > max) fail(`${fieldName} is too long.`)
    if (rejectDangerous && hasDangerousStringMaterial(text)) {
        fail(`${fieldName} contains forbidden cloud sync material.`)
    }
    return text
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

function normalizeNonNegativeInteger(value, fieldName, max = CLOUD_SYNC_LIMITS.maxDeviceSequence) {
    if (!Number.isSafeInteger(value) || value < 0 || value > max) {
        fail(`${fieldName} must be a non-negative safe integer.`)
    }
    return value
}

function normalizePositiveInteger(value, fieldName, max = CLOUD_SYNC_LIMITS.maxKeyVersion) {
    if (!Number.isSafeInteger(value) || value <= 0 || value > max) {
        fail(`${fieldName} must be a positive safe integer.`)
    }
    return value
}

function normalizeOwnerUid(value, fieldName = 'ownerUid') {
    const text = normalizeString(value, fieldName, {
        required: true,
        max: CLOUD_SYNC_LIMITS.maxUidLength,
        rejectDangerous: true
    })
    if (!OWNER_UID_PATTERN.test(text)) fail(`${fieldName} must be a safe Firebase uid.`)
    return text
}

function normalizeSafeId(value, fieldName, prefixes, { required = true, nullable = false } = {}) {
    if (value == null || value === '') {
        if (nullable) return null
        if (required) fail(`${fieldName} is required.`)
        return ''
    }
    const id = normalizeString(value, fieldName, {
        required,
        max: CLOUD_SYNC_LIMITS.maxIdLength,
        rejectDangerous: false
    })
    if (!SAFE_ID_PATTERN.test(id)) fail(`${fieldName} must be a safe id.`)
    if (CAPABILITY_ID_PATTERN.test(id)) fail(`${fieldName} cannot use a launch capability id shape.`)
    if (RAW_ACCOUNT_SLOT_ID_PATTERN.test(id)) fail(`${fieldName} cannot use a raw account slot id shape.`)
    if (prefixes && !prefixes.some(prefix => id.startsWith(prefix))) {
        fail(`${fieldName} must use an allowed safe id prefix.`)
    }
    return id
}

function normalizeBase64Url(value, fieldName, { maxBytes, minBytes = 1 } = {}) {
    const text = normalizeString(value, fieldName, {
        required: true,
        max: Math.ceil((maxBytes || CLOUD_SYNC_LIMITS.maxCiphertextBytes) * 4 / 3) + 8,
        rejectDangerous: false
    })
    if (!BASE64URL_PATTERN.test(text)) fail(`${fieldName} must be base64url data.`)
    const bytes = decodeBase64Url(text, fieldName)
    if (bytes.length < minBytes) fail(`${fieldName} is too short.`)
    if (maxBytes != null && bytes.length > maxBytes) fail(`${fieldName} is too large.`)
    return text
}

function normalizeHash(value, fieldName) {
    const text = normalizeString(value, fieldName, {
        required: true,
        max: CLOUD_SYNC_LIMITS.maxHashLength,
        rejectDangerous: false
    })
    if (!BASE64URL_PATTERN.test(text) && !HEX_PATTERN.test(text)) fail(`${fieldName} must be a hash string.`)
    return text
}

function bytesFrom(value, fieldName) {
    if (Buffer.isBuffer(value)) return Buffer.from(value)
    if (typeof value === 'string') return Buffer.from(value, 'utf8')
    if (ArrayBuffer.isView(value)) return Buffer.from(value.buffer, value.byteOffset, value.byteLength)
    if (value instanceof ArrayBuffer) return Buffer.from(value)
    fail(`${fieldName} must be bytes.`)
}

function normalizeSyncRootKey(value) {
    const bytes = bytesFrom(value, 'syncRootKey')
    if (bytes.length !== AES_KEY_BYTES) fail('syncRootKey must be exactly 32 bytes.')
    return bytes
}

function normalizeFixedBytes(value, fieldName, expectedLength) {
    const bytes = bytesFrom(value, fieldName)
    if (bytes.length !== expectedLength) fail(`${fieldName} must be exactly ${expectedLength} bytes.`)
    return bytes
}

function encodeBase64Url(bytes) {
    return Buffer.from(bytes).toString('base64url')
}

function decodeBase64Url(value, fieldName) {
    try {
        return Buffer.from(value, 'base64url')
    } catch (_) {
        fail(`${fieldName} must be valid base64url data.`)
    }
}

function sha256Base64Url(bytes) {
    return createHash('sha256').update(bytes).digest('base64url')
}

function looksLikeForbiddenField(key) {
    const normalized = normalizedKey(key)
    return SECRET_FIELD_MARKERS.some(marker => normalized.includes(marker)) ||
        AUTHORITY_FIELD_MARKERS.some(marker => normalized.includes(marker))
}

function looksLikeBackendPlaintextField(key) {
    return BACKEND_PLAINTEXT_FIELD_NAMES.has(normalizedKey(key))
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

function looksLikeShellCommand(value) {
    return /(?:^|[\s"'([{])(?:cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regedit|reg|schtasks|taskkill|start)\s+(?:\/|-\w|&|\||<|>)/i.test(value) ||
        /[;&|`><]\s*(?:cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|reg|taskkill)\b/i.test(value)
}

function looksLikeExecutableReference(value) {
    const fileReference = String.raw`(?:^|[\s"'([{\\/])[^\\/\s"'([{@:]+\.(?:exe|bat|cmd|ps1|vbs|lnk|scr|msi)(?=$|[\s"'\])},.;:!?])`
    return new RegExp(fileReference, 'i').test(value)
}

function hasDangerousStringMaterial(value) {
    return looksLikeSecretString(value) ||
        looksLikeWindowsPathString(value) ||
        looksLikeRegistryString(value) ||
        looksLikeProcessSelector(value) ||
        looksLikeShellCommand(value) ||
        looksLikeExecutableReference(value) ||
        CAPABILITY_ID_PATTERN.test(value) ||
        RAW_ACCOUNT_SLOT_ID_PATTERN.test(value)
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

function hasDangerousUrlPathMaterial(value) {
    const text = decodeUrlComponentText(value)
    return hasDangerousStringMaterial(text) ||
        /(?:^|[\\/])[A-Za-z]:[\\/]/i.test(text) ||
        /\bAppData\b/i.test(text) ||
        /\bBrowserProfile\b/i.test(text) ||
        /\bvault(?:\.meta|\.state)?\.json\b/i.test(text) ||
        CAPABILITY_ID_PATTERN.test(text) ||
        RAW_ACCOUNT_SLOT_ID_PATTERN.test(text)
}

function normalizeSnapshotBrowserUrl(value, fieldName) {
    const raw = normalizeString(value, fieldName, {
        required: true,
        max: 2048,
        rejectDangerous: false
    })
    let normalizedUrl = ''
    try {
        const draft = validateCloudDraft({
            product: 'wipesnap',
            schemaVersion: 1,
            draftId: 'snapshot_url_check',
            revisionId: 'snapshot_url_check_rev',
            baseRevisionId: null,
            authorDeviceId: 'snapshot_url_check_device',
            name: 'Snapshot URL Check',
            notes: '',
            isDefault: false,
            accountSlots: [],
            browserProfileSlots: [],
            browserTabs: [{
                id: 'snapshot_url_check_tab',
                url: raw,
                order: 0,
                label: '',
                notes: '',
                enabled: true,
                accountSlotId: '',
                profileSlotId: ''
            }],
            desiredApps: [],
            createdAt: 1,
            updatedAt: 1
        })
        normalizedUrl = draft.browserTabs[0].url
    } catch (_) {
        fail(`${fieldName} must be a safe public web URL.`)
    }

    const parsed = new URL(normalizedUrl)
    if (hasDangerousUrlPathMaterial(parsed.pathname)) {
        fail(`${fieldName} cannot contain filesystem, vault, AppData, browser profile, capability, or account-slot material.`)
    }
    return normalizedUrl
}

function shouldSkipOpaqueBackendValue(key) {
    return BACKEND_OPAQUE_VALUE_KEYS.has(normalizedKey(key))
}

export function assertNoForbiddenCloudSyncBackendPlaintext(value, path = 'cloud sync document') {
    if (Array.isArray(value)) {
        value.forEach((item, index) => assertNoForbiddenCloudSyncBackendPlaintext(item, `${path}[${index}]`))
        return true
    }
    if (isPlainObject(value)) {
        for (const [key, nested] of Object.entries(value)) {
            if (looksLikeBackendPlaintextField(key)) {
                fail(`${path}.${key} is plaintext snapshot or patch content and cannot be backend-visible.`)
            }
            if (looksLikeForbiddenField(key)) {
                fail(`${path}.${key} is forbidden in cloud sync backend documents.`)
            }
            if (!shouldSkipOpaqueBackendValue(key)) {
                assertNoForbiddenCloudSyncBackendPlaintext(nested, `${path}.${key}`)
            }
        }
        return true
    }
    if (typeof value === 'string' && hasDangerousStringMaterial(value)) {
        fail(`${path} contains forbidden cloud sync plaintext material.`)
    }
    return true
}

function assertNoForbiddenPayloadMaterial(value, path = 'cloud sync payload') {
    if (Array.isArray(value)) {
        value.forEach((item, index) => assertNoForbiddenPayloadMaterial(item, `${path}[${index}]`))
        return
    }
    if (isPlainObject(value)) {
        for (const [key, nested] of Object.entries(value)) {
            if (looksLikeForbiddenField(key)) fail(`${path}.${key} is forbidden in encrypted cloud sync payloads.`)
            assertNoForbiddenPayloadMaterial(nested, `${path}.${key}`)
        }
        return
    }
    if (typeof value === 'string' && path.endsWith('.url')) return
    if (typeof value === 'string' && hasDangerousStringMaterial(value)) {
        fail(`${path} contains forbidden cloud sync payload material.`)
    }
}

export function canonicalizeCloudSyncValue(value) {
    if (Array.isArray(value)) return value.map(canonicalizeCloudSyncValue)
    if (isPlainObject(value)) {
        const next = {}
        for (const key of Object.keys(value).sort()) {
            const nested = value[key]
            next[key] = nested === undefined ? null : canonicalizeCloudSyncValue(nested)
        }
        return next
    }
    if (value === undefined) return null
    if (typeof value === 'number') {
        if (!Number.isFinite(value)) fail('Canonical cloud sync numbers must be finite.')
        return value
    }
    return value
}

export function serializeCanonicalCloudSyncMetadata(value) {
    return JSON.stringify(canonicalizeCloudSyncValue(value))
}

function validatePayloadTopLevelKeys(payload, allowedKeys, fieldName) {
    for (const key of Object.keys(payload || {})) {
        if (!allowedKeys.has(key)) fail(`${fieldName}.${key} is not part of the supported encrypted payload schema.`)
    }
}

function normalizeSnapshotBoolean(value, fieldName) {
    if (typeof value !== 'boolean') fail(`${fieldName} must be a boolean.`)
    return value
}

function normalizeSnapshotOrder(value, fieldName) {
    return normalizeNonNegativeInteger(value, fieldName, SANITIZED_PRESET_SNAPSHOT_LIMITS.maxPresetItemRefs)
}

function normalizeSnapshotText(value, fieldName, max) {
    return normalizeString(value, fieldName, {
        required: true,
        max,
        rejectDangerous: true
    })
}

function validateSnapshotLimits(value) {
    const limits = requireObject(value, 'sanitized snapshot.limits')
    validatePayloadTopLevelKeys(limits, new Set(Object.keys(SANITIZED_PRESET_SNAPSHOT_LIMITS)), 'sanitized snapshot.limits')
    for (const [key, expected] of Object.entries(SANITIZED_PRESET_SNAPSHOT_LIMITS)) {
        if (limits[key] !== expected) fail(`sanitized snapshot.limits.${key} is invalid.`)
    }
    return { ...SANITIZED_PRESET_SNAPSHOT_LIMITS }
}

function validateSnapshotSelection(value) {
    const selection = requireObject(value, 'sanitized snapshot.selection')
    validatePayloadTopLevelKeys(selection, SNAPSHOT_SELECTION_KEYS, 'sanitized snapshot.selection')
    if (selection.metadataOnly !== true) fail('sanitized snapshot.selection.metadataOnly must be true.')
    if (selection.selectionKind !== 'metadata-only') fail('sanitized snapshot.selection.selectionKind must be metadata-only.')
    return {
        defaultPresetId: normalizeSafeId(selection.defaultPresetId, 'sanitized snapshot.selection.defaultPresetId', ['preset_'], {
            nullable: true,
            required: false
        }),
        nextPresetId: normalizeSafeId(selection.nextPresetId, 'sanitized snapshot.selection.nextPresetId', ['preset_'], {
            nullable: true,
            required: false
        }),
        metadataOnly: true,
        selectionKind: 'metadata-only'
    }
}

function expectedSnapshotItemSource(type) {
    if (type === 'browser-tab') return 'browser'
    if (type === 'desktop-app' || type === 'host-folder') return 'desktop'
    if (type === 'account-intention') return 'account'
    if (type === 'profile-intention') return 'profile'
    return ''
}

function expectedSnapshotItemIdPrefixes(type) {
    if (type === 'account-intention') return ['accti_']
    if (type === 'profile-intention') return ['profi_']
    return ['item_']
}

function validateSnapshotAvailableItem(value, index) {
    const fieldName = `sanitized snapshot.availableItems[${index}]`
    const item = requireObject(value, fieldName)
    validatePayloadTopLevelKeys(item, SNAPSHOT_AVAILABLE_ITEM_KEYS, fieldName)
    const type = normalizeString(item.type, `${fieldName}.type`, {
        required: true,
        max: 40,
        rejectDangerous: false
    })
    if (!SNAPSHOT_ITEM_TYPES.has(type)) fail(`${fieldName}.type is invalid.`)
    const status = normalizeString(item.status, `${fieldName}.status`, {
        required: true,
        max: 40,
        rejectDangerous: false
    })
    if (!SNAPSHOT_ITEM_STATUSES.has(status)) fail(`${fieldName}.status is invalid.`)
    const source = normalizeString(item.source, `${fieldName}.source`, {
        required: true,
        max: 40,
        rejectDangerous: false
    })
    if (!SNAPSHOT_ITEM_SOURCES.has(source) || source !== expectedSnapshotItemSource(type)) {
        fail(`${fieldName}.source is invalid for its type.`)
    }
    const normalized = {
        id: normalizeSafeId(item.id, `${fieldName}.id`, expectedSnapshotItemIdPrefixes(type)),
        type,
        label: normalizeSnapshotText(item.label, `${fieldName}.label`, SANITIZED_PRESET_SNAPSHOT_LIMITS.maxItemLabelLength),
        status,
        source
    }
    if (item.url != null) {
        if (type !== 'browser-tab') fail(`${fieldName}.url is only allowed on browser-tab items.`)
        normalized.url = normalizeSnapshotBrowserUrl(item.url, `${fieldName}.url`)
    }
    if (item.provider != null) {
        normalized.provider = normalizeString(item.provider, `${fieldName}.provider`, {
            required: true,
            max: 40,
            rejectDangerous: false
        }).toLowerCase()
    }
    if (item.identifierHint != null) {
        normalized.identifierHint = normalizeString(item.identifierHint, `${fieldName}.identifierHint`, {
            required: false,
            max: SANITIZED_PRESET_SNAPSHOT_LIMITS.maxAccountIdentifierHintLength,
            rejectDangerous: true
        })
    }
    if (item.state != null) {
        normalized.state = normalizeString(item.state, `${fieldName}.state`, {
            required: true,
            max: 80,
            rejectDangerous: false
        })
    }
    if (item.metadataOnly === true) normalized.metadataOnly = true
    if ((type === 'account-intention' || type === 'profile-intention') && normalized.metadataOnly !== true) {
        fail(`${fieldName}.metadataOnly must be true for account/profile intentions.`)
    }
    return normalized
}

function validateSnapshotItemRef(value, index, presetIndex, itemIds) {
    const fieldName = `sanitized snapshot.presets[${presetIndex}].itemRefs[${index}]`
    const ref = requireObject(value, fieldName)
    validatePayloadTopLevelKeys(ref, SNAPSHOT_ITEM_REF_KEYS, fieldName)
    if (ref.metadataOnly !== true) fail(`${fieldName}.metadataOnly must be true.`)
    const normalized = {
        id: normalizeSafeId(ref.id, `${fieldName}.id`, ['pref_']),
        itemId: normalizeSafeId(ref.itemId, `${fieldName}.itemId`, ['item_', 'accti_', 'profi_']),
        order: normalizeSnapshotOrder(ref.order, `${fieldName}.order`),
        enabled: normalizeSnapshotBoolean(ref.enabled, `${fieldName}.enabled`),
        metadataOnly: true
    }
    if (!itemIds.has(normalized.itemId)) fail(`${fieldName}.itemId references an unknown safe item.`)
    if (ref.accountIntentionId != null) {
        normalized.accountIntentionId = normalizeSafeId(ref.accountIntentionId, `${fieldName}.accountIntentionId`, ['accti_'])
    }
    if (ref.profileIntentionId != null) {
        normalized.profileIntentionId = normalizeSafeId(ref.profileIntentionId, `${fieldName}.profileIntentionId`, ['profi_'])
    }
    return normalized
}

function validateSnapshotPreset(value, index, itemIds) {
    const fieldName = `sanitized snapshot.presets[${index}]`
    const preset = requireObject(value, fieldName)
    validatePayloadTopLevelKeys(preset, SNAPSHOT_PRESET_KEYS, fieldName)
    const refs = Array.isArray(preset.itemRefs) ? preset.itemRefs : fail(`${fieldName}.itemRefs must be an array.`)
    if (refs.length > SANITIZED_PRESET_SNAPSHOT_LIMITS.maxPresetItemRefs) fail(`${fieldName}.itemRefs exceeds the sanitized snapshot limit.`)
    const itemRefs = refs.map((ref, refIndex) => validateSnapshotItemRef(ref, refIndex, index, itemIds))
    return {
        id: normalizeSafeId(preset.id, `${fieldName}.id`, ['preset_']),
        name: normalizeSnapshotText(preset.name, `${fieldName}.name`, SANITIZED_PRESET_SNAPSHOT_LIMITS.maxPresetNameLength),
        order: normalizeSnapshotOrder(preset.order, `${fieldName}.order`),
        enabled: normalizeSnapshotBoolean(preset.enabled, `${fieldName}.enabled`),
        itemRefs
    }
}

function assertUniqueIds(items, fieldName) {
    const seen = new Set()
    for (const item of items) {
        if (seen.has(item.id)) fail(`${fieldName} contains a duplicate id.`)
        seen.add(item.id)
    }
}

function validateSnapshotPayload(input) {
    const rawSnapshot = parseJsonInput(
        input,
        'sanitized snapshot JSON',
        SANITIZED_PRESET_SNAPSHOT_LIMITS.maxSnapshotJsonBytes
    )
    const snapshot = requireObject(rawSnapshot, 'sanitized snapshot')
    validatePayloadTopLevelKeys(snapshot, SNAPSHOT_TOP_LEVEL_KEYS, 'sanitized snapshot')
    assertNoForbiddenPayloadMaterial(snapshot, 'sanitized snapshot')

    if (snapshot.product !== 'wipesnap') fail('sanitized snapshot.product is not supported.')
    if (snapshot.kind !== SANITIZED_PRESET_SNAPSHOT_KIND) fail('sanitized snapshot.kind is not supported.')
    if (snapshot.schemaVersion !== SANITIZED_PRESET_SNAPSHOT_SCHEMA_VERSION) {
        fail('sanitized snapshot.schemaVersion is not supported.')
    }
    const availableItems = (Array.isArray(snapshot.availableItems)
        ? snapshot.availableItems
        : fail('sanitized snapshot.availableItems must be an array.'))
        .map(validateSnapshotAvailableItem)
    if (availableItems.length > SANITIZED_PRESET_SNAPSHOT_LIMITS.maxAvailableItems) {
        fail('sanitized snapshot.availableItems exceeds the sanitized snapshot limit.')
    }
    assertUniqueIds(availableItems, 'sanitized snapshot.availableItems')
    const itemIds = new Set(availableItems.map(item => item.id))
    const presets = (Array.isArray(snapshot.presets)
        ? snapshot.presets
        : fail('sanitized snapshot.presets must be an array.'))
        .map((preset, index) => validateSnapshotPreset(preset, index, itemIds))
    if (presets.length > SANITIZED_PRESET_SNAPSHOT_LIMITS.maxPresets) fail('sanitized snapshot.presets exceeds the sanitized snapshot limit.')
    assertUniqueIds(presets, 'sanitized snapshot.presets')

    const normalized = {
        product: 'wipesnap',
        kind: SANITIZED_PRESET_SNAPSHOT_KIND,
        schemaVersion: SANITIZED_PRESET_SNAPSHOT_SCHEMA_VERSION,
        snapshotId: normalizeSafeId(snapshot.snapshotId, 'sanitized snapshot.snapshotId', ['snap_']),
        revisionId: normalizeSafeId(snapshot.revisionId, 'sanitized snapshot.revisionId', ['srev_']),
        baseRevisionId: normalizeSafeId(snapshot.baseRevisionId, 'sanitized snapshot.baseRevisionId', ['srev_'], {
            nullable: true,
            required: false
        }),
        sourceDeviceId: normalizeSafeId(snapshot.sourceDeviceId, 'sanitized snapshot.sourceDeviceId', ['dev_']),
        timestamp: normalizeTimestamp(snapshot.timestamp, 'sanitized snapshot.timestamp'),
        limits: validateSnapshotLimits(snapshot.limits),
        selection: validateSnapshotSelection(snapshot.selection),
        presets,
        availableItems
    }
    if (jsonByteLength(normalized) > SANITIZED_PRESET_SNAPSHOT_LIMITS.maxSnapshotJsonBytes) {
        fail('sanitized snapshot JSON exceeds the byte limit.')
    }
    return normalized
}

function validatePatchPayload(input) {
    const patch = validateSafePresetPatch(input)
    return {
        product: patch.product,
        kind: SAFE_PRESET_PATCH_KIND,
        schemaVersion: SAFE_PRESET_PATCH_SCHEMA_VERSION,
        patchId: patch.patchId,
        patchRevisionId: patch.patchRevisionId,
        baseSnapshotRevisionId: patch.baseSnapshotRevisionId,
        authorDeviceId: patch.authorDeviceId,
        createdAt: patch.createdAt,
        updatedAt: patch.updatedAt,
        selection: patch.selection,
        presets: patch.presets,
        newBrowserItems: patch.newBrowserItems.map(item => ({
            id: item.id,
            url: item.url,
            label: item.label,
            notes: item.notes,
            enabled: item.enabled,
            ...(item.accountIntentionId ? { accountIntentionId: item.accountIntentionId } : {}),
            ...(item.profileIntentionId ? { profileIntentionId: item.profileIntentionId } : {}),
            metadataOnly: true
        }))
    }
}

export function validateCloudSyncPayloadForDocType(input, docType) {
    if (docType === CLOUD_SYNC_SNAPSHOT_DOC_TYPE) return validateSnapshotPayload(input)
    if (docType === CLOUD_SYNC_PATCH_DOC_TYPE) return validatePatchPayload(input)
    fail('cloud sync doc type is not supported.')
}

function payloadIdsForDocType(payload, docType) {
    if (docType === CLOUD_SYNC_SNAPSHOT_DOC_TYPE) {
        return {
            snapshotId: payload.snapshotId,
            patchId: null,
            revisionId: payload.revisionId,
            baseRevisionId: payload.baseRevisionId ?? null,
            deviceId: payload.sourceDeviceId
        }
    }
    if (docType === CLOUD_SYNC_PATCH_DOC_TYPE) {
        return {
            snapshotId: null,
            patchId: payload.patchId,
            revisionId: payload.patchRevisionId,
            baseRevisionId: payload.baseSnapshotRevisionId,
            deviceId: payload.authorDeviceId
        }
    }
    fail('cloud sync doc type is not supported.')
}

function normalizeDocType(value) {
    const docType = normalizeString(value, 'cloud sync envelope.docType', {
        required: true,
        max: 40,
        rejectDangerous: false
    })
    if (!DOC_TYPES.has(docType)) fail('cloud sync envelope.docType is not supported.')
    return docType
}

function createAadMetadata(envelope) {
    return {
        envelopeVersion: envelope.envelopeVersion,
        ownerUid: envelope.ownerUid,
        docType: envelope.docType,
        snapshotId: envelope.snapshotId,
        patchId: envelope.patchId,
        revisionId: envelope.revisionId,
        baseRevisionId: envelope.baseRevisionId,
        deviceId: envelope.deviceId,
        deviceSequence: envelope.deviceSequence,
        keyVersion: envelope.keyVersion
    }
}

function createSignatureMetadata(envelope) {
    return {
        ...createAadMetadata(envelope),
        product: envelope.product,
        recordType: envelope.recordType,
        schemaVersion: envelope.schemaVersion,
        createdAt: envelope.createdAt,
        updatedAt: envelope.updatedAt,
        encryption: envelope.encryption,
        ciphertextHash: envelope.ciphertextHash,
        tombstone: envelope.tombstone,
        conflict: envelope.conflict
    }
}

export function canonicalCloudSyncAad(envelope) {
    return serializeCanonicalCloudSyncMetadata(createAadMetadata(envelope))
}

export function canonicalCloudSyncSignatureMetadata(envelope) {
    return serializeCanonicalCloudSyncMetadata(createSignatureMetadata(envelope))
}

export function deriveCloudSyncContentKey({
    syncRootKey,
    docType,
    revisionId,
    keyVersion,
    salt
}) {
    const rootKey = normalizeSyncRootKey(syncRootKey)
    const normalizedDocType = normalizeDocType(docType)
    const normalizedRevisionId = normalizeSafeId(revisionId, 'revisionId', ['srev_', 'patchrev_'])
    const normalizedKeyVersion = normalizePositiveInteger(keyVersion, 'keyVersion')
    const saltBytes = normalizeFixedBytes(salt, 'salt', HKDF_SALT_BYTES)
    const info = Buffer.from(
        `wipesnap.cloud-sync.v1.${normalizedDocType}.${normalizedRevisionId}.keyVersion.${normalizedKeyVersion}`,
        'utf8'
    )
    return Buffer.from(hkdfSync('sha256', rootKey, saltBytes, info, AES_KEY_BYTES))
}

export function signCloudSyncCanonicalMetadata({ canonicalMetadata, privateKey }) {
    if (!privateKey) fail('signingPrivateKey is required.')
    const signer = createSign('sha256')
    signer.update(canonicalMetadata)
    signer.end()
    return signer.sign({ key: privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url')
}

export function verifyCloudSyncCanonicalMetadata({ canonicalMetadata, signature, publicKey }) {
    if (!publicKey) fail('verifyPublicKey is required.')
    const signatureBytes = decodeBase64Url(signature, 'cloud sync signature.value')
    const verifier = createVerify('sha256')
    verifier.update(canonicalMetadata)
    verifier.end()
    return verifier.verify({ key: publicKey, dsaEncoding: 'ieee-p1363' }, signatureBytes)
}

function createRandomBytes(options, length) {
    if (typeof options.randomBytes === 'function') return normalizeFixedBytes(options.randomBytes(length), 'random bytes', length)
    return nodeRandomBytes(length)
}

function validatePayloadMatchesEnvelope(payload, envelope) {
    const ids = payloadIdsForDocType(payload, envelope.docType)
    if (ids.revisionId !== envelope.revisionId) fail('cloud sync envelope revision does not match payload.')
    if ((ids.baseRevisionId ?? null) !== (envelope.baseRevisionId ?? null)) {
        fail('cloud sync envelope base revision does not match payload.')
    }
    if (ids.deviceId !== envelope.deviceId) fail('cloud sync envelope device id does not match payload.')
    if ((ids.snapshotId ?? null) !== (envelope.snapshotId ?? null)) fail('cloud sync envelope snapshot id does not match payload.')
    if ((ids.patchId ?? null) !== (envelope.patchId ?? null)) fail('cloud sync envelope patch id does not match payload.')
}

export function createEncryptedCloudSyncEnvelope(input = {}) {
    const options = requireObject(input, 'cloud sync envelope input')
    const docType = normalizeDocType(options.docType)
    const payload = validateCloudSyncPayloadForDocType(options.payload, docType)
    const ids = payloadIdsForDocType(payload, docType)
    const now = normalizeTimestamp(options.now ?? Date.now(), 'cloud sync envelope timestamp')
    const keyVersion = normalizePositiveInteger(options.keyVersion, 'cloud sync envelope.keyVersion')
    const salt = options.salt
        ? normalizeFixedBytes(options.salt, 'cloud sync envelope.encryption.salt', HKDF_SALT_BYTES)
        : createRandomBytes(options, HKDF_SALT_BYTES)
    const iv = options.iv
        ? normalizeFixedBytes(options.iv, 'cloud sync envelope.encryption.iv', AES_GCM_IV_BYTES)
        : createRandomBytes(options, AES_GCM_IV_BYTES)
    const envelopeBase = {
        product: 'wipesnap',
        recordType: CLOUD_SYNC_ENVELOPE_RECORD_TYPE,
        schemaVersion: CLOUD_SYNC_SCHEMA_VERSION,
        envelopeVersion: CLOUD_SYNC_ENVELOPE_VERSION,
        docType,
        ownerUid: normalizeOwnerUid(options.ownerUid, 'cloud sync envelope.ownerUid'),
        snapshotId: ids.snapshotId,
        patchId: ids.patchId,
        revisionId: ids.revisionId,
        baseRevisionId: ids.baseRevisionId,
        deviceId: normalizeSafeId(options.deviceId ?? ids.deviceId, 'cloud sync envelope.deviceId', ['dev_']),
        deviceSequence: normalizeNonNegativeInteger(options.deviceSequence, 'cloud sync envelope.deviceSequence'),
        keyVersion,
        createdAt: normalizeTimestamp(options.createdAt ?? now, 'cloud sync envelope.createdAt'),
        updatedAt: normalizeTimestamp(options.updatedAt ?? options.createdAt ?? now, 'cloud sync envelope.updatedAt'),
        tombstone: validateCloudSyncTombstoneMetadata(options.tombstone ?? null),
        conflict: validateCloudSyncConflictMetadata(options.conflict ?? null)
    }
    validatePayloadMatchesEnvelope(payload, envelopeBase)

    const aad = Buffer.from(canonicalCloudSyncAad(envelopeBase), 'utf8')
    const contentKey = deriveCloudSyncContentKey({
        syncRootKey: options.syncRootKey,
        docType,
        revisionId: envelopeBase.revisionId,
        keyVersion,
        salt
    })
    const plaintext = Buffer.from(serializeCanonicalCloudSyncMetadata(payload), 'utf8')
    const cipher = createCipheriv('aes-256-gcm', contentKey, iv, { authTagLength: AES_GCM_TAG_BYTES })
    cipher.setAAD(aad)
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()])
    const tag = cipher.getAuthTag()
    const envelope = {
        ...envelopeBase,
        encryption: {
            alg: CLOUD_SYNC_CONTENT_ENCRYPTION,
            kdf: CLOUD_SYNC_KEY_DERIVATION,
            salt: encodeBase64Url(salt),
            iv: encodeBase64Url(iv),
            tag: encodeBase64Url(tag)
        },
        ciphertext: encodeBase64Url(ciphertext),
        ciphertextHash: sha256Base64Url(ciphertext)
    }
    envelope.signature = {
        alg: CLOUD_SYNC_SIGNING_ALGORITHM,
        keyId: normalizeString(options.signingKeyId ?? envelopeBase.deviceId, 'cloud sync envelope.signature.keyId', {
            required: true,
            max: CLOUD_SYNC_LIMITS.maxIdLength,
            rejectDangerous: false
        }),
        value: signCloudSyncCanonicalMetadata({
            canonicalMetadata: canonicalCloudSyncSignatureMetadata(envelope),
            privateKey: options.signingPrivateKey
        })
    }

    return validateCloudSyncEnvelope(envelope)
}

function validateEncryption(value) {
    const encryption = requireObject(value, 'cloud sync envelope.encryption')
    rejectUnknownKeys(encryption, ENCRYPTION_KEYS, 'cloud sync envelope.encryption')
    if (encryption.alg !== CLOUD_SYNC_CONTENT_ENCRYPTION) fail('cloud sync envelope.encryption.alg is not supported.')
    if (encryption.kdf !== CLOUD_SYNC_KEY_DERIVATION) fail('cloud sync envelope.encryption.kdf is not supported.')
    return {
        alg: CLOUD_SYNC_CONTENT_ENCRYPTION,
        kdf: CLOUD_SYNC_KEY_DERIVATION,
        salt: normalizeBase64Url(encryption.salt, 'cloud sync envelope.encryption.salt', {
            minBytes: HKDF_SALT_BYTES,
            maxBytes: HKDF_SALT_BYTES
        }),
        iv: normalizeBase64Url(encryption.iv, 'cloud sync envelope.encryption.iv', {
            minBytes: AES_GCM_IV_BYTES,
            maxBytes: AES_GCM_IV_BYTES
        }),
        tag: normalizeBase64Url(encryption.tag, 'cloud sync envelope.encryption.tag', {
            minBytes: AES_GCM_TAG_BYTES,
            maxBytes: AES_GCM_TAG_BYTES
        })
    }
}

function validateSignature(value) {
    const signature = requireObject(value, 'cloud sync envelope.signature')
    rejectUnknownKeys(signature, SIGNATURE_KEYS, 'cloud sync envelope.signature')
    if (signature.alg !== CLOUD_SYNC_SIGNING_ALGORITHM) fail('cloud sync envelope.signature.alg is not supported.')
    return {
        alg: CLOUD_SYNC_SIGNING_ALGORITHM,
        keyId: normalizeString(signature.keyId, 'cloud sync envelope.signature.keyId', {
            required: true,
            max: CLOUD_SYNC_LIMITS.maxIdLength,
            rejectDangerous: false
        }),
        value: normalizeBase64Url(signature.value, 'cloud sync envelope.signature.value', {
            minBytes: 64,
            maxBytes: 72
        })
    }
}

export function validateCloudSyncTombstoneMetadata(input) {
    if (input == null) return null
    const tombstone = requireObject(input, 'cloud sync tombstone')
    rejectUnknownKeys(tombstone, TOMBSTONE_KEYS, 'cloud sync tombstone')
    if (tombstone.status !== 'tombstoned') fail('cloud sync tombstone.status must be tombstoned.')
    const reason = normalizeString(tombstone.reason, 'cloud sync tombstone.reason', {
        required: true,
        max: 40,
        rejectDangerous: false
    })
    if (!TOMBSTONE_REASONS.has(reason)) fail('cloud sync tombstone.reason is not supported.')
    return {
        status: 'tombstoned',
        reason,
        tombstonedAt: normalizeTimestamp(tombstone.tombstonedAt, 'cloud sync tombstone.tombstonedAt'),
        tombstonedByDeviceId: normalizeSafeId(tombstone.tombstonedByDeviceId, 'cloud sync tombstone.tombstonedByDeviceId', ['dev_']),
        supersededByRevisionId: normalizeSafeId(
            tombstone.supersededByRevisionId,
            'cloud sync tombstone.supersededByRevisionId',
            ['srev_', 'patchrev_'],
            { required: false, nullable: true }
        )
    }
}

export function validateCloudSyncConflictMetadata(input) {
    if (input == null) return null
    const conflict = requireObject(input, 'cloud sync conflict')
    rejectUnknownKeys(conflict, CONFLICT_KEYS, 'cloud sync conflict')
    if (conflict.status !== 'conflict') fail('cloud sync conflict.status must be conflict.')
    const reason = normalizeString(conflict.reason, 'cloud sync conflict.reason', {
        required: true,
        max: 40,
        rejectDangerous: false
    })
    if (!CONFLICT_REASONS.has(reason)) fail('cloud sync conflict.reason is not supported.')
    return {
        status: 'conflict',
        reason,
        detectedAt: normalizeTimestamp(conflict.detectedAt, 'cloud sync conflict.detectedAt'),
        detectedByDeviceId: normalizeSafeId(conflict.detectedByDeviceId, 'cloud sync conflict.detectedByDeviceId', ['dev_']),
        baseRevisionId: normalizeSafeId(conflict.baseRevisionId, 'cloud sync conflict.baseRevisionId', ['srev_', 'patchrev_']),
        currentRevisionId: normalizeSafeId(conflict.currentRevisionId, 'cloud sync conflict.currentRevisionId', ['srev_', 'patchrev_']),
        conflictingRevisionId: normalizeSafeId(conflict.conflictingRevisionId, 'cloud sync conflict.conflictingRevisionId', ['srev_', 'patchrev_'])
    }
}

export function validateCloudSyncEnvelope(input, options = {}) {
    const rawEnvelope = parseJsonInput(input, 'cloud sync envelope JSON', CLOUD_SYNC_LIMITS.maxEnvelopeJsonBytes)
    const envelope = requireObject(rawEnvelope, 'cloud sync envelope')
    assertNoForbiddenCloudSyncBackendPlaintext(envelope)
    rejectUnknownKeys(envelope, ENVELOPE_KEYS, 'cloud sync envelope')

    if (envelope.product !== 'wipesnap') fail('cloud sync envelope.product is not supported.')
    if (envelope.recordType !== CLOUD_SYNC_ENVELOPE_RECORD_TYPE) fail('cloud sync envelope.recordType is not supported.')
    if (envelope.schemaVersion !== CLOUD_SYNC_SCHEMA_VERSION) fail('cloud sync envelope.schemaVersion is not supported.')
    if (envelope.envelopeVersion !== CLOUD_SYNC_ENVELOPE_VERSION) {
        fail('cloud sync envelope.envelopeVersion is not supported.')
    }

    const docType = normalizeDocType(envelope.docType)
    if (options.expectedDocType && docType !== options.expectedDocType) {
        fail('cloud sync envelope doc type does not match the expected doc type.')
    }
    const revisionId = normalizeSafeId(
        envelope.revisionId,
        'cloud sync envelope.revisionId',
        docType === CLOUD_SYNC_SNAPSHOT_DOC_TYPE ? ['srev_'] : ['patchrev_']
    )
    const keyVersion = normalizePositiveInteger(envelope.keyVersion, 'cloud sync envelope.keyVersion')
    if (options.activeKeyVersion != null && keyVersion !== options.activeKeyVersion) {
        fail('cloud sync envelope uses a stale key version.')
    }

    const normalized = {
        product: 'wipesnap',
        recordType: CLOUD_SYNC_ENVELOPE_RECORD_TYPE,
        schemaVersion: CLOUD_SYNC_SCHEMA_VERSION,
        envelopeVersion: CLOUD_SYNC_ENVELOPE_VERSION,
        docType,
        ownerUid: normalizeOwnerUid(envelope.ownerUid, 'cloud sync envelope.ownerUid'),
        snapshotId: normalizeSafeId(envelope.snapshotId, 'cloud sync envelope.snapshotId', ['snap_'], {
            nullable: docType !== CLOUD_SYNC_SNAPSHOT_DOC_TYPE,
            required: docType === CLOUD_SYNC_SNAPSHOT_DOC_TYPE
        }),
        patchId: normalizeSafeId(envelope.patchId, 'cloud sync envelope.patchId', ['patch_'], {
            nullable: docType !== CLOUD_SYNC_PATCH_DOC_TYPE,
            required: docType === CLOUD_SYNC_PATCH_DOC_TYPE
        }),
        revisionId,
        baseRevisionId: normalizeSafeId(envelope.baseRevisionId, 'cloud sync envelope.baseRevisionId', ['srev_', 'patchrev_'], {
            nullable: true,
            required: false
        }),
        deviceId: normalizeSafeId(envelope.deviceId, 'cloud sync envelope.deviceId', ['dev_']),
        deviceSequence: normalizeNonNegativeInteger(envelope.deviceSequence, 'cloud sync envelope.deviceSequence'),
        keyVersion,
        createdAt: normalizeTimestamp(envelope.createdAt, 'cloud sync envelope.createdAt'),
        updatedAt: normalizeTimestamp(envelope.updatedAt, 'cloud sync envelope.updatedAt'),
        encryption: validateEncryption(envelope.encryption),
        ciphertext: normalizeBase64Url(envelope.ciphertext, 'cloud sync envelope.ciphertext', {
            maxBytes: CLOUD_SYNC_LIMITS.maxCiphertextBytes
        }),
        ciphertextHash: normalizeHash(envelope.ciphertextHash, 'cloud sync envelope.ciphertextHash'),
        signature: validateSignature(envelope.signature),
        tombstone: validateCloudSyncTombstoneMetadata(envelope.tombstone),
        conflict: validateCloudSyncConflictMetadata(envelope.conflict)
    }
    if (normalized.docType === CLOUD_SYNC_SNAPSHOT_DOC_TYPE && normalized.patchId !== null) {
        fail('cloud sync snapshot envelopes cannot include a patch id.')
    }
    if (normalized.docType === CLOUD_SYNC_PATCH_DOC_TYPE && normalized.snapshotId !== null) {
        fail('cloud sync patch envelopes cannot include a snapshot id.')
    }
    if (jsonByteLength(normalized) > CLOUD_SYNC_LIMITS.maxEnvelopeJsonBytes) {
        fail('cloud sync envelope JSON exceeds the byte limit.')
    }
    return normalized
}

export function verifyCloudSyncEnvelopeSignature({ envelope, publicKey }) {
    const normalized = validateCloudSyncEnvelope(envelope)
    const ciphertext = decodeBase64Url(normalized.ciphertext, 'cloud sync envelope.ciphertext')
    if (sha256Base64Url(ciphertext) !== normalized.ciphertextHash) {
        fail('cloud sync envelope ciphertext hash does not match ciphertext.')
    }
    const valid = verifyCloudSyncCanonicalMetadata({
        canonicalMetadata: canonicalCloudSyncSignatureMetadata(normalized),
        signature: normalized.signature.value,
        publicKey
    })
    if (!valid) fail('cloud sync envelope signature is not valid.')
    return true
}

export function decryptCloudSyncEnvelope(input = {}) {
    const options = requireObject(input, 'cloud sync decrypt input')
    const envelope = validateCloudSyncEnvelope(options.envelope, {
        expectedDocType: options.expectedDocType,
        activeKeyVersion: options.activeKeyVersion
    })
    if (options.expectedOwnerUid != null && envelope.ownerUid !== options.expectedOwnerUid) {
        fail('cloud sync envelope owner uid does not match the expected owner.')
    }
    verifyCloudSyncEnvelopeSignature({ envelope, publicKey: options.verifyPublicKey })

    const salt = decodeBase64Url(envelope.encryption.salt, 'cloud sync envelope.encryption.salt')
    const iv = decodeBase64Url(envelope.encryption.iv, 'cloud sync envelope.encryption.iv')
    const tag = decodeBase64Url(envelope.encryption.tag, 'cloud sync envelope.encryption.tag')
    const ciphertext = decodeBase64Url(envelope.ciphertext, 'cloud sync envelope.ciphertext')
    const contentKey = deriveCloudSyncContentKey({
        syncRootKey: options.syncRootKey,
        docType: envelope.docType,
        revisionId: envelope.revisionId,
        keyVersion: envelope.keyVersion,
        salt
    })
    const decipher = createDecipheriv('aes-256-gcm', contentKey, iv, { authTagLength: AES_GCM_TAG_BYTES })
    decipher.setAAD(Buffer.from(canonicalCloudSyncAad(envelope), 'utf8'))
    decipher.setAuthTag(tag)
    let plaintext
    try {
        plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8')
    } catch (_) {
        fail('cloud sync envelope could not be decrypted or authenticated.')
    }
    let payload
    try {
        payload = JSON.parse(plaintext)
    } catch (_) {
        fail('cloud sync envelope plaintext was not valid JSON.')
    }
    payload = validateCloudSyncPayloadForDocType(payload, envelope.docType)
    validatePayloadMatchesEnvelope(payload, envelope)
    return { envelope, payload }
}

function normalizePublicKeyRecord(input, fieldName, expectedAlg) {
    const keyRecord = requireObject(input, fieldName)
    rejectUnknownKeys(keyRecord, PUBLIC_KEY_KEYS, fieldName)
    if (keyRecord.alg !== expectedAlg) fail(`${fieldName}.alg is not supported.`)
    const spki = normalizeBase64Url(keyRecord.spki, `${fieldName}.spki`, {
        minBytes: 32,
        maxBytes: CLOUD_SYNC_LIMITS.maxPublicKeyBytes
    })
    return {
        alg: expectedAlg,
        spki,
        fingerprint: normalizeHash(keyRecord.fingerprint || sha256Base64Url(decodeBase64Url(spki, `${fieldName}.spki`)), `${fieldName}.fingerprint`)
    }
}

export function validateCloudSyncDeviceRecord(input) {
    const device = requireObject(parseJsonInput(input, 'cloud sync device JSON', 64 * 1024), 'cloud sync device')
    assertNoForbiddenCloudSyncBackendPlaintext(device)
    rejectUnknownKeys(device, DEVICE_RECORD_KEYS, 'cloud sync device')
    if (device.product !== 'wipesnap') fail('cloud sync device.product is not supported.')
    if (device.recordType !== CLOUD_SYNC_DEVICE_RECORD_TYPE) fail('cloud sync device.recordType is not supported.')
    if (device.schemaVersion !== CLOUD_SYNC_SCHEMA_VERSION) fail('cloud sync device.schemaVersion is not supported.')
    const role = normalizeString(device.role, 'cloud sync device.role', {
        required: true,
        max: 40,
        rejectDangerous: false
    })
    if (!DEVICE_ROLES.has(role)) fail('cloud sync device.role is not supported.')
    const status = normalizeString(device.status, 'cloud sync device.status', {
        required: true,
        max: 40,
        rejectDangerous: false
    })
    if (!DEVICE_STATUSES.has(status)) fail('cloud sync device.status is not supported.')
    const platform = normalizeString(device.platform, 'cloud sync device.platform', {
        required: true,
        max: 40,
        rejectDangerous: false
    })
    if (!DEVICE_PLATFORMS.has(platform)) fail('cloud sync device.platform is not supported.')
    const syncScopes = Array.isArray(device.syncScopes) ? device.syncScopes : fail('cloud sync device.syncScopes must be an array.')
    if (syncScopes.length > SYNC_SCOPES.size) fail('cloud sync device.syncScopes has too many entries.')
    const normalizedScopes = syncScopes.map((scope, index) => {
        const text = normalizeString(scope, `cloud sync device.syncScopes[${index}]`, {
            required: true,
            max: 40,
            rejectDangerous: false
        })
        if (!SYNC_SCOPES.has(text)) fail('cloud sync device.syncScopes contains an unsupported scope.')
        return text
    })
    if (new Set(normalizedScopes).size !== normalizedScopes.length) fail('cloud sync device.syncScopes contains duplicates.')
    return {
        product: 'wipesnap',
        recordType: CLOUD_SYNC_DEVICE_RECORD_TYPE,
        schemaVersion: CLOUD_SYNC_SCHEMA_VERSION,
        ownerUid: normalizeOwnerUid(device.ownerUid, 'cloud sync device.ownerUid'),
        deviceId: normalizeSafeId(device.deviceId, 'cloud sync device.deviceId', ['dev_']),
        role,
        status,
        platform,
        syncScopes: normalizedScopes,
        signingPublicKey: normalizePublicKeyRecord(device.signingPublicKey, 'cloud sync device.signingPublicKey', CLOUD_SYNC_SIGNING_ALGORITHM),
        wrapPublicKey: normalizePublicKeyRecord(device.wrapPublicKey, 'cloud sync device.wrapPublicKey', 'RSA-OAEP-256'),
        enrollmentEpoch: normalizePositiveInteger(device.enrollmentEpoch, 'cloud sync device.enrollmentEpoch'),
        keyVersion: normalizePositiveInteger(device.keyVersion, 'cloud sync device.keyVersion'),
        deviceSequence: normalizeNonNegativeInteger(device.deviceSequence, 'cloud sync device.deviceSequence'),
        createdAt: normalizeTimestamp(device.createdAt, 'cloud sync device.createdAt'),
        updatedAt: normalizeTimestamp(device.updatedAt, 'cloud sync device.updatedAt'),
        revokedAt: normalizeTimestamp(device.revokedAt, 'cloud sync device.revokedAt', {
            allowNull: true,
            required: false
        }),
        revokedByDeviceId: normalizeSafeId(device.revokedByDeviceId, 'cloud sync device.revokedByDeviceId', ['dev_'], {
            nullable: true,
            required: false
        })
    }
}

export function validateCloudSyncKeyGrant(input) {
    const grant = requireObject(parseJsonInput(input, 'cloud sync key grant JSON', 64 * 1024), 'cloud sync key grant')
    assertNoForbiddenCloudSyncBackendPlaintext(grant)
    rejectUnknownKeys(grant, KEY_GRANT_KEYS, 'cloud sync key grant')
    if (grant.product !== 'wipesnap') fail('cloud sync key grant.product is not supported.')
    if (grant.recordType !== CLOUD_SYNC_KEY_GRANT_RECORD_TYPE) fail('cloud sync key grant.recordType is not supported.')
    if (grant.schemaVersion !== CLOUD_SYNC_SCHEMA_VERSION) fail('cloud sync key grant.schemaVersion is not supported.')
    const wrapAlg = normalizeString(grant.wrapAlg, 'cloud sync key grant.wrapAlg', {
        required: true,
        max: 40,
        rejectDangerous: false
    })
    if (!WRAPPING_ALGORITHMS.has(wrapAlg)) fail('cloud sync key grant.wrapAlg is not supported.')
    return {
        product: 'wipesnap',
        recordType: CLOUD_SYNC_KEY_GRANT_RECORD_TYPE,
        schemaVersion: CLOUD_SYNC_SCHEMA_VERSION,
        ownerUid: normalizeOwnerUid(grant.ownerUid, 'cloud sync key grant.ownerUid'),
        grantId: normalizeSafeId(grant.grantId, 'cloud sync key grant.grantId', ['grant_']),
        recipientDeviceId: normalizeSafeId(grant.recipientDeviceId, 'cloud sync key grant.recipientDeviceId', ['dev_']),
        createdByDeviceId: normalizeSafeId(grant.createdByDeviceId, 'cloud sync key grant.createdByDeviceId', ['dev_']),
        keyVersion: normalizePositiveInteger(grant.keyVersion, 'cloud sync key grant.keyVersion'),
        wrapAlg,
        wrappedKeyCiphertext: normalizeBase64Url(grant.wrappedKeyCiphertext, 'cloud sync key grant.wrappedKeyCiphertext', {
            minBytes: 32,
            maxBytes: CLOUD_SYNC_LIMITS.maxWrappedKeyBytes
        }),
        wrappedKeyHash: normalizeHash(grant.wrappedKeyHash, 'cloud sync key grant.wrappedKeyHash'),
        createdAt: normalizeTimestamp(grant.createdAt, 'cloud sync key grant.createdAt'),
        revokedAt: normalizeTimestamp(grant.revokedAt, 'cloud sync key grant.revokedAt', {
            allowNull: true,
            required: false
        }),
        revokedByDeviceId: normalizeSafeId(grant.revokedByDeviceId, 'cloud sync key grant.revokedByDeviceId', ['dev_'], {
            nullable: true,
            required: false
        })
    }
}

import { randomBytes as cryptoRandomBytes } from 'crypto'
import { isAbsolute, win32 } from 'path'

export const CAPABILITY_SCHEMA_VERSION = 1
export const CAPABILITY_VAULT_SCHEMA_VERSION = 1
export const CAPABILITY_ID_BYTES = 32
export const CAPABILITY_ID_PREFIX = 'cap_'

export const CAPABILITY_TYPES = Object.freeze([
    'host-exe',
    'host-folder',
    'registry-uninstall',
    'app-paths',
    'start-menu-shortcut',
    'shortcut',
    'shell-execute',
    'protocol-uri',
    'protocol',
    'packaged-app',
    'vault-archive',
    'vault-directory',
    'imported-app'
])

export const CAPABILITY_LAUNCH_METHODS = Object.freeze([
    'spawn',
    'shell-execute',
    'protocol',
    'packaged-app'
])

export const CAPABILITY_OWNERSHIP_POLICIES = Object.freeze([
    'owned-process',
    'owned-tree',
    'external',
    'none'
])

export const CAPABILITY_ARGS_POLICIES = Object.freeze([
    'none',
    'allowlist'
])

export const DEFAULT_CAPABILITY_MAX_ARGS = 8
export const DEFAULT_CAPABILITY_MAX_ARG_LENGTH = 256
export const MAX_CAPABILITY_ARGS = 32
export const MAX_CAPABILITY_ARG_LENGTH = 1024

const TYPE_SET = new Set(CAPABILITY_TYPES)
const METHOD_SET = new Set(CAPABILITY_LAUNCH_METHODS)
const OWNERSHIP_SET = new Set(CAPABILITY_OWNERSHIP_POLICIES)
const ARGS_POLICY_SET = new Set(CAPABILITY_ARGS_POLICIES)

const MAX_DISPLAY_NAME_LENGTH = 160
const MAX_STRING_LENGTH = 4096
const MAX_POLICY_STRING_LENGTH = 256
const MAX_ARG_PREFIXES = 32
const CAPABILITY_ID_PATTERN = /^cap_[a-f0-9]{64}$/
const PROVENANCE_PATTERN = /^[a-z0-9][a-z0-9-]{0,79}$/
const STORAGE_ID_PATTERN = /^[A-Za-z0-9._-]{1,160}$/
const SCHEME_PATTERN = /^[a-z][a-z0-9+.-]{1,39}$/i

const RECORD_KEYS = new Set([
    'version',
    'capabilityId',
    'type',
    'provenance',
    'displayName',
    'launch',
    'policy',
    'verification'
])

const LAUNCH_KEYS = new Set([
    'method',
    'path',
    'uri',
    'appId',
    'packagedAppId',
    'storageId',
    'manifestId',
    'shortcutPath',
    'shortcutTargetPath',
    'shortcutArguments',
    'shortcutWorkingDirectory',
    'shortcutIconLocation',
    'registryKey',
    'registryDisplayName',
    'registryInstallLocation',
    'registryDisplayIcon',
    'appPathsKey',
    'appPathsExecutableName',
    'appPathsPathValue',
    'protocolScheme',
    'protocolCommand',
    'protocolRegistryKey'
])

const LAUNCH_KEYS_BY_TYPE = Object.freeze({
    'host-exe': new Set(['method', 'path']),
    'host-folder': new Set(['method', 'path']),
    'registry-uninstall': new Set([
        'method',
        'path',
        'registryKey',
        'registryDisplayName',
        'registryInstallLocation',
        'registryDisplayIcon'
    ]),
    'app-paths': new Set([
        'method',
        'path',
        'appPathsKey',
        'appPathsExecutableName',
        'appPathsPathValue'
    ]),
    'start-menu-shortcut': new Set([
        'method',
        'path',
        'shortcutPath',
        'shortcutTargetPath',
        'shortcutArguments',
        'shortcutWorkingDirectory',
        'shortcutIconLocation'
    ]),
    shortcut: new Set([
        'method',
        'path',
        'shortcutPath',
        'shortcutTargetPath',
        'shortcutArguments',
        'shortcutWorkingDirectory',
        'shortcutIconLocation'
    ]),
    'shell-execute': new Set([
        'method',
        'path',
        'shortcutPath',
        'shortcutTargetPath',
        'shortcutArguments',
        'shortcutWorkingDirectory',
        'shortcutIconLocation'
    ]),
    'protocol-uri': new Set([
        'method',
        'uri',
        'protocolScheme',
        'protocolCommand',
        'protocolRegistryKey'
    ]),
    protocol: new Set([
        'method',
        'uri',
        'protocolScheme',
        'protocolCommand',
        'protocolRegistryKey'
    ]),
    'packaged-app': new Set([
        'method',
        'path',
        'appId',
        'packagedAppId'
    ]),
    'vault-archive': new Set([
        'method',
        'storageId',
        'manifestId'
    ]),
    'vault-directory': new Set([
        'method',
        'storageId',
        'manifestId'
    ]),
    'imported-app': new Set([
        'method',
        'storageId',
        'manifestId'
    ])
})

const POLICY_KEYS = new Set([
    'allowedArgs',
    'allowedPrefixes',
    'maxArgs',
    'maxArgLength',
    'canCloseFromWipesnap',
    'ownership'
])

const ARGS_POLICY_KEYS = new Set([
    'allowedArgs',
    'allowedPrefixes',
    'maxArgs',
    'maxArgLength'
])

const VERIFICATION_KEYS = new Set([
    'lastVerifiedAt',
    'hostFingerprint'
])

function fail(message) {
    throw new Error(message)
}

function isPlainObject(value) {
    return !!value && typeof value === 'object' && !Array.isArray(value)
}

function requirePlainObject(value, fieldName) {
    if (!isPlainObject(value)) fail(`${fieldName} must be an object.`)
    return value
}

function rejectUnknownKeys(value, allowedKeys, fieldName) {
    for (const key of Object.keys(value)) {
        if (!allowedKeys.has(key)) fail(`${fieldName}.${key} is not supported by capability schema v${CAPABILITY_SCHEMA_VERSION}.`)
    }
}

function rejectUnsupportedLaunchKeysForType(value, type) {
    const allowedKeys = LAUNCH_KEYS_BY_TYPE[type]
    if (!allowedKeys) fail(`Unsupported capability type: ${type}`)
    for (const key of Object.keys(value)) {
        if (!LAUNCH_KEYS.has(key)) {
            fail(`capability.launch.${key} is not supported by capability schema v${CAPABILITY_SCHEMA_VERSION}.`)
        }
        if (!allowedKeys.has(key)) {
            fail(`capability.launch.${key} is not supported for ${type} capability launch.`)
        }
    }
}

function normalizeString(value, fieldName, {
    required = true,
    max = MAX_STRING_LENGTH,
    allowEmpty = false,
    pattern = null
} = {}) {
    if (value == null) {
        if (required) fail(`${fieldName} is required.`)
        return ''
    }
    if (typeof value !== 'string') fail(`${fieldName} must be a string.`)
    if (value.includes('\0')) fail(`${fieldName} contains an invalid null byte.`)
    if (/[\r\n]/.test(value)) fail(`${fieldName} cannot contain control line breaks.`)
    const trimmed = value.trim()
    if (required && !trimmed) fail(`${fieldName} is required.`)
    if (!allowEmpty && value.length > 0 && !trimmed) fail(`${fieldName} cannot be blank.`)
    if (trimmed.length > max) fail(`${fieldName} is too long.`)
    if (pattern && trimmed && !pattern.test(trimmed)) fail(`${fieldName} is invalid.`)
    return trimmed
}

function normalizeOptionalString(value, fieldName, options = {}) {
    if (value == null || value === '') return ''
    return normalizeString(value, fieldName, { ...options, required: false })
}

function normalizeBoolean(value, fieldName, defaultValue = false) {
    if (value == null) return defaultValue
    if (typeof value !== 'boolean') fail(`${fieldName} must be a boolean.`)
    return value
}

function normalizeBoundedPositiveInteger(value, fieldName, defaultValue, maxValue) {
    if (value == null) return defaultValue
    if (!Number.isSafeInteger(value) || value < 1) fail(`${fieldName} must be a positive safe integer.`)
    if (value > maxValue) fail(`${fieldName} cannot exceed ${maxValue}.`)
    return value
}

function normalizeEnum(value, fieldName, allowedValues) {
    const normalized = normalizeString(value, fieldName, { max: MAX_POLICY_STRING_LENGTH })
    if (!allowedValues.has(normalized)) fail(`${fieldName} is not supported.`)
    return normalized
}

function isAbsoluteFilesystemPath(value) {
    return isAbsolute(value) || win32.isAbsolute(value)
}

function isUncPath(value) {
    return String(value || '').startsWith('\\\\')
}

function hasTraversalSegment(value) {
    return String(value || '')
        .split(/[\\/]+/)
        .some(part => part === '..')
}

function isExecutablePath(value) {
    return /\.(?:exe|bat|cmd)$/i.test(String(value || '').trim())
}

function isProtocolUri(value) {
    return /^[a-z][a-z0-9+.-]{1,39}:(?:\/\/.*)?$/i.test(String(value || '').trim())
}

function getUriScheme(value) {
    const match = String(value || '').trim().match(/^([a-z][a-z0-9+.-]*):/i)
    return match ? match[1].toLowerCase() : ''
}

function isPackagedAppPath(value) {
    return /^shell:AppsFolder\\/i.test(String(value || '').trim())
}

function normalizeLocalPath(value, fieldName, { executable = null } = {}) {
    const pathValue = normalizeString(value, fieldName)
    if (!isAbsoluteFilesystemPath(pathValue)) fail(`${fieldName} must be an absolute local filesystem path.`)
    if (isUncPath(pathValue)) fail(`${fieldName} cannot be a network/UNC path.`)
    if (hasTraversalSegment(pathValue)) fail(`${fieldName} cannot contain parent-directory traversal.`)
    if (executable === true && !isExecutablePath(pathValue)) fail(`${fieldName} must be a direct executable path.`)
    if (executable === false && isExecutablePath(pathValue)) fail(`${fieldName} cannot be a direct executable path.`)
    return pathValue
}

function normalizeStorageId(value, fieldName) {
    return normalizeString(value, fieldName, {
        max: 160,
        pattern: STORAGE_ID_PATTERN
    })
}

function normalizeIsoTimestamp(value, fieldName) {
    const timestamp = normalizeString(value, fieldName, { max: 64 })
    const parsed = Date.parse(timestamp)
    if (!Number.isFinite(parsed)) fail(`${fieldName} must be a valid ISO timestamp.`)
    return new Date(parsed).toISOString()
}

function resolveTimestamp(now) {
    const value = typeof now === 'function' ? now() : now
    if (value instanceof Date) return value.toISOString()
    if (typeof value === 'number' && Number.isFinite(value)) return new Date(value).toISOString()
    if (value == null) return new Date().toISOString()
    return normalizeIsoTimestamp(String(value), 'verification.lastVerifiedAt')
}

function defaultLaunchMethodForType(type) {
    if (type === 'host-folder' || type === 'shell-execute') return 'shell-execute'
    if (type === 'protocol' || type === 'protocol-uri') return 'protocol'
    if (type === 'packaged-app') return 'packaged-app'
    return 'spawn'
}

function defaultOwnershipForType(type) {
    if (['host-exe', 'vault-archive', 'vault-directory', 'imported-app'].includes(type)) {
        return 'owned-process'
    }
    return 'external'
}

function normalizeLaunch(launch, type) {
    const value = requirePlainObject(launch, 'capability.launch')
    rejectUnsupportedLaunchKeysForType(value, type)

    const method = normalizeEnum(value.method, 'capability.launch.method', METHOD_SET)
    const next = { method }

    if (['host-exe', 'registry-uninstall', 'app-paths', 'start-menu-shortcut', 'shortcut'].includes(type)) {
        if (method !== 'spawn') fail(`capability.launch.method must be spawn for ${type}.`)
        next.path = normalizeLocalPath(value.path, 'capability.launch.path', { executable: true })
    } else if (type === 'host-folder' || type === 'shell-execute') {
        if (method !== 'shell-execute') fail(`capability.launch.method must be shell-execute for ${type}.`)
        next.path = normalizeLocalPath(value.path, 'capability.launch.path', { executable: false })
    } else if (type === 'protocol' || type === 'protocol-uri') {
        if (method !== 'protocol') fail(`capability.launch.method must be protocol for ${type}.`)
        const uri = normalizeString(value.uri || value.path, 'capability.launch.uri', { max: 2048 })
        if (!isProtocolUri(uri)) fail('capability.launch.uri must be a protocol URI.')
        next.uri = uri
    } else if (type === 'packaged-app') {
        if (method !== 'packaged-app') fail('capability.launch.method must be packaged-app for packaged-app.')
        const appId = normalizeOptionalString(value.appId, 'capability.launch.appId', { max: 512 })
        const packagedAppId = normalizeOptionalString(value.packagedAppId, 'capability.launch.packagedAppId', { max: 512 })
        if (appId && packagedAppId && appId !== packagedAppId) {
            fail('capability.launch.appId must match capability.launch.packagedAppId.')
        }
        if (appId || packagedAppId) {
            next.appId = appId || packagedAppId
        } else {
            const pathValue = normalizeString(value.path, 'capability.launch.path', { max: 1024 })
            if (!isPackagedAppPath(pathValue)) fail('capability.launch.path must be a shell:AppsFolder activation path.')
            next.path = pathValue
        }
    } else if (['vault-archive', 'vault-directory', 'imported-app'].includes(type)) {
        if (method !== 'spawn') fail(`capability.launch.method must be spawn for ${type}.`)
        next.storageId = normalizeStorageId(value.storageId, 'capability.launch.storageId')
    } else {
        fail(`Unsupported capability type: ${type}`)
    }

    const optionalFieldsByType = {
        'registry-uninstall': ['registryKey', 'registryDisplayName', 'registryInstallLocation', 'registryDisplayIcon'],
        'app-paths': ['appPathsKey', 'appPathsExecutableName', 'appPathsPathValue'],
        'start-menu-shortcut': ['shortcutPath', 'shortcutTargetPath', 'shortcutArguments', 'shortcutWorkingDirectory', 'shortcutIconLocation'],
        shortcut: ['shortcutPath', 'shortcutTargetPath', 'shortcutArguments', 'shortcutWorkingDirectory', 'shortcutIconLocation'],
        'shell-execute': ['shortcutPath', 'shortcutTargetPath', 'shortcutArguments', 'shortcutWorkingDirectory', 'shortcutIconLocation'],
        'protocol-uri': ['protocolCommand', 'protocolRegistryKey'],
        protocol: ['protocolCommand', 'protocolRegistryKey'],
        'vault-archive': ['manifestId'],
        'vault-directory': ['manifestId'],
        'imported-app': ['manifestId']
    }

    for (const key of optionalFieldsByType[type] || []) {
        const normalized = normalizeOptionalString(value[key], `capability.launch.${key}`)
        if (normalized) next[key] = normalized
    }

    const protocolScheme = normalizeOptionalString(value.protocolScheme, 'capability.launch.protocolScheme', {
        max: 40,
        pattern: SCHEME_PATTERN
    })
    if (protocolScheme) {
        const uriScheme = getUriScheme(next.uri)
        if (uriScheme && uriScheme !== protocolScheme.toLowerCase()) {
            fail('capability.launch.protocolScheme must match capability.launch.uri.')
        }
        next.protocolScheme = protocolScheme.toLowerCase()
    } else if (next.uri) {
        next.protocolScheme = getUriScheme(next.uri)
    }

    return next
}

function normalizeArgsPolicyFields(value, fieldName, { rejectUnknown = true } = {}) {
    if (rejectUnknown) rejectUnknownKeys(value, ARGS_POLICY_KEYS, fieldName)

    const allowedArgs = normalizeEnum(value.allowedArgs ?? 'none', `${fieldName}.allowedArgs`, ARGS_POLICY_SET)
    const next = { allowedArgs }

    if (allowedArgs === 'allowlist') {
        const prefixes = Array.isArray(value.allowedPrefixes) ? value.allowedPrefixes : []
        if (prefixes.length === 0) fail(`${fieldName}.allowedPrefixes is required when allowedArgs is allowlist.`)
        if (prefixes.length > MAX_ARG_PREFIXES) fail(`${fieldName}.allowedPrefixes cannot contain more than ${MAX_ARG_PREFIXES} entries.`)
        next.allowedPrefixes = prefixes.map((prefix, index) => normalizeString(prefix, `${fieldName}.allowedPrefixes[${index}]`, {
            max: MAX_POLICY_STRING_LENGTH
        }))
        next.maxArgs = normalizeBoundedPositiveInteger(
            value.maxArgs,
            `${fieldName}.maxArgs`,
            DEFAULT_CAPABILITY_MAX_ARGS,
            MAX_CAPABILITY_ARGS
        )
        next.maxArgLength = normalizeBoundedPositiveInteger(
            value.maxArgLength,
            `${fieldName}.maxArgLength`,
            DEFAULT_CAPABILITY_MAX_ARG_LENGTH,
            MAX_CAPABILITY_ARG_LENGTH
        )
    } else if (value.allowedPrefixes != null || value.maxArgs != null || value.maxArgLength != null) {
        fail(`${fieldName} argument allowlist fields require allowedArgs to be allowlist.`)
    }

    return next
}

export function normalizeCapabilityArgsPolicy(policy, fieldName = 'capability args policy') {
    const value = policy == null ? {} : requirePlainObject(policy, fieldName)
    return normalizeArgsPolicyFields(value, fieldName)
}

export function normalizeCapabilityUserArgs(value, fieldName = 'userArgs') {
    if (value == null || value === '') return []
    if (!Array.isArray(value)) fail(`${fieldName} must be an array.`)
    if (value.length > MAX_CAPABILITY_ARGS) fail(`${fieldName} cannot contain more than ${MAX_CAPABILITY_ARGS} arguments.`)
    return value.map((arg, index) => normalizeString(arg, `${fieldName}[${index}]`, {
        max: MAX_CAPABILITY_ARG_LENGTH
    }))
}

export function validateCapabilityUserArgs(value, record, { fieldName = 'userArgs' } = {}) {
    const userArgs = normalizeCapabilityUserArgs(value, fieldName)
    if (userArgs.length === 0) return []

    const capabilityId = record?.capabilityId || 'unknown capability'
    const policy = record?.policy || {}
    const argsPolicy = normalizeCapabilityArgsPolicy({
        allowedArgs: policy.allowedArgs,
        allowedPrefixes: policy.allowedPrefixes,
        maxArgs: policy.maxArgs,
        maxArgLength: policy.maxArgLength
    }, 'capability.policy')

    if (argsPolicy.allowedArgs !== 'allowlist') {
        fail(`Capability ${capabilityId} does not allow renderer-supplied launch arguments.`)
    }
    if (userArgs.length > argsPolicy.maxArgs) {
        fail(`Capability ${capabilityId} received too many launch arguments.`)
    }
    for (const arg of userArgs) {
        if (arg.length > argsPolicy.maxArgLength) {
            fail(`Capability ${capabilityId} received an overlong launch argument.`)
        }
        if (!argsPolicy.allowedPrefixes.some(prefix => arg.startsWith(prefix))) {
            fail(`Capability ${capabilityId} received a launch argument outside its allowlist.`)
        }
    }

    return userArgs
}

function normalizePolicy(policy, type) {
    const value = policy == null ? {} : requirePlainObject(policy, 'capability.policy')
    rejectUnknownKeys(value, POLICY_KEYS, 'capability.policy')

    const argsPolicy = normalizeArgsPolicyFields(value, 'capability.policy', { rejectUnknown: false })
    const next = {
        ...argsPolicy,
        canCloseFromWipesnap: normalizeBoolean(value.canCloseFromWipesnap, 'capability.policy.canCloseFromWipesnap', false),
        ownership: normalizeEnum(value.ownership ?? defaultOwnershipForType(type), 'capability.policy.ownership', OWNERSHIP_SET)
    }

    if (!next.canCloseFromWipesnap && ['owned-tree'].includes(next.ownership)) {
        fail('capability.policy.ownership cannot grant owned-tree cleanup when canCloseFromWipesnap is false.')
    }

    return next
}

function normalizeVerification(verification) {
    const value = verification == null ? {} : requirePlainObject(verification, 'capability.verification')
    rejectUnknownKeys(value, VERIFICATION_KEYS, 'capability.verification')

    const next = {
        lastVerifiedAt: normalizeIsoTimestamp(value.lastVerifiedAt, 'capability.verification.lastVerifiedAt')
    }
    const hostFingerprint = normalizeOptionalString(value.hostFingerprint, 'capability.verification.hostFingerprint', {
        max: 512
    })
    if (hostFingerprint) next.hostFingerprint = hostFingerprint
    return next
}

function cloneValue(value) {
    return JSON.parse(JSON.stringify(value))
}

function freezeDeep(value) {
    if (!value || typeof value !== 'object') return value
    Object.freeze(value)
    for (const nested of Object.values(value)) freezeDeep(nested)
    return value
}

function setRecord(records, record) {
    if (records.has(record.capabilityId)) fail(`Duplicate capability record: ${record.capabilityId}`)
    records.set(record.capabilityId, freezeDeep(cloneValue(record)))
}

function normalizeInitialRecords(records) {
    if (records == null) return []
    if (Array.isArray(records)) return records
    if (records instanceof Map) return [...records.values()]
    if (isPlainObject(records)) {
        return Object.entries(records).map(([key, record]) => {
            const normalized = validateCapabilityRecord(record)
            if (key !== normalized.capabilityId) fail('Capability vault record key must match capabilityId.')
            return normalized
        })
    }
    fail('Capability records must be an array, map, or object keyed by capabilityId.')
}

export function generateCapabilityId({ randomBytes = cryptoRandomBytes } = {}) {
    const bytes = randomBytes(CAPABILITY_ID_BYTES)
    if (!Buffer.isBuffer(bytes) || bytes.length !== CAPABILITY_ID_BYTES) {
        fail(`Capability ID random source must return ${CAPABILITY_ID_BYTES} bytes.`)
    }
    return `${CAPABILITY_ID_PREFIX}${bytes.toString('hex')}`
}

export function validateCapabilityId(capabilityId, fieldName = 'capabilityId') {
    const value = normalizeString(capabilityId, fieldName, { max: CAPABILITY_ID_PREFIX.length + CAPABILITY_ID_BYTES * 2 })
    if (!CAPABILITY_ID_PATTERN.test(value)) fail(`${fieldName} is invalid.`)
    return value
}

export function createCapabilityRecord(input, {
    randomBytes = cryptoRandomBytes,
    now = Date.now
} = {}) {
    const value = requirePlainObject(input, 'capability input')
    const type = normalizeEnum(value.type, 'capability.type', TYPE_SET)
    const launchInput = {
        ...(isPlainObject(value.launch) ? value.launch : {}),
        method: value.launch?.method || defaultLaunchMethodForType(type)
    }

    const record = {
        version: CAPABILITY_SCHEMA_VERSION,
        capabilityId: generateCapabilityId({ randomBytes }),
        type,
        provenance: normalizeString(value.provenance, 'capability.provenance', {
            max: 80,
            pattern: PROVENANCE_PATTERN
        }),
        displayName: normalizeString(value.displayName, 'capability.displayName', {
            max: MAX_DISPLAY_NAME_LENGTH
        }),
        launch: normalizeLaunch(launchInput, type),
        policy: normalizePolicy(value.policy, type),
        verification: normalizeVerification({
            ...(isPlainObject(value.verification) ? value.verification : {}),
            lastVerifiedAt: value.verification?.lastVerifiedAt || resolveTimestamp(now)
        })
    }

    return validateCapabilityRecord(record)
}

export function validateCapabilityRecord(record) {
    const value = requirePlainObject(record, 'capability record')
    rejectUnknownKeys(value, RECORD_KEYS, 'capability')

    if (value.version !== CAPABILITY_SCHEMA_VERSION) {
        fail(`Capability record version must be ${CAPABILITY_SCHEMA_VERSION}.`)
    }

    const type = normalizeEnum(value.type, 'capability.type', TYPE_SET)
    return {
        version: CAPABILITY_SCHEMA_VERSION,
        capabilityId: validateCapabilityId(value.capabilityId, 'capability.capabilityId'),
        type,
        provenance: normalizeString(value.provenance, 'capability.provenance', {
            max: 80,
            pattern: PROVENANCE_PATTERN
        }),
        displayName: normalizeString(value.displayName, 'capability.displayName', {
            max: MAX_DISPLAY_NAME_LENGTH
        }),
        launch: normalizeLaunch(value.launch, type),
        policy: normalizePolicy(value.policy, type),
        verification: normalizeVerification(value.verification)
    }
}

export function validateCapabilityVaultValue(vaultValue) {
    const value = vaultValue == null
        ? { version: CAPABILITY_VAULT_SCHEMA_VERSION, records: {} }
        : requirePlainObject(vaultValue, 'capability vault value')
    const keys = new Set(['version', 'records'])
    rejectUnknownKeys(value, keys, 'capability vault value')
    if (value.version !== CAPABILITY_VAULT_SCHEMA_VERSION) {
        fail(`Capability vault value version must be ${CAPABILITY_VAULT_SCHEMA_VERSION}.`)
    }
    const recordsValue = requirePlainObject(value.records, 'capability vault value.records')
    const records = {}
    for (const [key, record] of Object.entries(recordsValue)) {
        const normalized = validateCapabilityRecord(record)
        if (key !== normalized.capabilityId) fail('Capability vault record key must match capabilityId.')
        records[normalized.capabilityId] = normalized
    }
    return {
        version: CAPABILITY_VAULT_SCHEMA_VERSION,
        records
    }
}

export class InMemoryCapabilityStore {
    #records = new Map()

    constructor({ records = null, vaultValue = null } = {}) {
        if (records != null && vaultValue != null) fail('Provide either capability records or a vault value, not both.')
        const sourceRecords = vaultValue != null
            ? Object.values(validateCapabilityVaultValue(vaultValue).records)
            : normalizeInitialRecords(records)

        for (const record of sourceRecords) {
            setRecord(this.#records, validateCapabilityRecord(record))
        }
    }

    create(input, options = {}) {
        const record = createCapabilityRecord(input, options)
        setRecord(this.#records, record)
        return cloneValue(record)
    }

    put(record) {
        const normalized = validateCapabilityRecord(record)
        this.#records.set(normalized.capabilityId, freezeDeep(cloneValue(normalized)))
        return cloneValue(normalized)
    }

    read(capabilityId) {
        const id = validateCapabilityId(capabilityId)
        const record = this.#records.get(id)
        return record ? cloneValue(record) : null
    }

    require(capabilityId) {
        const record = this.read(capabilityId)
        if (!record) fail('Capability is missing, stale, or unavailable.')
        return record
    }

    has(capabilityId) {
        return this.read(capabilityId) !== null
    }

    ids() {
        return [...this.#records.keys()]
    }

    toVaultValue() {
        const records = {}
        for (const [capabilityId, record] of this.#records.entries()) {
            records[capabilityId] = cloneValue(record)
        }
        return {
            version: CAPABILITY_VAULT_SCHEMA_VERSION,
            records
        }
    }
}

export function createCapabilityStore(options = {}) {
    return new InMemoryCapabilityStore(options)
}

import crypto from 'crypto'

export const ACCOUNT_SLOT_PROVIDERS = Object.freeze(['google'])
export const ACCOUNT_SLOT_STATES = Object.freeze([
    'unknown',
    'signed-in',
    'needs-recheck',
    'needs-auth',
    'needs-phone-approval',
    'needs-passkey',
    'blocked-or-suspicious',
    'user-action-required'
])

const PROVIDER_SET = new Set(ACCOUNT_SLOT_PROVIDERS)
const STATE_SET = new Set(ACCOUNT_SLOT_STATES)
const SLOT_KEYS = new Set(['id', 'provider', 'label', 'identifierHint', 'state', 'lastCheckedAt', 'notes'])
const CREATE_KEYS = new Set(['provider', 'label', 'identifierHint', 'state', 'lastCheckedAt', 'notes'])
const UPDATE_KEYS = SLOT_KEYS
const DELETE_KEYS = new Set(['id'])
const SECRET_FIELD_MARKERS = [
    'password',
    'passcode',
    'backupcode',
    'cookie',
    'token',
    'oauth',
    'refreshtoken',
    'accesstoken',
    'secret',
    'credential'
]
const AUTHORITY_FIELD_MARKERS = [
    'path',
    'vault',
    'file',
    'capability',
    'storage',
    'material',
    'registry',
    'shell',
    'process',
    'browser'
]
const MAX_SLOTS = 32
const MAX_LABEL_LENGTH = 80
const MAX_IDENTIFIER_HINT_LENGTH = 160
const MAX_NOTES_LENGTH = 1000
const MAX_TIMESTAMP = 8_640_000_000_000_000
const ACCOUNT_SLOT_ID_PATTERN = /^acct_[a-f0-9]{32,64}$/

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

function looksLikeSecretField(key) {
    const normalized = normalizedKey(key)
    return SECRET_FIELD_MARKERS.some(marker => normalized.includes(marker))
}

function looksLikeAuthorityField(key) {
    const normalized = normalizedKey(key)
    return AUTHORITY_FIELD_MARKERS.some(marker => normalized.includes(marker))
}

function rejectUnsafeUnknownFields(value, allowedKeys, fieldName) {
    for (const key of Object.keys(value || {})) {
        if (allowedKeys.has(key)) continue
        if (looksLikeSecretField(key)) {
            fail(`${fieldName}.${key} is not accepted because it looks like account secret material.`)
        }
        if (looksLikeAuthorityField(key)) {
            fail(`${fieldName}.${key} is not accepted because account slots cannot carry vault, filesystem, browser, or capability material.`)
        }
    }
}

function normalizeString(value, fieldName, {
    required = false,
    max,
    multiline = false,
    rejectSecretMaterial = false
} = {}) {
    if (value == null) {
        if (required) fail(`${fieldName} is required.`)
        return ''
    }
    if (typeof value !== 'string') fail(`${fieldName} must be a string.`)
    if (value.includes('\0')) fail(`${fieldName} contains an invalid null byte.`)

    let text = value.replace(/\r\n?/g, '\n')
    const controlPattern = multiline
        ? /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/
        : /[\u0000-\u001F\u007F]/
    if (controlPattern.test(text)) fail(`${fieldName} contains unsupported control whitespace.`)

    text = text.trim()
    if (required && !text) fail(`${fieldName} is required.`)
    if (!required && !text) return ''
    if (text.length > max) fail(`${fieldName} is too long.`)
    if (rejectSecretMaterial && /\b(password|passcode|backup\s*code|cookie|oauth|refresh\s*token|access\s*token|token|secret|credential)\b\s*[:=]/i.test(text)) {
        fail(`${fieldName} cannot contain account secret material.`)
    }
    return text
}

function normalizeProvider(value, fieldName = 'provider') {
    const provider = normalizeString(value, fieldName, { required: true, max: 40 })
    if (!PROVIDER_SET.has(provider)) fail(`${fieldName} is not supported.`)
    return provider
}

function normalizeState(value, fieldName = 'state', { defaultValue = 'unknown' } = {}) {
    if (value == null || value === '') return defaultValue
    const state = normalizeString(value, fieldName, { required: true, max: 80 })
    if (!STATE_SET.has(state)) fail(`${fieldName} is not supported.`)
    return state
}

function normalizeLastCheckedAt(value, fieldName = 'lastCheckedAt') {
    if (value == null || value === '') return 0
    if (typeof value !== 'number' || !Number.isFinite(value) || value < 0 || value > MAX_TIMESTAMP) {
        fail(`${fieldName} must be a non-negative timestamp.`)
    }
    return Math.floor(value)
}

function normalizeAccountSlotId(value, fieldName = 'id') {
    const id = normalizeString(value, fieldName, { required: true, max: 80 })
    if (!ACCOUNT_SLOT_ID_PATTERN.test(id)) fail(`${fieldName} must be a main-issued account slot id.`)
    return id
}

export function createAccountSlotId({ randomBytes = crypto.randomBytes } = {}) {
    const bytes = randomBytes(24)
    if (!Buffer.isBuffer(bytes) || bytes.length < 16) {
        fail('Account slot id source returned insufficient random bytes.')
    }
    return `acct_${bytes.toString('hex')}`
}

export function validateAccountSlotRecord(value, {
    fieldName = 'accountSlots[]',
    requireId = true
} = {}) {
    const slot = requireObject(value, fieldName)
    rejectUnsafeUnknownFields(slot, SLOT_KEYS, fieldName)

    const next = {
        provider: normalizeProvider(slot.provider, `${fieldName}.provider`),
        label: normalizeString(slot.label, `${fieldName}.label`, {
            required: true,
            max: MAX_LABEL_LENGTH
        }),
        identifierHint: normalizeString(slot.identifierHint, `${fieldName}.identifierHint`, {
            max: MAX_IDENTIFIER_HINT_LENGTH
        }),
        state: normalizeState(slot.state, `${fieldName}.state`),
        lastCheckedAt: normalizeLastCheckedAt(slot.lastCheckedAt, `${fieldName}.lastCheckedAt`),
        notes: normalizeString(slot.notes, `${fieldName}.notes`, {
            max: MAX_NOTES_LENGTH,
            multiline: true,
            rejectSecretMaterial: true
        })
    }

    if (requireId) {
        next.id = normalizeAccountSlotId(slot.id, `${fieldName}.id`)
        return {
            id: next.id,
            provider: next.provider,
            label: next.label,
            identifierHint: next.identifierHint,
            state: next.state,
            lastCheckedAt: next.lastCheckedAt,
            notes: next.notes
        }
    }

    return next
}

export function normalizeAccountSlots(value, { fieldName = 'accountSlots' } = {}) {
    if (value == null) return []
    if (!Array.isArray(value)) fail(`${fieldName} must be an array.`)
    if (value.length > MAX_SLOTS) fail(`${fieldName} cannot contain more than ${MAX_SLOTS} slots.`)

    const seenIds = new Set()
    return value.map((slot, index) => {
        const normalized = validateAccountSlotRecord(slot, {
            fieldName: `${fieldName}[${index}]`,
            requireId: true
        })
        if (seenIds.has(normalized.id)) fail(`${fieldName} contains a duplicate account slot id.`)
        seenIds.add(normalized.id)
        return normalized
    })
}

export function validateCreateAccountSlotInput(input) {
    const payload = requireObject(input, 'create-account-slot payload')
    rejectUnsafeUnknownFields(payload, CREATE_KEYS, 'create-account-slot payload')
    if ('id' in payload) fail('Account slot ids are issued by the main process.')
    return validateAccountSlotRecord(payload, {
        fieldName: 'create-account-slot payload',
        requireId: false
    })
}

export function validateUpdateAccountSlotInput(input) {
    const payload = requireObject(input, 'update-account-slot payload')
    rejectUnsafeUnknownFields(payload, UPDATE_KEYS, 'update-account-slot payload')
    const patch = {
        id: normalizeAccountSlotId(payload.id, 'update-account-slot payload.id')
    }
    if ('provider' in payload) patch.provider = normalizeProvider(payload.provider, 'update-account-slot payload.provider')
    if ('label' in payload) {
        patch.label = normalizeString(payload.label, 'update-account-slot payload.label', {
            required: true,
            max: MAX_LABEL_LENGTH
        })
    }
    if ('identifierHint' in payload) {
        patch.identifierHint = normalizeString(payload.identifierHint, 'update-account-slot payload.identifierHint', {
            max: MAX_IDENTIFIER_HINT_LENGTH
        })
    }
    if ('state' in payload) patch.state = normalizeState(payload.state, 'update-account-slot payload.state')
    if ('lastCheckedAt' in payload) patch.lastCheckedAt = normalizeLastCheckedAt(payload.lastCheckedAt, 'update-account-slot payload.lastCheckedAt')
    if ('notes' in payload) {
        patch.notes = normalizeString(payload.notes, 'update-account-slot payload.notes', {
            max: MAX_NOTES_LENGTH,
            multiline: true,
            rejectSecretMaterial: true
        })
    }
    return patch
}

export function validateDeleteAccountSlotInput(input) {
    const payload = requireObject(input, 'delete-account-slot payload')
    rejectUnsafeUnknownFields(payload, DELETE_KEYS, 'delete-account-slot payload')
    return { id: normalizeAccountSlotId(payload.id, 'delete-account-slot payload.id') }
}

export function createAccountSlot(input, existingSlots = [], options = {}) {
    const existing = normalizeAccountSlots(existingSlots)
    const slotInput = validateCreateAccountSlotInput(input)
    const existingIds = new Set(existing.map(slot => slot.id))

    for (let attempt = 0; attempt < 5; attempt += 1) {
        const id = createAccountSlotId(options)
        if (!existingIds.has(id)) {
            return {
                id,
                ...slotInput
            }
        }
    }

    fail('Unable to allocate a unique account slot id.')
}

export function updateAccountSlot(input, existingSlots = []) {
    const existing = normalizeAccountSlots(existingSlots)
    const patch = validateUpdateAccountSlotInput(input)
    const index = existing.findIndex(slot => slot.id === patch.id)
    if (index < 0) fail('Account slot id was not found.')

    const nextSlots = existing.map((slot, slotIndex) => {
        if (slotIndex !== index) return slot
        return validateAccountSlotRecord({
            ...slot,
            ...patch
        }, {
            fieldName: 'update-account-slot payload',
            requireId: true
        })
    })
    return nextSlots
}

export function deleteAccountSlot(input, existingSlots = []) {
    const existing = normalizeAccountSlots(existingSlots)
    const { id } = validateDeleteAccountSlotInput(input)
    const nextSlots = existing.filter(slot => slot.id !== id)
    if (nextSlots.length === existing.length) fail('Account slot id was not found.')
    return nextSlots
}

export function attachAccountSlots(workspace, accountSlots) {
    return {
        ...(isPlainObject(workspace) ? workspace : {}),
        accountSlots: normalizeAccountSlots(accountSlots || [])
    }
}

async function persistAccountSlots(workspace, accountSlots, deps, operation) {
    const nextWorkspace = attachAccountSlots(workspace, accountSlots)
    const payload = { ...nextWorkspace, _honeyToken: deps.honeyToken }
    const driveInfo = await deps.getDriveInfo()
    const encryptedVault = deps.encryptVault(payload, deps.getActiveMasterPassword(), driveInfo)
    const meta = deps.loadVaultMeta ? (deps.loadVaultMeta() || { version: '1.0.0' }) : { version: '1.0.0' }

    if (deps.commitVaultMeta) {
        deps.commitVaultMeta({ vault: encryptedVault, meta, operation })
    } else {
        deps.writeVault(encryptedVault)
        deps.saveVaultMeta(meta)
    }

    return nextWorkspace
}

function createFailure(error) {
    return {
        success: false,
        error: error?.message || 'Account slot operation failed.',
        accountSlots: []
    }
}

export function loadAccountSlotsFromWorkspace(workspace) {
    return normalizeAccountSlots(workspace?.accountSlots || [])
}

export function loadAccountSlotsHandlerCore({ input, deps }) {
    try {
        deps.requireActiveSession()
        if (input !== undefined) fail('load-account-slots does not accept renderer input.')
        const workspace = deps.loadActiveVaultWorkspace()
        return {
            success: true,
            accountSlots: loadAccountSlotsFromWorkspace(workspace)
        }
    } catch (err) {
        return createFailure(err)
    }
}

export async function createAccountSlotHandlerCore({ input, deps }) {
    try {
        deps.requireActiveSession()
        const slotInput = validateCreateAccountSlotInput(input)
        const workspace = deps.loadActiveVaultWorkspace()
        const existing = loadAccountSlotsFromWorkspace(workspace)
        const accountSlot = createAccountSlot(slotInput, existing, {
            randomBytes: deps.randomBytes || crypto.randomBytes
        })
        const accountSlots = [...existing, accountSlot]
        await persistAccountSlots(workspace, accountSlots, deps, 'create-account-slot')
        return { success: true, accountSlot, accountSlots }
    } catch (err) {
        return createFailure(err)
    }
}

export async function updateAccountSlotHandlerCore({ input, deps }) {
    try {
        deps.requireActiveSession()
        const patch = validateUpdateAccountSlotInput(input)
        const workspace = deps.loadActiveVaultWorkspace()
        const accountSlots = updateAccountSlot(patch, loadAccountSlotsFromWorkspace(workspace))
        const accountSlot = accountSlots.find(slot => slot.id === patch.id) || null
        await persistAccountSlots(workspace, accountSlots, deps, 'update-account-slot')
        return { success: true, accountSlot, accountSlots }
    } catch (err) {
        return createFailure(err)
    }
}

export async function deleteAccountSlotHandlerCore({ input, deps }) {
    try {
        deps.requireActiveSession()
        const request = validateDeleteAccountSlotInput(input)
        const workspace = deps.loadActiveVaultWorkspace()
        const accountSlots = deleteAccountSlot(request, loadAccountSlotsFromWorkspace(workspace))
        await persistAccountSlots(workspace, accountSlots, deps, 'delete-account-slot')
        return { success: true, accountSlots }
    } catch (err) {
        return createFailure(err)
    }
}

import { isAbsolute, normalize, parse as pathParse, win32 } from 'path'
import { safeAppName } from './appManifest.js'

const MAX_STRING_LENGTH = 4096
const MAX_NAME_LENGTH = 160
const MAX_ARGS_LENGTH = 2048
const MAX_ARGS = 100
const MAX_TABS = 200
const MAX_APPS = 200
const MAX_PAYLOAD_IDS = 100
const RESET_TOKEN_PATTERN = /^[a-f0-9]{32,64}$/i

export const HOST_LAUNCH_SOURCE_TYPES = new Set([
    'host-exe',
    'host-folder',
    'registry-uninstall',
    'app-paths',
    'start-menu-shortcut',
    'shell-execute',
    'protocol-uri',
    'packaged-app'
])

export const LAUNCH_SOURCE_TYPES = new Set([
    'vault-archive',
    'vault-directory',
    ...HOST_LAUNCH_SOURCE_TYPES
])

export const LAUNCH_METHODS = new Set([
    'spawn',
    'shell-execute',
    'protocol',
    'packaged-app',
    'unknown'
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

function normalizeString(value, fieldName, {
    required = false,
    max = MAX_STRING_LENGTH,
    allowEmpty = false
} = {}) {
    if (value == null) {
        if (required) fail(`${fieldName} is required.`)
        return ''
    }
    if (typeof value !== 'string') fail(`${fieldName} must be a string.`)
    if (value.includes('\0')) fail(`${fieldName} contains an invalid null byte.`)
    const trimmed = value.trim()
    if (required && !trimmed) fail(`${fieldName} is required.`)
    if (!allowEmpty && value.length > 0 && !trimmed) fail(`${fieldName} cannot be blank.`)
    if (trimmed.length > max) fail(`${fieldName} is too long.`)
    return trimmed
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

function normalizeNumber(value, fieldName, defaultValue = 0) {
    if (value == null || value === '') return defaultValue
    if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
        fail(`${fieldName} must be a non-negative number.`)
    }
    return value
}

function hasTraversalSegment(value) {
    return String(value || '')
        .split(/[\\/]+/)
        .some(part => part === '..')
}

function normalizeRelativePath(value, fieldName, { required = false } = {}) {
    const relPath = normalizeString(value, fieldName, { required, max: MAX_STRING_LENGTH })
    if (!relPath) return ''
    if (relPath.includes(':') || isAbsolute(relPath) || relPath.startsWith('\\\\')) {
        fail(`${fieldName} must be a relative path.`)
    }
    if (hasTraversalSegment(relPath)) fail(`${fieldName} cannot contain parent-directory traversal.`)
    return normalize(relPath)
}

function isAbsoluteFilesystemPath(value) {
    return isAbsolute(value) || win32.isAbsolute(value)
}

function isUncPath(value) {
    return String(value || '').startsWith('\\\\')
}

function normalizeAbsolutePath(value, fieldName, { required = false, allowUnc = false } = {}) {
    const pathValue = normalizeString(value, fieldName, { required, max: MAX_STRING_LENGTH })
    if (!pathValue) return ''
    if (!isAbsoluteFilesystemPath(pathValue)) fail(`${fieldName} must be an absolute filesystem path.`)
    if (!allowUnc && isUncPath(pathValue)) fail(`${fieldName} cannot be a network/UNC path.`)
    if (hasTraversalSegment(pathValue)) fail(`${fieldName} cannot contain parent-directory traversal.`)
    return pathValue
}

function normalizeLaunchPath(value, fieldName = 'path') {
    const pathValue = normalizeString(value, fieldName, { required: true, max: MAX_STRING_LENGTH })
    if (pathValue.startsWith('[USB]')) {
        const rest = pathValue.slice('[USB]'.length)
        if (!rest.startsWith('\\') && !rest.startsWith('/')) {
            fail(`${fieldName} uses an invalid [USB] macro path.`)
        }
        if (hasTraversalSegment(rest)) fail(`${fieldName} cannot contain parent-directory traversal.`)
        return pathValue
    }

    if (/^shell:AppsFolder\\/i.test(pathValue)) return pathValue
    if (/^[a-z][a-z0-9+.-]{1,39}:$/i.test(pathValue)) return pathValue
    if (/^[a-z][a-z0-9+.-]{1,39}:\/\//i.test(pathValue)) return pathValue

    if (pathValue.startsWith('\\\\')) fail(`${fieldName} cannot be a network/UNC path.`)
    if (/^[a-zA-Z]:[\\/]/.test(pathValue)) return pathValue

    // Folder launches and legacy saved records can be relative only if they are
    // explicit shell/protocol references. Anything else becomes ambiguous fast.
    fail(`${fieldName} must be an absolute path, [USB] path, protocol URI, or packaged app activation path.`)
}

function normalizeDisplayName(value, fieldName = 'name') {
    const name = normalizeString(value, fieldName, { required: true, max: MAX_NAME_LENGTH })
    if (/[\r\n\t]/.test(name)) fail(`${fieldName} cannot contain control whitespace.`)
    return name
}

function normalizeLaunchSourceType(value) {
    if (value == null || value === '') return null
    const sourceType = normalizeString(value, 'launchSourceType', { max: 80 })
    if (!LAUNCH_SOURCE_TYPES.has(sourceType)) fail(`Unsupported launchSourceType: ${sourceType}`)
    return sourceType
}

function normalizeLaunchMethod(value) {
    if (value == null || value === '') return null
    const method = normalizeString(value, 'launchMethod', { max: 80 })
    if (!LAUNCH_METHODS.has(method)) fail(`Unsupported launchMethod: ${method}`)
    return method
}

function isExecutablePath(value) {
    return /\.(?:exe|bat|cmd)$/i.test(String(value || '').trim())
}

function getUriScheme(value) {
    const match = String(value || '').trim().match(/^([a-z][a-z0-9+.-]*):/i)
    return match ? match[1].toLowerCase() : ''
}

function normalizeId(value, fieldName = 'id') {
    if (value == null || value === '') return undefined
    if (typeof value === 'number') {
        if (!Number.isSafeInteger(value) || value < 0) fail(`${fieldName} must be a safe non-negative integer.`)
        return value
    }
    return normalizeString(value, fieldName, { max: 128 })
}

function validateBrowserUrl(value, fieldName) {
    const url = normalizeString(value, fieldName, { required: true, max: 2048 })
    if (/\s/.test(url)) fail(`${fieldName} cannot contain whitespace.`)

    const looksLikeHostPort = /^[^:/?#]+:\d{1,5}(?:[/?#].*)?$/i.test(url)
    const explicitScheme = url.match(/^([a-z][a-z0-9+.-]*):/i)
    if (explicitScheme && !/^https?:\/\//i.test(url) && !looksLikeHostPort) {
        fail(`${fieldName} must use http or https.`)
    }

    const candidate = /^https?:\/\//i.test(url) ? url : `https://${url}`
    let parsed
    try {
        parsed = new URL(candidate)
    } catch (_) {
        fail(`${fieldName} must be a valid web URL.`)
    }

    if (!['http:', 'https:'].includes(parsed.protocol)) fail(`${fieldName} must use http or https.`)
    if (parsed.username || parsed.password) fail(`${fieldName} cannot include username or password credentials.`)
    const hostname = parsed.hostname.toLowerCase()
    const isLocalhost = hostname === 'localhost'
    const isIpv4 = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname)
    const isIpv6 = hostname.includes(':')
    if (isIpv4) {
        const octets = hostname.split('.').map(part => Number(part))
        if (octets.some(octet => !Number.isInteger(octet) || octet < 0 || octet > 255)) {
            fail(`${fieldName} must include a valid IPv4 address.`)
        }
    }
    if (!hostname || (!isLocalhost && !isIpv4 && !isIpv6 && !hostname.includes('.'))) {
        fail(`${fieldName} must include a valid host name.`)
    }

    return parsed.href
}

function defaultLaunchSourceForPath(pathValue) {
    const kind = describePathKind(pathValue)
    if (kind === 'usb-macro') return 'vault-archive'
    if (kind === 'packaged-app') return 'packaged-app'
    if (kind === 'protocol') return 'protocol-uri'
    if (kind === 'absolute') return 'host-exe'
    return null
}

function defaultLaunchMethodForSource(sourceType) {
    if (sourceType === 'protocol-uri') return 'protocol'
    if (sourceType === 'packaged-app') return 'packaged-app'
    if (sourceType === 'shell-execute' || sourceType === 'host-folder') return 'shell-execute'
    return 'spawn'
}

function validateLaunchContract(pathValue, sourceType, launchMethod, fieldPrefix) {
    const kind = describePathKind(pathValue)
    if (kind === 'unc') fail(`${fieldPrefix}.path cannot be a network/UNC path.`)

    if (sourceType === 'vault-archive' || sourceType === 'vault-directory') {
        if (kind !== 'usb-macro') fail(`${fieldPrefix}.path must be a [USB] app path for ${sourceType}.`)
        if (launchMethod !== 'spawn') fail(`${fieldPrefix}.launchMethod must be spawn for ${sourceType}.`)
        return
    }

    if (sourceType === 'host-exe') {
        if (kind !== 'absolute') fail(`${fieldPrefix}.path must be an absolute local executable path for host-exe.`)
        if (!isExecutablePath(pathValue)) fail(`${fieldPrefix}.path must be a direct executable for host-exe.`)
        if (launchMethod !== 'spawn') fail(`${fieldPrefix}.launchMethod must be spawn for host-exe.`)
        return
    }

    if (['registry-uninstall', 'app-paths', 'start-menu-shortcut'].includes(sourceType)) {
        if (kind !== 'absolute') fail(`${fieldPrefix}.path must be an absolute local path for ${sourceType}.`)
        if (launchMethod !== 'spawn') fail(`${fieldPrefix}.launchMethod must be spawn for ${sourceType}.`)
        return
    }

    if (sourceType === 'host-folder') {
        if (kind !== 'absolute') fail(`${fieldPrefix}.path must be an absolute local folder path for host-folder.`)
        if (isExecutablePath(pathValue)) fail(`${fieldPrefix}.path cannot be a direct executable for host-folder.`)
        if (launchMethod !== 'shell-execute') fail(`${fieldPrefix}.launchMethod must be shell-execute for host-folder.`)
        return
    }

    if (sourceType === 'shell-execute') {
        if (kind !== 'absolute') fail(`${fieldPrefix}.path must be an absolute local path for shell-execute.`)
        if (isExecutablePath(pathValue)) fail(`${fieldPrefix}.path cannot be a direct executable for shell-execute.`)
        if (launchMethod !== 'shell-execute') fail(`${fieldPrefix}.launchMethod must be shell-execute for shell-execute.`)
        return
    }

    if (sourceType === 'protocol-uri') {
        if (kind !== 'protocol') fail(`${fieldPrefix}.path must be a protocol URI for protocol-uri.`)
        if (launchMethod !== 'protocol') fail(`${fieldPrefix}.launchMethod must be protocol for protocol-uri.`)
        return
    }

    if (sourceType === 'packaged-app') {
        if (kind !== 'packaged-app') fail(`${fieldPrefix}.path must be a shell:AppsFolder activation path for packaged-app.`)
        if (launchMethod !== 'packaged-app') fail(`${fieldPrefix}.launchMethod must be packaged-app for packaged-app.`)
    }
}

function normalizeArgs(value, fieldName) {
    if (Array.isArray(value)) {
        if (value.length > MAX_ARGS) fail(`${fieldName} cannot contain more than ${MAX_ARGS} arguments.`)
        return value.map((arg, argIndex) => normalizeString(arg, `${fieldName}[${argIndex}]`, { max: MAX_ARGS_LENGTH }))
    }
    return normalizeOptionalString(value, fieldName, { max: MAX_ARGS_LENGTH })
}

function includeDefined(target, key, value) {
    if (value !== undefined && value !== null && value !== '') target[key] = value
}

function copyOptionalString(target, source, key, fieldPrefix, max = MAX_STRING_LENGTH) {
    const value = normalizeOptionalString(source[key], `${fieldPrefix}.${key}`, { max })
    if (value) target[key] = value
}

function copyReferenceFields(target, source, sourceType, fieldPrefix) {
    if (sourceType === 'registry-uninstall') {
        for (const key of ['registryKey', 'registryDisplayName', 'registryInstallLocation', 'registryDisplayIcon']) {
            copyOptionalString(target, source, key, fieldPrefix)
        }
    } else if (sourceType === 'app-paths') {
        for (const key of ['appPathsKey', 'appPathsExecutableName', 'appPathsPathValue']) {
            copyOptionalString(target, source, key, fieldPrefix)
        }
    } else if (sourceType === 'start-menu-shortcut' || sourceType === 'shell-execute') {
        for (const key of ['shortcutPath', 'shortcutTargetPath', 'shortcutArguments', 'shortcutWorkingDirectory', 'shortcutIconLocation']) {
            copyOptionalString(target, source, key, fieldPrefix)
        }
    } else if (sourceType === 'host-folder') {
        return
    } else if (sourceType === 'protocol-uri') {
        for (const key of ['protocolScheme', 'protocolCommand', 'protocolRegistryKey']) {
            copyOptionalString(target, source, key, fieldPrefix)
        }
        const pathScheme = getUriScheme(target.path)
        if (target.protocolScheme) {
            if (pathScheme && pathScheme !== target.protocolScheme.toLowerCase()) {
                fail(`${fieldPrefix}.protocolScheme must match the URI scheme in ${fieldPrefix}.path.`)
            }
            target.protocolScheme = target.protocolScheme.toLowerCase()
        } else if (pathScheme) {
            target.protocolScheme = pathScheme
        }
    } else if (sourceType === 'packaged-app') {
        copyOptionalString(target, source, 'packagedAppId', fieldPrefix)
    } else {
        copyOptionalString(target, source, 'manifestId', fieldPrefix, 160)
    }
}

export function getCanonicalAppStorageId(name) {
    const displayName = normalizeDisplayName(name)
    const storageId = safeAppName(displayName)
    if (!storageId || storageId === 'App') fail('App name does not produce a valid storage id.')
    return storageId
}

export function getCanonicalArchiveName(name) {
    return `${getCanonicalAppStorageId(name)}.tar.zst`
}

export function createAvailableAppStorageId(name, isTaken = () => false) {
    const baseId = getCanonicalAppStorageId(name)
    if (!isTaken(baseId)) return baseId

    for (let suffix = 2; suffix < 1000; suffix += 1) {
        const candidate = `${baseId}-${suffix}`
        if (!isTaken(candidate)) return candidate
    }

    fail('Unable to allocate a unique app storage id.')
}

export function validatePinInput(value, { allowNull = true } = {}) {
    if (value == null || value === '') {
        if (allowNull) return null
        fail('PIN is required.')
    }
    const pin = normalizeString(value, 'PIN', { required: true, max: 16 })
    if (!/^\d{4}$/.test(pin)) fail('PIN must be exactly 4 digits.')
    return pin
}

export function validatePasswordInput(value, fieldName = 'masterPassword') {
    const password = normalizeString(value, fieldName, { required: true, max: MAX_STRING_LENGTH })
    if (password.length < 8) fail(`${fieldName} must be at least 8 characters.`)
    return password
}

export function validateBooleanInput(value, fieldName) {
    return normalizeBoolean(value, fieldName)
}

export function validateFactoryResetInput(value, { expectedToken } = {}) {
    const payload = requireObject(value, 'factory-reset payload')
    const token = normalizeString(payload.token, 'factory reset token', { required: true, max: 128 })
    if (!RESET_TOKEN_PATTERN.test(token)) fail('Factory reset token is invalid.')
    if (expectedToken && token !== expectedToken) fail('Factory reset token is invalid or expired.')
    return { token }
}

export function validateWorkspaceInput(value) {
    const workspace = requireObject(value || {}, 'workspace')
    const webTabs = Array.isArray(workspace.webTabs) ? workspace.webTabs : []
    const desktopApps = Array.isArray(workspace.desktopApps) ? workspace.desktopApps : []

    if (webTabs.length > MAX_TABS) fail(`workspace.webTabs cannot contain more than ${MAX_TABS} items.`)
    if (desktopApps.length > MAX_APPS) fail(`workspace.desktopApps cannot contain more than ${MAX_APPS} items.`)

    const next = {
        webTabs: webTabs.map(validateWebTabInput),
        desktopApps: desktopApps.map(validateDesktopAppInput)
    }
    copyOptionalString(next, workspace, 'name', 'workspace', MAX_NAME_LENGTH)
    return next
}

export function validateWebTabInput(tab, index = 0) {
    const value = requireObject(tab, `workspace.webTabs[${index}]`)
    const fieldPrefix = `workspace.webTabs[${index}]`
    const id = normalizeId(value.id, `${fieldPrefix}.id`)
    const next = {
        url: validateBrowserUrl(value.url, `${fieldPrefix}.url`),
        enabled: normalizeBoolean(value.enabled, `workspace.webTabs[${index}].enabled`, true)
    }
    includeDefined(next, 'id', id)
    return next
}

export function validateDesktopAppInput(appConfig, index = 0) {
    const value = requireObject(appConfig, `workspace.desktopApps[${index}]`)
    const fieldPrefix = `workspace.desktopApps[${index}]`
    const name = normalizeDisplayName(value.name, `${fieldPrefix}.name`)
    const path = normalizeLaunchPath(value.path, `${fieldPrefix}.path`)
    const launchSourceType = normalizeLaunchSourceType(value.launchSourceType) || defaultLaunchSourceForPath(path)
    if (!launchSourceType) fail(`${fieldPrefix}.launchSourceType is required for this path.`)
    const launchMethod = normalizeLaunchMethod(value.launchMethod) || defaultLaunchMethodForSource(launchSourceType)
    validateLaunchContract(path, launchSourceType, launchMethod, fieldPrefix)

    const id = normalizeId(value.id, `${fieldPrefix}.id`)
    const next = {
        name,
        path,
        args: normalizeArgs(value.args, `${fieldPrefix}.args`),
        portableData: normalizeBoolean(value.portableData, `workspace.desktopApps[${index}].portableData`, false),
        enabled: normalizeBoolean(value.enabled, `workspace.desktopApps[${index}].enabled`, true),
        launchSourceType,
        launchMethod
    }

    includeDefined(next, 'id', id)
    copyOptionalString(next, value, 'launchCapabilityId', fieldPrefix, 96)
    copyReferenceFields(next, value, launchSourceType, fieldPrefix)
    return next
}

export function validateSaveVaultInput(value) {
    const payload = requireObject(value, 'save-vault payload')
    return {
        masterPassword: validatePasswordInput(payload.masterPassword),
        currentPassword: payload.currentPassword ? validatePasswordInput(payload.currentPassword, 'currentPassword') : '',
        pin: validatePinInput(payload.pin),
        fastBoot: normalizeBoolean(payload.fastBoot, 'fastBoot', false),
        hiddenMaster: normalizeBoolean(payload.hiddenMaster, 'hiddenMaster', false),
        workspace: validateWorkspaceInput(payload.workspace || {})
    }
}

export function validateImportAppInput(value) {
    const payload = requireObject(value, 'import-app payload')
    const name = normalizeDisplayName(payload.name)
    return {
        sourcePath: normalizeAbsolutePath(payload.sourcePath, 'sourcePath', { required: true }),
        name,
        exe: normalizeOptionalString(payload.exe, 'exe', { max: 260 }),
        relativeExePath: normalizeRelativePath(payload.relativeExePath || payload.exe, 'relativeExePath', { required: true }),
        importData: normalizeBoolean(payload.importData, 'importData', false),
        dataPath: normalizeAbsolutePath(payload.dataPath, 'dataPath'),
        sizeMB: normalizeNumber(payload.sizeMB, 'sizeMB'),
        dataSizeMB: normalizeNumber(payload.dataSizeMB, 'dataSizeMB'),
        storageId: getCanonicalAppStorageId(name),
        archiveName: getCanonicalArchiveName(name)
    }
}

export function validatePayloadIdsInput(value) {
    const payload = requireObject(value || {}, 'cleanup-stale-appdata payload')
    if (!Array.isArray(payload.payloadIds) || payload.payloadIds.length === 0) {
        fail('Select at least one AppData payload to remove.')
    }
    if (payload.payloadIds.length > MAX_PAYLOAD_IDS) fail(`Cannot remove more than ${MAX_PAYLOAD_IDS} payloads at once.`)
    const payloadIds = payload.payloadIds.map((id, index) => {
        const normalized = normalizeString(id, `payloadIds[${index}]`, { required: true, max: 64 })
        if (!/^[a-f0-9]{16}$/i.test(normalized)) fail(`payloadIds[${index}] is not a valid payload id.`)
        return normalized
    })
    return { payloadIds }
}

export function validateCaptureSessionInput(value) {
    const payload = value == null ? {} : requireObject(value, 'capture-session payload')
    return {
        masterPassword: payload.masterPassword
            ? validatePasswordInput(payload.masterPassword)
            : ''
    }
}

export function validateQuitOptions(value) {
    const payload = value == null ? {} : requireObject(value, 'quit-and-relaunch options')
    return {
        closeApps: normalizeBoolean(payload.closeApps, 'closeApps', false)
    }
}

export function describePathKind(pathValue) {
    const value = String(pathValue || '')
    if (value.startsWith('[USB]')) return 'usb-macro'
    if (/^shell:AppsFolder\\/i.test(value)) return 'packaged-app'
    if (/^[a-z][a-z0-9+.-]{1,39}:$/i.test(value)) return 'protocol'
    if (/^[a-z][a-z0-9+.-]{1,39}:\/\//i.test(value)) return 'protocol'
    if (value.startsWith('\\\\')) return 'unc'
    if (pathParse(value).root) return 'absolute'
    return 'unknown'
}

import { createReadStream, existsSync, readdirSync, readFileSync, statSync, writeFileSync } from 'fs'
import { join, relative, resolve, basename, extname } from 'path'
import { execFileSync } from 'child_process'
import crypto from 'crypto'
import { resolveAppCapability, SUPPORT_TIERS } from './appAdapters.js'

export const APP_MANIFEST_SCHEMA_VERSION = 2
export const BINARY_ARCHIVE_POLICY_VERSION = 2

export const ADAPTER_EVIDENCE_LEVELS = Object.freeze({
    FAMILY_VERIFIED: 'family-verified',
    APP_CERTIFIED: 'app-certified',
    EXPERIMENTAL: 'experimental',
    NONE: 'none'
})

export const LAUNCH_SOURCE_TYPES = Object.freeze({
    VAULT_ARCHIVE: 'vault-archive',
    VAULT_DIRECTORY: 'vault-directory',
    HOST_EXE: 'host-exe',
    REGISTRY_UNINSTALL: 'registry-uninstall',
    APP_PATHS: 'app-paths',
    START_MENU_SHORTCUT: 'start-menu-shortcut',
    SHELL_EXECUTE: 'shell-execute',
    PROTOCOL_URI: 'protocol-uri',
    PACKAGED_APP: 'packaged-app'
})

export const LAUNCH_METHODS = Object.freeze({
    SPAWN: 'spawn',
    SHELL_EXECUTE: 'shell-execute',
    PROTOCOL: 'protocol',
    PACKAGED_APP: 'packaged-app',
    UNKNOWN: 'unknown'
})

export const OWNERSHIP_PROOF_LEVELS = Object.freeze({
    STRONG: 'strong',
    MEDIUM: 'medium',
    WEAK: 'weak',
    NONE: 'none'
})

export const CLOSE_POLICIES = Object.freeze({
    NEVER: 'never',
    OWNED_PROCESS_ONLY: 'owned-process-only',
    OWNED_TREE: 'owned-tree',
    ADAPTER_DEFINED: 'adapter-defined'
})

export const DATA_MANAGEMENT_LEVELS = Object.freeze({
    MANAGED: 'managed',
    UNMANAGED: 'unmanaged',
    UNSUPPORTED: 'unsupported'
})

export const SUPPORT_FIELD_NAMES = Object.freeze([
    'supportTier',
    'supportSummary',
    'adapterEvidence',
    'launchSourceType',
    'launchMethod',
    'ownershipProofLevel',
    'closePolicy',
    'canQuitFromOmniLaunch',
    'availabilityStatus',
    'dataManagement',
    'requiresElevation',
    'resolvedAt',
    'resolvedHostId',
    'launchAdapter',
    'runtimeAdapter',
    'dataAdapters',
    'registryAdapters',
    'limitations',
    'certification',
    'importedDataSupported',
    'importedDataSupportLevel',
    'importedDataAdapterId',
    'importedDataSupportReason'
])

export const APPDATA_SKIP_DIRS = new Set([
    'CachedData', 'Cache', 'Code Cache', 'GPUCache',
    'GrShaderCache', 'ShaderCache', 'DawnWebGPUCache',
    'DawnGraphiteCache', 'Service Worker', 'ScriptCache',
    'Crashpad', 'logs', 'blob_storage',
    'component_crx_cache', 'extensions_crx_cache',
    'Safe Browsing', 'WasmTtsEngine', 'BrowserMetrics',
    'optimization_guide_model_store', 'OnDeviceHeadSuggestModel',
    'MediaFoundationWidevineCdm'
])

// Binary archives must preserve application runtime payloads. Keep this list
// conservative; broad AppData cleanup names like "logs" are valid code folders.
export const BINARY_ARCHIVE_EXCLUDE_DIRS = new Set([])
export const BINARY_ARCHIVE_EXCLUDE_FILES = new Set([
    'unins000.exe',
    'unins000.dat',
    'unins000.msg'
])

const DANGEROUS_DIR_NAMES = new Set([
    'uninst',
    'uninstall',
    'uninstaller',
    'install',
    'installer',
    'installers',
    'update',
    'updates',
    'updater',
    'crashpad'
])

const DANGEROUS_EXE_PATTERNS = [
    /^unins\d*\.exe$/i,
    /^uninstall(er)?\.exe$/i,
    /^uninstall/i,
    /^setup/i,
    /^install(er)?/i,
    /^update(r)?/i,
    /(^|[-_])update(r)?([-_]|\.|$)/i,
    /^old_/i,
    /crash/i,
    /^createdump\.exe$/i,
    /^dump/i,
    /helper/i,
    /restartagent/i
]

const KNOWN_REQUIRED_FILE_RELATIONS = [
    {
        anchor: 'resources/app/node_modules/@sentry/core/build/esm/index.js',
        requires: ['resources/app/node_modules/@sentry/core/build/esm/logs/internal.js']
    },
    {
        anchor: 'resources/app/node_modules/@sentry/core/build/cjs/index.js',
        requires: ['resources/app/node_modules/@sentry/core/build/cjs/logs/internal.js']
    },
    {
        anchor: 'resources/app/node_modules/@opentelemetry/otlp-transformer/build/esm/logs/index.js',
        requires: ['resources/app/node_modules/@opentelemetry/otlp-transformer/build/esm/logs/internal.js']
    },
    {
        anchor: 'resources/app/node_modules/@opentelemetry/otlp-transformer/build/esnext/logs/index.js',
        requires: ['resources/app/node_modules/@opentelemetry/otlp-transformer/build/esnext/logs/internal.js']
    },
    {
        anchor: 'resources/app/node_modules/@opentelemetry/otlp-transformer/build/src/logs/index.js',
        requires: ['resources/app/node_modules/@opentelemetry/otlp-transformer/build/src/logs/internal.js']
    }
]

export function safeAppName(name) {
    return String(name || 'App').replace(/[^a-zA-Z0-9_-]/g, '_')
}

function normalizeSlashes(value) {
    return String(value || '').replace(/\\/g, '/').replace(/^\/+/, '')
}

function toLowerSlash(value) {
    return normalizeSlashes(value).toLowerCase()
}

function stripArchiveRoot(entry, archiveRoot) {
    const normalized = normalizeSlashes(entry)
    if (!archiveRoot) return normalized
    const root = normalizeSlashes(archiveRoot)
    if (normalized.toLowerCase() === root.toLowerCase()) return ''
    if (normalized.toLowerCase().startsWith(`${root.toLowerCase()}/`)) {
        return normalized.slice(root.length + 1)
    }
    return normalized
}

function windowsRel(value) {
    return normalizeSlashes(value).replace(/\//g, '\\')
}

function fileExistsCaseInsensitive(rootDir, relativePath) {
    return existsSync(join(rootDir, ...normalizeSlashes(relativePath).split('/')))
}

function getPathSegments(value) {
    return normalizeSlashes(value)
        .split('/')
        .filter(Boolean)
        .map(part => part.toLowerCase())
}

export function isDangerousExecutablePath(exePath) {
    if (!exePath) return true
    const normalized = normalizeSlashes(exePath)
    const base = basename(normalized).toLowerCase()
    if (extname(base).toLowerCase() !== '.exe') return false
    if (DANGEROUS_EXE_PATTERNS.some(pattern => pattern.test(base))) return true

    const segments = getPathSegments(normalized).slice(0, -1)
    return segments.some(segment => DANGEROUS_DIR_NAMES.has(segment))
}

export function extractExeFromCommand(value) {
    if (!value) return null
    const match = String(value).match(/([a-zA-Z]:\\[^"*?<>|]+\.exe)/i)
    return match ? match[1] : null
}

function buildNameAliases(appName) {
    const raw = String(appName || '').trim().toLowerCase()
    const compact = raw.replace(/[^a-z0-9]/g, '')
    const aliases = new Set([raw, compact])

    if (raw.includes('microsoft edge')) aliases.add('msedge')
    if (raw.includes('google chrome')) aliases.add('chrome')
    if (raw.includes('obs')) {
        aliases.add('obs')
        aliases.add('obs64')
        aliases.add('obs32')
    }
    if (raw.includes('rstudio')) aliases.add('rstudio')
    if (raw.includes('swi') || raw.includes('prolog')) {
        aliases.add('swipl-win')
        aliases.add('swipl')
    }
    if (raw.includes('epic') && raw.includes('pen')) aliases.add('epicpen')
    if (raw.includes('visual studio code')) aliases.add('code')
    if (raw.includes('cursor')) aliases.add('cursor')
    if (raw.includes('slack')) aliases.add('slack')
    if (raw.includes('notion')) aliases.add('notion')

    return [...aliases].filter(Boolean)
}

function scoreCandidate(candidate, appName, rootDir) {
    const aliases = buildNameAliases(appName)
    const relSlash = normalizeSlashes(candidate.relativePath)
    const relLower = relSlash.toLowerCase()
    const base = basename(relSlash)
    const baseNoExt = base.replace(/\.exe$/i, '').toLowerCase()
    const baseCompact = baseNoExt.replace(/[^a-z0-9]/g, '')
    const segments = getPathSegments(relSlash)
    const depth = Math.max(0, segments.length - 1)
    const reasons = []

    if (candidate.dangerous) {
        return { score: -10000, reasons: ['dangerous-executable'] }
    }

    let score = 0
    if (candidate.source && candidate.source !== 'scan') {
        score += 35
        reasons.push(`source:${candidate.source}`)
    }

    for (const alias of aliases) {
        const compactAlias = alias.replace(/[^a-z0-9]/g, '')
        if (baseNoExt === alias || baseCompact === compactAlias) {
            score += 90
            reasons.push('name-exact')
            break
        }
        if (baseCompact.includes(compactAlias) || compactAlias.includes(baseCompact)) {
            score += 45
            reasons.push('name-close')
            break
        }
    }

    if (depth === 0) {
        score += 25
        reasons.push('top-level')
    } else if (depth <= 2) {
        score += 12
        reasons.push('shallow')
    }

    if (segments.includes('bin')) {
        score += 10
        reasons.push('bin-folder')
    }
    if (segments.some(part => /^\d+\./.test(part))) {
        score += 8
        reasons.push('version-folder')
    }

    if (/helper|agent|stub|broker|service|crash|dump|update/i.test(baseNoExt)) {
        score -= 40
        reasons.push('helper-penalty')
    }

    if (candidate.sizeBytes) {
        score += Math.min(20, Math.floor(candidate.sizeBytes / (1024 * 1024)))
        reasons.push('has-size')
    }

    if (rootDir) {
        try {
            const rootBase = basename(rootDir).toLowerCase().replace(/[^a-z0-9]/g, '')
            if (rootBase && baseCompact === rootBase) {
                score += 35
                reasons.push('root-name-match')
            }
        } catch (_) { }
    }

    return { score, reasons }
}

function confidenceForScore(score) {
    if (score >= 95) return 'high'
    if (score >= 55) return 'medium'
    return 'low'
}

function addCandidate(map, candidate) {
    if (!candidate?.relativePath) return
    const key = toLowerSlash(candidate.relativePath)
    const existing = map.get(key)
    if (!existing || (candidate.source && existing.source === 'scan')) {
        map.set(key, candidate)
    }
}

function collectExeCandidatesFromDirectory(rootDir, appName, seedCandidates = []) {
    const root = resolve(rootDir)
    const candidateMap = new Map()
    const maxDepth = 6
    const maxCandidates = 500
    const stack = [{ dir: root, depth: 0 }]

    for (const seed of seedCandidates) {
        const seedPath = seed?.path ? resolve(seed.path) : null
        if (!seedPath || !seedPath.toLowerCase().startsWith(root.toLowerCase())) continue
        if (!seedPath.toLowerCase().endsWith('.exe')) continue
        const rel = relative(root, seedPath)
        addCandidate(candidateMap, {
            path: seedPath,
            relativePath: rel,
            source: seed.source || 'seed',
            sizeBytes: existsSync(seedPath) ? safeStatSize(seedPath) : 0,
            dangerous: isDangerousExecutablePath(rel)
        })
    }

    while (stack.length > 0 && candidateMap.size < maxCandidates) {
        const current = stack.pop()
        let entries = []
        try {
            entries = readdirSync(current.dir, { withFileTypes: true })
        } catch (_) {
            continue
        }

        for (const entry of entries) {
            const fullPath = join(current.dir, entry.name)
            if (entry.isDirectory()) {
                if (current.depth < maxDepth) stack.push({ dir: fullPath, depth: current.depth + 1 })
                continue
            }
            if (!entry.isFile() || !entry.name.toLowerCase().endsWith('.exe')) continue
            const rel = relative(root, fullPath)
            addCandidate(candidateMap, {
                path: fullPath,
                relativePath: rel,
                source: 'scan',
                sizeBytes: safeStatSize(fullPath),
                dangerous: isDangerousExecutablePath(rel)
            })
        }
    }

    return finalizeCandidateSelection([...candidateMap.values()], appName, root)
}

function safeStatSize(filePath) {
    try { return statSync(filePath).size } catch (_) { return 0 }
}

function finalizeCandidateSelection(candidates, appName, rootDir = '') {
    const scored = candidates.map(candidate => {
        const scoredCandidate = { ...candidate }
        const scoring = scoreCandidate(scoredCandidate, appName, rootDir)
        scoredCandidate.score = scoring.score
        scoredCandidate.confidence = confidenceForScore(scoring.score)
        scoredCandidate.reasons = scoring.reasons
        scoredCandidate.relativePath = windowsRel(scoredCandidate.relativePath)
        return scoredCandidate
    }).sort((a, b) => b.score - a.score)

    const selected = scored.find(candidate => !candidate.dangerous && candidate.score > 0) || null
    return {
        selected,
        candidates: scored.slice(0, 25),
        confidence: selected?.confidence || 'none'
    }
}

export function selectBestExecutable(rootDir, appName, seedCandidates = []) {
    if (!rootDir || !existsSync(rootDir)) {
        return { selected: null, candidates: [], confidence: 'none' }
    }
    return collectExeCandidatesFromDirectory(rootDir, appName, seedCandidates)
}

export function inferArchiveRoot(entries) {
    const first = entries.map(normalizeSlashes).find(Boolean)
    return first ? first.split('/')[0] : ''
}

export function selectBestExecutableFromArchiveEntries(entries, appName, seedRelativePath = '') {
    const archiveRoot = inferArchiveRoot(entries)
    const candidateMap = new Map()
    const normalizedSeed = toLowerSlash(seedRelativePath)

    for (const entry of entries) {
        const stripped = stripArchiveRoot(entry, archiveRoot)
        if (!stripped.toLowerCase().endsWith('.exe')) continue
        addCandidate(candidateMap, {
            path: null,
            relativePath: stripped,
            source: toLowerSlash(stripped) === normalizedSeed ? 'legacy-path' : 'archive',
            sizeBytes: 0,
            dangerous: isDangerousExecutablePath(stripped)
        })
    }

    return {
        archiveRoot,
        ...finalizeCandidateSelection([...candidateMap.values()], appName, archiveRoot)
    }
}

export function inferAppType(rootDir) {
    try {
        const rootName = basename(rootDir || '').toLowerCase()
        if (rootName.includes('edge') && fileExistsCaseInsensitive(rootDir, 'msedge.exe')) return 'chromium'
        if (existsSync(join(rootDir, 'resources', 'app', 'product.json'))) return 'vscode-family'
        if (existsSync(join(rootDir, 'resources', 'app.asar')) || existsSync(join(rootDir, 'resources', 'app'))) return 'electron'
        if (existsSync(join(rootDir, 'locales')) && existsSync(join(rootDir, 'resources'))) return 'electron'
        const subs = readdirSync(rootDir, { withFileTypes: true }).filter(d => d.isDirectory())
        for (const sub of subs) {
            if (/^\d+\./.test(sub.name) && existsSync(join(rootDir, sub.name, 'chrome.dll'))) return 'chromium'
            if (/^\d+\./.test(sub.name) && (
                existsSync(join(rootDir, sub.name, 'msedge.exe')) ||
                existsSync(join(rootDir, sub.name, 'msedge.dll')) ||
                existsSync(join(rootDir, sub.name, 'chrome_elf.dll')) ||
                existsSync(join(rootDir, sub.name, 'resources.pak'))
            )) return 'chromium'
            if (existsSync(join(rootDir, sub.name, 'resources', 'app.asar')) ||
                existsSync(join(rootDir, sub.name, 'resources', 'app'))) return 'electron'
        }
    } catch (_) { }
    return 'native'
}

export function inferProfiles(appType, appName) {
    const lowerName = String(appName || '').toLowerCase()
    let launchProfile = 'native-windowed'
    let dataMode = 'none'

    if (lowerName.includes('microsoft edge') || lowerName === 'edge') {
        launchProfile = 'chromium-browser'
        dataMode = 'chromium-user-data'
    } else if (appType === 'vscode-family' || lowerName.includes('cursor') || lowerName.includes('visual studio code')) {
        launchProfile = 'vscode-family'
        dataMode = 'vscode-user-data'
    } else if (appType === 'chromium') {
        launchProfile = 'chromium-browser'
        dataMode = 'chromium-user-data'
    } else if (appType === 'electron') {
        launchProfile = 'electron-standard'
        dataMode = 'electron-user-data'
    } else if (lowerName.includes('swi') || lowerName.includes('prolog')) {
        launchProfile = 'runtime-gui'
    }

    return {
        launchProfile,
        dataProfile: { mode: dataMode },
        readinessProfile: {
            mode: launchProfile === 'background-process' ? 'process' : 'visible-window',
            timeoutMs: launchProfile === 'vscode-family' ? 20000 : 15000
        }
    }
}

export const IMPORTED_APPDATA_SUPPORT_LEVELS = Object.freeze({
    VERIFIED: 'verified',
    UNSUPPORTED: 'unsupported'
})

export function resolveImportedAppDataCapability({
    appType,
    appName,
    launchProfile,
    dataProfile
} = {}) {
    const inferred = inferProfiles(appType || 'native', appName || '')
    const capability = resolveAppCapability({
        appType,
        appName,
        launchProfile: launchProfile || inferred.launchProfile,
        dataProfile: dataProfile || inferred.dataProfile
    })

    return {
        importedDataSupported: capability.importedDataSupported,
        importedDataSupportLevel: capability.importedDataSupportLevel,
        importedDataAdapterId: capability.importedDataAdapterId,
        importedDataSupportReason: capability.importedDataSupportReason
    }
}

export function resolveManifestDataProfile(appType, appName, importData) {
    const profiles = inferProfiles(appType, appName)
    if (profiles.launchProfile === 'chromium-browser') return profiles.dataProfile

    const capability = resolveImportedAppDataCapability({
        appType,
        appName,
        launchProfile: profiles.launchProfile,
        dataProfile: profiles.dataProfile
    })

    return importData && capability.importedDataSupported
        ? profiles.dataProfile
        : { mode: 'none' }
}

function defaultAdapterEvidence(supportTier) {
    if (supportTier === SUPPORT_TIERS.VERIFIED) return ADAPTER_EVIDENCE_LEVELS.FAMILY_VERIFIED
    if (supportTier === SUPPORT_TIERS.BEST_EFFORT) return ADAPTER_EVIDENCE_LEVELS.EXPERIMENTAL
    return ADAPTER_EVIDENCE_LEVELS.NONE
}

function inferManifestLaunchSource(manifest) {
    if (manifest?.launchSourceType) return manifest.launchSourceType
    if (manifest?.archiveName) return LAUNCH_SOURCE_TYPES.VAULT_ARCHIVE
    return LAUNCH_SOURCE_TYPES.VAULT_DIRECTORY
}

function defaultOwnershipProofLevel(launchSourceType, launchMethod) {
    if (launchMethod === LAUNCH_METHODS.PROTOCOL ||
        launchMethod === LAUNCH_METHODS.PACKAGED_APP ||
        launchSourceType === LAUNCH_SOURCE_TYPES.PROTOCOL_URI ||
        launchSourceType === LAUNCH_SOURCE_TYPES.PACKAGED_APP) {
        return OWNERSHIP_PROOF_LEVELS.NONE
    }

    if (launchMethod === LAUNCH_METHODS.SHELL_EXECUTE ||
        launchSourceType === LAUNCH_SOURCE_TYPES.SHELL_EXECUTE ||
        launchSourceType === LAUNCH_SOURCE_TYPES.START_MENU_SHORTCUT) {
        return OWNERSHIP_PROOF_LEVELS.WEAK
    }

    if (launchSourceType === LAUNCH_SOURCE_TYPES.VAULT_ARCHIVE ||
        launchSourceType === LAUNCH_SOURCE_TYPES.VAULT_DIRECTORY) {
        return OWNERSHIP_PROOF_LEVELS.STRONG
    }

    return OWNERSHIP_PROOF_LEVELS.MEDIUM
}

function closePolicyForOwnership(ownershipProofLevel) {
    if (ownershipProofLevel === OWNERSHIP_PROOF_LEVELS.STRONG) return CLOSE_POLICIES.OWNED_TREE
    if (ownershipProofLevel === OWNERSHIP_PROOF_LEVELS.MEDIUM) return CLOSE_POLICIES.OWNED_PROCESS_ONLY
    return CLOSE_POLICIES.NEVER
}

function dataManagementForCapability(capability, dataProfile) {
    const dataMode = String(dataProfile?.mode || capability?.dataMode || 'none').toLowerCase()
    if (!dataMode || dataMode === 'none') {
        return capability?.supportTier === SUPPORT_TIERS.NEEDS_ADAPTER
            ? DATA_MANAGEMENT_LEVELS.UNSUPPORTED
            : DATA_MANAGEMENT_LEVELS.UNMANAGED
    }

    return capability?.importedDataSupported
        ? DATA_MANAGEMENT_LEVELS.MANAGED
        : DATA_MANAGEMENT_LEVELS.UNSUPPORTED
}

function normalizeCertification(certification) {
    const status = ['uncertified', 'verified', 'failed'].includes(certification?.status)
        ? certification.status
        : 'uncertified'

    return {
        status,
        lastCheckedAt: certification?.lastCheckedAt || null,
        checks: Array.isArray(certification?.checks) ? certification.checks.map(check => ({ ...check })) : []
    }
}

export function resolveManifestSupportFields({
    appType,
    appName,
    launchProfile,
    dataProfile,
    adapterEvidence,
    launchSourceType = LAUNCH_SOURCE_TYPES.VAULT_ARCHIVE,
    launchMethod = LAUNCH_METHODS.SPAWN,
    ownershipProofLevel,
    closePolicy,
    canQuitFromOmniLaunch,
    availabilityStatus,
    dataManagement,
    requiresElevation,
    resolvedAt,
    resolvedHostId,
    launchAdapter,
    runtimeAdapter,
    dataAdapters,
    registryAdapters,
    limitations,
    certification
} = {}) {
    const capability = resolveAppCapability({
        appType,
        appName,
        launchProfile,
        dataProfile
    })
    const resolvedLaunchSourceType = launchSourceType || LAUNCH_SOURCE_TYPES.VAULT_ARCHIVE
    const resolvedLaunchMethod = launchMethod || LAUNCH_METHODS.SPAWN
    const resolvedOwnership = ownershipProofLevel || defaultOwnershipProofLevel(resolvedLaunchSourceType, resolvedLaunchMethod)
    const resolvedClosePolicy = closePolicy || closePolicyForOwnership(resolvedOwnership)
    const resolvedAdapterEvidence = Object.values(ADAPTER_EVIDENCE_LEVELS).includes(adapterEvidence)
        ? adapterEvidence
        : defaultAdapterEvidence(capability.supportTier)
    const resolvedCanQuit = typeof canQuitFromOmniLaunch === 'boolean'
        ? canQuitFromOmniLaunch
        : resolvedClosePolicy !== CLOSE_POLICIES.NEVER
    const resolvedDataManagement = Object.values(DATA_MANAGEMENT_LEVELS).includes(dataManagement)
        ? dataManagement
        : dataManagementForCapability(capability, dataProfile || capability.dataProfile)
    const resolvedLimitations = Array.isArray(limitations)
        ? limitations
        : (Array.isArray(capability.limitations) ? capability.limitations : [])

    return {
        supportTier: capability.supportTier,
        supportSummary: capability.supportSummary,
        adapterEvidence: resolvedAdapterEvidence,
        launchSourceType: resolvedLaunchSourceType,
        launchMethod: resolvedLaunchMethod,
        ownershipProofLevel: resolvedOwnership,
        closePolicy: resolvedClosePolicy,
        canQuitFromOmniLaunch: resolvedCanQuit,
        availabilityStatus: availabilityStatus || 'available',
        dataManagement: resolvedDataManagement,
        requiresElevation: typeof requiresElevation === 'boolean' ? requiresElevation : false,
        resolvedAt: resolvedAt || null,
        resolvedHostId: resolvedHostId || null,
        launchAdapter: launchAdapter || capability.launchAdapter || 'none',
        runtimeAdapter: runtimeAdapter || capability.runtimeAdapter || 'none',
        dataAdapters: Array.isArray(dataAdapters) ? [...dataAdapters] : [],
        registryAdapters: Array.isArray(registryAdapters) ? [...registryAdapters] : [],
        limitations: [...resolvedLimitations],
        certification: normalizeCertification(certification),
        importedDataSupported: capability.importedDataSupported,
        importedDataSupportLevel: capability.importedDataSupportLevel,
        importedDataAdapterId: capability.importedDataAdapterId,
        importedDataSupportReason: capability.importedDataSupportReason
    }
}

export function pickSupportFields(source = {}) {
    const picked = {}
    for (const fieldName of SUPPORT_FIELD_NAMES) {
        if (source[fieldName] === undefined) continue
        if (Array.isArray(source[fieldName])) {
            picked[fieldName] = [...source[fieldName]]
        } else if (source[fieldName] && typeof source[fieldName] === 'object') {
            picked[fieldName] = JSON.parse(JSON.stringify(source[fieldName]))
        } else {
            picked[fieldName] = source[fieldName]
        }
    }
    return picked
}

function supportSnapshot(source = {}) {
    return {
        schemaVersion: source.schemaVersion,
        ...pickSupportFields(source)
    }
}

function hasRelativePath(relativePaths, relPath) {
    const needle = toLowerSlash(relPath)
    return relativePaths.has(needle)
}

export function detectRequiredFilesFromRoot(rootDir) {
    const present = new Set()
    for (const relation of KNOWN_REQUIRED_FILE_RELATIONS) {
        if (fileExistsCaseInsensitive(rootDir, relation.anchor)) present.add(toLowerSlash(relation.anchor))
        for (const required of relation.requires) {
            if (fileExistsCaseInsensitive(rootDir, required)) present.add(toLowerSlash(required))
        }
    }
    return detectRequiredFilesFromSet(present)
}

export function detectRequiredFilesFromArchiveEntries(entries) {
    const archiveRoot = inferArchiveRoot(entries)
    const present = new Set(entries.map(entry => toLowerSlash(stripArchiveRoot(entry, archiveRoot))).filter(Boolean))
    return detectRequiredFilesFromSet(present)
}

function detectRequiredFilesFromSet(present) {
    const required = new Set()
    for (const relation of KNOWN_REQUIRED_FILE_RELATIONS) {
        if (!hasRelativePath(present, relation.anchor)) continue
        for (const target of relation.requires) required.add(windowsRel(target))
    }
    return [...required]
}

export function missingRequiredFilesFromArchive(entries, requiredFiles) {
    const archiveRoot = inferArchiveRoot(entries)
    const present = new Set(entries.map(entry => toLowerSlash(stripArchiveRoot(entry, archiveRoot))).filter(Boolean))
    return (requiredFiles || []).filter(file => !hasRelativePath(present, file))
}

export function validateExtractedAppCache(localAppRoot, manifest, selectedRelativePath) {
    const selectedRelative = selectedRelativePath || manifest?.selectedExecutable?.relativePath || ''
    const requiredFiles = manifest?.requiredFiles || []
    const missingFiles = []

    if (!selectedRelative || !fileExistsCaseInsensitive(localAppRoot, selectedRelative)) {
        missingFiles.push(selectedRelative || '<selected executable>')
    }

    for (const required of requiredFiles) {
        if (!fileExistsCaseInsensitive(localAppRoot, required)) missingFiles.push(required)
    }

    const policyVersion = manifest?.binaryArchivePolicyVersion ?? null
    const policyStatus = policyVersion === BINARY_ARCHIVE_POLICY_VERSION
        ? 'current'
        : (policyVersion == null ? 'unknown' : 'legacy')

    let status = missingFiles.length ? 'failed' : 'ok'
    if (manifest?.repairStatus === 'needs-reimport') status = 'failed'

    return {
        status,
        policyStatus,
        binaryArchivePolicyVersion: policyVersion,
        currentBinaryArchivePolicyVersion: BINARY_ARCHIVE_POLICY_VERSION,
        unsafeExclusionPolicyDetected: !!manifest?.unsafeExclusionPolicyDetected,
        selectedExecutable: selectedRelative || null,
        requiredFiles,
        missingFiles
    }
}

export function getManifestPath(vaultDir, appNameOrSafeName) {
    return join(vaultDir, 'Apps', `${safeAppName(appNameOrSafeName)}.quickpass-app.json`)
}

function isMicrosoftEdgeManifest(manifest) {
    const displayName = String(manifest?.displayName || manifest?.safeName || '').toLowerCase()
    const selected = String(manifest?.selectedExecutable?.relativePath || manifest?.legacyPath || '').toLowerCase()
    const candidates = Array.isArray(manifest?.candidateExecutables) ? manifest.candidateExecutables : []

    return displayName.includes('microsoft edge') ||
        displayName === 'edge' ||
        basename(selected.replace(/\\/g, '/')).toLowerCase() === 'msedge.exe' ||
        candidates.some(candidate => basename(String(candidate?.relativePath || candidate?.path || '').replace(/\\/g, '/')).toLowerCase() === 'msedge.exe')
}

export function normalizeManifestProfiles(manifest) {
    if (!manifest || typeof manifest !== 'object') return { manifest, changed: false }

    const nextManifest = {
        ...manifest,
        schemaVersion: APP_MANIFEST_SCHEMA_VERSION
    }

    if (isMicrosoftEdgeManifest(manifest)) {
        const profiles = inferProfiles('chromium', manifest.displayName || 'Microsoft Edge')
        Object.assign(nextManifest, {
            appType: 'chromium',
            launchProfile: profiles.launchProfile,
            dataProfile: profiles.dataProfile,
            readinessProfile: manifest.readinessProfile || profiles.readinessProfile
        })

        if (manifest.readinessProfile?.mode !== profiles.readinessProfile.mode ||
            manifest.readinessProfile?.timeoutMs !== profiles.readinessProfile.timeoutMs) {
            nextManifest.readinessProfile = profiles.readinessProfile
        }
    }

    const importedDataCapability = resolveImportedAppDataCapability({
        appType: nextManifest.appType,
        appName: nextManifest.displayName || nextManifest.safeName,
        launchProfile: nextManifest.launchProfile,
        dataProfile: nextManifest.dataProfile
    })

    const currentDataMode = String(nextManifest.dataProfile?.mode || '').toLowerCase()
    if (!importedDataCapability.importedDataSupported &&
        currentDataMode &&
        currentDataMode !== 'none') {
        nextManifest.dataProfile = { mode: 'none' }
        nextManifest.importedDataSupportLevel = importedDataCapability.importedDataSupportLevel
        nextManifest.importedDataSupportReason = importedDataCapability.importedDataSupportReason
    }

    const supportFields = resolveManifestSupportFields({
        appType: nextManifest.appType,
        appName: nextManifest.displayName || nextManifest.safeName,
        launchProfile: nextManifest.launchProfile,
        dataProfile: nextManifest.dataProfile,
        adapterEvidence: nextManifest.adapterEvidence,
        launchSourceType: inferManifestLaunchSource(nextManifest),
        launchMethod: nextManifest.launchMethod || LAUNCH_METHODS.SPAWN,
        ownershipProofLevel: nextManifest.ownershipProofLevel,
        closePolicy: nextManifest.closePolicy,
        canQuitFromOmniLaunch: nextManifest.canQuitFromOmniLaunch,
        availabilityStatus: nextManifest.availabilityStatus,
        dataManagement: nextManifest.dataManagement,
        requiresElevation: nextManifest.requiresElevation,
        resolvedAt: nextManifest.resolvedAt,
        resolvedHostId: nextManifest.resolvedHostId,
        launchAdapter: nextManifest.launchAdapter,
        runtimeAdapter: nextManifest.runtimeAdapter,
        dataAdapters: nextManifest.dataAdapters,
        registryAdapters: nextManifest.registryAdapters,
        limitations: nextManifest.limitations,
        certification: nextManifest.certification
    })
    Object.assign(nextManifest, supportFields)

    const changed = JSON.stringify({
        schemaVersion: manifest.schemaVersion,
        appType: manifest.appType,
        launchProfile: manifest.launchProfile,
        dataProfile: manifest.dataProfile,
        readinessProfile: manifest.readinessProfile,
        importedDataSupportLevel: manifest.importedDataSupportLevel,
        importedDataSupportReason: manifest.importedDataSupportReason,
        support: supportSnapshot(manifest)
    }) !== JSON.stringify({
        schemaVersion: nextManifest.schemaVersion,
        appType: nextManifest.appType,
        launchProfile: nextManifest.launchProfile,
        dataProfile: nextManifest.dataProfile,
        readinessProfile: nextManifest.readinessProfile,
        importedDataSupportLevel: nextManifest.importedDataSupportLevel,
        importedDataSupportReason: nextManifest.importedDataSupportReason,
        support: supportSnapshot(nextManifest)
    })

    return { manifest: nextManifest, changed }
}

export function readAppManifest(vaultDir, appNameOrSafeName) {
    if (!vaultDir || !appNameOrSafeName) return null
    const manifestPath = getManifestPath(vaultDir, appNameOrSafeName)
    if (!existsSync(manifestPath)) return null
    try {
        return JSON.parse(readFileSync(manifestPath, 'utf8'))
    } catch (_) {
        return null
    }
}

export function writeAppManifest(vaultDir, manifest) {
    const manifestPath = getManifestPath(vaultDir, manifest.safeName || manifest.displayName)
    writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8')
    return manifestPath
}

function normalizeAppConfigImportedData(appConfig, manifest) {
    if (!appConfig?.portableData) return appConfig

    const capability = resolveImportedAppDataCapability({
        appType: manifest?.appType,
        appName: manifest?.displayName || manifest?.safeName || appConfig?.name,
        launchProfile: manifest?.launchProfile || appConfig?.launchProfile,
        dataProfile: manifest?.dataProfile || appConfig?.dataProfile
    })

    if (capability.importedDataSupported) return appConfig

    return {
        ...appConfig,
        portableData: false,
        dataProfile: { mode: 'none' },
        importedDataSupportLevel: capability.importedDataSupportLevel,
        importedDataSupportReason: capability.importedDataSupportReason
    }
}

export function hashFile(filePath) {
    return new Promise((resolveHash, rejectHash) => {
        const hash = crypto.createHash('sha256')
        const stream = createReadStream(filePath)
        stream.on('data', chunk => hash.update(chunk))
        stream.on('error', rejectHash)
        stream.on('end', () => resolveHash(hash.digest('hex')))
    })
}

export function listArchiveEntries(archivePath) {
    const output = execFileSync('tar', ['--zstd', '-tf', archivePath], {
        encoding: 'utf8',
        maxBuffer: 100 * 1024 * 1024,
        timeout: 60000
    })
    return output.split(/\r?\n/).map(line => line.trim()).filter(Boolean)
}

export function createImportManifest({
    displayName,
    safeName,
    sourcePath,
    archiveName,
    archiveRoot,
    selectedExecutable,
    candidateExecutables,
    appType,
    importData,
    archiveHash,
    archiveSizeBytes,
    legacyPath,
    requiredFiles
}) {
    const profiles = inferProfiles(appType, displayName)
    const manifest = {
        schemaVersion: APP_MANIFEST_SCHEMA_VERSION,
        manifestId: safeName || safeAppName(displayName),
        displayName,
        safeName: safeName || safeAppName(displayName),
        archiveName,
        archiveRoot,
        sourcePathAtImport: sourcePath,
        binaryArchivePolicyVersion: BINARY_ARCHIVE_POLICY_VERSION,
        binaryExclusions: {
            excludedDirs: [...BINARY_ARCHIVE_EXCLUDE_DIRS],
            excludedFiles: [...BINARY_ARCHIVE_EXCLUDE_FILES]
        },
        unsafeExclusionPolicyDetected: false,
        archiveHash,
        archiveSizeBytes,
        selectedExecutable,
        candidateExecutables: candidateExecutables || [],
        appType,
        launchProfile: profiles.launchProfile,
        dataProfile: resolveManifestDataProfile(appType, displayName, !!importData),
        readinessProfile: profiles.readinessProfile,
        requiredFiles: requiredFiles || [],
        legacyPath: legacyPath || null,
        repairStatus: 'current'
    }
    return normalizeManifestProfiles(manifest).manifest
}

function buildLegacyManifest({ appConfig, vaultDir, parsedPath, archiveEntries, directoryRoot }) {
    const displayName = appConfig.name || parsedPath.appName
    const safeName = safeAppName(displayName)
    const archiveName = `${parsedPath.appName}.tar.zst`
    const currentExe = parsedPath.exeRelative

    let selection
    let archiveRoot = parsedPath.appName
    let requiredFiles = []
    let missingRequiredFiles = []
    let appType = 'native'
    let sourcePathAtImport = null

    if (archiveEntries) {
        selection = selectBestExecutableFromArchiveEntries(archiveEntries, displayName, currentExe)
        archiveRoot = selection.archiveRoot || archiveRoot
        requiredFiles = detectRequiredFilesFromArchiveEntries(archiveEntries)
        missingRequiredFiles = missingRequiredFilesFromArchive(archiveEntries, requiredFiles)
    } else if (directoryRoot) {
        selection = selectBestExecutable(directoryRoot, displayName, [{ path: join(directoryRoot, currentExe), source: 'legacy-path' }])
        requiredFiles = detectRequiredFilesFromRoot(directoryRoot)
        appType = inferAppType(directoryRoot)
        sourcePathAtImport = directoryRoot
    } else {
        selection = { selected: null, candidates: [], confidence: 'none' }
    }

    const selectedExecutable = selection.selected ? {
        relativePath: selection.selected.relativePath,
        selectionSource: selection.selected.source || 'legacy-repair',
        confidence: selection.selected.confidence,
        score: selection.selected.score,
        reasons: selection.selected.reasons || []
    } : null

    const currentDangerous = isDangerousExecutablePath(currentExe)
    const selectedChanged = !!selectedExecutable && toLowerSlash(selectedExecutable.relativePath) !== toLowerSlash(currentExe)
    let repairStatus = 'legacy-manifest-created'
    if (missingRequiredFiles.length > 0) repairStatus = 'needs-reimport'
    else if (currentDangerous || selectedChanged) repairStatus = 'auto-repaired'

    const profiles = inferProfiles(appType, displayName)
    const manifest = {
        schemaVersion: APP_MANIFEST_SCHEMA_VERSION,
        manifestId: safeName,
        displayName,
        safeName,
        archiveName,
        archiveRoot,
        sourcePathAtImport,
        binaryArchivePolicyVersion: 0,
        binaryExclusions: {
            excludedDirs: ['unknown-legacy-policy'],
            excludedFiles: []
        },
        unsafeExclusionPolicyDetected: !!archiveEntries,
        archiveHash: null,
        archiveSizeBytes: null,
        selectedExecutable,
        candidateExecutables: selection.candidates || [],
        appType,
        launchProfile: profiles.launchProfile,
        dataProfile: resolveManifestDataProfile(appType, displayName, !!appConfig.portableData),
        readinessProfile: profiles.readinessProfile,
        requiredFiles,
        missingRequiredFiles,
        legacyPath: appConfig.path || null,
        repairStatus
    }
    return normalizeManifestProfiles(manifest).manifest
}

export function parseVaultAppPath(appPath, vaultDir) {
    if (!appPath || !vaultDir || !String(appPath).toLowerCase().startsWith(String(vaultDir).toLowerCase())) return null
    const relPath = String(appPath).slice(String(vaultDir).length)
    const parts = relPath.split(/[\\/]/).filter(Boolean)
    if (parts[0] !== 'Apps' || parts.length < 3) return null
    return {
        appName: parts[1],
        exeRelative: parts.slice(2).join('\\'),
        parts
    }
}

export function repairLegacyAppConfig(appConfig, vaultDir, options = {}) {
    const { persist = true } = options
    const parsedPath = parseVaultAppPath(appConfig?.path, vaultDir)
    if (!parsedPath) {
        return { appConfig, manifest: null, repaired: false, reason: 'not-vault-app' }
    }

    const manifest = readAppManifest(vaultDir, appConfig.name || parsedPath.appName)
    if (manifest) {
        const normalized = normalizeManifestProfiles(manifest)
        const activeManifest = normalized.manifest
        if (persist && normalized.changed) {
            try { writeAppManifest(vaultDir, activeManifest) } catch (_) { }
        }
        const profileNormalizedReason = persist ? 'manifest-profile-normalized' : 'manifest-profile-normalized-readonly'
        const selected = activeManifest.selectedExecutable?.relativePath
        if (selected && !isDangerousExecutablePath(selected)) {
            const normalizedConfig = normalizeAppConfigImportedData({
                ...appConfig,
                path: join(vaultDir, 'Apps', parsedPath.appName, selected),
                manifestId: activeManifest.manifestId,
                launchProfile: activeManifest.launchProfile,
                dataProfile: activeManifest.dataProfile,
                readinessProfile: activeManifest.readinessProfile,
                ...pickSupportFields(activeManifest)
            }, activeManifest)
            return {
                appConfig: normalizedConfig,
                manifest: activeManifest,
                repaired: false,
                reason: normalized.changed ? profileNormalizedReason : 'manifest-existing'
            }
        }
        return {
            appConfig: {
                ...appConfig,
                manifestId: activeManifest.manifestId,
                ...pickSupportFields(activeManifest)
            },
            manifest: activeManifest,
            repaired: false,
            reason: 'manifest-no-safe-selection'
        }
    }

    const archivePath = join(vaultDir, 'Apps', `${parsedPath.appName}.tar.zst`)
    const directoryRoot = join(vaultDir, 'Apps', parsedPath.appName)
    let archiveEntries = null
    if (existsSync(archivePath)) {
        try { archiveEntries = listArchiveEntries(archivePath) } catch (_) { archiveEntries = null }
    }

    const directoryExists = existsSync(directoryRoot)
    if (!archiveEntries && !directoryExists) {
        return { appConfig, manifest: null, repaired: false, reason: 'payload-missing' }
    }

    const builtManifest = buildLegacyManifest({
        appConfig,
        vaultDir,
        parsedPath,
        archiveEntries,
        directoryRoot: directoryExists ? directoryRoot : null
    })
    if (persist) {
        try { writeAppManifest(vaultDir, builtManifest) } catch (_) { }
    }

    const selected = builtManifest.selectedExecutable?.relativePath
    const canAutoRepair = selected && !isDangerousExecutablePath(selected) && builtManifest.selectedExecutable.confidence !== 'low'
    let repairedConfig = {
        ...appConfig,
        manifestId: builtManifest.manifestId,
        launchProfile: builtManifest.launchProfile,
        dataProfile: builtManifest.dataProfile,
        readinessProfile: builtManifest.readinessProfile,
        ...pickSupportFields(builtManifest)
    }
    if (canAutoRepair) {
        repairedConfig.path = join(vaultDir, 'Apps', parsedPath.appName, selected)
    }
    repairedConfig = normalizeAppConfigImportedData(repairedConfig, builtManifest)

    return {
        appConfig: repairedConfig,
        manifest: builtManifest,
        repaired: canAutoRepair && toLowerSlash(selected) !== toLowerSlash(parsedPath.exeRelative),
        reason: persist ? builtManifest.repairStatus : 'legacy-manifest-inspected'
    }
}

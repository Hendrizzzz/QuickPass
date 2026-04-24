import assert from 'assert/strict'
import {
    existsSync,
    mkdirSync,
    mkdtempSync,
    readFileSync,
    rmSync,
    symlinkSync,
    writeFileSync
} from 'fs'
import { join } from 'path'
import {
    ADAPTER_EVIDENCE_LEVELS,
    APP_MANIFEST_SCHEMA_VERSION,
    createImportManifest,
    DATA_MANAGEMENT_LEVELS,
    getManifestPath,
    LAUNCH_SOURCE_TYPES,
    repairLegacyAppConfig,
    resolveAppPathsSupportFields,
    resolveHostExeSupportFields,
    resolveImportedAppDataCapability,
    resolveRegistryUninstallSupportFields,
    resolveStartMenuShortcutSupportFields,
    safeAppName,
    writeAppManifest
} from '../src/main/appManifest.js'
import {
    APP_ADAPTER_IDS,
    SUPPORT_TIERS,
    resolveAppCapability
} from '../src/main/appAdapters.js'
import {
    findStaleUnsupportedAppDataPayloads,
    isSafePayloadDirectory,
    selectStaleAppDataPayloads
} from '../src/main/staleAppData.js'

const tempRoot = mkdtempSync(join(process.cwd(), '.tmp-lifecycle-probe-'))

function makeVault(label) {
    const vaultDir = join(tempRoot, label)
    mkdirSync(join(vaultDir, 'Apps'), { recursive: true })
    mkdirSync(join(vaultDir, 'AppData'), { recursive: true })
    return vaultDir
}

function makeVaultApp(vaultDir, name, exeName = 'app.exe') {
    const appDir = join(vaultDir, 'Apps', name)
    mkdirSync(appDir, { recursive: true })
    const exePath = join(appDir, exeName)
    writeFileSync(exePath, '')
    return exePath
}

function makeAppDataPayload(vaultDir, name) {
    const payloadPath = join(vaultDir, 'AppData', safeAppName(name))
    mkdirSync(payloadPath, { recursive: true })
    writeFileSync(join(payloadPath, 'payload.txt'), 'probe-data')
    return payloadPath
}

function makeManifest(vaultDir, name, selectedExecutable, overrides = {}) {
    const manifest = {
        schemaVersion: 1,
        manifestId: safeAppName(name),
        displayName: name,
        safeName: safeAppName(name),
        selectedExecutable: { relativePath: selectedExecutable, confidence: 'high' },
        candidateExecutables: [],
        appType: 'native',
        launchProfile: 'native-windowed',
        dataProfile: { mode: 'none' },
        readinessProfile: 'standard',
        requiredFiles: [],
        repairStatus: 'probe',
        ...overrides
    }
    writeAppManifest(vaultDir, manifest)
    return manifest
}

async function runProbe(name, fn) {
    process.stdout.write(`- ${name}: `)
    await fn()
    console.log('PASS')
}

try {
    console.log('Starting QuickPass lifecycle probes...\n')

    await runProbe('app capability resolver keeps golden adapter classifications stable', async () => {
        const edge = resolveAppCapability({
            appType: 'chromium',
            appName: 'Microsoft Edge',
            launchProfile: 'chromium-browser',
            dataProfile: { mode: 'chromium-user-data' }
        })
        assert.equal(edge.supportTier, SUPPORT_TIERS.VERIFIED)
        assert.equal(edge.importedDataSupported, true)
        assert.equal(edge.importedDataAdapterId, APP_ADAPTER_IDS.CHROMIUM_USER_DATA_DIR)
        assert.equal(edge.runtimeAdapter, APP_ADAPTER_IDS.CHROMIUM_USER_DATA_DIR)

        const cursor = resolveAppCapability({
            appType: 'vscode-family',
            appName: 'Cursor',
            launchProfile: 'vscode-family',
            dataProfile: { mode: 'vscode-user-data' }
        })
        assert.equal(cursor.supportTier, SUPPORT_TIERS.VERIFIED)
        assert.equal(cursor.importedDataSupported, true)
        assert.equal(cursor.importedDataAdapterId, APP_ADAPTER_IDS.VSCODE_USER_DATA_DIR)
        assert.equal(cursor.runtimeAdapter, APP_ADAPTER_IDS.VSCODE_USER_DATA_DIR)

        const discord = resolveAppCapability({
            appType: 'electron',
            appName: 'Discord',
            launchProfile: 'electron-standard',
            dataProfile: { mode: 'electron-user-data' }
        })
        assert.equal(discord.supportTier, SUPPORT_TIERS.BEST_EFFORT)
        assert.equal(discord.importedDataSupported, false)
        assert.equal(discord.importedDataAdapterId, APP_ADAPTER_IDS.ELECTRON_USER_DATA_DIR)
        assert.equal(discord.runtimeAdapter, APP_ADAPTER_IDS.ELECTRON_USER_DATA_DIR)

        const nativeApp = resolveAppCapability({
            appType: 'native',
            appName: 'Subtitle Edit',
            launchProfile: 'native-windowed',
            dataProfile: { mode: 'none' }
        })
        assert.equal(nativeApp.supportTier, SUPPORT_TIERS.LAUNCH_ONLY)
        assert.equal(nativeApp.importedDataSupported, false)
        assert.equal(nativeApp.importedDataAdapterId, APP_ADAPTER_IDS.NONE)
        assert.equal(nativeApp.runtimeAdapter, APP_ADAPTER_IDS.NONE)

        const obs = resolveAppCapability({
            appType: 'native',
            appName: 'OBS Studio',
            launchProfile: 'native-windowed',
            dataProfile: { mode: 'none' }
        })
        assert.equal(obs.supportTier, SUPPORT_TIERS.NEEDS_ADAPTER)
        assert.equal(obs.importedDataSupported, false)
        assert.equal(obs.importedDataAdapterId, APP_ADAPTER_IDS.NONE)
        assert.equal(obs.launchAdapter, APP_ADAPTER_IDS.OBS_PORTABLE)
    })

    await runProbe('Manifest V2 emits support fields for golden app families', async () => {
        const makeGoldenManifest = (displayName, appType, importData = true) => createImportManifest({
            displayName,
            safeName: safeAppName(displayName),
            sourcePath: `C:\\Probe\\${safeAppName(displayName)}`,
            archiveName: `${safeAppName(displayName)}.tar.zst`,
            archiveRoot: displayName,
            selectedExecutable: { relativePath: 'app.exe', confidence: 'high' },
            candidateExecutables: [],
            appType,
            importData,
            archiveHash: 'probe',
            archiveSizeBytes: 1,
            requiredFiles: []
        })

        const edge = makeGoldenManifest('Microsoft Edge', 'chromium')
        assert.equal(edge.schemaVersion, APP_MANIFEST_SCHEMA_VERSION)
        assert.equal(edge.supportTier, SUPPORT_TIERS.VERIFIED)
        assert.equal(edge.adapterEvidence, ADAPTER_EVIDENCE_LEVELS.FAMILY_VERIFIED)
        assert.equal(edge.launchSourceType, LAUNCH_SOURCE_TYPES.VAULT_ARCHIVE)
        assert.equal(edge.dataManagement, DATA_MANAGEMENT_LEVELS.MANAGED)
        assert.equal(edge.importedDataAdapterId, APP_ADAPTER_IDS.CHROMIUM_USER_DATA_DIR)

        const cursor = makeGoldenManifest('Cursor', 'vscode-family')
        assert.equal(cursor.supportTier, SUPPORT_TIERS.VERIFIED)
        assert.equal(cursor.adapterEvidence, ADAPTER_EVIDENCE_LEVELS.FAMILY_VERIFIED)
        assert.equal(cursor.importedDataAdapterId, APP_ADAPTER_IDS.VSCODE_USER_DATA_DIR)

        const discord = makeGoldenManifest('Discord', 'electron')
        assert.equal(discord.supportTier, SUPPORT_TIERS.BEST_EFFORT)
        assert.equal(discord.dataProfile.mode, 'none')
        assert.equal(discord.dataManagement, DATA_MANAGEMENT_LEVELS.UNMANAGED)
        assert.equal(discord.importedDataSupported, false)

        const nativeApp = makeGoldenManifest('Subtitle Edit', 'native', false)
        assert.equal(nativeApp.supportTier, SUPPORT_TIERS.LAUNCH_ONLY)
        assert.equal(nativeApp.dataManagement, DATA_MANAGEMENT_LEVELS.UNMANAGED)
        assert.equal(nativeApp.importedDataSupported, false)

        const obs = makeGoldenManifest('OBS Studio', 'native', false)
        assert.equal(obs.supportTier, SUPPORT_TIERS.NEEDS_ADAPTER)
        assert.equal(obs.launchAdapter, APP_ADAPTER_IDS.OBS_PORTABLE)
        assert.equal(obs.dataManagement, DATA_MANAGEMENT_LEVELS.UNSUPPORTED)
        assert.equal(obs.importedDataSupported, false)
    })

    await runProbe('manual host exe support fields are launch-only and data unmanaged', async () => {
        const fields = resolveHostExeSupportFields({
            appName: 'Notepad',
            availabilityStatus: 'unknown'
        })

        assert.equal(fields.supportTier, SUPPORT_TIERS.LAUNCH_ONLY)
        assert.equal(fields.launchSourceType, LAUNCH_SOURCE_TYPES.HOST_EXE)
        assert.equal(fields.launchMethod, 'spawn')
        assert.equal(fields.ownershipProofLevel, 'none')
        assert.equal(fields.closePolicy, 'never')
        assert.equal(fields.canQuitFromOmniLaunch, false)
        assert.equal(fields.availabilityStatus, 'unknown')
        assert.equal(fields.dataManagement, DATA_MANAGEMENT_LEVELS.UNMANAGED)
        assert.equal(fields.importedDataSupported, false)
        assert.equal(fields.importedDataAdapterId, APP_ADAPTER_IDS.NONE)
    })

    await runProbe('registry uninstall support fields are launch references only', async () => {
        const fields = resolveRegistryUninstallSupportFields({
            appName: 'Registry App Probe',
            availabilityStatus: 'available'
        })

        assert.equal(fields.supportTier, SUPPORT_TIERS.LAUNCH_ONLY)
        assert.equal(fields.launchSourceType, LAUNCH_SOURCE_TYPES.REGISTRY_UNINSTALL)
        assert.equal(fields.launchMethod, 'spawn')
        assert.equal(fields.dataManagement, DATA_MANAGEMENT_LEVELS.UNMANAGED)
        assert.equal(fields.importedDataSupported, false)
        assert.equal(fields.canQuitFromOmniLaunch, false)
        assert.equal(fields.availabilityStatus, 'available')
        assert.match(fields.supportSummary, /Registry-discovered host app/)
    })

    await runProbe('App Paths and Start Menu shortcut fields preserve ownership classes', async () => {
        const appPaths = resolveAppPathsSupportFields({
            appName: 'App Paths Probe',
            availabilityStatus: 'available'
        })
        assert.equal(appPaths.launchSourceType, LAUNCH_SOURCE_TYPES.APP_PATHS)
        assert.equal(appPaths.launchMethod, 'spawn')
        assert.equal(appPaths.dataManagement, DATA_MANAGEMENT_LEVELS.UNMANAGED)
        assert.equal(appPaths.closeManagedAfterSpawn, true)
        assert.equal(appPaths.canQuitFromOmniLaunch, false)

        const strongShortcut = resolveStartMenuShortcutSupportFields({
            appName: 'Strong Shortcut Probe',
            availabilityStatus: 'available',
            strongDirectExecutable: true
        })
        assert.equal(strongShortcut.launchSourceType, LAUNCH_SOURCE_TYPES.START_MENU_SHORTCUT)
        assert.equal(strongShortcut.closeManagedAfterSpawn, true)
        assert.equal(strongShortcut.canQuitFromOmniLaunch, false)

        const weakShortcut = resolveStartMenuShortcutSupportFields({
            appName: 'Weak Shortcut Probe',
            availabilityStatus: 'available',
            strongDirectExecutable: false,
            warning: 'Shortcut has launch arguments.'
        })
        assert.equal(weakShortcut.launchSourceType, LAUNCH_SOURCE_TYPES.START_MENU_SHORTCUT)
        assert.equal(weakShortcut.closeManagedAfterSpawn, false)
        assert.equal(weakShortcut.canQuitFromOmniLaunch, false)
        assert.match(weakShortcut.limitations.join(' '), /launch arguments/i)
    })

    await runProbe('generic Electron import manifest normalizes imported AppData to none', async () => {
        const manifest = createImportManifest({
            displayName: 'Generic Electron Probe',
            safeName: 'Generic_Electron_Probe',
            sourcePath: 'C:\\Probe\\GenericElectron\\app.exe',
            archiveName: 'Generic_Electron_Probe.tar.zst',
            archiveRoot: 'Generic Electron Probe',
            selectedExecutable: { relativePath: 'app.exe', confidence: 'high' },
            candidateExecutables: [],
            appType: 'electron',
            importData: true,
            archiveHash: 'probe',
            archiveSizeBytes: 1,
            requiredFiles: []
        })
        assert.equal(manifest.launchProfile, 'electron-standard')
        assert.equal(manifest.dataProfile.mode, 'none')

        const capability = resolveImportedAppDataCapability({
            appType: manifest.appType,
            launchProfile: manifest.launchProfile,
            dataProfile: manifest.dataProfile
        })
        assert.equal(capability.importedDataSupported, false)
    })

    await runProbe('legacy generic Electron repair clears unsupported imported AppData', async () => {
        const vaultDir = makeVault('legacy-electron-repair')
        const name = 'Legacy Electron Probe'
        const exePath = makeVaultApp(vaultDir, name)
        makeManifest(vaultDir, name, 'app.exe', {
            appType: 'electron',
            launchProfile: 'electron-standard',
            dataProfile: { mode: 'electron-user-data' }
        })

        const repaired = repairLegacyAppConfig({ name, path: exePath, portableData: true }, vaultDir)
        assert.equal(repaired.appConfig.portableData, false)
        assert.equal(repaired.appConfig.dataProfile.mode, 'none')
        assert.equal(repaired.manifest.dataProfile.mode, 'none')

        const writtenManifest = JSON.parse(readFileSync(getManifestPath(vaultDir, name), 'utf8'))
        assert.equal(writtenManifest.dataProfile.mode, 'none')
    })

    await runProbe('stale inspection does not create missing legacy manifests', async () => {
        const vaultDir = makeVault('readonly-scan')
        const name = 'Read Only Legacy Probe'
        const exePath = makeVaultApp(vaultDir, name)
        const payloadPath = makeAppDataPayload(vaultDir, name)
        const manifestPath = getManifestPath(vaultDir, name)
        assert.equal(existsSync(manifestPath), false)

        const inspected = repairLegacyAppConfig({ name, path: exePath, portableData: true }, vaultDir, { persist: false })
        assert.equal(inspected.reason, 'legacy-manifest-inspected')
        assert.equal(existsSync(manifestPath), false)

        const payloads = await findStaleUnsupportedAppDataPayloads({
            desktopApps: [{ name, path: exePath, portableData: true }]
        }, vaultDir)

        assert.equal(existsSync(manifestPath), false)
        assert.equal(payloads.some(payload => payload.path === payloadPath), true)
    })

    await runProbe('stale inspection does not rewrite existing manifests unless explicitly persisted', async () => {
        const vaultDir = makeVault('readonly-normalization')
        const name = 'Readonly Bad Manifest Probe'
        const exePath = makeVaultApp(vaultDir, name)
        makeManifest(vaultDir, name, 'app.exe', {
            appType: 'electron',
            launchProfile: 'electron-standard',
            dataProfile: { mode: 'electron-user-data' }
        })
        const manifestPath = getManifestPath(vaultDir, name)
        const before = readFileSync(manifestPath, 'utf8')

        const inspected = repairLegacyAppConfig({ name, path: exePath, portableData: true }, vaultDir, { persist: false })
        assert.equal(inspected.reason, 'manifest-profile-normalized-readonly')
        assert.equal(readFileSync(manifestPath, 'utf8'), before)

        await findStaleUnsupportedAppDataPayloads({
            desktopApps: [{ name, path: exePath, portableData: true }]
        }, vaultDir)

        assert.equal(readFileSync(manifestPath, 'utf8'), before)
    })

    await runProbe('supported-but-disabled imported AppData payloads are surfaced as orphaned', async () => {
        const vaultDir = makeVault('supported-disabled-orphan')
        const name = 'Supported Disabled Probe'
        const exePath = makeVaultApp(vaultDir, name, 'code.exe')
        const payloadPath = makeAppDataPayload(vaultDir, name)
        makeManifest(vaultDir, name, 'code.exe', {
            appType: 'vscode-family',
            launchProfile: 'vscode-family',
            dataProfile: { mode: 'none' }
        })

        const payloads = await findStaleUnsupportedAppDataPayloads({
            desktopApps: [{
                name,
                path: exePath,
                portableData: false,
                launchProfile: 'vscode-family',
                dataProfile: { mode: 'none' }
            }]
        }, vaultDir)

        assert.equal(payloads.some(payload => payload.path === payloadPath && payload.orphaned), true)
    })

    await runProbe('active supported imported AppData payloads are not marked stale', async () => {
        const vaultDir = makeVault('supported-active-reference')
        const name = 'Supported Active Probe'
        const exePath = makeVaultApp(vaultDir, name, 'code.exe')
        const payloadPath = makeAppDataPayload(vaultDir, name)
        makeManifest(vaultDir, name, 'code.exe', {
            appType: 'vscode-family',
            launchProfile: 'vscode-family',
            dataProfile: { mode: 'vscode-user-data' }
        })

        const payloads = await findStaleUnsupportedAppDataPayloads({
            desktopApps: [{
                name,
                path: exePath,
                portableData: true,
                launchProfile: 'vscode-family',
                dataProfile: { mode: 'vscode-user-data' }
            }]
        }, vaultDir)

        assert.equal(payloads.some(payload => payload.path === payloadPath), false)
    })

    await runProbe('cleanup selection rejects missing or empty payload ids', async () => {
        assert.throws(() => selectStaleAppDataPayloads(undefined, []), /Select at least one AppData payload/)
        assert.throws(() => selectStaleAppDataPayloads([], []), /Select at least one AppData payload/)
        assert.throws(() => selectStaleAppDataPayloads([''], []), /Select at least one valid AppData payload/)
    })

    await runProbe('junction-like payload roots are blocked before deletion', async () => {
        const vaultDir = makeVault('junction-block')
        const appDataRoot = join(vaultDir, 'AppData')
        const target = join(vaultDir, 'outside-target')
        const link = join(appDataRoot, 'LinkedPayload')
        mkdirSync(target, { recursive: true })
        symlinkSync(target, link, 'junction')

        const safety = isSafePayloadDirectory(appDataRoot, link)
        assert.equal(safety.safe, false)
        assert.match(safety.reason, /symbolic-link|junction/i)
    })

    await runProbe('orphan junction-like payloads are surfaced but cleanup-blocked', async () => {
        const vaultDir = makeVault('junction-orphan-scan')
        const appDataRoot = join(vaultDir, 'AppData')
        const target = join(vaultDir, 'outside-target')
        const link = join(appDataRoot, 'LinkedOrphan')
        mkdirSync(target, { recursive: true })
        symlinkSync(target, link, 'junction')

        const payloads = await findStaleUnsupportedAppDataPayloads({ desktopApps: [] }, vaultDir)
        const blocked = payloads.find(payload => payload.path === link)
        assert.equal(!!blocked, true)
        assert.equal(blocked.cleanupBlocked, true)
        assert.match(blocked.cleanupBlockedReason, /symbolic-link|junction/i)
    })

    console.log('\nQuickPass lifecycle probes passed.')
} finally {
    rmSync(tempRoot, { recursive: true, force: true })
}

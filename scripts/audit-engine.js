const assert = require('assert')
const fs = require('fs')
const { join } = require('path')

console.log('Starting QuickPass orchestration audit...\n')

const engineCode = fs.readFileSync(join(process.cwd(), 'src/main/engine.js'), 'utf-8')
const indexCode = fs.readFileSync(join(process.cwd(), 'src/main/index.js'), 'utf-8')
const manifestCode = fs.readFileSync(join(process.cwd(), 'src/main/appManifest.js'), 'utf-8')
const appAdaptersCode = fs.readFileSync(join(process.cwd(), 'src/main/appAdapters.js'), 'utf-8')
const staleAppDataCode = fs.readFileSync(join(process.cwd(), 'src/main/staleAppData.js'), 'utf-8')
const importAppsModalCode = fs.readFileSync(join(process.cwd(), 'src/renderer/src/components/ImportAppsModal.jsx'), 'utf-8')
const dashboardCode = fs.readFileSync(join(process.cwd(), 'src/renderer/src/components/DashboardScreen.jsx'), 'utf-8')
const packageJson = JSON.parse(fs.readFileSync(join(process.cwd(), 'package.json'), 'utf-8'))

function runCheck(name, check) {
    process.stdout.write(`- ${name}: `)
    try {
        check()
        console.log('PASS')
    } catch (err) {
        console.error('FAIL')
        console.error(`  ${err.message}`)
        process.exit(1)
    }
}

runCheck('File Explorer orchestration for folder launches', () => {
    assert(
        engineCode.includes("spawn('explorer.exe', [appPath, ...args]") ||
        engineCode.includes('spawn("explorer.exe", [appPath, ...args]'),
        'Expected folder launches to use explorer.exe with the resolved appPath.'
    )
})

runCheck('Graceful app teardown with timeout escalation', () => {
    assert(
        engineCode.includes('function buildTaskkillCommand') &&
        engineCode.includes("${tree ? ' /T' : ''}") &&
        engineCode.includes("${force ? ' /F' : ''}"),
        'Expected centralized taskkill command construction with explicit /T and /F support.'
    )
    assert(
        engineCode.includes("killPidSync(app.pid, { tree: true, force: false })") &&
        engineCode.includes("killPidSync(app.pid, { tree: true, force: true })") &&
        engineCode.includes("killPidSync(pid, { tree: true, force: true })"),
        'Expected graceful root kills, force escalation, and owned successor tree-force kills.'
    )
})

runCheck('Legacy launcher delegates to the active implementation', () => {
    assert(
        engineCode.includes('async function launchDesktopAppLegacy(appConfig, onStatus, vaultDir) {') &&
        engineCode.includes('return launchDesktopApp(appConfig, onStatus, vaultDir)'),
        'Expected the legacy launcher path to delegate to the active launchDesktopApp implementation.'
    )
})

runCheck('Imported AppData uses an explicit support matrix', () => {
    assert(
        engineCode.includes('function resolveRuntimeDataPlan') &&
        manifestCode.includes('function resolveImportedAppDataCapability') &&
        manifestCode.includes('function resolveManifestDataProfile') &&
        manifestCode.includes('function normalizeAppConfigImportedData') &&
        manifestCode.includes('dataProfile: resolveManifestDataProfile') &&
        engineCode.includes("runtimeProfileSupportLevel: RUNTIME_DATA_SUPPORT_LEVELS.BEST_EFFORT") &&
        engineCode.includes("importedDataSupportLevel: RUNTIME_DATA_SUPPORT_LEVELS.UNSUPPORTED") &&
        engineCode.includes("runtimeSupportWarning: 'Using best-effort Electron runtime isolation.") &&
        engineCode.includes('supportsImportedAppDataRedirection') &&
        indexCode.includes('requestedImportData && !importedDataCapability.importedDataSupported') &&
        indexCode.includes('importData: effectiveImportData') &&
        indexCode.includes("ipcMain.handle('scan-stale-appdata'") &&
        indexCode.includes("ipcMain.handle('cleanup-stale-appdata'") &&
        indexCode.includes('function loadActiveVaultWorkspace') &&
        indexCode.includes('findStaleUnsupportedAppDataPayloads(workspace, getVaultDir()') &&
        indexCode.includes('!Array.isArray(payloadIds) || payloadIds.length === 0') &&
        staleAppDataCode.includes('realpathSync.native') &&
        staleAppDataCode.includes('lstatSync') &&
        staleAppDataCode.includes('cleanupBlocked') &&
        staleAppDataCode.includes('findStaleUnsupportedAppDataPayloads') &&
        staleAppDataCode.includes('orphaned: true') &&
        importAppsModalCode.includes('canImportAppData(app)') &&
        importAppsModalCode.includes('App data import unavailable') &&
        engineCode.includes('imported-data-misconfigured') &&
        engineCode.includes('imported-data-unsupported') &&
        engineCode.includes('getUnsupportedImportedDataMessage'),
        'Expected imported AppData support to be centralized and enforced across UI, import, manifest creation, and launch.'
    )
})

runCheck('App adapter resolver foundation is explicit and regression-covered', () => {
    assert(
        appAdaptersCode.includes('export const SUPPORT_TIERS') &&
        appAdaptersCode.includes('export const APP_ADAPTER_IDS') &&
        appAdaptersCode.includes('export function resolveAppCapability') &&
        appAdaptersCode.includes("CHROMIUM_USER_DATA_DIR: 'chromium-user-data-dir'") &&
        appAdaptersCode.includes("VSCODE_USER_DATA_DIR: 'vscode-user-data-dir'") &&
        appAdaptersCode.includes("ELECTRON_USER_DATA_DIR: 'electron-user-data-dir'") &&
        appAdaptersCode.includes("NATIVE_LAUNCH_ONLY: 'native-launch-only'") &&
        appAdaptersCode.includes("OBS_PORTABLE: 'obs-portable'") &&
        manifestCode.includes('resolveAppCapability') &&
        manifestCode.includes("from './appAdapters.js'") &&
        manifestCode.includes('const capability = resolveAppCapability') &&
        fs.readFileSync(join(process.cwd(), 'scripts/lifecycle-probe.js'), 'utf-8').includes('app capability resolver keeps golden adapter classifications stable'),
        'Expected a pure app adapter resolver with support tiers, adapter IDs, appManifest delegation, and lifecycle golden coverage.'
    )
})

runCheck('Manifest V2 support metadata is visible without new app powers', () => {
    const lifecycleProbeCode = fs.readFileSync(join(process.cwd(), 'scripts/lifecycle-probe.js'), 'utf-8')
    assert(
        manifestCode.includes('export const APP_MANIFEST_SCHEMA_VERSION = 2') &&
        manifestCode.includes('export function resolveManifestSupportFields') &&
        manifestCode.includes('export function pickSupportFields') &&
        manifestCode.includes("launchSourceType: resolvedLaunchSourceType") &&
        manifestCode.includes("launchMethod: resolvedLaunchMethod") &&
        manifestCode.includes("ownershipProofLevel: resolvedOwnership") &&
        manifestCode.includes('const resolvedDataManagement') &&
        manifestCode.includes("dataManagement: resolvedDataManagement") &&
        indexCode.includes('resolveManifestSupportFields') &&
        indexCode.includes('...pickSupportFields(manifest)') &&
        engineCode.includes('...pickSupportFields(manifest)') &&
        engineCode.includes('supportTier: supportFields.supportTier') &&
        importAppsModalCode.includes('getSupportBadge') &&
        importAppsModalCode.includes('Verified adapter') &&
        dashboardCode.includes('getSupportBadge') &&
        lifecycleProbeCode.includes('Manifest V2 emits support fields for golden app families'),
        'Expected Manifest V2 support fields to flow through manifests, scan/import results, diagnostics, and renderer support badges.'
    )
})

runCheck('Stale AppData cleanup is saved-state and confirmation guarded', () => {
    assert(
        importAppsModalCode.includes('canImportAppData(app)') &&
        indexCode.includes('const workspace = loadActiveVaultWorkspace()') &&
        indexCode.includes('Select at least one AppData payload to remove.') &&
        staleAppDataCode.includes('Selected AppData payloads are no longer stale in the saved workspace.') &&
        indexCode.includes('isSafePayloadDirectory') &&
        staleAppDataCode.includes('Refused to remove symbolic-link or junction AppData payload.') &&
        importAppsModalCode.includes('App data import unavailable'),
        'Expected stale AppData cleanup to rederive saved-state payloads and reject unsafe deletion targets.'
    )
    assert(
        dashboardCode.includes('hasUnsavedAppChanges') &&
        dashboardCode.includes('Save or discard workspace changes before removing unused AppData.') &&
        dashboardCode.includes('showStaleCleanupConfirm') &&
        dashboardCode.includes('Delete unused AppData') &&
        dashboardCode.includes('removableStaleAppDataPayloads'),
        'Expected Dashboard cleanup to be blocked by unsaved changes and guarded by explicit confirmation.'
    )
})

runCheck('Stale AppData inspection is read-only and executable-probe backed', () => {
    assert(
        manifestCode.includes('repairLegacyAppConfig(appConfig, vaultDir, options = {})') &&
        manifestCode.includes('const { persist = true } = options') &&
        manifestCode.includes('persist && normalized.changed') &&
        manifestCode.includes('manifest-profile-normalized-readonly') &&
        manifestCode.includes("persist ? builtManifest.repairStatus : 'legacy-manifest-inspected'") &&
        staleAppDataCode.includes('persistLegacyRepairs = false') &&
        staleAppDataCode.includes('repairLegacyAppConfig(desktopApp, vaultDir, { persist: persistLegacyRepairs })') &&
        staleAppDataCode.includes('function hasActiveImportedAppData') &&
        staleAppDataCode.includes('appConfig?.portableData === false') &&
        staleAppDataCode.includes('!entry.isDirectory() && !entry.isSymbolicLink()') &&
        staleAppDataCode.includes('selectStaleAppDataPayloads') &&
        packageJson.scripts?.['probe:lifecycle']?.includes('scripts/lifecycle-probe.js'),
        'Expected stale AppData inspection to be read-only by default and covered by lifecycle probes.'
    )
})

runCheck('Successor query failures block unsafe sync and cleanup', () => {
    assert(
        engineCode.includes('const successorDiscoveryFailed = shouldEvaluateSuccessors') &&
        engineCode.includes('const successorDiscoveryUncertain = shouldEvaluateSuccessors') &&
        engineCode.includes('const successorSafetyBlocked = successorDiscoveryFailed || successorDiscoveryUncertain') &&
        engineCode.includes('Could not confirm successor shutdown:') &&
        engineCode.includes('Could not confirm successor shutdown before sync:') &&
        engineCode.includes('No successor ownership proof was available after launcher exit') &&
        engineCode.includes('!successorSafetyBlocked'),
        'Expected teardown to treat successor query failure and successor uncertainty as unsafe for sync and runtime-profile cleanup.'
    )
})

runCheck('USB hardware kill-cord hook', () => {
    assert(
        indexCode.includes("const { usb } = require('usb')") && indexCode.includes("usb.on('detach', usbListener)"),
        'Expected native USB detach listener to be wired.'
    )
})

runCheck('Cryptographic memory wipe on quit', () => {
    assert(
        indexCode.includes("app.on('before-quit', async (e) => {") && indexCode.includes('setActiveMasterPassword(null)'),
        'Expected Electron before-quit hook to clear cached master password.'
    )
})

runCheck('Browser bot-mitigation init script', () => {
    assert(
        engineCode.includes("Object.defineProperty(navigator, 'webdriver', { get: () => undefined })") &&
        engineCode.includes('if (!window.chrome)') &&
        engineCode.includes('window.chrome = { runtime: {} }'),
        'Expected webdriver patch and conservative window.chrome fallback.'
    )
})

runCheck('Browser URL classification skips internal/error pages', () => {
    assert(engineCode.includes('function createSkippedBrowserResult'), 'Expected structured skipped browser result helper.')
    assert(engineCode.includes("'chrome-error': 'browser-error-page'"), 'Expected chrome-error scheme classification.')
    assert(engineCode.includes("'view-source': 'browser-internal-page'"), 'Expected view-source scheme classification.')
    assert(engineCode.includes("'mailto': 'external-protocol-url'"), 'Expected mailto scheme classification.')
    assert(engineCode.includes('hostPortPattern'), 'Expected host:port preservation before generic scheme rejection.')
    assert(engineCode.includes('classification.capturable'), 'Expected capture filtering through URL classification.')
    assert(engineCode.includes('!classification.launchable'), 'Expected launch filtering before page.goto retries.')
})

runCheck('Diagnostics cycles start at action boundary', () => {
    assert(indexCode.includes("beginDiagnosticsCycle('setup')"), 'Expected setup IPC handler to begin a diagnostics cycle before cleanup.')
    assert(indexCode.includes("beginDiagnosticsCycle('edit')"), 'Expected edit IPC handler to begin a diagnostics cycle before cleanup.')
    assert(indexCode.includes("beginDiagnosticsCycle('launch')"), 'Expected launch IPC handler to begin a diagnostics cycle before cleanup.')
    assert(engineCode.includes('skipDiagnosticsCycle'), 'Expected engine launch functions to support caller-owned diagnostics cycles.')
    assert(engineCode.includes('JSON.parse(JSON.stringify(snapshot))'), 'Expected archived diagnostics cycles to be deep cloned.')
    assert(engineCode.includes('ensureAppDiagnosticInActiveCycle'), 'Expected app cleanup diagnostics to be reattached to the active cycle.')
})

runCheck('Desktop readiness verifies window/process evidence', () => {
    assert(engineCode.includes('function ensureAppReadiness'), 'Expected desktop readiness verification helper.')
    assert(engineCode.includes('MainWindowHandle'), 'Expected visible-window probing through MainWindowHandle.')
    assert(engineCode.includes('collectRelatedProcessSnapshot'), 'Expected related process tree snapshots.')
    assert(engineCode.includes('fallbackFromMissedHandoff'), 'Expected launcher handoff misses to fall back to readiness evidence.')
    assert(engineCode.includes("launchVerifiedBy: 'visible-window'"), 'Expected visible-window readiness to replace initial PID success.')
    assert(engineCode.includes("'running-no-window'"), 'Expected no-window diagnostics for running apps.')
    assert(engineCode.includes("'exited-early'"), 'Expected early-exit diagnostics.')
})

runCheck('Desktop readiness hardening avoids P1 regressions', () => {
    assert(!engineCode.includes('spawnSync'), 'Expected readiness probing to avoid blocking spawnSync in the main process.')
    assert(engineCode.includes('DESKTOP_APP_LAUNCH_CONCURRENCY'), 'Expected bounded app launch/readiness concurrency.')
    assert(engineCode.includes('READINESS_EMPTY_TREE_GRACE_MS'), 'Expected empty process-tree grace before exited-early.')
    assert(!engineCode.includes('findPidsByProcessNameSync'), 'Expected sync teardown to avoid bare same-name process fallback.')
    assert(engineCode.includes('refused same-name teardown fallback'), 'Expected sync teardown to fail closed when no ownership fingerprint is available.')
    assert(engineCode.includes('collectReadinessSnapshotFromPowerShell'), 'Expected collapsed readiness snapshot collection.')
    assert(engineCode.includes("'readiness-probe-failed'"), 'Expected probe failures to surface as a distinct readiness status.')
    assert(!engineCode.includes('Get-CimInstance Win32_Process | ForEach-Object'), 'Expected readiness snapshots to avoid full process-table enumeration.')
})

runCheck('Browser app ownership is isolated and cleanup-safe', () => {
    assert(manifestCode.includes('msedge.dll') && manifestCode.includes('normalizeManifestProfiles'), 'Expected Edge/Chromium manifests to be detected and normalized.')
    assert(engineCode.includes('resolveEffectiveLaunchProfile'), 'Expected launch path to compute an effective runtime profile.')
    assert(engineCode.includes('needsRuntimeUserDataDir'), 'Expected runtime profile handling beyond appConfig.portableData.')
    assert(engineCode.includes('QuickPass-AppRuntime'), 'Expected runtime-only isolated user-data directories for browser apps.')
    assert(engineCode.includes('isOwnedRuntimeProfilePath'), 'Expected strict ownership validation before runtime profile deletion.')
    assert(engineCode.includes('findRuntimeProfileUsersSync'), 'Expected live process checks before runtime profile deletion.')
    assert(engineCode.includes('wipeAllRuntimeAppProfiles'), 'Expected global stale runtime profile cleanup.')
    assert(indexCode.includes('wipeAllRuntimeAppProfiles'), 'Expected app lifecycle cleanup to include runtime-only profiles.')
    assert(engineCode.includes('runtimeProfileWipeSkippedForSafety'), 'Expected unsafe runtime profile wipes to be skipped and diagnosed.')
    assert(engineCode.includes('--no-default-browser-check') && engineCode.includes('--no-first-run'), 'Expected Chromium/Edge launch hardening args.')
    assert(engineCode.includes('cleanupRequiresStrongOwnership'), 'Expected diagnostics for cleanup ownership requirements.')
    assert(engineCode.includes('allowProcessNameFallback: !strongOwnershipRequired'), 'Expected browser cleanup to disable broad same-name fallback.')
    assert(engineCode.includes('cleanupSkippedForSafety'), 'Expected weak browser cleanup to be skipped and diagnosed.')
})

runCheck('Early-exit diagnostics and top-level window evidence', () => {
    assert(engineCode.includes('boundedStdout') && engineCode.includes('boundedStderr'), 'Expected bounded stdout/stderr capture for short-lived runtime failures.')
    assert(engineCode.includes('exitCode') && engineCode.includes('exitSignal') && engineCode.includes('lifetimeMs'), 'Expected desktop app exit metadata in diagnostics.')
    assert(engineCode.includes('EnumWindows') && engineCode.includes('GetWindowThreadProcessId'), 'Expected top-level window enumeration for visible-window readiness.')
    assert(engineCode.includes('windowDetectionSource'), 'Expected readiness diagnostics to record the window detection source.')
})

console.log('\nQuickPass orchestration audit passed.')

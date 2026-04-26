import { useState, useEffect, useRef } from 'react'
import ImportAppsModal from './ImportAppsModal'

export default function DashboardScreen({ driveInfo, workspace, vaultMeta, onSave, onCancel }) {
    const [webTabs, setWebTabs] = useState(workspace?.webTabs || [])
    const [desktopApps, setDesktopApps] = useState(workspace?.desktopApps || [])
    const [saving, setSaving] = useState(false)
    const [error, setError] = useState('')
    const [sessionWarning, setSessionWarning] = useState('')
    const [staleAppDataPayloads, setStaleAppDataPayloads] = useState([])
    const [staleAppDataLoading, setStaleAppDataLoading] = useState(false)
    const [staleAppDataStatus, setStaleAppDataStatus] = useState('')
    const [showStaleCleanupConfirm, setShowStaleCleanupConfirm] = useState(false)
    const staleAppDataScanRef = useRef(0)

    const [showAppForm, setShowAppForm] = useState(false)
    const [appForm, setAppForm] = useState({ name: '', path: '', args: '', portableData: false })
    const [hostInstalledApps, setHostInstalledApps] = useState([])
    const [hostInstalledLoading, setHostInstalledLoading] = useState(false)
    const [hostInstalledError, setHostInstalledError] = useState('')
    const [showImportModal, setShowImportModal] = useState(false)

    const [masterPassword, setMasterPassword] = useState('')
    const [currentMasterPassword, setCurrentMasterPassword] = useState('')
    const [confirmMasterPassword, setConfirmMasterPassword] = useState('')
    const [expandedSecurityOption, setExpandedSecurityOption] = useState(null) // 'password' | 'pin' | null

    // Security fields
    const [usePin, setUsePin] = useState(false)
    const [pin, setPin] = useState('')
    const [confirmPin, setConfirmPin] = useState('')
    const [fastBoot, setFastBoot] = useState(false)
    const [clearCacheOnExit, setClearCacheOnExit] = useState(true) // default ON = zero footprint

    // Read the freshest meta from disk on mount to perfectly sync security UI toggles
    useEffect(() => {
        const fetchMeta = async () => {
            const latestMeta = await window.omnilaunch.loadVaultMeta()
            if (latestMeta) {
                setUsePin(latestMeta.hasPIN || false)
                setFastBoot(latestMeta.fastBoot || false)
                setClearCacheOnExit(latestMeta.clearCacheOnExit !== false) // default ON
            } else if (vaultMeta) {
                // Fallback to prop if fetch fails
                setUsePin(vaultMeta.hasPIN || false)
                setFastBoot(vaultMeta.fastBoot || false)
                setClearCacheOnExit(vaultMeta.clearCacheOnExit !== false)
            }
        }
        fetchMeta()
    }, [])

    // Session edit/recapture state
    const [sessionMode, setSessionMode] = useState(null) // 'edit' | 'recapture'
    const [browserOpen, setBrowserOpen] = useState(false)
    const [captureSuccess, setCaptureSuccess] = useState(false)
    const isInSessionMode = sessionMode !== null
    const hasUnsavedAppChanges = JSON.stringify(desktopApps) !== JSON.stringify(workspace?.desktopApps || [])

    const HOST_LAUNCH_SOURCE_TYPES = new Set(['host-exe', 'host-folder', 'registry-uninstall', 'app-paths', 'start-menu-shortcut', 'shell-execute', 'protocol-uri', 'packaged-app'])
    const isManualHostExePath = (path) => /\.exe$/i.test(String(path || '').trim())
    const isManualAbsoluteHostPath = (path) => /^[a-z]:\\/i.test(String(path || '').trim())
    const isHostLaunchForm = (form = appForm) => HOST_LAUNCH_SOURCE_TYPES.has(form.launchSourceType) || isManualHostExePath(form.path)
    const getAppDisplayName = (app) => app?.name || app?.displayName || ''
    const toCapabilityWorkspaceEntry = (app) => {
        if (app?.quarantined) {
            return {
                id: app.id,
                displayName: getAppDisplayName(app) || 'Quarantined app',
                enabled: false,
                quarantined: true,
                quarantineReason: app.quarantineReason,
                quarantineCode: app.quarantineCode
            }
        }
        const displayName = getAppDisplayName(app)
        return {
            id: app.id,
            capabilityId: app.capabilityId,
            displayName,
            name: displayName,
            enabled: app.enabled !== false
        }
    }
    const toCapabilityWorkspace = (apps) => apps.map(toCapabilityWorkspaceEntry)

    const createManualHostExeFields = (name) => ({
        supportTier: 'launch-only',
        supportSummary: 'Host-installed launch-only app. Data is unmanaged and only available on PCs where this .exe exists.',
        adapterEvidence: 'none',
        launchSourceType: 'host-exe',
        launchMethod: 'spawn',
        ownershipProofLevel: 'none',
        closePolicy: 'never',
        canQuitFromOmniLaunch: false,
        availabilityStatus: 'unknown',
        dataManagement: 'unmanaged',
        requiresElevation: false,
        resolvedAt: null,
        resolvedHostId: null,
        launchAdapter: 'native-launch-only',
        runtimeAdapter: 'none',
        dataAdapters: [],
        registryAdapters: [],
        limitations: [
            'Data is not copied or synced by OmniLaunch.',
            'Quit is enabled only after OmniLaunch launches and owns the process.'
        ],
        certification: { status: 'uncertified', lastCheckedAt: null, checks: [] },
        importedDataSupported: false,
        importedDataSupportLevel: 'unsupported',
        importedDataAdapterId: 'none',
        importedDataSupportReason: `Host-installed app data is unmanaged for ${name || 'this app'}.`
    })

    const createManualHostFolderFields = () => ({
        supportTier: 'launch-only',
        supportSummary: 'Host folder launch reference. OmniLaunch opens it through the Windows shell and does not own a child process.',
        adapterEvidence: 'none',
        launchSourceType: 'host-folder',
        launchMethod: 'shell-execute',
        ownershipProofLevel: 'none',
        closePolicy: 'never',
        canQuitFromOmniLaunch: false,
        closeManagedAfterSpawn: false,
        availabilityStatus: 'unknown',
        dataManagement: 'unmanaged',
        requiresElevation: false,
        launchAdapter: 'windows-shell-folder',
        runtimeAdapter: 'none',
        dataAdapters: [],
        registryAdapters: [],
        limitations: [
            'Folders are opened by the Windows shell.',
            'OmniLaunch cannot prove process ownership for a folder launch.',
            'Quit and cleanup are disabled for this launch source.'
        ],
        certification: { status: 'uncertified', lastCheckedAt: null, checks: [] },
        importedDataSupported: false,
        importedDataSupportLevel: 'unsupported',
        importedDataAdapterId: 'none',
        importedDataSupportReason: 'Folders do not have portable app data management.'
    })

    const handleUnsupportedBrowseSelection = (selected) => {
        if (selected?.success !== false) return false
        setError(selected.error || 'Selected app cannot be added.')
        return true
    }

    const browseExe = async () => {
        const selected = await window.omnilaunch.browseExe()
        if (!selected || handleUnsupportedBrowseSelection(selected)) return

        const filePath = typeof selected === 'string' ? selected : selected.path
        if (!filePath) {
            setError('Selected executable did not include a launch capability.')
            return
        }
        const name = selected.displayName || selected.name || filePath.split('\\').pop().replace('.exe', '')
        const selectedFields = typeof selected === 'object' ? selected : {}
        const hostSupportFields = selectedFields.launchSourceType === 'vault-archive' || selectedFields.launchSourceType === 'vault-directory'
            ? {}
            : createManualHostExeFields(name)
        setError('')
        setAppForm({
            ...appForm,
            ...hostSupportFields,
            ...selectedFields,
            path: filePath,
            name,
            portableData: false
        })
    }

    const browseFolder = async () => {
        const selected = await window.omnilaunch.browseFolder()
        if (!selected || handleUnsupportedBrowseSelection(selected)) return

        const folderPath = typeof selected === 'string' ? selected : selected.path
        if (!folderPath) {
            setError('Selected folder did not include a launch capability.')
            return
        }
        const name = selected.displayName || selected.name || folderPath.split('\\').pop()
        setError('')
        setAppForm({
            ...(typeof selected === 'object' ? selected : {}),
            name,
            path: folderPath,
            args: appForm.args || '',
            portableData: false,
            ...createManualHostFolderFields()
        })
    }

    const scanInstalledApps = async () => {
        setHostInstalledLoading(true)
        setHostInstalledError('')
        try {
            const result = await window.omnilaunch.scanHostInstalledApps()
            if (!result?.success) {
                throw new Error(result?.error || 'Installed app scan failed')
            }
            setHostInstalledApps(result.apps || [])
        } catch (err) {
            setHostInstalledError(err.message || 'Installed app scan failed')
            setHostInstalledApps([])
        } finally {
            setHostInstalledLoading(false)
        }
    }

    const selectInstalledApp = (app) => {
        setAppForm({
            ...app,
            args: app.args || '',
            portableData: false
        })
    }

    const getHostSourceLabel = (item) => {
        if (item?.launchSourceType === 'app-paths') return 'App Paths'
        if (item?.launchSourceType === 'start-menu-shortcut') return 'Shortcut'
        if (item?.launchSourceType === 'shell-execute') return 'Shell'
        if (item?.launchSourceType === 'protocol-uri') return 'Protocol'
        if (item?.launchSourceType === 'packaged-app') return 'Packaged'
        if (item?.launchSourceType === 'registry-uninstall') return 'Registry'
        if (item?.launchSourceType === 'host-folder') return 'Folder'
        return 'Host EXE'
    }

    const addDesktopApp = () => {
        if (!appForm.capabilityId) {
            setError('Select an app or folder from the picker before adding it.')
            return
        }
        const isKnownHostLaunch = HOST_LAUNCH_SOURCE_TYPES.has(appForm.launchSourceType)
        const isHostExe = isManualHostExePath(appForm.path) && !isKnownHostLaunch
        const isHostFolder = isManualAbsoluteHostPath(appForm.path) && !isHostExe && !isKnownHostLaunch
        const isHostLaunch = isKnownHostLaunch || isHostExe || isHostFolder
        const nextApp = {
            ...appForm,
            ...(isHostExe ? createManualHostExeFields(appForm.name) : {}),
            ...(isHostFolder ? createManualHostFolderFields() : {}),
            portableData: isHostLaunch ? false : appForm.portableData,
            id: Date.now(),
            enabled: true
        }
        setDesktopApps([...desktopApps, toCapabilityWorkspaceEntry(nextApp)])
        setAppForm({ name: '', path: '', args: '', portableData: false })
        setShowAppForm(false)
    }

    const getSupportBadge = (item) => {
        const badges = {
            verified: {
                label: item?.adapterEvidence === 'app-certified' ? 'Certified app' : 'Verified adapter',
                className: 'bg-emerald-900/35 text-emerald-300 border-emerald-700/40'
            },
            'best-effort': {
                label: 'Best effort',
                className: 'bg-amber-900/30 text-amber-300 border-amber-700/40'
            },
            'launch-only': {
                label: 'Launch only',
                className: 'bg-slate-800/70 text-slate-300 border-slate-600/50'
            },
            'needs-adapter': {
                label: 'Needs adapter',
                className: 'bg-orange-900/35 text-orange-300 border-orange-700/40'
            },
            unsupported: {
                label: 'Unsupported',
                className: 'bg-red-900/35 text-red-300 border-red-700/40'
            }
        }

        return item?.supportTier ? badges[item.supportTier] : null
    }

    const toggleItem = (list, setList, index) => {
        const updated = [...list]
        updated[index] = { ...updated[index], enabled: !updated[index].enabled }
        setList(updated)
    }

    const handleSaveClick = async () => {
        setSaving(true)
        setError('')
        const workspacePayload = { webTabs, desktopApps: toCapabilityWorkspace(desktopApps) }
        const result = await window.omnilaunch.saveWorkspace(workspacePayload)
        if (result.success) {
            onSave(false, result.workspace || workspacePayload)
        } else {
            setError(result.error || 'Save failed')
            setSaving(false)
        }
    }

    const handleUpdatePassword = async () => {
        if (!currentMasterPassword.trim()) return setError('Current password is required')
        if (masterPassword.length < 8) return setError('Password must be at least 8 characters')
        if (masterPassword !== confirmMasterPassword) return setError('Passwords do not match')

        setSaving(true)
        setError('')
        const result = await window.omnilaunch.saveVault({
            masterPassword,
            currentPassword: currentMasterPassword,
            pin: null, // Wipe PIN securely when password changes
            fastBoot: false, // Wipe FastBoot securely when password changes
            workspace: { webTabs, desktopApps: toCapabilityWorkspace(desktopApps) }
        })

        if (result.success) {
            setCurrentMasterPassword('')
            setMasterPassword('')
            setConfirmMasterPassword('')
            setUsePin(false)
            setFastBoot(false)
            setExpandedSecurityOption(null)
            setError('Password updated! (PIN & FastBoot disabled)')
            setTimeout(() => setError(''), 4000)
        } else {
            setError(result.error || 'Update failed')
        }
        setSaving(false)
    }

    const handleUpdatePin = async () => {
        if (pin.length !== 4) return setError('PIN must be exactly 4 digits')
        if (pin !== confirmPin) return setError('PINs do not match')

        setSaving(true)
        setError('')
        const result = await window.omnilaunch.updatePin(pin)

        if (result.success) {
            setUsePin(true)
            setPin('')
            setConfirmPin('')
            setExpandedSecurityOption(null)
            setError('PIN updated successfully!')
            setTimeout(() => setError(''), 3000)
        } else {
            setError(result.error || 'PIN update failed')
        }
        setSaving(false)
    }

    const handleDisablePin = async () => {
        // Phase 17.2: USB uses hidden password and must keep at least one unlock method.
        if (driveInfo?.supportsConvenienceUnlock && !fastBoot) {
            setError('Enable Fast Boot first - PIN is your only unlock method on USB drives')
            return
        }
        setSaving(true)
        setError('')
        const result = await window.omnilaunch.updatePin(null)

        if (result.success) {
            setUsePin(false)
            setPin('')
            setConfirmPin('')
            setExpandedSecurityOption(null)
            setError('PIN disabled.')
            setTimeout(() => setError(''), 3000)
        } else {
            setError(result.error || 'Failed to disable PIN')
        }
        setSaving(false)
    }

    const handleToggleFastBoot = async () => {
        const newState = !fastBoot
        // Phase 17.2: USB uses hidden password and must keep at least one unlock method.
        if (!newState && driveInfo?.supportsConvenienceUnlock && !usePin) {
            setError('Enable PIN first - Fast Boot is your only unlock method on USB drives')
            return
        }
        setError('')
        const result = await window.omnilaunch.updateFastBoot(newState)
        if (result.success) {
            setFastBoot(newState)
        } else {
            setError('Failed to update FastBoot')
        }
    }

    const handleToggleClearCache = async () => {
        const newState = !clearCacheOnExit
        setError('')
        const result = await window.omnilaunch.updateClearCache(newState)
        if (result.success) {
            setClearCacheOnExit(newState)
        } else {
            setError('Failed to update setting')
        }
    }

    const refreshStaleAppDataPayloads = async () => {
        if (!window.omnilaunch?.scanStaleAppData) return
        const requestId = ++staleAppDataScanRef.current
        setStaleAppDataLoading(true)
        try {
            const result = await window.omnilaunch.scanStaleAppData()
            if (requestId === staleAppDataScanRef.current && result?.success) {
                setStaleAppDataPayloads(result.payloads || [])
            }
        } finally {
            if (requestId === staleAppDataScanRef.current) {
                setStaleAppDataLoading(false)
            }
        }
    }

    useEffect(() => {
        if (isInSessionMode || hasUnsavedAppChanges) {
            staleAppDataScanRef.current += 1
            setStaleAppDataPayloads([])
            setStaleAppDataLoading(false)
            setShowStaleCleanupConfirm(false)
            return
        }

        const timer = setTimeout(() => {
            refreshStaleAppDataPayloads()
        }, 400)

        return () => clearTimeout(timer)
    }, [hasUnsavedAppChanges, isInSessionMode])

    const handleCleanupStaleAppData = async () => {
        if (hasUnsavedAppChanges) {
            setError('Save or discard workspace changes before removing unused AppData.')
            setShowStaleCleanupConfirm(false)
            return
        }
        const removablePayloads = staleAppDataPayloads.filter(payload => !payload.cleanupBlocked)
        if (removablePayloads.length === 0 || staleAppDataLoading) return
        setStaleAppDataLoading(true)
        setStaleAppDataStatus('')
        setError('')
        try {
            const result = await window.omnilaunch.cleanupStaleAppData({
                payloadIds: removablePayloads.map(payload => payload.id)
            })
            if (result?.success) {
                setStaleAppDataPayloads(result.remainingPayloads || [])
                setShowStaleCleanupConfirm(false)
                setStaleAppDataStatus(`${result.removed?.length || 0} unused AppData payload${result.removed?.length === 1 ? '' : 's'} removed.`)
                setTimeout(() => setStaleAppDataStatus(''), 4000)
            } else {
                setStaleAppDataPayloads(result?.remainingPayloads || staleAppDataPayloads)
                setError(result?.error || 'Could not remove unused AppData')
            }
        } finally {
            setStaleAppDataLoading(false)
        }
    }

    const getTabLoadWarning = (result) => {
        if (result?.tabsSuccessful !== false) return ''
        const skippedCount = (result.webResults || []).filter((tab) => tab.skipped).length
        const failedCount = (result.webResults || []).filter((tab) => !tab.success && !tab.skipped).length
        if (failedCount > 0) {
            return `${failedCount} tab${failedCount === 1 ? '' : 's'} failed to load. Reload manually before saving.`
        }
        if (skippedCount > 0) {
            return `${skippedCount} browser-owned tab${skippedCount === 1 ? '' : 's'} will be skipped when you save.`
        }
        return 'Browser opened, but one or more tabs failed to load. Reload manually before saving.'
    }

    const startBrowserSession = async (mode, launcher) => {
        setSessionMode(mode)
        setBrowserOpen(true)
        setError('')
        setSessionWarning('')

        try {
            const result = await launcher()
            if (!result?.success) {
                setSessionMode(null)
                setBrowserOpen(false)
                setError(result?.error || 'Failed to open browser')
                return
            }

            setSessionWarning(getTabLoadWarning(result))
        } catch (err) {
            setSessionMode(null)
            setBrowserOpen(false)
            setSessionWarning('')
            setError(err?.message || 'Failed to open browser')
        }
    }

    // Edit: opens browser with current saved tabs
    const handleEdit = async () => {
        await startBrowserSession('edit', () => window.omnilaunch.startSessionEdit())
    }

    // Re-capture: opens fresh browser from scratch
    const handleRecapture = async () => {
        await startBrowserSession('recapture', () => window.omnilaunch.startSessionSetup())
    }

    // Save and close after edit/recapture
    const handleSessionSave = async () => {
        setSaving(true)
        setError('')
        setSessionWarning('')
        const result = await window.omnilaunch.captureSession({})
        if (result.success) {
            const newWebTabs = result.urls.map(url => ({ url, enabled: true }))
            // Jump directly to LaunchingScreen and trigger auto-relaunch
            onSave(true, { ...workspace, webTabs: newWebTabs })
        } else {
            setError(result.error || 'Capture failed')
            setSaving(false)
        }
    }

    const staleAppDataTotalMB = staleAppDataPayloads.reduce((total, payload) => total + (payload.sizeMB || 0), 0)
    const removableStaleAppDataPayloads = staleAppDataPayloads.filter(payload => !payload.cleanupBlocked)

    return (
        <div className="card p-6 w-full max-w-sm animate-slide-up flex flex-col" style={{ maxHeight: 540 }}>
            <div className="flex items-center justify-between mb-4 flex-shrink-0">
                <h1 className="text-lg font-semibold text-white">Settings</h1>
                {!isInSessionMode && (
                    <button className="btn-secondary text-xs py-1 px-3" onClick={onCancel}>Close</button>
                )}
            </div>

            {/* Scrollable content area */}
            <div className="flex-1 overflow-y-auto min-h-0">

            {/* Session Edit/Recapture Mode */}
            {isInSessionMode && (
                <div className="mb-4 animate-fade-in">
                    <div className="p-3 rounded-lg bg-[#14141c] border border-[#2a2a3a] mb-3">
                        <p className="text-sm text-white font-medium mb-1">
                            {browserOpen
                                ? sessionMode === 'edit' ? 'Editing your tabs' : 'Browser is open'
                                : 'Session updated!'}
                        </p>
                        <p className="text-xs text-secondary">
                            {browserOpen
                                ? sessionMode === 'edit'
                                    ? 'Modify your tabs, log into new sites, then save.'
                                    : 'Navigate to your sites, log in, then save.'
                                : `${webTabs.length} tabs saved`}
                        </p>
                        {browserOpen && (
                            <p className="text-xs text-[#d4a44a] mt-2">Do not close Chrome until you save.</p>
                        )}
                    </div>

                    {browserOpen && sessionWarning && (
                        <p className="text-xs text-[#d4a44a] text-center mb-2">{sessionWarning}</p>
                    )}

                    {browserOpen && (
                        <>
                            <button className="btn-primary w-full mb-2" disabled={saving} onClick={handleSessionSave}>
                                {saving ? (
                                    <span className="flex items-center justify-center gap-2">
                                        <div className="spinner" style={{ width: 14, height: 14, borderWidth: 2 }} /> Saving...
                                    </span>
                                ) : 'Save & Close Browser'}
                            </button>
                            <button className="btn-secondary w-full text-xs" onClick={() => {
                                setSessionMode(null)
                                setBrowserOpen(false)
                                setSessionWarning('')
                            }}>
                                Cancel
                            </button>
                        </>
                    )}
                    {error && <p className="text-error text-xs text-center mt-2">{error}</p>}
                    {captureSuccess && <p className="text-xs text-center mt-2" style={{ color: '#4a9' }}>Session updated!</p>}
                </div>
            )}

            {/* Saved Web Tabs */}
            {!isInSessionMode && (
                <div className="mb-4">
                    <div className="flex items-center justify-between mb-2">
                        <span className="section-label">Saved Tabs</span>
                        <div className="flex gap-1">
                            <button className="btn-secondary text-xs py-1 px-2" onClick={handleEdit} title="Open browser with saved tabs for modification">
                                Edit
                            </button>
                            <button className="btn-secondary text-xs py-1 px-2" onClick={handleRecapture} title="Start fresh with a new browser">
                                Re-capture
                            </button>
                        </div>
                    </div>

                    {webTabs.length === 0 && (
                        <p className="text-muted text-xs text-center py-3">No tabs saved yet</p>
                    )}

                    {webTabs.map((tab, i) => (
                        <div key={i} className="list-item flex items-center gap-3 mb-2">
                            <div
                                className={`toggle-track ${tab.enabled ? 'active' : ''}`}
                                onClick={() => toggleItem(webTabs, setWebTabs, i)}
                            >
                                <div className="toggle-thumb" />
                            </div>
                            <div className="flex-1 min-w-0">
                                <p className="text-sm text-white truncate">{tab.url}</p>
                            </div>
                        </div>
                    ))}
                </div>
            )}

            {/* Desktop Apps & Folders */}
            {!isInSessionMode && (
                <div className="mb-4">
                    <div className="flex items-center justify-between mb-2">
                        <span className="section-label">Apps & Folders</span>
                        <div className="flex gap-1">
                            <button className="btn-secondary text-xs py-1 px-2" onClick={() => setShowImportModal(true)}>
                                Import from PC
                            </button>
                            <button className="btn-secondary text-xs py-1 px-3" onClick={() => setShowAppForm(!showAppForm)}>
                                {showAppForm ? 'Cancel' : '+ Add'}
                            </button>
                        </div>
                    </div>

                    {showAppForm && (
                        <div className="flex flex-col gap-2 p-3 rounded-md mb-2 animate-fade-in bg-[#14141c]">
                            <input className="form-input text-sm" placeholder="Display Name" value={appForm.name} onChange={(e) => setAppForm({ ...appForm, name: e.target.value })} />
                            <div className="flex gap-2">
                                <input className="form-input text-sm flex-1" placeholder="Path (.exe or folder)" value={appForm.path} readOnly />
                                <div className="flex flex-col gap-1 justify-center">
                                    <button className="btn-secondary text-[10px] whitespace-nowrap px-2 py-0.5" onClick={browseExe}>.EXE</button>
                                    <button className="btn-secondary text-[10px] whitespace-nowrap px-2 py-0.5" onClick={browseFolder}>Folder</button>
                                    <button className="btn-secondary text-[10px] whitespace-nowrap px-2 py-0.5" onClick={scanInstalledApps}>
                                        {hostInstalledLoading ? '...' : 'Installed'}
                                    </button>
                                </div>
                            </div>
                            {(hostInstalledApps.length > 0 || hostInstalledError) && (
                                <div className="max-h-32 overflow-y-auto rounded-md border border-[#2a2a3a] bg-[#101018]">
                                    {hostInstalledError && (
                                        <p className="text-[10px] text-error p-2">{hostInstalledError}</p>
                                    )}
                                    {hostInstalledApps.slice(0, 25).map((app) => {
                                        const selectedHostApp = appForm.path === app.path && appForm.launchSourceType === app.launchSourceType

                                        return (
                                        <button
                                            key={app.registryKey || app.appPathsKey || app.shortcutPath || `${app.launchSourceType}:${app.path}`}
                                            type="button"
                                            className={`w-full text-left px-2 py-1.5 border-b border-[#242435] last:border-b-0 hover:bg-[#1a1a2e] ${selectedHostApp ? 'bg-[#1a1a2e]' : ''}`}
                                            onClick={() => selectInstalledApp(app)}
                                        >
                                            <span className="flex items-center gap-1.5">
                                                <span className="text-xs text-white truncate">{app.name}</span>
                                                <span className="px-1 py-0.5 rounded text-[9px] bg-[#1a1a2e] text-muted border border-[#2a2a3a] flex-shrink-0">{getHostSourceLabel(app)}</span>
                                            </span>
                                            <span className="block text-[10px] text-muted truncate">{app.path}</span>
                                            {app.args && (
                                                <span className="block text-[10px] text-[#b8c7ff] truncate">Args: {app.args}</span>
                                            )}
                                            {app.shortcutClassification?.warning && (
                                                <span className="block text-[10px] text-[#d4a44a] truncate">{app.shortcutClassification.warning}</span>
                                            )}
                                            {app.launchSourceType === 'protocol-uri' && (
                                                <span className="block text-[10px] text-[#d4a44a] truncate">No ownership: protocol handler launch</span>
                                            )}
                                            {app.launchSourceType === 'packaged-app' && (
                                                <span className="block text-[10px] text-[#d4a44a] truncate">No ownership: Windows packaged app activation</span>
                                            )}
                                        </button>
                                        )
                                    })}
                                </div>
                            )}
                            <input className="form-input text-sm" placeholder="Launch Args (optional)" value={appForm.args} onChange={(e) => setAppForm({ ...appForm, args: e.target.value })} />
                            {appForm.shortcutClassification?.warning && (
                                <p className="text-[10px] text-[#d4a44a]">{appForm.shortcutClassification.warning}</p>
                            )}
                            <label className="flex items-center gap-2 text-xs text-secondary cursor-pointer py-1">
                                <input
                                    type="checkbox"
                                    checked={isHostLaunchForm(appForm) ? false : appForm.portableData}
                                    disabled={isHostLaunchForm(appForm)}
                                    onChange={(e) => setAppForm({ ...appForm, portableData: e.target.checked })}
                                    className="accent-[#5b7bd5]"
                                />
                                <span>
                                    {isHostLaunchForm(appForm)
                                        ? `${getHostSourceLabel(appForm)} data unmanaged`
                                        : <>Keep app data on USB <span className="text-muted">(Electron/Chrome apps)</span></>}
                                </span>
                            </label>
                            <button className="btn-primary text-sm py-2" onClick={addDesktopApp}>Add Item</button>
                        </div>
                    )}

                    {desktopApps.length === 0 && !showAppForm && (
                        <p className="text-muted text-xs text-center py-3">No apps or folders configured</p>
                    )}

                    {desktopApps.map((dApp, i) => {
                        const supportBadge = getSupportBadge(dApp)

                        return (
                            <div key={dApp.id} className="list-item flex items-center gap-3 mb-2">
                                <div
                                    className={`toggle-track ${dApp.enabled ? 'active' : ''}`}
                                    onClick={() => toggleItem(desktopApps, setDesktopApps, i)}
                                >
                                    <div className="toggle-thumb" />
                                </div>
                                <div className="flex-1 min-w-0">
                                    <div className="flex items-center gap-1.5">
                                        <p className="text-sm text-white truncate">{getAppDisplayName(dApp)}</p>
                                        {dApp.portableData && (
                                            <span className="px-1.5 py-0.5 rounded text-[10px] bg-blue-900/40 text-blue-400 border border-blue-800/40 flex-shrink-0">Portable</span>
                                        )}
                                        {supportBadge && (
                                            <span className={`px-1.5 py-0.5 rounded text-[10px] border flex-shrink-0 ${supportBadge.className}`}>
                                                {supportBadge.label}
                                            </span>
                                        )}
                                    </div>
                                    <p className="text-xs text-muted truncate">{dApp.path || dApp.quarantineReason || 'Launch capability saved'}</p>
                                    {dApp.args && (
                                        <p className="text-[10px] text-[#b8c7ff] truncate">Args: {dApp.args}</p>
                                    )}
                                    {dApp.shortcutClassification?.warning && (
                                        <p className="text-[10px] text-[#d4a44a] truncate">{dApp.shortcutClassification.warning}</p>
                                    )}
                                    {dApp.supportSummary && (
                                        <p className="text-[10px] text-[#d4a44a] truncate">{dApp.supportSummary}</p>
                                    )}
                                </div>
                                <button className="btn-danger-text" onClick={() => setDesktopApps(desktopApps.filter((_, j) => j !== i))}>Remove</button>
                            </div>
                        )
                    })}

                    {hasUnsavedAppChanges && (
                        <div className="mt-3 p-3 rounded-md border border-[#4d5a7d]/70 bg-[#111827]">
                            <p className="text-xs text-[#b8c7ff] font-medium">Cleanup paused while changes are unsaved</p>
                            <p className="text-[11px] text-[#aab5d6] mt-1">
                                Save or discard workspace changes before removing unused AppData.
                            </p>
                        </div>
                    )}

                    {!hasUnsavedAppChanges && staleAppDataPayloads.length > 0 && (
                        <div className="mt-3 p-3 rounded-md border border-[#6f4b1f]/70 bg-[#22170c]">
                            <p className="text-xs text-[#f0c978] font-medium">Unused imported AppData found</p>
                            <p className="text-[11px] text-[#d8b985] mt-1">
                                QuickPass no longer uses this data because the app profile is unsupported or no saved app references the payload.
                            </p>
                            <p className="text-[11px] text-muted mt-1 truncate">
                                {staleAppDataPayloads.map(payload => payload.name).join(', ')}
                            </p>
                            <button
                                className="btn-secondary text-[11px] py-1.5 px-2 mt-2"
                                disabled={staleAppDataLoading}
                                onClick={() => setShowStaleCleanupConfirm(true)}
                            >
                                {staleAppDataLoading ? 'Checking...' : `Review cleanup (${staleAppDataTotalMB} MB)`}
                            </button>
                        </div>
                    )}

                    {staleAppDataStatus && (
                        <p className="text-xs text-[#6fd68a] text-center mt-2">{staleAppDataStatus}</p>
                    )}
                </div>
            )}

            {/* Modular Security Settings */}
            {!isInSessionMode && (
                <div className="mb-4">
                    <div className="flex items-center justify-between mb-2">
                        <span className="section-label">Security Options</span>
                    </div>

                    <div className="flex flex-col gap-2">

                        {/* Master Password Accordion (Local PC Only) */}
                        {!driveInfo?.isRemovable && (
                            <div className="border border-[#2a2a3a] rounded-md overflow-hidden">
                                <button
                                    className="w-full text-left p-3 bg-[#1a1a24] hover:bg-[#20202c] transition-colors text-sm text-white flex justify-between items-center"
                                    onClick={() => setExpandedSecurityOption(expandedSecurityOption === 'password' ? null : 'password')}
                                >
                                    <span>Change Master Password</span>
                                    <span className="text-secondary text-xs">{expandedSecurityOption === 'password' ? '^' : 'v'}</span>
                                </button>
                                {expandedSecurityOption === 'password' && (
                                    <div className="p-3 bg-[#14141c] flex flex-col gap-2 animate-fade-in border-t border-[#2a2a3a]">
                                        <p className="text-xs text-muted mb-1">Changing the master password will reset all other security configurations.</p>
                                            <input
                                                type="password"
                                                className={`form-input text-sm ${error && error.includes('assword') ? 'error' : ''}`}
                                                placeholder="Current Master Password"
                                                value={currentMasterPassword}
                                                onChange={(e) => { setCurrentMasterPassword(e.target.value); setError('') }}
                                                autoFocus
                                            />
                                            <input
                                                type="password"
                                                className={`form-input text-sm ${error && error.includes('assword') ? 'error' : ''}`}
                                                placeholder="New Master Password (8+ chars)"
                                                value={masterPassword}
                                                onChange={(e) => { setMasterPassword(e.target.value); setError('') }}
                                            />
                                        <input
                                            type="password"
                                            className={`form-input text-sm ${error && error.includes('assword') ? 'error' : ''}`}
                                            placeholder="Confirm Master Password"
                                            value={confirmMasterPassword}
                                            onChange={(e) => { setConfirmMasterPassword(e.target.value); setError('') }}
                                        />
                                        <div className="flex gap-2 mt-1">
                                            <button className="btn-secondary flex-1 text-xs" disabled={saving} onClick={() => { setExpandedSecurityOption(null); setCurrentMasterPassword(''); setMasterPassword(''); setConfirmMasterPassword('') }}>Cancel</button>
                                            <button className="btn-primary flex-1 text-xs py-2" disabled={saving || !currentMasterPassword.trim() || !masterPassword.trim()} onClick={handleUpdatePassword}>Update Password</button>
                                        </div>
                                    </div>
                                )}
                            </div>
                        )}

                        {/* PIN Unlock Accordion */}
                        {driveInfo?.supportsConvenienceUnlock && (
                            <div className="border border-[#2a2a3a] rounded-md overflow-hidden">
                                <button
                                    className="w-full text-left p-3 bg-[#1a1a24] hover:bg-[#20202c] transition-colors text-sm text-white flex justify-between items-center"
                                    onClick={() => setExpandedSecurityOption(expandedSecurityOption === 'pin' ? null : 'pin')}
                                >
                                    <div className="flex items-center gap-2">
                                        <span>PIN Access</span>
                                        {usePin && <span className="px-1.5 py-0.5 rounded text-[10px] bg-green-900/40 text-green-400 border border-green-800/40">Active</span>}
                                    </div>
                                    <span className="text-secondary text-xs">{expandedSecurityOption === 'pin' ? '^' : 'v'}</span>
                                </button>
                                {expandedSecurityOption === 'pin' && (
                                    <div className="p-3 bg-[#14141c] flex flex-col gap-2 animate-fade-in border-t border-[#2a2a3a]">
                                        <p className="text-xs text-muted mb-1">{usePin ? 'Update your active 4-digit PIN.' : 'Set up a 4-digit PIN for quick unlocking.'}</p>
                                        <div className="flex gap-2 mb-1">
                                            <input
                                                type="password"
                                                className={`form-input text-center tracking-[0.2em] flex-1 ${error && error.includes('PIN') ? 'error' : ''}`}
                                                placeholder="New 4-Digit PIN"
                                                maxLength={4}
                                                inputMode="numeric"
                                                value={pin}
                                                onChange={(e) => { setPin(e.target.value.replace(/\D/g, '').slice(0, 4)); setError('') }}
                                                autoFocus
                                            />
                                            <input
                                                type="password"
                                                className={`form-input text-center tracking-[0.2em] flex-1 ${error && error.includes('PIN') ? 'error' : ''}`}
                                                placeholder="Confirm PIN"
                                                maxLength={4}
                                                inputMode="numeric"
                                                value={confirmPin}
                                                onChange={(e) => { setConfirmPin(e.target.value.replace(/\D/g, '').slice(0, 4)); setError('') }}
                                            />
                                        </div>
                                        <div className="flex gap-2">
                                            {usePin && (
                                                <button className="btn-danger-text flex-1 text-xs border border-red-900/30 py-2 hover:bg-red-900/20" disabled={saving} onClick={handleDisablePin}>
                                                    Disable PIN
                                                </button>
                                            )}
                                            <button className="btn-primary flex-1 text-xs py-2" disabled={saving} onClick={handleUpdatePin}>
                                                {usePin ? 'Update PIN' : 'Enable PIN'}
                                            </button>
                                        </div>
                                    </div>
                                )}
                            </div>
                        )}

                        {/* Fast Boot Toggle */}
                        {driveInfo?.supportsConvenienceUnlock && (
                            <div className="border border-[#2a2a3a] rounded-md overflow-hidden bg-[#1a1a24] p-3 flex justify-between items-center">
                                <div>
                                    <p className="text-sm text-white">Fast Boot</p>
                                    <p className="text-xs text-muted mt-0.5">Skip PIN & unlock directly via hardware</p>
                                </div>
                                <div className={`toggle-track ${fastBoot ? 'active' : ''}`} onClick={handleToggleFastBoot}>
                                    <div className="toggle-thumb" />
                                </div>
                            </div>
                        )}

                        {/* Clear App Cache on Exit Toggle */}
                        <div className="border border-[#2a2a3a] rounded-md overflow-hidden bg-[#1a1a24] p-3 flex justify-between items-center">
                            <div>
                                <p className="text-sm text-white">Clear App Cache on Exit</p>
                                <p className="text-xs text-muted mt-0.5">{clearCacheOnExit ? 'Apps re-extract on each launch (~2 min)' : 'Instant launches - cached apps persist'}</p>
                            </div>
                            <div className={`toggle-track ${clearCacheOnExit ? 'active' : ''}`} onClick={handleToggleClearCache}>
                                <div className="toggle-thumb" />
                            </div>
                        </div>

                        {error && !error.includes('assword') && !error.includes('PIN') && (
                            <p className="text-error text-xs text-center mt-1">{error}</p>
                        )}
                    </div>
                </div>
            )}

            </div>

            {/* Save Desktop Apps Changes - STICKY */}
            {!isInSessionMode && (
                <div className="flex-shrink-0 pt-3">
                    <button className="btn-primary w-full" disabled={saving} onClick={handleSaveClick}>
                        {saving ? (
                            <span className="flex items-center justify-center gap-2">
                                <div className="spinner" style={{ width: 14, height: 14, borderWidth: 2 }} /> Saving...
                            </span>
                        ) : 'Save Changes'}
                    </button>
                </div>
            )}

            {showImportModal && (
                <ImportAppsModal
                    onClose={() => setShowImportModal(false)}
                    onImportComplete={(importedApps) => {
                        setDesktopApps(prev => [...prev, ...toCapabilityWorkspace(importedApps)])
                        setShowImportModal(false)
                    }}
                />
            )}

            {showStaleCleanupConfirm && (
                <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
                    <div className="w-full max-w-sm rounded-lg border border-[#6f4b1f] bg-[#17110a] shadow-2xl p-4">
                        <p className="text-sm text-white font-semibold">Delete unused AppData?</p>
                        <p className="text-xs text-[#d8b985] mt-2">
                            This permanently removes the listed AppData payloads from the vault. Only data unused by the saved workspace is eligible.
                        </p>
                        <div className="mt-3 max-h-36 overflow-y-auto flex flex-col gap-2">
                            {staleAppDataPayloads.map(payload => (
                                <div key={payload.id} className="rounded bg-black/20 border border-[#3a2a18] p-2">
                                    <p className="text-xs text-white truncate">{payload.name}</p>
                                    <p className="text-[11px] text-muted">{payload.sizeMB || 0} MB - {payload.orphaned ? 'orphaned' : 'unsupported'}</p>
                                    <p className="text-[10px] text-[#d8b985] truncate">{payload.reason}</p>
                                    {payload.cleanupBlocked && (
                                        <p className="text-[10px] text-red-300 truncate">{payload.cleanupBlockedReason || 'Cleanup blocked for safety.'}</p>
                                    )}
                                </div>
                            ))}
                        </div>
                        <div className="flex gap-2 mt-4">
                            <button
                                className="btn-secondary flex-1 text-xs"
                                disabled={staleAppDataLoading}
                                onClick={() => setShowStaleCleanupConfirm(false)}
                            >
                                Cancel
                            </button>
                            <button
                                className="btn-danger-text flex-1 text-xs border border-red-900/50 rounded-md py-2"
                                disabled={staleAppDataLoading || removableStaleAppDataPayloads.length === 0}
                                onClick={handleCleanupStaleAppData}
                            >
                                {staleAppDataLoading ? 'Deleting...' : 'Delete unused AppData'}
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    )
}

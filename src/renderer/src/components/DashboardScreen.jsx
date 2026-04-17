import { useState, useEffect } from 'react'
import ImportAppsModal from './ImportAppsModal'

export default function DashboardScreen({ driveInfo, workspace, vaultMeta, onSave, onCancel }) {
    const [webTabs, setWebTabs] = useState(workspace?.webTabs || [])
    const [desktopApps, setDesktopApps] = useState(workspace?.desktopApps || [])
    const [saving, setSaving] = useState(false)
    const [error, setError] = useState('')
    const [sessionWarning, setSessionWarning] = useState('')

    const [showAppForm, setShowAppForm] = useState(false)
    const [appForm, setAppForm] = useState({ name: '', path: '', args: '', portableData: false })
    const [showImportModal, setShowImportModal] = useState(false)

    const [masterPassword, setMasterPassword] = useState('')
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

    const browseExe = async () => {
        const filePath = await window.omnilaunch.browseExe()
        if (filePath) {
            const name = filePath.split('\\').pop().replace('.exe', '')
            setAppForm({ ...appForm, path: filePath, name })
        }
    }

    const browseFolder = async () => {
        const folderPath = await window.omnilaunch.browseFolder()
        if (folderPath) {
            const name = folderPath.split('\\').pop()
            setAppForm({ ...appForm, path: folderPath, name })
        }
    }

    const addDesktopApp = () => {
        if (!appForm.path.trim()) return
        setDesktopApps([...desktopApps, { ...appForm, id: Date.now(), enabled: true }])
        setAppForm({ name: '', path: '', args: '', portableData: false })
        setShowAppForm(false)
    }

    const toggleItem = (list, setList, index) => {
        const updated = [...list]
        updated[index] = { ...updated[index], enabled: !updated[index].enabled }
        setList(updated)
    }

    const handleSaveClick = async () => {
        setSaving(true)
        setError('')
        const result = await window.omnilaunch.saveWorkspace({ webTabs, desktopApps })
        if (result.success) {
            onSave(false, { webTabs, desktopApps })
        } else {
            setError(result.error || 'Save failed')
            setSaving(false)
        }
    }

    const handleUpdatePassword = async () => {
        if (masterPassword.length < 8) return setError('Password must be at least 8 characters')
        if (masterPassword !== confirmMasterPassword) return setError('Passwords do not match')

        setSaving(true)
        setError('')
        const result = await window.omnilaunch.saveVault({
            masterPassword,
            pin: null, // Wipe PIN securely when password changes
            fastBoot: false, // Wipe FastBoot securely when password changes
            workspace: { webTabs, desktopApps }
        })

        if (result.success) {
            await window.omnilaunch.setMasterPassword(masterPassword)
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
        if (driveInfo?.isRemovable && !fastBoot) {
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
        if (!newState && driveInfo?.isRemovable && !usePin) {
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

    const getTabLoadWarning = (result) => {
        if (result?.tabsSuccessful !== false) return ''
        const failedCount = (result.webResults || []).filter((tab) => !tab.success).length
        return failedCount > 0
            ? `${failedCount} tab${failedCount === 1 ? '' : 's'} failed to load. Reload manually before saving.`
            : 'Browser opened, but one or more tabs failed to load. Reload manually before saving.'
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
        // Phase 17.2: USB users do not know the hidden master password.
        // backend falls back to cached activeMasterPasswordBuffer (index.js:1011)
        if (!driveInfo?.isRemovable && !masterPassword.trim()) {
            setError('Enter your master password first')
            return
        }
        setSaving(true)
        setError('')
        setSessionWarning('')
        const result = await window.omnilaunch.captureSession({ masterPassword })
        if (result.success) {
            const newWebTabs = result.urls.map(url => ({ url, enabled: true }))
            // Jump directly to LaunchingScreen and trigger auto-relaunch
            onSave(true, { ...workspace, webTabs: newWebTabs })
        } else {
            setError(result.error || 'Capture failed')
            setSaving(false)
        }
    }

    const isInSessionMode = sessionMode !== null

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
                            {/* Phase 17.2: Hide password input for USB; backend uses cached password. */}
                            {!driveInfo?.isRemovable && (
                                <input
                                    type="password"
                                    className="form-input text-sm mb-2"
                                    placeholder="Master Password (to re-encrypt)"
                                    value={masterPassword}
                                    onChange={(e) => { setMasterPassword(e.target.value); setError('') }}
                                />
                            )}
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
                                </div>
                            </div>
                            <input className="form-input text-sm" placeholder="Launch Args (optional)" value={appForm.args} onChange={(e) => setAppForm({ ...appForm, args: e.target.value })} />
                            <label className="flex items-center gap-2 text-xs text-secondary cursor-pointer py-1">
                                <input
                                    type="checkbox"
                                    checked={appForm.portableData}
                                    onChange={(e) => setAppForm({ ...appForm, portableData: e.target.checked })}
                                    className="accent-[#5b7bd5]"
                                />
                                <span>Keep app data on USB <span className="text-muted">(Electron/Chrome apps)</span></span>
                            </label>
                            <button className="btn-primary text-sm py-2" onClick={addDesktopApp}>Add Item</button>
                        </div>
                    )}

                    {desktopApps.length === 0 && !showAppForm && (
                        <p className="text-muted text-xs text-center py-3">No apps or folders configured</p>
                    )}

                    {desktopApps.map((dApp, i) => (
                        <div key={dApp.id} className="list-item flex items-center gap-3 mb-2">
                            <div
                                className={`toggle-track ${dApp.enabled ? 'active' : ''}`}
                                onClick={() => toggleItem(desktopApps, setDesktopApps, i)}
                            >
                                <div className="toggle-thumb" />
                            </div>
                            <div className="flex-1 min-w-0">
                                <div className="flex items-center gap-1.5">
                                    <p className="text-sm text-white truncate">{dApp.name}</p>
                                    {dApp.portableData && (
                                        <span className="px-1.5 py-0.5 rounded text-[10px] bg-blue-900/40 text-blue-400 border border-blue-800/40 flex-shrink-0">Portable</span>
                                    )}
                                </div>
                                <p className="text-xs text-muted truncate">{dApp.path}</p>
                            </div>
                            <button className="btn-danger-text" onClick={() => setDesktopApps(desktopApps.filter((_, j) => j !== i))}>Remove</button>
                        </div>
                    ))}
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
                                            placeholder="New Master Password (8+ chars)"
                                            value={masterPassword}
                                            onChange={(e) => { setMasterPassword(e.target.value); setError('') }}
                                            autoFocus
                                        />
                                        <input
                                            type="password"
                                            className={`form-input text-sm ${error && error.includes('assword') ? 'error' : ''}`}
                                            placeholder="Confirm Master Password"
                                            value={confirmMasterPassword}
                                            onChange={(e) => { setConfirmMasterPassword(e.target.value); setError('') }}
                                        />
                                        <div className="flex gap-2 mt-1">
                                            <button className="btn-secondary flex-1 text-xs" disabled={saving} onClick={() => { setExpandedSecurityOption(null); setMasterPassword(''); setConfirmMasterPassword('') }}>Cancel</button>
                                            <button className="btn-primary flex-1 text-xs py-2" disabled={saving || !masterPassword.trim()} onClick={handleUpdatePassword}>Update Password</button>
                                        </div>
                                    </div>
                                )}
                            </div>
                        )}

                        {/* PIN Unlock Accordion */}
                        {driveInfo?.isRemovable && (
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
                        {driveInfo?.isRemovable && (
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
                        setDesktopApps(prev => [...prev, ...importedApps])
                        setShowImportModal(false)
                    }}
                />
            )}
        </div>
    )
}

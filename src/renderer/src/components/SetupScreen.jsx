import { useState, useEffect } from 'react'
import ImportAppsModal from './ImportAppsModal'

export default function SetupScreen({ driveInfo, onComplete }) {
    const isRemovable = driveInfo?.isRemovable
    const supportsConvenienceUnlock = driveInfo?.supportsConvenienceUnlock
    const [step, setStep] = useState(1)
    const [masterPassword, setMasterPassword] = useState('')
    const [confirmPassword, setConfirmPassword] = useState('')
    // Flash Drives completely skip Master Password prompts and use an incredibly strong hidden 64-char AES key.
    const [hiddenMasterPassword] = useState(() => Array.from(crypto.getRandomValues(new Uint8Array(32))).map(b => b.toString(16).padStart(2, '0')).join(''))
    const [pin, setPin] = useState('')
    const [confirmPin, setConfirmPin] = useState('')
    const [fastBoot, setFastBoot] = useState(false)
    const [error, setError] = useState('')
    const [sessionWarning, setSessionWarning] = useState('')
    const [saving, setSaving] = useState(false)

    const [desktopApps, setDesktopApps] = useState([])
    const [showAppForm, setShowAppForm] = useState(false)
    const [appForm, setAppForm] = useState({ name: '', path: '', args: '' })
    const [showImportModal, setShowImportModal] = useState(false)

    // Session capture state
    const [sessionState, setSessionState] = useState('idle')
    const [capturedCount, setCapturedCount] = useState(0)
    const [capturedSkippedCount, setCapturedSkippedCount] = useState(0)
    const [capturedUrls, setCapturedUrls] = useState([])

    const sessionDisconnected = sessionState === 'disconnected'
    const browserReady = sessionState === 'open' || sessionState === 'saving'
    const openingBrowser = sessionState === 'opening'
    const savingSession = sessionState === 'saving'
    const getAppDisplayName = (app) => app?.name || app?.displayName || ''
    const toCapabilityWorkspaceEntry = (app) => {
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
        setError('')
        setAppForm({ ...appForm, ...(typeof selected === 'object' ? selected : {}), path: filePath, name })
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
            ...appForm,
            ...(typeof selected === 'object' ? selected : {}),
            path: folderPath,
            name,
            portableData: false,
            launchSourceType: 'host-folder',
            launchMethod: 'shell-execute'
        })
    }

    const addDesktopApp = () => {
        if (!appForm.capabilityId) {
            setError('Select an app or folder from the picker before adding it.')
            return
        }
        const path = appForm.path.trim()
        const isAbsoluteHostPath = /^[a-z]:\\/i.test(path)
        const isExecutablePath = /\.(exe|bat|cmd)$/i.test(path)
        const inferredHostFolder = isAbsoluteHostPath && !isExecutablePath && !appForm.launchSourceType
        const nextApp = {
            ...appForm,
            ...(inferredHostFolder ? {
                portableData: false,
                launchSourceType: 'host-folder',
                launchMethod: 'shell-execute'
            } : {}),
            id: Date.now(),
            enabled: true
        }
        setDesktopApps([...desktopApps, toCapabilityWorkspaceEntry(nextApp)])
        setAppForm({ name: '', path: '', args: '' })
        setShowAppForm(false)
    }

    // Save vault (password + desktop apps) and proceed to session capture
    const handleProceedToCapture = async () => {
        setSaving(true)
        setError('')
        setSessionWarning('')

        // Save vault with desktop apps only; web tabs come from session capture.
        const workspace = { webTabs: [], desktopApps: toCapabilityWorkspace(desktopApps) }
        const result = await window.omnilaunch.saveVault({
            masterPassword: supportsConvenienceUnlock ? hiddenMasterPassword : masterPassword,
            pin: supportsConvenienceUnlock && pin ? pin : null,
            fastBoot: supportsConvenienceUnlock ? fastBoot : false,
            workspace
        })

        if (result.success) {
            setSaving(false)
            setSessionState('idle')
            setCapturedCount(0)
            setCapturedSkippedCount(0)
            setCapturedUrls([])
            setStep(3) // Advance to the browser session step
        } else {
            setError(result.error || 'Failed to save vault')
            setSaving(false)
        }
    }

    // Listen for browser disconnect (user accidentally closed Chrome)
    // Uses a dedicated polling-based IPC channel and fires within 1 second.
    useEffect(() => {
        const cleanup = window.omnilaunch.onBrowserDisconnect(() => {
            setSessionState((prev) => (prev === 'complete' ? prev : 'disconnected'))
            setSessionWarning('')
            setError('Chrome was closed. Click "Reopen Browser" to try again.')
        })
        return cleanup
    }, [])

    // Open browser for session setup
    const handleOpenBrowser = async () => {
        setSessionState('opening')
        setError('')
        setSessionWarning('')

        try {
            const result = await window.omnilaunch.startSessionSetup()
            if (!result?.success) {
                setSessionState('idle')
                setError(result?.error || 'Failed to open browser')
                return
            }

            if (result.tabsSuccessful === false) {
                const skippedCount = (result.webResults || []).filter((tab) => tab.skipped).length
                const failedCount = (result.webResults || []).filter((tab) => !tab.success && !tab.skipped).length
                setSessionWarning(
                    failedCount > 0
                        ? `${failedCount} tab${failedCount === 1 ? '' : 's'} failed to load. Reload manually before saving.`
                        : skippedCount > 0
                            ? `${skippedCount} browser-owned tab${skippedCount === 1 ? '' : 's'} will be skipped when you save.`
                        : 'Browser opened, but one or more tabs failed to load. Reload manually before saving.'
                )
            }

            const sessionCheck = await window.omnilaunch.hasActiveBrowserSession()
            if (sessionCheck.success && sessionCheck.active) {
                setSessionState('open')
                return
            }

            setSessionState('disconnected')
            setSessionWarning('')
            setError('Chrome was closed. Click "Reopen Browser" to try again.')
        } catch (err) {
            setSessionState('idle')
            setSessionWarning('')
            setError(err?.message || 'Failed to open browser')
            return
        }
    }

    // Capture session and finish setup
    const handleSaveAndFinish = async () => {
        setError('')
        setSessionWarning('')
        const sessionCheck = await window.omnilaunch.hasActiveBrowserSession()

        if (!sessionCheck.success || !sessionCheck.active) {
            setSessionState('disconnected')
            setError('Chrome was closed. Click "Reopen Browser" to try again.')
            return
        }

        setSessionState('saving')

        const result = await window.omnilaunch.captureSession({})
        if (result.success) {
            setCapturedCount(result.tabCount)
            setCapturedSkippedCount(result.skippedCount || 0)
            setCapturedUrls(result.urls || [])
            setSessionState('complete')
            // Show success briefly, then complete setup
            setTimeout(() => onComplete(), 1500)
        } else {
            if (result.error === 'No active browser session') {
                setSessionState('disconnected')
                setError('Chrome was closed. Click "Reopen Browser" to try again.')
                return
            }

            setSessionState('open')
            setError(result.error || 'Failed to capture session')
        }
    }

    // Since Removable skips Password, and Local skips PIN, they both have exactly 3 steps.
    const totalSteps = 3
    const sessionStep = 3
    const appsStep = 2

    return (
        <div className="card p-6 w-full max-w-sm animate-slide-up flex flex-col" style={{ maxHeight: 560 }}>
            {/* Header */}
            <div className="text-center mb-5 flex-shrink-0">
                <h1 className="text-lg font-semibold text-white">
                    {step === sessionStep ? 'Set Up Your Browser' : 'Initial Setup'}
                </h1>
                <p className="text-secondary text-xs mt-1">
                    {step === sessionStep
                        ? 'Log into your sites and we\'ll remember them'
                        : supportsConvenienceUnlock ? 'USB Drive - PIN unlock available' : isRemovable ? 'USB Drive - master password required' : 'Local Drive'}
                </p>
            </div>

            {/* Step Indicator */}
            <div className="step-indicator mb-5 flex-shrink-0">
                {Array.from({ length: totalSteps }, (_, i) => i + 1).map((s) => (
                    <div key={s} className={`step-dot ${step === s ? 'active' : step > s ? 'done' : ''}`} />
                ))}
            </div>

            {/* Step 1: Master Password (Local PC Only) */}
            {step === 1 && !supportsConvenienceUnlock && (
                <div className="flex flex-col gap-3 animate-fade-in">
                    <p className="text-secondary text-sm">
                        Create a master password. This encrypts everything on your local drive.
                    </p>
                    <input
                        type="password"
                        className="form-input"
                        placeholder="Master Password (8+ characters)"
                        value={masterPassword}
                        onChange={(e) => { setMasterPassword(e.target.value); setError('') }}
                    />
                    <input
                        type="password"
                        className={`form-input ${error ? 'error' : ''}`}
                        placeholder="Confirm Password"
                        value={confirmPassword}
                        onChange={(e) => { setConfirmPassword(e.target.value); setError('') }}
                    />
                    <button
                        className="btn-primary w-full"
                        disabled={masterPassword.length < 8}
                        onClick={() => {
                            if (masterPassword !== confirmPassword) {
                                setError('Passwords do not match')
                                return
                            }
                            setError('')
                            setStep(2)
                        }}
                    >
                        Continue
                    </button>
                    {error && <p className="text-error text-xs text-center">{error}</p>}
                </div>
            )}

            {/* Step 1: PIN Setup (USB Flash Drive Only) */}
            {step === 1 && supportsConvenienceUnlock && (
                <div className="flex flex-col gap-3 animate-fade-in">
                    <p className="text-secondary text-sm">
                        Create a 4-digit PIN for quick daily access.
                    </p>
                    <input
                        type="password"
                        className="form-input text-center tracking-[0.5em]"
                        placeholder="4-Digit PIN"
                        maxLength={4}
                        inputMode="numeric"
                        value={pin}
                        onChange={(e) => {
                            const val = e.target.value.replace(/\D/g, '').slice(0, 4)
                            setPin(val)
                            setError('')
                        }}
                    />
                    <input
                        type="password"
                        className={`form-input text-center tracking-[0.5em] ${error ? 'error' : ''}`}
                        placeholder="Confirm PIN"
                        maxLength={4}
                        inputMode="numeric"
                        value={confirmPin}
                        onChange={(e) => {
                            const val = e.target.value.replace(/\D/g, '').slice(0, 4)
                            setConfirmPin(val)
                            setError('')
                        }}
                    />

                    {/* Fast Boot */}
                    <div className="flex items-center justify-between p-3 rounded-md bg-[#14141c]">
                        <div>
                            <p className="text-sm text-white font-medium">Fast Boot</p>
                            <p className="text-xs text-muted">Skip PIN - hardware-only unlock</p>
                        </div>
                        <div
                            className={`toggle-track ${fastBoot ? 'active' : ''}`}
                            onClick={() => setFastBoot(!fastBoot)}
                        >
                            <div className="toggle-thumb" />
                        </div>
                    </div>

                    <div className="flex gap-2">
                        <button
                            className="btn-primary w-full"
                            disabled={pin.length !== 4}
                            onClick={() => {
                                if (pin !== confirmPin) {
                                    setError('PINs do not match')
                                    return
                                }
                                setError('')
                                setStep(2)
                            }}
                        >
                            Continue
                        </button>
                    </div>
                    {error && <p className="text-error text-xs text-center">{error}</p>}
                </div>
            )}

            {/* Desktop Apps & Folders Step (Step 2) */}
            {step === appsStep && (
                <div className="flex flex-col flex-1 min-h-0 animate-fade-in">
                    {/* Description + section header - STICKY */}
                    <div className="flex-shrink-0">
                        <p className="text-secondary text-sm mb-4">
                            Add portable apps or project folders to launch with your workspace. You can skip this.
                        </p>
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
                    </div>

                    {/* App list - SCROLLABLE */}
                    <div className="flex-1 overflow-y-auto min-h-0 mb-3">
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
                                <input className="form-input text-sm" placeholder="Launch Arguments (optional)" value={appForm.args} onChange={(e) => setAppForm({ ...appForm, args: e.target.value })} />
                                <button className="btn-primary text-sm py-2" onClick={addDesktopApp}>Add Item</button>
                            </div>
                        )}

                        {desktopApps.map((dApp, i) => (
                            <div key={dApp.id} className="list-item flex items-center justify-between mb-2">
                                <div className="flex-1 min-w-0">
                                    <p className="text-sm text-white truncate">{getAppDisplayName(dApp)}</p>
                                    <p className="text-xs text-muted truncate">{dApp.path || 'Launch capability saved'}</p>
                                </div>
                                <button className="btn-danger-text" onClick={() => setDesktopApps(desktopApps.filter((_, j) => j !== i))}>
                                    Remove
                                </button>
                            </div>
                        ))}

                        {desktopApps.length === 0 && !showAppForm && (
                            <p className="text-muted text-xs text-center py-3">No desktop apps added</p>
                        )}
                    </div>

                    {/* Navigation buttons - STICKY */}
                    <div className="flex-shrink-0">
                        <div className="flex gap-2">
                            <button className="btn-secondary flex-1" onClick={() => setStep(1)}>Back</button>
                            <button
                                className="btn-primary flex-1"
                                disabled={saving}
                                onClick={handleProceedToCapture}
                            >
                                {saving ? (
                                    <span className="flex items-center justify-center gap-2">
                                        <div className="spinner" style={{ width: 14, height: 14, borderWidth: 2 }} /> Saving...
                                    </span>
                                ) : desktopApps.length === 0 ? 'Skip & Continue' : 'Continue'}
                            </button>
                        </div>
                        {error && <p className="text-error text-xs text-center mt-2">{error}</p>}
                    </div>

                    {showImportModal && (
                        <ImportAppsModal
                            onClose={() => setShowImportModal(false)}
                            onImportComplete={(importedApps) => {
                                setDesktopApps(prev => [...prev, ...toCapabilityWorkspace(importedApps)])
                                setShowImportModal(false)
                            }}
                        />
                    )}
                </div>
            )}

            {/* Session Capture Step (Final Step) */}
            {step === sessionStep && (
                <div className="flex flex-col gap-4 animate-fade-in">
                    {/* Before browser is opened */}
                    {sessionState === 'idle' && !capturedCount && (
                        <>
                            <div className="p-4 rounded-lg bg-[#14141c] border border-[#2a2a3a]">
                                <div className="flex items-start gap-3 mb-3">
                                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#5b7bd5" strokeWidth="2" strokeLinecap="round" className="mt-0.5 flex-shrink-0">
                                        <circle cx="12" cy="12" r="10" />
                                        <path d="M12 16v-4" />
                                        <path d="M12 8h.01" />
                                    </svg>
                                    <div>
                                        <p className="text-sm text-white font-medium mb-1">Here's what will happen:</p>
                                        <ol className="text-xs text-secondary space-y-1.5 list-decimal pl-4">
                                            <li>A Chrome browser will open</li>
                                            <li>Open your favorite sites (YouTube, ChatGPT, etc.)</li>
                                            <li>Log into each one normally</li>
                                            <li>Come back here and click <strong className="text-white">Save & Finish</strong></li>
                                        </ol>
                                    </div>
                                </div>

                                <div className="flex items-start gap-2 p-2 rounded-md bg-[#1a1520] border border-[#3a2a2a]">
                                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#d4a44a" strokeWidth="2" strokeLinecap="round" className="mt-0.5 flex-shrink-0">
                                        <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
                                        <line x1="12" y1="9" x2="12" y2="13" />
                                        <line x1="12" y1="17" x2="12.01" y2="17" />
                                    </svg>
                                    <p className="text-xs text-[#d4a44a]">
                                        Don't close the Chrome browser until you've saved!
                                    </p>
                                </div>
                            </div>

                            <button className="btn-primary w-full" onClick={handleOpenBrowser}>
                                Open Browser
                            </button>
                            {error && <p className="text-error text-xs text-center animate-fade-in">{error}</p>}
                            <button className="btn-secondary w-full text-xs" onClick={() => setStep(appsStep)}>
                                Back
                            </button>
                        </>
                    )}

                    {/* Browser is opening */}
                    {openingBrowser && !capturedCount && (
                        <div className="text-center py-6 animate-fade-in">
                            <div className="w-12 h-12 mx-auto mb-3 rounded-full flex items-center justify-center bg-[#1a1a2e]">
                                <div className="spinner" style={{ width: 18, height: 18, borderWidth: 2 }} />
                            </div>
                            <p className="text-sm text-white font-medium">Opening browser...</p>
                            <p className="text-xs text-secondary mt-1">Preparing your setup session</p>
                        </div>
                    )}

                    {sessionDisconnected && !capturedCount && (
                        <>
                            <div className="p-4 rounded-lg bg-[#14141c] border border-[#3a2a2a] animate-fade-in">
                                <div className="flex items-start gap-3">
                                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#d4a44a" strokeWidth="2" strokeLinecap="round" className="mt-0.5 flex-shrink-0">
                                        <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
                                        <line x1="12" y1="9" x2="12" y2="13" />
                                        <line x1="12" y1="17" x2="12.01" y2="17" />
                                    </svg>
                                    <div>
                                        <p className="text-sm text-white font-medium mb-1">Browser was closed</p>
                                        <p className="text-xs text-secondary">
                                            Reopen the browser, sign in again if needed, then click Save & Finish.
                                        </p>
                                    </div>
                                </div>
                            </div>

                            {error && <p className="text-error text-xs text-center animate-fade-in">{error}</p>}

                            <button className="btn-primary w-full" onClick={handleOpenBrowser}>
                                Reopen Browser
                            </button>
                            <button className="btn-secondary w-full text-xs" onClick={() => setStep(appsStep)}>
                                Back
                            </button>
                        </>
                    )}

                    {browserReady && !capturedCount && (
                        <>
                            <div className="text-center py-4">
                                <div className="w-12 h-12 mx-auto mb-3 rounded-full flex items-center justify-center bg-[#1a1a2e]">
                                    {!savingSession ? (
                                        <div className="w-3 h-3 rounded-full bg-[#4a9]" style={{ animation: 'pulse 2s infinite' }} />
                                    ) : (
                                        <div className="spinner" style={{ width: 18, height: 18, borderWidth: 2 }} />
                                    )}
                                </div>
                                <p className="text-sm text-white font-medium">
                                    {savingSession ? 'Saving your session...' : 'Browser is open'}
                                </p>
                                <p className="text-xs text-secondary mt-1">
                                    {savingSession
                                        ? 'Encrypting cookies and tabs...'
                                        : 'Log into your sites, then come back here'}
                                </p>
                            </div>

                            {sessionWarning && (
                                <p className="text-xs text-center text-[#d4a44a] animate-fade-in">{sessionWarning}</p>
                            )}

                            <button
                                className="btn-primary w-full"
                                disabled={savingSession}
                                onClick={handleSaveAndFinish}
                            >
                                {savingSession ? (
                                    <span className="flex items-center justify-center gap-2">
                                        <div className="spinner" style={{ width: 14, height: 14, borderWidth: 2 }} />
                                        Saving...
                                    </span>
                                ) : 'Save & Finish'}
                            </button>

                            {error && <p className="text-error text-xs text-center mt-2">{error}</p>}

                            <p className="text-muted text-center" style={{ fontSize: 10 }}>
                                Don't close Chrome until you click Save & Finish
                            </p>
                        </>
                    )}

                    {/* Success */}
                    {capturedCount > 0 && (
                        <div className="text-center py-6 animate-fade-in">
                            <div className="w-12 h-12 mx-auto mb-3 rounded-full flex items-center justify-center bg-[#1a2a1a]">
                                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#4a9" strokeWidth="2.5" strokeLinecap="round">
                                    <polyline points="20 6 9 17 4 12" />
                                </svg>
                            </div>
                            <p className="text-base text-white font-semibold">Setup Complete!</p>
                            <p className="text-xs text-secondary mt-1">
                                {capturedCount} tab{capturedCount !== 1 ? 's' : ''} saved and encrypted
                            </p>
                            {capturedSkippedCount > 0 && (
                                <p className="text-xs text-[#d4a44a] mt-1">
                                    {capturedSkippedCount} browser-owned tab{capturedSkippedCount === 1 ? '' : 's'} skipped
                                </p>
                            )}
                            <div className="mt-3 space-y-1">
                                {capturedUrls.slice(0, 5).map((url, i) => (
                                    <p key={i} className="text-xs text-muted truncate">{url}</p>
                                ))}
                                {capturedUrls.length > 5 && (
                                    <p className="text-xs text-muted">+{capturedUrls.length - 5} more</p>
                                )}
                            </div>
                        </div>
                    )}
                </div>
            )}
        </div>
    )
}

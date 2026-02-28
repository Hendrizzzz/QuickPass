import { useState, useEffect, useRef } from 'react'

export default function SetupScreen({ driveInfo, onComplete }) {
    const isRemovable = driveInfo?.isRemovable
    const [step, setStep] = useState(1)
    const [masterPassword, setMasterPassword] = useState('')
    const [confirmPassword, setConfirmPassword] = useState('')
    // Flash Drives completely skip Master Password prompts and use an incredibly strong hidden 64-char AES key.
    const [hiddenMasterPassword] = useState(() => Array.from(crypto.getRandomValues(new Uint8Array(32))).map(b => b.toString(16).padStart(2, '0')).join(''))
    const [pin, setPin] = useState('')
    const [confirmPin, setConfirmPin] = useState('')
    const [fastBoot, setFastBoot] = useState(false)
    const [error, setError] = useState('')
    const [saving, setSaving] = useState(false)

    const [desktopApps, setDesktopApps] = useState([])
    const [showAppForm, setShowAppForm] = useState(false)
    const [appForm, setAppForm] = useState({ name: '', path: '', args: '' })

    // Session capture state
    const [browserOpen, setBrowserOpen] = useState(false)
    const [capturing, setCapturing] = useState(false)
    const [capturedCount, setCapturedCount] = useState(0)
    const [capturedUrls, setCapturedUrls] = useState([])

    const browseExe = async () => {
        const filePath = await window.omnilaunch.browseExe()
        if (filePath) {
            const name = filePath.split('\\').pop().replace('.exe', '')
            setAppForm({ ...appForm, path: filePath, name })
        }
    }

    const addDesktopApp = () => {
        if (!appForm.path.trim()) return
        setDesktopApps([...desktopApps, { ...appForm, id: Date.now(), enabled: true }])
        setAppForm({ name: '', path: '', args: '' })
        setShowAppForm(false)
    }

    // Save vault (password + desktop apps) and proceed to session capture
    const handleProceedToCapture = async () => {
        setSaving(true)
        setError('')

        // Save vault with desktop apps only (no webTabs yet — those come from session capture)
        const workspace = { webTabs: [], desktopApps }
        const result = await window.omnilaunch.saveVault({
            masterPassword: isRemovable ? hiddenMasterPassword : masterPassword,
            pin: isRemovable && pin ? pin : null,
            fastBoot: isRemovable ? fastBoot : false,
            workspace
        })

        if (result.success) {
            setSaving(false)
            setStep(3) // Advance to the browser session step
        } else {
            setError(result.error || 'Failed to save vault')
            setSaving(false)
        }
    }

    // Listen for browser disconnect (user accidentally closed Chrome)
    // Uses a dedicated polling-based IPC channel — fires within 1 second
    useEffect(() => {
        const cleanup = window.omnilaunch.onBrowserDisconnect(() => {
            setBrowserOpen(false)
            setCapturing(false)
            setError('Chrome was closed. Click "Open Browser" to try again.')
        })
        return cleanup
    }, [])

    // Open browser for session setup
    const handleOpenBrowser = async () => {
        setBrowserOpen(true)
        setError('')
        await window.omnilaunch.startSessionSetup()
    }

    // Capture session and finish setup
    const handleSaveAndFinish = async () => {
        setCapturing(true)
        setError('')

        const result = await window.omnilaunch.captureSession({ masterPassword: isRemovable ? hiddenMasterPassword : masterPassword })
        if (result.success) {
            setCapturedCount(result.tabCount)
            setCapturedUrls(result.urls || [])
            // Show success briefly, then complete setup
            setTimeout(() => onComplete(), 1500)
        } else {
            setError(result.error || 'Failed to capture session')
            setCapturing(false)
        }
    }

    // Since Removable skips Password, and Local skips PIN, they both have exactly 3 steps.
    const totalSteps = 3
    const sessionStep = 3
    const appsStep = 2

    return (
        <div className="card p-6 w-full max-w-sm animate-slide-up overflow-y-auto" style={{ maxHeight: 560 }}>
            {/* Header */}
            <div className="text-center mb-5">
                <h1 className="text-lg font-semibold text-white">
                    {step === sessionStep ? 'Set Up Your Browser' : 'Initial Setup'}
                </h1>
                <p className="text-secondary text-xs mt-1">
                    {step === sessionStep
                        ? 'Log into your sites and we\'ll remember them'
                        : isRemovable ? 'USB Drive — PIN unlock available' : 'Local Drive'}
                </p>
            </div>

            {/* Step Indicator */}
            <div className="step-indicator mb-5">
                {Array.from({ length: totalSteps }, (_, i) => i + 1).map((s) => (
                    <div key={s} className={`step-dot ${step === s ? 'active' : step > s ? 'done' : ''}`} />
                ))}
            </div>

            {/* Step 1: Master Password (Local PC Only) */}
            {step === 1 && !isRemovable && (
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
            {step === 1 && isRemovable && (
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
                            <p className="text-xs text-muted">Skip PIN — hardware-only unlock</p>
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

            {/* Desktop Apps Step (Step 2) */}
            {step === appsStep && (
                <div className="flex flex-col gap-4 animate-fade-in">
                    <p className="text-secondary text-sm">
                        Add desktop apps to launch with your workspace. You can skip this.
                    </p>

                    <div>
                        <div className="flex items-center justify-between mb-2">
                            <span className="section-label">Desktop Apps</span>
                            <button className="btn-secondary text-xs py-1 px-3" onClick={() => setShowAppForm(!showAppForm)}>
                                {showAppForm ? 'Cancel' : '+ Add'}
                            </button>
                        </div>

                        {showAppForm && (
                            <div className="flex flex-col gap-2 p-3 rounded-md mb-2 animate-fade-in bg-[#14141c]">
                                <input className="form-input text-sm" placeholder="App Name" value={appForm.name} onChange={(e) => setAppForm({ ...appForm, name: e.target.value })} />
                                <div className="flex gap-2">
                                    <input className="form-input text-sm flex-1" placeholder="Path to .exe" value={appForm.path} readOnly />
                                    <button className="btn-secondary text-xs whitespace-nowrap" onClick={browseExe}>Browse</button>
                                </div>
                                <input className="form-input text-sm" placeholder="Launch Arguments (optional)" value={appForm.args} onChange={(e) => setAppForm({ ...appForm, args: e.target.value })} />
                                <button className="btn-primary text-sm py-2" onClick={addDesktopApp}>Add App</button>
                            </div>
                        )}

                        {desktopApps.map((dApp, i) => (
                            <div key={dApp.id} className="list-item flex items-center justify-between mb-2">
                                <div className="flex-1 min-w-0">
                                    <p className="text-sm text-white truncate">{dApp.name}</p>
                                    <p className="text-xs text-muted truncate">{dApp.path}</p>
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

                    <div className="flex gap-2 mt-1">
                        <button className="btn-secondary flex-1" onClick={() => setStep(isRemovable ? 2 : 1)}>Back</button>
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
            )}

            {/* Session Capture Step (Final Step) */}
            {step === sessionStep && (
                <div className="flex flex-col gap-4 animate-fade-in">
                    {/* Before browser is opened */}
                    {!browserOpen && !capturedCount && (
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

                    {/* Browser is open — waiting for user */}
                    {browserOpen && !capturedCount && (
                        <>
                            <div className="text-center py-4">
                                <div className="w-12 h-12 mx-auto mb-3 rounded-full flex items-center justify-center bg-[#1a1a2e]">
                                    {!capturing ? (
                                        <div className="w-3 h-3 rounded-full bg-[#4a9]" style={{ animation: 'pulse 2s infinite' }} />
                                    ) : (
                                        <div className="spinner" style={{ width: 18, height: 18, borderWidth: 2 }} />
                                    )}
                                </div>
                                <p className="text-sm text-white font-medium">
                                    {capturing ? 'Saving your session...' : 'Browser is open'}
                                </p>
                                <p className="text-xs text-secondary mt-1">
                                    {capturing
                                        ? 'Encrypting cookies and tabs...'
                                        : 'Log into your sites, then come back here'}
                                </p>
                            </div>

                            <button
                                className="btn-primary w-full"
                                disabled={capturing}
                                onClick={handleSaveAndFinish}
                            >
                                {capturing ? (
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

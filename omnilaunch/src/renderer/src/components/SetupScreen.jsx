import { useState } from 'react'

export default function SetupScreen({ driveInfo, onComplete }) {
    const isRemovable = driveInfo?.isRemovable
    const [step, setStep] = useState(1)
    const [masterPassword, setMasterPassword] = useState('')
    const [confirmPassword, setConfirmPassword] = useState('')
    const [pin, setPin] = useState('')
    const [confirmPin, setConfirmPin] = useState('')
    const [fastBoot, setFastBoot] = useState(false)
    const [error, setError] = useState('')
    const [saving, setSaving] = useState(false)

    const [webTabs, setWebTabs] = useState([])
    const [desktopApps, setDesktopApps] = useState([])

    const [showWebForm, setShowWebForm] = useState(false)
    const [webForm, setWebForm] = useState({ url: '', email: '', password: '', totpSecret: '' })

    const addWebTab = () => {
        if (!webForm.url.trim()) return
        setWebTabs([...webTabs, { ...webForm, id: Date.now(), enabled: true }])
        setWebForm({ url: '', email: '', password: '', totpSecret: '' })
        setShowWebForm(false)
    }

    const [showAppForm, setShowAppForm] = useState(false)
    const [appForm, setAppForm] = useState({ name: '', path: '', args: '' })

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

    const handleSave = async () => {
        setSaving(true)
        setError('')
        const workspace = { webTabs, desktopApps }
        const result = await window.omnilaunch.saveVault({
            masterPassword,
            pin: isRemovable && pin ? pin : null,
            fastBoot: isRemovable ? fastBoot : false,
            workspace
        })
        if (result.success) {
            onComplete()
        } else {
            setError(result.error || 'Failed to save vault')
            setSaving(false)
        }
    }

    return (
        <div className="card p-6 w-full max-w-sm animate-slide-up overflow-y-auto" style={{ maxHeight: 540 }}>
            {/* Header */}
            <div className="text-center mb-5">
                <h1 className="text-lg font-semibold text-white">Initial Setup</h1>
                <p className="text-secondary text-xs mt-1">
                    {isRemovable ? 'USB Drive — PIN unlock available' : 'Local Drive — Password required'}
                </p>
            </div>

            {/* Step Indicator */}
            <div className="step-indicator mb-5">
                {[1, 2, 3].map((s) => (
                    <div key={s} className={`step-dot ${step === s ? 'active' : step > s ? 'done' : ''}`} />
                ))}
            </div>

            {/* Step 1: Master Password */}
            {step === 1 && (
                <div className="flex flex-col gap-3 animate-fade-in">
                    <p className="text-secondary text-sm">
                        Create a master password. This is your primary recovery key.
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
                            setStep(isRemovable ? 2 : 3)
                        }}
                    >
                        Continue
                    </button>
                    {error && <p className="text-error text-xs text-center">{error}</p>}
                </div>
            )}

            {/* Step 2: PIN Setup (USB Only) */}
            {step === 2 && isRemovable && (
                <div className="flex flex-col gap-3 animate-fade-in">
                    <p className="text-secondary text-sm">
                        Create a 4-digit PIN for quick daily access. This PIN is bound to this USB drive's hardware.
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
                        <button className="btn-secondary flex-1" onClick={() => setStep(1)}>Back</button>
                        <button
                            className="btn-primary flex-1"
                            disabled={!fastBoot && (pin.length !== 4)}
                            onClick={() => {
                                if (!fastBoot && pin !== confirmPin) {
                                    setError('PINs do not match')
                                    return
                                }
                                setError('')
                                setStep(3)
                            }}
                        >
                            Continue
                        </button>
                    </div>
                    {error && <p className="text-error text-xs text-center">{error}</p>}
                </div>
            )}

            {/* Step 3: Workspace Configuration */}
            {step === 3 && (
                <div className="flex flex-col gap-4 animate-fade-in">
                    {/* Web Tabs Section */}
                    <div>
                        <div className="flex items-center justify-between mb-2">
                            <span className="section-label">Web Tabs</span>
                            <button className="btn-secondary text-xs py-1 px-3" onClick={() => setShowWebForm(!showWebForm)}>
                                {showWebForm ? 'Cancel' : '+ Add'}
                            </button>
                        </div>

                        {showWebForm && (
                            <div className="flex flex-col gap-2 p-3 rounded-md mb-2 animate-fade-in bg-[#14141c]">
                                <input className="form-input text-sm" placeholder="URL (e.g. classroom.google.com)" value={webForm.url} onChange={(e) => setWebForm({ ...webForm, url: e.target.value })} />
                                <input className="form-input text-sm" placeholder="Email" value={webForm.email} onChange={(e) => setWebForm({ ...webForm, email: e.target.value })} />
                                <input className="form-input text-sm" type="password" placeholder="Password" value={webForm.password} onChange={(e) => setWebForm({ ...webForm, password: e.target.value })} />
                                <div>
                                    <input className="form-input text-sm" placeholder="2FA Secret Key (optional)" value={webForm.totpSecret} onChange={(e) => setWebForm({ ...webForm, totpSecret: e.target.value })} />
                                    <p className="text-muted text-[10px] mt-1">
                                        Google Account &rarr; Security &rarr; 2-Step Verification &rarr; Authenticator App &rarr; "Can't scan it?" &rarr; Copy the key
                                    </p>
                                </div>
                                <button className="btn-primary text-sm py-2" onClick={addWebTab}>Add Web Tab</button>
                            </div>
                        )}

                        {webTabs.map((tab, i) => (
                            <div key={tab.id} className="list-item flex items-center justify-between mb-2">
                                <div className="flex-1 min-w-0">
                                    <p className="text-sm text-white truncate">{tab.url}</p>
                                    <p className="text-xs text-muted truncate">{tab.email}</p>
                                </div>
                                <button className="btn-danger-text" onClick={() => setWebTabs(webTabs.filter((_, j) => j !== i))}>
                                    Remove
                                </button>
                            </div>
                        ))}
                    </div>

                    {/* Desktop Apps Section */}
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
                    </div>

                    {/* Save */}
                    <div className="flex gap-2 mt-1">
                        <button className="btn-secondary flex-1" onClick={() => setStep(isRemovable ? 2 : 1)}>Back</button>
                        <button
                            className="btn-primary flex-1"
                            disabled={saving || (webTabs.length === 0 && desktopApps.length === 0)}
                            onClick={handleSave}
                        >
                            {saving ? (
                                <span className="flex items-center justify-center gap-2">
                                    <div className="spinner" style={{ width: 14, height: 14, borderWidth: 2 }} /> Encrypting...
                                </span>
                            ) : 'Save & Encrypt'}
                        </button>
                    </div>
                    {error && <p className="text-error text-xs text-center mt-2">{error}</p>}
                </div>
            )}
        </div>
    )
}

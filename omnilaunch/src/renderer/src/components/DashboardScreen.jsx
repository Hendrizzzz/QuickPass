import { useState } from 'react'

export default function DashboardScreen({ driveInfo, workspace, vaultMeta, onSave, onCancel }) {
    const [webTabs, setWebTabs] = useState(workspace?.webTabs || [])
    const [desktopApps, setDesktopApps] = useState(workspace?.desktopApps || [])
    const [saving, setSaving] = useState(false)
    const [error, setError] = useState('')

    const [showWebForm, setShowWebForm] = useState(false)
    const [webForm, setWebForm] = useState({ url: '', email: '', password: '', totpSecret: '' })
    const [showAppForm, setShowAppForm] = useState(false)
    const [appForm, setAppForm] = useState({ name: '', path: '', args: '' })

    const [masterPassword, setMasterPassword] = useState('')
    const [showPasswordPrompt, setShowPasswordPrompt] = useState(false)

    const addWebTab = () => {
        if (!webForm.url.trim()) return
        setWebTabs([...webTabs, { ...webForm, id: Date.now(), enabled: true }])
        setWebForm({ url: '', email: '', password: '', totpSecret: '' })
        setShowWebForm(false)
    }

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

    const toggleItem = (list, setList, index) => {
        const updated = [...list]
        updated[index] = { ...updated[index], enabled: !updated[index].enabled }
        setList(updated)
    }

    const handleSaveClick = () => setShowPasswordPrompt(true)

    const handleFinalSave = async () => {
        if (!masterPassword.trim()) {
            setError('Password required to re-encrypt vault')
            return
        }
        setSaving(true)
        setError('')
        const result = await window.omnilaunch.saveVault({
            masterPassword,
            pin: vaultMeta?.hasPIN ? null : null,
            fastBoot: vaultMeta?.fastBoot || false,
            workspace: { webTabs, desktopApps }
        })
        if (result.success) {
            onSave()
        } else {
            setError(result.error || 'Save failed')
            setSaving(false)
        }
    }

    return (
        <div className="card p-6 w-full max-w-sm animate-slide-up overflow-y-auto" style={{ maxHeight: 540 }}>
            <div className="flex items-center justify-between mb-4">
                <h1 className="text-lg font-semibold text-white">Settings</h1>
                <button className="btn-secondary text-xs py-1 px-3" onClick={onCancel}>Close</button>
            </div>

            {/* Web Tabs */}
            <div className="mb-4">
                <div className="flex items-center justify-between mb-2">
                    <span className="section-label">Web Tabs</span>
                    <button className="btn-secondary text-xs py-1 px-3" onClick={() => setShowWebForm(!showWebForm)}>
                        {showWebForm ? 'Cancel' : '+ Add'}
                    </button>
                </div>

                {showWebForm && (
                    <div className="flex flex-col gap-2 p-3 rounded-md mb-2 animate-fade-in bg-[#14141c]">
                        <input className="form-input text-sm" placeholder="URL" value={webForm.url} onChange={(e) => setWebForm({ ...webForm, url: e.target.value })} />
                        <input className="form-input text-sm" placeholder="Email" value={webForm.email} onChange={(e) => setWebForm({ ...webForm, email: e.target.value })} />
                        <input className="form-input text-sm" type="password" placeholder="Password" value={webForm.password} onChange={(e) => setWebForm({ ...webForm, password: e.target.value })} />
                        <input className="form-input text-sm" placeholder="2FA Secret (optional)" value={webForm.totpSecret} onChange={(e) => setWebForm({ ...webForm, totpSecret: e.target.value })} />
                        <button className="btn-primary text-sm py-2" onClick={addWebTab}>Add</button>
                    </div>
                )}

                {webTabs.length === 0 && !showWebForm && (
                    <p className="text-muted text-xs text-center py-3">No web tabs configured</p>
                )}

                {webTabs.map((tab, i) => (
                    <div key={tab.id} className="list-item flex items-center gap-3 mb-2">
                        <div
                            className={`toggle-track ${tab.enabled ? 'active' : ''}`}
                            onClick={() => toggleItem(webTabs, setWebTabs, i)}
                        >
                            <div className="toggle-thumb" />
                        </div>
                        <div className="flex-1 min-w-0">
                            <p className="text-sm text-white truncate">{tab.url}</p>
                            <p className="text-xs text-muted truncate">{tab.email}</p>
                        </div>
                        <button className="btn-danger-text" onClick={() => setWebTabs(webTabs.filter((_, j) => j !== i))}>Remove</button>
                    </div>
                ))}
            </div>

            {/* Desktop Apps */}
            <div className="mb-4">
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
                        <input className="form-input text-sm" placeholder="Launch Args (optional)" value={appForm.args} onChange={(e) => setAppForm({ ...appForm, args: e.target.value })} />
                        <button className="btn-primary text-sm py-2" onClick={addDesktopApp}>Add</button>
                    </div>
                )}

                {desktopApps.length === 0 && !showAppForm && (
                    <p className="text-muted text-xs text-center py-3">No desktop apps configured</p>
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
                            <p className="text-sm text-white truncate">{dApp.name}</p>
                            <p className="text-xs text-muted truncate">{dApp.path}</p>
                        </div>
                        <button className="btn-danger-text" onClick={() => setDesktopApps(desktopApps.filter((_, j) => j !== i))}>Remove</button>
                    </div>
                ))}
            </div>

            {/* Save */}
            {!showPasswordPrompt ? (
                <button className="btn-primary w-full" onClick={handleSaveClick}>
                    Save Changes
                </button>
            ) : (
                <div className="flex flex-col gap-3 animate-fade-in">
                    <p className="text-secondary text-xs text-center">Enter master password to re-encrypt:</p>
                    <input
                        type="password"
                        className={`form-input text-sm ${error ? 'error' : ''}`}
                        placeholder="Master Password"
                        value={masterPassword}
                        onChange={(e) => { setMasterPassword(e.target.value); setError('') }}
                        autoFocus
                    />
                    <button className="btn-primary w-full" disabled={saving} onClick={handleFinalSave}>
                        {saving ? (
                            <span className="flex items-center justify-center gap-2">
                                <div className="spinner" style={{ width: 14, height: 14, borderWidth: 2 }} /> Encrypting...
                            </span>
                        ) : 'Encrypt & Save'}
                    </button>
                    {error && <p className="text-error text-xs text-center">{error}</p>}
                </div>
            )}
        </div>
    )
}

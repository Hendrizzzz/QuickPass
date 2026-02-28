import { useState, useEffect } from 'react'

export default function LaunchingScreen({ workspace, autoLaunch = true, onSettingsClick }) {
    const [phase, setPhase] = useState('launching')
    const [progress, setProgress] = useState(0)
    const [totalItems, setTotalItems] = useState(0)
    const [loadedItems, setLoadedItems] = useState([])
    const [errorMsg, setErrorMsg] = useState(null)
    const [savingSession, setSavingSession] = useState(false)
    const [saveSuccess, setSaveSuccess] = useState(false)

    useEffect(() => {
        if (!workspace) return

        const enabledTabs = workspace.webTabs?.filter((t) => t.enabled) || []
        const enabledApps = workspace.desktopApps?.filter((a) => a.enabled) || []
        const total = enabledTabs.length + enabledApps.length

        if (total === 0) {
            setPhase('ready')
            return
        }

        setTotalItems(total)

        // If returning from settings, skip launching and jump straight to ready
        if (!autoLaunch) {
            setPhase('ready')
            setProgress(100)
            return
        }

        const cleanup = window.omnilaunch.onLaunchStatus((msg) => {
            if (msg === 'LAUNCH_COMPLETE') return

            if (msg.includes('[OK]')) {
                const cleanName = msg
                    .replace(/\[Tab \d+\]\s*/, '')
                    .replace(/\[App \d+\]\s*/, '')
                    .replace('[OK] ', '')
                    .replace(' — ready', '')
                    .replace(' — launched', '')
                    .trim()

                if (cleanName) {
                    setLoadedItems(prev => {
                        const updated = [...prev, cleanName]
                        setProgress(Math.round((updated.length / total) * 100))
                        return updated
                    })
                }
            }
        })

        window.omnilaunch.launchWorkspace(workspace).then((result) => {
            if (result.success) {
                setPhase('ready')
                setProgress(100)
            } else {
                setPhase('error')
                setErrorMsg(result.error)
            }
        }).catch((err) => {
            setPhase('error')
            setErrorMsg(err.message)
        })

        return cleanup
    }, [workspace])

    // Save current browser state mid-session
    const handleSaveSession = async () => {
        setSavingSession(true)
        setSaveSuccess(false)
        const result = await window.omnilaunch.saveCurrentSession()
        setSavingSession(false)
        if (result.success) {
            setSaveSuccess(true)
            setTimeout(() => setSaveSuccess(false), 3000)
        }
    }

    // Quit: close browser + desktop apps + exit
    const handleQuit = async () => {
        await window.omnilaunch.quitAndRelaunch({ closeApps: true })
        window.omnilaunch.close()
    }

    // Friendly domain name from URL
    const getDomain = (url) => {
        try {
            return new URL(url.startsWith('http') ? url : `https://${url}`).hostname.replace('www.', '')
        } catch {
            return url
        }
    }

    return (
        <div className="card p-6 w-full max-w-sm animate-slide-up" style={{ maxHeight: 520 }}>
            {/* ─── LAUNCHING STATE ─── */}
            {phase === 'launching' && (
                <div className="flex flex-col items-center animate-fade-in">
                    <div className="w-14 h-14 mx-auto mb-4 rounded-full flex items-center justify-center bg-[#1a1a2e]">
                        <div className="spinner" style={{ width: 22, height: 22, borderWidth: 2 }} />
                    </div>

                    <h1 className="text-base font-semibold text-white mb-1">Launching Workspace</h1>
                    <p className="text-secondary text-xs mb-4">
                        {loadedItems.length} of {totalItems} items loaded
                    </p>

                    {/* Progress Bar */}
                    <div className="w-full h-1.5 rounded-full bg-[#14141c] mb-4 overflow-hidden">
                        <div
                            className="h-full rounded-full transition-all duration-500 ease-out"
                            style={{
                                width: `${progress}%`,
                                background: 'linear-gradient(90deg, #5b7bd5, #7b5bd5)'
                            }}
                        />
                    </div>

                    <div className="w-full space-y-1.5" style={{ maxHeight: 200, overflowY: 'auto' }}>
                        {loadedItems.map((item, i) => (
                            <div key={i} className="flex items-center gap-2 animate-fade-in">
                                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#4a9" strokeWidth="3" strokeLinecap="round">
                                    <polyline points="20 6 9 17 4 12" />
                                </svg>
                                <span className="text-xs text-secondary truncate">{getDomain(item)}</span>
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {/* ─── READY STATE ─── */}
            {phase === 'ready' && (
                <div className="flex flex-col animate-fade-in">
                    {/* Success Header */}
                    <div className="text-center mb-4">
                        <div className="w-14 h-14 mx-auto mb-3 rounded-full flex items-center justify-center bg-[#1a2a1a]">
                            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#4a9" strokeWidth="2.5" strokeLinecap="round">
                                <polyline points="20 6 9 17 4 12" />
                            </svg>
                        </div>
                        <h1 className="text-lg font-semibold text-white">Workspace Ready</h1>
                        <p className="text-secondary text-xs mt-1">
                            {loadedItems.length > 0
                                ? `${loadedItems.length} item${loadedItems.length !== 1 ? 's' : ''} launched`
                                : 'All set'}
                        </p>
                    </div>

                    {/* Loaded Items */}
                    {loadedItems.length > 0 && (
                        <div className="mb-4 p-3 rounded-lg bg-[#14141c]" style={{ maxHeight: 140, overflowY: 'auto' }}>
                            <div className="space-y-2">
                                {loadedItems.map((item, i) => (
                                    <div key={i} className="flex items-center gap-2.5">
                                        <div className="w-5 h-5 rounded flex items-center justify-center flex-shrink-0" style={{ background: '#1a2a1a' }}>
                                            <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="#4a9" strokeWidth="3" strokeLinecap="round">
                                                <polyline points="20 6 9 17 4 12" />
                                            </svg>
                                        </div>
                                        <span className="text-xs text-white truncate">{getDomain(item)}</span>
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}

                    {/* Action Buttons — Clean 3-button layout */}
                    <div className="space-y-2">
                        {/* Save Session — full width, primary */}
                        <button
                            className="btn-primary w-full text-sm py-2.5"
                            disabled={savingSession}
                            onClick={handleSaveSession}
                        >
                            {savingSession ? (
                                <span className="flex items-center justify-center gap-2">
                                    <div className="spinner" style={{ width: 12, height: 12, borderWidth: 2 }} />
                                    Saving...
                                </span>
                            ) : saveSuccess ? (
                                <span className="flex items-center justify-center gap-1.5">
                                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
                                        <polyline points="20 6 9 17 4 12" />
                                    </svg>
                                    Saved!
                                </span>
                            ) : (
                                <span className="flex items-center justify-center gap-1.5">
                                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
                                        <path d="M19 21H5a2 2 0 01-2-2V5a2 2 0 012-2h11l5 5v11a2 2 0 01-2 2z" />
                                        <polyline points="17 21 17 13 7 13 7 21" />
                                        <polyline points="7 3 7 8 15 8" />
                                    </svg>
                                    Save Session
                                </span>
                            )}
                        </button>

                        {/* Settings + Quit row */}
                        <div className="flex gap-2">
                            <button
                                className="btn-secondary flex-1 text-xs py-2"
                                onClick={onSettingsClick}
                            >
                                <span className="flex items-center justify-center gap-1.5">
                                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
                                        <circle cx="12" cy="12" r="3" />
                                        <path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z" />
                                    </svg>
                                    Settings
                                </span>
                            </button>

                            <button
                                className="flex-1 text-xs py-2 rounded-md border border-[#3a2a2a] text-[#d44] hover:bg-[#2a1a1a] transition-colors"
                                onClick={handleQuit}
                            >
                                <span className="flex items-center justify-center gap-1.5">
                                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
                                        <path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4" />
                                        <polyline points="16 17 21 12 16 7" />
                                        <line x1="21" y1="12" x2="9" y2="12" />
                                    </svg>
                                    Quit
                                </span>
                            </button>
                        </div>
                    </div>

                    <p className="text-muted text-center mt-3" style={{ fontSize: 10 }}>
                        Save your tabs & logins before unplugging
                    </p>
                </div>
            )}

            {/* ─── ERROR STATE ─── */}
            {phase === 'error' && (
                <div className="flex flex-col items-center animate-fade-in">
                    <div className="w-14 h-14 mx-auto mb-4 rounded-full flex items-center justify-center bg-[#2a1a1a]">
                        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#d44" strokeWidth="2" strokeLinecap="round">
                            <circle cx="12" cy="12" r="10" />
                            <line x1="15" y1="9" x2="9" y2="15" />
                            <line x1="9" y1="9" x2="15" y2="15" />
                        </svg>
                    </div>
                    <h1 className="text-base font-semibold text-white mb-1">Launch Failed</h1>
                    <p className="text-error text-xs text-center mb-4">{errorMsg}</p>

                    <div className="flex gap-2 w-full">
                        <button className="btn-secondary flex-1 text-sm" onClick={handleQuit}>
                            Quit
                        </button>
                    </div>
                </div>
            )}
        </div>
    )
}

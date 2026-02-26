import { useState, useEffect, useRef } from 'react'

export default function LaunchingScreen({ workspace, onGearClick }) {
    const [status, setStatus] = useState('Preparing workspace...')
    const [logs, setLogs] = useState([])
    const [done, setDone] = useState(false)
    const [error, setError] = useState(null)
    const logsEndRef = useRef(null)

    useEffect(() => {
        logsEndRef.current?.scrollIntoView({ behavior: 'smooth' })
    }, [logs])

    useEffect(() => {
        if (!workspace) return

        const enabledTabs = workspace.webTabs?.filter((t) => t.enabled) || []
        const enabledApps = workspace.desktopApps?.filter((a) => a.enabled) || []
        const total = enabledTabs.length + enabledApps.length

        if (total === 0) {
            setStatus('No items configured. Open settings to add tabs or apps.')
            setDone(true)
            return
        }

        const cleanup = window.omnilaunch.onLaunchStatus((msg) => {
            setLogs((prev) => [...prev, { text: msg, time: new Date().toLocaleTimeString() }])
            setStatus(msg)
        })

        setStatus(`Launching ${total} items...`)
        window.omnilaunch.launchWorkspace(workspace).then((result) => {
            if (result.success) {
                setStatus('Workspace ready')
                setDone(true)
            } else {
                setStatus('Completed with errors')
                setError(result.error)
                setDone(true)
            }
        }).catch((err) => {
            setError(err.message)
            setStatus('Launch failed')
            setDone(true)
        })

        return cleanup
    }, [workspace])

    const getLogType = (text) => {
        if (text.includes('[OK]') || text.includes('ready') || text.includes('complete') || text.includes('done')) return 'success'
        if (text.includes('[WARN]') || text.includes('failed') || text.includes('Could not')) return 'warning'
        return 'default'
    }

    return (
        <div className="card p-6 w-full max-w-md animate-slide-up overflow-hidden relative" style={{ maxHeight: 520 }}>
            {/* Settings Icon (always available) */}
            <button onClick={onGearClick} className="btn-icon absolute top-3 right-3" title="Settings">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
                    <circle cx="12" cy="12" r="3" />
                    <path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z" />
                </svg>
            </button>

            {/* Header */}
            <div className="text-center mb-4">
                <div
                    className="w-10 h-10 mx-auto mb-3 rounded-lg flex items-center justify-center"
                    style={{ background: done ? (error ? '#2a1a1a' : '#1a2a1a') : '#1a1a2e' }}
                >
                    {done ? (
                        error ? (
                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#d44" strokeWidth="2" strokeLinecap="round">
                                <circle cx="12" cy="12" r="10" />
                                <line x1="15" y1="9" x2="9" y2="15" />
                                <line x1="9" y1="9" x2="15" y2="15" />
                            </svg>
                        ) : (
                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#4a9" strokeWidth="2" strokeLinecap="round">
                                <polyline points="20 6 9 17 4 12" />
                            </svg>
                        )
                    ) : (
                        <div className="spinner" style={{ width: 18, height: 18, borderWidth: 2 }} />
                    )}
                </div>
                <h1 className="text-base font-semibold text-white">
                    {done ? (error ? 'Completed with Issues' : 'Workspace Ready') : 'Launching...'}
                </h1>
                <p className="text-secondary text-xs mt-1 truncate">{status}</p>
            </div>

            {/* Log Feed */}
            <div
                className="rounded-md p-3 overflow-y-auto"
                style={{
                    background: '#12121a',
                    maxHeight: 280,
                    fontFamily: "'Consolas', 'Courier New', monospace",
                    fontSize: 11,
                    lineHeight: 1.5
                }}
            >
                {logs.length === 0 && !done && (
                    <div className="flex items-center gap-2 text-muted">
                        <div className="spinner" style={{ width: 12, height: 12, borderWidth: 1.5 }} />
                        <span>Initializing automation engine...</span>
                    </div>
                )}

                {logs.map((log, i) => {
                    const type = getLogType(log.text)
                    return (
                        <div key={i} className="flex gap-2 py-0.5">
                            <span className="text-muted whitespace-nowrap">{log.time}</span>
                            <span className={type === 'success' ? 'text-success' : type === 'warning' ? 'text-warning' : 'text-secondary'}>
                                {log.text}
                            </span>
                        </div>
                    )
                })}
                <div ref={logsEndRef} />
            </div>

            {/* Error */}
            {error && (
                <p className="text-error text-xs text-center mt-3 animate-fade-in">{error}</p>
            )}

            {/* Done */}
            {done && !error && (
                <div className="text-center mt-3">
                    <p className="text-muted text-xs">
                        Browsers are open. Unplug USB to destroy session.
                    </p>
                </div>
            )}

            {/* Spinner */}
            {!done && (
                <div className="flex justify-center mt-4">
                    <div className="spinner" />
                </div>
            )}
        </div>
    )
}

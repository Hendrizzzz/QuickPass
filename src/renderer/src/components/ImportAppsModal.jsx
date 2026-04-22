import { useEffect, useRef, useState } from 'react'

export default function ImportAppsModal({ onClose, onImportComplete }) {
    const [phase, setPhase] = useState('scanning') // scanning | selection | importing | done
    const [apps, setApps] = useState([])
    const [selected, setSelected] = useState({})
    const [progress, setProgress] = useState({})
    const [importedApps, setImportedApps] = useState([])
    const [failedApps, setFailedApps] = useState([])
    const [error, setError] = useState('')
    const [elapsed, setElapsed] = useState(0)
    const cleanupRef = useRef(null)

    useEffect(() => {
        let cancelled = false
        window.omnilaunch.scanApps().then((results) => {
            if (cancelled) return
            setApps(results)
            setPhase('selection')
        }).catch((err) => {
            if (cancelled) return
            setError('Scan failed: ' + err.message)
            setPhase('selection')
        })
        return () => { cancelled = true }
    }, [])

    useEffect(() => {
        if (phase !== 'importing') {
            setElapsed(0)
            return
        }

        const start = Date.now()
        const interval = setInterval(() => {
            setElapsed(Math.floor((Date.now() - start) / 1000))
        }, 1000)

        return () => clearInterval(interval)
    }, [phase])

    useEffect(() => {
        cleanupRef.current = window.omnilaunch.onImportProgress((data) => {
            setProgress((prev) => ({ ...prev, [data.name]: data }))
        })

        return () => {
            if (cleanupRef.current) cleanupRef.current()
        }
    }, [])

    const toggleApp = (name) => {
        setSelected((prev) => {
            const current = prev[name]
            if (current?.checked) {
                const copy = { ...prev }
                delete copy[name]
                return copy
            }

            const app = apps.find((item) => item.name === name)
            return {
                ...prev,
                [name]: { checked: true, importData: canImportAppData(app) }
            }
        })
    }

    const toggleData = (name) => {
        const app = apps.find((item) => item.name === name)
        if (!canImportAppData(app)) return
        setSelected((prev) => ({
            ...prev,
            [name]: { ...prev[name], importData: !prev[name]?.importData }
        }))
    }

    const getSelectedCount = () => Object.values(selected).filter((value) => value.checked).length

    const getTotalSize = () => {
        let total = 0
        for (const app of apps) {
            const sel = selected[app.name]
            if (!sel?.checked) continue
            total += app.sizeMB
            if (sel.importData && app.dataPath) total += app.dataSizeMB
        }
        return total
    }

    const formatSize = (mb) => {
        if (mb >= 1024) return `${(mb / 1024).toFixed(1)} GB`
        return `${mb} MB`
    }

    const canImportAppData = (app) => !!app?.dataPath && app.importedDataSupported !== false

    const getCompatibilityNote = (app) => {
        if (app.type === 'chromium') {
            return 'Login sessions may not transfer between PCs.'
        }
        if (app.type === 'vscode-family') {
            return 'VS Code-family data import is supported; some accounts may still require sign-in on a new PC.'
        }
        if (app.type === 'electron') {
            return 'Imported app data is not verified for generic Electron apps. Launch-only isolation is best-effort.'
        }
        return 'Launch only - app data is not portable.'
    }

    const handleImport = async () => {
        const appsToImport = apps.filter((app) => selected[app.name]?.checked)
        if (appsToImport.length === 0) return

        setPhase('importing')
        const completed = []
        const failed = []

        window.omnilaunch.notifyImportStarted()
        try {
            for (const app of appsToImport) {
                const sel = selected[app.name]
                setProgress((prev) => ({
                    ...prev,
                    [app.name]: { phase: 'binary', percent: 0, copiedMB: 0, totalMB: app.sizeMB }
                }))

                const result = await window.omnilaunch.importApp({
                    sourcePath: app.sourcePath,
                    name: app.name,
                    exe: app.exe,
                    relativeExePath: app.relativeExePath || app.exe,
                    importData: canImportAppData(app) && sel.importData && !!app.dataPath,
                    dataPath: app.dataPath,
                    sizeMB: app.sizeMB || 0,
                    dataSizeMB: app.dataSizeMB || 0
                })

                if (result.success) {
                    completed.push(result.appConfig)
                    setProgress((prev) => ({
                        ...prev,
                        [app.name]: { phase: 'done', percent: 100 }
                    }))
                } else {
                    failed.push({ name: app.name, error: result.error || 'Import failed' })
                    setProgress((prev) => ({
                        ...prev,
                        [app.name]: { phase: 'error', error: result.error }
                    }))
                }
            }

            setImportedApps(completed)
            setFailedApps(failed)
            setPhase('done')
        } catch (err) {
            setImportedApps(completed)
            setFailedApps([...failed, { name: 'Unexpected', error: err.message || 'Import failed unexpectedly' }])
            setPhase('done')
        } finally {
            window.omnilaunch.notifyImportFinished()
        }
    }

    const handleDone = () => {
        onImportComplete(importedApps)
    }

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 animate-fade-in">
            <div className="card p-5 w-full max-w-sm animate-slide-up flex flex-col" style={{ maxHeight: 520 }}>
                {phase === 'scanning' && (
                    <div className="flex flex-col items-center py-8">
                        <div className="spinner mb-4" style={{ width: 24, height: 24, borderWidth: 2 }} />
                        <p className="text-sm text-white">Scanning for apps...</p>
                        <p className="text-xs text-muted mt-1">Checking installed programs</p>
                    </div>
                )}

                {phase === 'selection' && (
                    <div className="flex flex-col flex-1 min-h-0">
                        <div className="flex items-center justify-between mb-3 flex-shrink-0">
                            <h2 className="text-base font-semibold text-white">Import Apps from PC</h2>
                            <button className="btn-secondary text-xs py-1 px-2" onClick={onClose}>X</button>
                        </div>

                        <div className="mb-3 rounded-md border border-[#3a2a2a] bg-[#1a1520] p-2.5">
                            <p className="text-[11px] text-[#d4a44a]">
                                Browser-based and Electron apps may need a fresh sign-in on a different PC.
                            </p>
                        </div>

                        {apps.length === 0 && !error && (
                            <p className="text-muted text-xs text-center py-6">No portable apps found on this PC</p>
                        )}

                        {error && (
                            <p className="text-error text-xs text-center py-4">{error}</p>
                        )}

                        <div className="flex-1 overflow-y-auto min-h-0 mb-3">
                            {apps.map((app) => {
                                const sel = selected[app.name]
                                const isChecked = sel?.checked || false

                                return (
                                    <div key={app.name} className={`p-2.5 rounded-lg mb-1.5 border transition-colors ${isChecked ? 'bg-[#1a1a2e] border-[#3a3a5a]' : 'bg-[#14141c] border-[#2a2a3a]'}`}>
                                        <div className="flex items-center gap-2.5 cursor-pointer" onClick={() => toggleApp(app.name)}>
                                            <input
                                                type="checkbox"
                                                checked={isChecked}
                                                onChange={() => toggleApp(app.name)}
                                                className="accent-[#5b7bd5] flex-shrink-0"
                                                onClick={(e) => e.stopPropagation()}
                                            />
                                            <div className="flex-1 min-w-0">
                                                <div className="flex items-center gap-1.5">
                                                    <span className="text-sm text-white truncate">{app.name}</span>
                                                    {app.alreadyImported && (
                                                        <span className="px-1.5 py-0.5 rounded text-[9px] bg-green-900/40 text-green-400 border border-green-800/40 flex-shrink-0">
                                                            Imported
                                                        </span>
                                                    )}
                                                    <span className="px-1.5 py-0.5 rounded text-[9px] bg-[#1a1a2e] text-muted border border-[#2a2a3a] flex-shrink-0">
                                                        {app.type === 'electron' ? 'Electron' : app.type === 'chromium' ? 'Chromium' : app.type === 'vscode-family' ? 'VS Code' : 'Native'}
                                                    </span>
                                                </div>
                                            </div>
                                            <span className="text-xs text-muted flex-shrink-0">{formatSize(app.sizeMB)}</span>
                                        </div>

                                        {isChecked && (
                                            <div className="mt-2 ml-6 animate-fade-in">
                                                <p className="text-[11px] text-[#d4a44a] mb-2">
                                                    {getCompatibilityNote(app)}
                                                </p>
                                            </div>
                                        )}

                                        {isChecked && app.dataPath && (
                                            <div className="ml-6 animate-fade-in">
                                                <label className="flex items-center gap-2 cursor-pointer">
                                                    <input
                                                        type="checkbox"
                                                        checked={canImportAppData(app) ? (sel?.importData || false) : false}
                                                        disabled={!canImportAppData(app)}
                                                        onChange={() => toggleData(app.name)}
                                                        className="accent-[#5b7bd5]"
                                                    />
                                                    <span className="text-xs text-secondary">
                                                        {canImportAppData(app) ? 'Include logins & data' : 'App data import unavailable'}
                                                    </span>
                                                    <span className="text-xs text-muted ml-auto">{formatSize(app.dataSizeMB)}</span>
                                                </label>
                                                {!canImportAppData(app) && (
                                                    <p className="text-[10px] text-muted mt-1">
                                                        {app.importedDataSupportReason || 'QuickPass does not have a verified imported AppData adapter for this app.'}
                                                    </p>
                                                )}
                                            </div>
                                        )}
                                    </div>
                                )
                            })}
                        </div>

                        <div className="flex-shrink-0">
                            {getSelectedCount() > 0 && (
                                <div className="border-t border-[#2a2a3a] pt-3">
                                    <div className="flex justify-between mb-2">
                                        <span className="text-xs text-muted">{getSelectedCount()} app{getSelectedCount() !== 1 ? 's' : ''} selected</span>
                                        <span className="text-xs text-white font-medium">Total: {formatSize(getTotalSize())}</span>
                                    </div>
                                    <button className="btn-primary w-full text-sm py-2" onClick={handleImport}>
                                        Import Selected
                                    </button>
                                </div>
                            )}

                            {getSelectedCount() === 0 && apps.length > 0 && (
                                <p className="text-muted text-xs text-center py-2">Select apps to import</p>
                            )}
                        </div>
                    </div>
                )}

                {phase === 'importing' && (
                    <div className="flex flex-col flex-1 min-h-0">
                        <div className="flex-shrink-0">
                            <div className="flex items-center justify-between mb-3">
                                <h2 className="text-base font-semibold text-white">Importing...</h2>
                                <span className="text-xs font-mono text-muted tabular-nums">
                                    {String(Math.floor(elapsed / 60)).padStart(2, '0')}:{String(elapsed % 60).padStart(2, '0')}
                                </span>
                            </div>

                            <div className="flex items-center gap-2 p-2.5 rounded-md mb-3 bg-[#1a1520] border border-[#3a2a2a]">
                                <p className="text-xs text-[#d4a44a] font-medium">
                                    Warning: please do not close the app while importing. This may take several minutes.
                                </p>
                            </div>
                        </div>

                        <div className="flex-1 overflow-y-auto min-h-0 space-y-3">
                            {apps.filter((app) => selected[app.name]?.checked).map((app) => {
                                const prog = progress[app.name]
                                const isDone = prog?.phase === 'done'
                                const isError = prog?.phase === 'error'
                                const isActive = prog && !isDone && !isError

                                return (
                                    <div key={app.name} className="p-2.5 rounded-lg bg-[#14141c] border border-[#2a2a3a]">
                                        <div className="flex items-center gap-2 mb-1">
                                            {isDone && (
                                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#4a9" strokeWidth="3" strokeLinecap="round"><polyline points="20 6 9 17 4 12" /></svg>
                                            )}
                                            {isError && (
                                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#d44" strokeWidth="3" strokeLinecap="round"><line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" /></svg>
                                            )}
                                            {isActive && (
                                                <div className="spinner flex-shrink-0" style={{ width: 12, height: 12, borderWidth: 2 }} />
                                            )}
                                            {!prog && (
                                                <span className="text-muted text-xs">...</span>
                                            )}
                                            <span className="text-sm text-white">{app.name}</span>
                                            {isDone && <span className="text-xs text-muted ml-auto">Done</span>}
                                            {isError && <span className="text-xs text-error ml-auto">Failed</span>}
                                        </div>

                                        {isActive && (
                                            <>
                                                <div className="w-full h-1.5 rounded-full bg-[#0a0a14] overflow-hidden mb-1">
                                                    <div
                                                        className="h-full rounded-full transition-all duration-300"
                                                        style={{
                                                            width: `${prog.percent || 0}%`,
                                                            background: 'linear-gradient(90deg, #5b7bd5, #7b5bd5)'
                                                        }}
                                                    />
                                                </div>
                                                <p className="text-[10px] text-muted">
                                                    {prog.phase === 'compressing' ? 'Compressing' : prog.phase === 'binary' ? 'Copying to USB' : 'Copying logins & data'}... {prog.copiedMB || 0}/{prog.totalMB || 0} MB
                                                </p>
                                            </>
                                        )}
                                    </div>
                                )
                            })}
                        </div>
                    </div>
                )}

                {phase === 'done' && (
                    <div className="flex flex-col flex-1 min-h-0 animate-fade-in">
                        <div className="flex flex-col items-center mb-4 flex-shrink-0">
                            {failedApps.length === 0 ? (
                                <>
                                    <div className="w-12 h-12 mx-auto mb-3 rounded-full flex items-center justify-center bg-[#1a2a1a]">
                                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#4a9" strokeWidth="2.5" strokeLinecap="round">
                                            <polyline points="20 6 9 17 4 12" />
                                        </svg>
                                    </div>
                                    <h2 className="text-base font-semibold text-white">Import Complete</h2>
                                </>
                            ) : importedApps.length > 0 ? (
                                <>
                                    <div className="w-12 h-12 mx-auto mb-3 rounded-full flex items-center justify-center bg-[#2a2a1a]">
                                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#d4a44a" strokeWidth="2.5" strokeLinecap="round">
                                            <path d="M12 9v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                                        </svg>
                                    </div>
                                    <h2 className="text-base font-semibold text-white">Import Partially Complete</h2>
                                    <p className="text-xs text-muted mt-1">{importedApps.length} succeeded, {failedApps.length} failed</p>
                                </>
                            ) : (
                                <>
                                    <div className="w-12 h-12 mx-auto mb-3 rounded-full flex items-center justify-center bg-[#2a1a1a]">
                                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#e55" strokeWidth="2.5" strokeLinecap="round">
                                            <circle cx="12" cy="12" r="10" />
                                            <line x1="15" y1="9" x2="9" y2="15" />
                                            <line x1="9" y1="9" x2="15" y2="15" />
                                        </svg>
                                    </div>
                                    <h2 className="text-base font-semibold text-white">Import Failed</h2>
                                    <p className="text-xs text-muted mt-1">All {failedApps.length} imports failed</p>
                                </>
                            )}
                        </div>

                        <div className="flex-1 overflow-y-auto min-h-0 mb-4">
                            <div className="space-y-2">
                                {importedApps.map((app) => (
                                    <div key={app.name} className="flex items-center gap-2 p-2 rounded bg-[#14141c]">
                                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#4a9" strokeWidth="3" strokeLinecap="round"><polyline points="20 6 9 17 4 12" /></svg>
                                        <span className="text-sm text-white">{app.name}</span>
                                        {app.portableData ? (
                                            <span className="text-[10px] text-muted ml-auto">with data</span>
                                        ) : (
                                            <span className="text-[10px] text-muted ml-auto">binary only</span>
                                        )}
                                    </div>
                                ))}
                                {failedApps.map((app) => (
                                    <div key={app.name} className="flex items-center gap-2 p-2 rounded bg-[#1c1414]">
                                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#e55" strokeWidth="3" strokeLinecap="round">
                                            <line x1="18" y1="6" x2="6" y2="18" />
                                            <line x1="6" y1="6" x2="18" y2="18" />
                                        </svg>
                                        <span className="text-sm text-white">{app.name}</span>
                                        <span className="text-[10px] text-red-400 ml-auto truncate max-w-[140px]">{app.error}</span>
                                    </div>
                                ))}
                            </div>
                        </div>

                        <div className="flex-shrink-0">
                            {importedApps.length > 0 ? (
                                <>
                                    <p className="text-xs text-muted text-center mb-3">
                                        Apps added to your workspace. Click Save Changes to finalize.
                                    </p>
                                    <button className="btn-primary w-full text-sm py-2" onClick={handleDone}>
                                        Done
                                    </button>
                                </>
                            ) : (
                                <button className="btn-secondary w-full text-sm py-2" onClick={onClose}>
                                    Close
                                </button>
                            )}
                        </div>
                    </div>
                )}
            </div>
        </div>
    )
}

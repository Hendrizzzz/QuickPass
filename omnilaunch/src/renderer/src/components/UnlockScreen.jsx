import { useState, useRef, useEffect } from 'react'

export default function UnlockScreen({ driveInfo, vaultMeta, onUnlock, onGearClick }) {
    const isRemovable = driveInfo?.isRemovable
    const hasPIN = vaultMeta?.hasPIN && isRemovable
    const hardwareMismatch =
        vaultMeta?.isRemovable && vaultMeta?.createdOn !== driveInfo?.serialNumber

    const usePIN = hasPIN && !hardwareMismatch

    const [pin, setPin] = useState('')
    const [password, setPassword] = useState('')
    const [error, setError] = useState(
        hardwareMismatch ? 'Hardware change detected. Enter your master password.' : ''
    )
    const [loading, setLoading] = useState(false)
    const hiddenInputRef = useRef(null)

    useEffect(() => {
        if (hiddenInputRef.current) hiddenInputRef.current.focus()
    }, [])

    const handlePinSubmit = async () => {
        if (pin.length !== 4) return
        setLoading(true)
        setError('')
        const result = await window.omnilaunch.unlockWithPin(pin)
        if (result.success) {
            onUnlock(result.workspace)
        } else if (result.error === 'HARDWARE_MISMATCH') {
            setError(result.message)
            setPin('')
        } else {
            setError('Invalid PIN')
            setPin('')
            setLoading(false)
        }
    }

    useEffect(() => {
        if (usePIN && pin.length === 4) handlePinSubmit()
    }, [pin])

    const handlePasswordSubmit = async (e) => {
        e.preventDefault()
        if (!password.trim()) return
        setLoading(true)
        setError('')
        const result = await window.omnilaunch.unlockWithPassword(password)
        if (result.success) {
            onUnlock(result.workspace)
        } else {
            setError('Invalid password')
            setPassword('')
            setLoading(false)
        }
    }

    const handleGear = async () => {
        if (usePIN && pin.length === 4) {
            setLoading(true)
            const result = await window.omnilaunch.unlockWithPin(pin)
            if (result.success) {
                onGearClick(result.workspace)
                return
            }
            setLoading(false)
        } else if (!usePIN && password.trim().length > 0) {
            setLoading(true)
            const result = await window.omnilaunch.unlockWithPassword(password)
            if (result.success) {
                onGearClick(result.workspace)
                return
            }
            setLoading(false)
            setError('Invalid password')
            return
        }
        setError('Enter your password/PIN first, then click settings.')
    }

    const handlePinKeyDown = (e) => {
        if (e.key === 'Backspace') {
            setPin((prev) => prev.slice(0, -1))
            setError('')
        } else if (/^[0-9]$/.test(e.key) && pin.length < 4) {
            setPin((prev) => prev + e.key)
            setError('')
        }
    }

    return (
        <div className="card p-8 w-full max-w-sm animate-slide-up relative">
            {/* Settings Icon */}
            <button onClick={handleGear} className="btn-icon absolute top-3 right-3" title="Settings">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
                    <circle cx="12" cy="12" r="3" />
                    <path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z" />
                </svg>
            </button>

            {/* Header */}
            <div className="text-center mb-8">
                <div className="w-12 h-12 mx-auto mb-4 rounded-lg flex items-center justify-center bg-[#252530]">
                    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#5b7bd5" strokeWidth="2" strokeLinecap="round">
                        <rect x="3" y="11" width="18" height="11" rx="2" />
                        <path d="M7 11V7a5 5 0 0110 0v4" />
                    </svg>
                </div>
                <h1 className="text-lg font-semibold text-white">OmniLaunch</h1>
                <p className="text-secondary text-xs mt-1">
                    {isRemovable ? 'USB Drive' : 'Local Drive'}
                </p>
            </div>

            {/* PIN Mode */}
            {usePIN && (
                <div className="flex flex-col items-center gap-6" onClick={() => hiddenInputRef.current?.focus()}>
                    <p className="text-secondary text-sm">Enter your 4-digit PIN</p>
                    <div className="flex gap-4">
                        {[0, 1, 2, 3].map((i) => (
                            <div
                                key={i}
                                className={`pin-dot ${pin.length > i ? 'filled' : ''} ${error && !loading ? 'error' : ''}`}
                            />
                        ))}
                    </div>
                    <input
                        ref={hiddenInputRef}
                        type="text"
                        inputMode="numeric"
                        className="absolute opacity-0 w-0 h-0"
                        onKeyDown={handlePinKeyDown}
                        autoFocus
                    />
                    {loading && (
                        <div className="flex items-center gap-2">
                            <div className="spinner" />
                            <span className="text-secondary text-sm">Decrypting...</span>
                        </div>
                    )}
                </div>
            )}

            {/* Password Mode */}
            {!usePIN && (
                <form onSubmit={handlePasswordSubmit} className="flex flex-col gap-3">
                    <p className="text-secondary text-sm text-center">
                        {hardwareMismatch
                            ? 'Drive changed. Enter your master password.'
                            : 'Enter your Master Password'}
                    </p>
                    <input
                        type="password"
                        className={`form-input ${error ? 'error' : ''}`}
                        placeholder="Master Password"
                        value={password}
                        onChange={(e) => { setPassword(e.target.value); setError('') }}
                        autoFocus
                    />
                    <button type="submit" className="btn-primary w-full" disabled={loading || !password.trim()}>
                        {loading ? (
                            <span className="flex items-center justify-center gap-2">
                                <div className="spinner" style={{ width: 16, height: 16, borderWidth: 2 }} />
                                Decrypting...
                            </span>
                        ) : 'Unlock'}
                    </button>
                </form>
            )}

            {/* Error */}
            {error && !loading && (
                <p className="text-error text-xs text-center mt-3 animate-fade-in">{error}</p>
            )}
        </div>
    )
}

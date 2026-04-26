import { useState, useRef, useEffect } from 'react'

export default function UnlockScreen({ driveInfo, vaultMeta, onUnlock }) {
    const isRemovable = driveInfo?.isRemovable
    const hasPIN = vaultMeta?.hasPIN && isRemovable && vaultMeta?.supportsConvenienceUnlock
    const hardwareMismatch = !!vaultMeta?.hardwareMismatch

    const usePIN = hasPIN && !hardwareMismatch

    const [pin, setPin] = useState('')
    const [password, setPassword] = useState('')
    const [resetConfirming, setResetConfirming] = useState(false)
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
        const result = await window.wipesnap.unlockWithPin(pin)
        if (result.success) {
            onUnlock(result.workspace)
        } else if (result.error === 'HARDWARE_MISMATCH') {
            setError(result.message)
            setPin('')
        } else if (result.error === 'PIN_LOCKED') {
            const retrySeconds = Math.max(1, Math.ceil((result.retryAfterMs || 60_000) / 1000))
            setError(`Too many PIN attempts. Try again in about ${retrySeconds} seconds.`)
            setPin('')
            setLoading(false)
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
        const result = await window.wipesnap.unlockWithPassword(password)
        if (result.success) {
            onUnlock(result.workspace)
        } else {
            setError('Invalid password')
            setPassword('')
            setLoading(false)
        }
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

    const handleFactoryReset = async () => {
        setLoading(true)
        setResetConfirming(false)
        const tokenResult = await window.wipesnap.beginFactoryReset()
        if (!tokenResult?.success) {
            setError(tokenResult?.error || 'Factory reset could not start')
            setLoading(false)
            return
        }
        const resetResult = await window.wipesnap.factoryReset({ token: tokenResult.token })
        if (resetResult?.success) {
            window.location.reload()
        } else {
            setError(resetResult?.error || 'Factory reset failed')
            setLoading(false)
        }
    }

    return (
        <div className="card p-8 w-full max-w-sm animate-slide-up relative">
            {/* Header */}
            <div className="text-center mb-8">
                <div className="w-12 h-12 mx-auto mb-4 rounded-lg flex items-center justify-center bg-[#252530]">
                    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#5b7bd5" strokeWidth="2" strokeLinecap="round">
                        <rect x="3" y="11" width="18" height="11" rx="2" />
                        <path d="M7 11V7a5 5 0 0110 0v4" />
                    </svg>
                </div>
                <h1 className="text-lg font-semibold text-white">Wipesnap</h1>
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

            {/* Factory Reset */}
            {!loading && (
                <div className="mt-8 text-center border-t border-[#2a2a3a] pt-4">
                    {resetConfirming ? (
                        <div className="animate-fade-in">
                            <p className="text-error text-xs mb-2 font-medium">WARNING: This will delete the saved vault workspace and unlock settings.</p>
                            <div className="flex gap-2 justify-center">
                                <button className="btn-secondary text-xs py-1 px-3" onClick={() => setResetConfirming(false)}>Cancel</button>
                                <button className="btn-danger-text text-xs py-1 px-3 font-semibold" onClick={handleFactoryReset}>Yes, Wipe Vault</button>
                            </div>
                        </div>
                    ) : (
                        <button className="text-xs text-muted hover:text-white transition-colors" onClick={() => setResetConfirming(true)}>
                            Forgot Password? Factory Reset
                        </button>
                    )}
                </div>
            )}
        </div>
    )
}

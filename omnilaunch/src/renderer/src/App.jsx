import { useState, useEffect } from 'react'
import UnlockScreen from './components/UnlockScreen'
import SetupScreen from './components/SetupScreen'
import DashboardScreen from './components/DashboardScreen'
import LaunchingScreen from './components/LaunchingScreen'

export default function App() {
    const [screen, setScreen] = useState('loading')
    const [driveInfo, setDriveInfo] = useState(null)
    const [workspace, setWorkspace] = useState(null)
    const [vaultMeta, setVaultMeta] = useState(null)
    const [error, setError] = useState(null)

    useEffect(() => {
        async function boot() {
            try {
                const info = await window.omnilaunch.getDriveInfo()
                setDriveInfo(info)

                const exists = await window.omnilaunch.vaultExists()
                if (!exists) {
                    setScreen('setup')
                    return
                }

                const meta = await window.omnilaunch.loadVaultMeta()
                setVaultMeta(meta)

                if (meta?.fastBoot && meta?.fastBootVault) {
                    const result = await window.omnilaunch.tryFastBoot()
                    if (result.success) {
                        setWorkspace(result.workspace)
                        setScreen('launching')
                        return
                    }
                }

                setScreen('unlock')
            } catch (e) {
                setError(e.message)
                setScreen('unlock')
            }
        }
        boot()
    }, [])

    const handleSetupComplete = () => {
        setScreen('loading')
        setTimeout(async () => {
            const exists = await window.omnilaunch.vaultExists()
            if (exists) {
                const meta = await window.omnilaunch.loadVaultMeta()
                setVaultMeta(meta)
                setScreen('unlock')
            }
        }, 100)
    }

    const handleUnlock = (ws) => {
        setWorkspace(ws)
        setScreen('launching')
    }

    const handleGearClick = (ws) => {
        setWorkspace(ws)
        setScreen('dashboard')
    }

    const handleDashboardSave = () => {
        setScreen('loading')
        setTimeout(async () => {
            const meta = await window.omnilaunch.loadVaultMeta()
            setVaultMeta(meta)
            setScreen('unlock')
        }, 100)
    }

    return (
        <div className="w-full h-full bg-[#1a1a24] relative overflow-hidden flex flex-col">
            {/* Titlebar */}
            <div className="titlebar">
                <button
                    onClick={() => window.omnilaunch.close()}
                    className="btn-icon"
                    style={{ width: 28, height: 28 }}
                    title="Close"
                >
                    <svg width="10" height="10" viewBox="0 0 10 10" fill="none" stroke="currentColor" strokeWidth="1.5">
                        <path d="M1 1l8 8M9 1l-8 8" />
                    </svg>
                </button>
            </div>

            {/* Main Content */}
            <div className="flex-1 flex items-center justify-center px-6 pb-6">
                {screen === 'loading' && (
                    <div className="flex flex-col items-center gap-3 animate-fade-in">
                        <div className="spinner" />
                        <p className="text-secondary text-sm">Loading...</p>
                    </div>
                )}

                {screen === 'setup' && (
                    <SetupScreen driveInfo={driveInfo} onComplete={handleSetupComplete} />
                )}

                {screen === 'unlock' && (
                    <UnlockScreen
                        driveInfo={driveInfo}
                        vaultMeta={vaultMeta}
                        onUnlock={handleUnlock}
                        onGearClick={handleGearClick}
                    />
                )}

                {screen === 'dashboard' && (
                    <DashboardScreen
                        driveInfo={driveInfo}
                        workspace={workspace}
                        vaultMeta={vaultMeta}
                        onSave={handleDashboardSave}
                        onCancel={() => setScreen('unlock')}
                    />
                )}

                {screen === 'launching' && (
                    <LaunchingScreen workspace={workspace} />
                )}
            </div>
        </div>
    )
}

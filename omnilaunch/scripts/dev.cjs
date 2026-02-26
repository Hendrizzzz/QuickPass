/**
 * OmniLaunch Dev Launcher
 * Builds the app using electron-vite, then launches Electron with
 * ELECTRON_RUN_AS_NODE properly unset (required when running inside
 * Electron-based IDEs like Antigravity/Cursor/VS Code).
 */
const { execSync, spawn } = require('child_process')
const path = require('path')

const projectRoot = path.join(__dirname, '..')

// Step 1: Build all three targets with electron-vite
console.log('[OmniLaunch] Building...')
execSync('npx electron-vite build', {
    cwd: projectRoot,
    stdio: 'inherit',
    env: { ...process.env }
})

// Step 2: Resolve the electron binary path
const electronPath = require('electron')

// Step 3: Launch Electron with ELECTRON_RUN_AS_NODE explicitly removed
console.log('[OmniLaunch] Launching Electron...')
const env = { ...process.env }
delete env.ELECTRON_RUN_AS_NODE

const child = spawn(electronPath, ['.'], {
    cwd: projectRoot,
    stdio: 'inherit',
    env
})

child.on('close', (code) => {
    process.exit(code)
})

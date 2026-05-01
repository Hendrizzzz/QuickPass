const { copyFileSync, existsSync, mkdirSync, readdirSync, rmSync, statSync } = require('fs')
const { basename, join, relative, resolve, sep } = require('path')

const repoRoot = resolve(__dirname, '..')
const sourceDir = join(repoRoot, 'src', 'phone-planner')
const targetDir = join(repoRoot, 'out', 'phone-planner-staging')

const PHONE_PLANNER_STAGING_FILES = Object.freeze([
    'app.js',
    'index.html',
    'manifest.webmanifest',
    'phonePlannerCloudCrypto.js',
    'phonePlannerCloudStorage.js',
    'phonePlannerCloudWorkflow.js',
    'phonePlannerCore.js',
    'phonePlannerFirebaseConfig.js',
    'phonePlannerFirebaseRest.js',
    'phonePlannerStorage.js',
    'service-worker.js',
    'styles.css',
    'firebase-staging-config.example.json'
])

const OPTIONAL_STAGING_CONFIG = 'firebase-staging-config.json'
const FORBIDDEN_ARTIFACT_NAMES = new Set([
    'vault.json',
    'vault.meta.json',
    'vault.state.json',
    'package.json',
    'firebase.json'
])
const FORBIDDEN_ARTIFACT_SEGMENTS = new Set([
    'Apps',
    'AppData',
    'BrowserProfile',
    'dist',
    'functions',
    'tests',
    '_planning'
])

function fail(message) {
    throw new Error(message)
}

function isWithin(parent, candidate) {
    const relativePath = relative(parent, candidate)
    return relativePath === '' || !!relativePath && !relativePath.startsWith('..') && !relativePath.includes(`..${sep}`)
}

function assertSafeTarget() {
    const outRoot = resolve(repoRoot, 'out')
    const resolvedTarget = resolve(targetDir)
    if (!isWithin(outRoot, resolvedTarget) || resolvedTarget.toLowerCase() === outRoot.toLowerCase()) {
        fail(`Refusing to build phone planner outside the out/ staging artifact root: ${resolvedTarget}`)
    }
}

function copyAllowlistedFile(fileName) {
    const sourcePath = resolve(sourceDir, fileName)
    const targetPath = resolve(targetDir, basename(fileName))
    if (!isWithin(sourceDir, sourcePath)) fail(`Refusing to copy outside phone planner source: ${fileName}`)
    if (!isWithin(targetDir, targetPath)) fail(`Refusing to write outside phone planner staging artifact: ${fileName}`)
    if (!existsSync(sourcePath) || !statSync(sourcePath).isFile()) {
        fail(`Missing phone planner staging source file: ${fileName}`)
    }
    copyFileSync(sourcePath, targetPath)
}

function assertSafeArtifactFiles(root = targetDir) {
    if (!existsSync(root)) return true
    for (const entry of readdirSync(root, { withFileTypes: true })) {
        const fullPath = join(root, entry.name)
        if (FORBIDDEN_ARTIFACT_NAMES.has(entry.name)) {
            fail(`Forbidden file in phone planner staging artifact: ${entry.name}`)
        }
        if (FORBIDDEN_ARTIFACT_SEGMENTS.has(entry.name)) {
            fail(`Forbidden directory in phone planner staging artifact: ${entry.name}`)
        }
        if (entry.isDirectory()) assertSafeArtifactFiles(fullPath)
    }
    return true
}

function buildPhonePlannerStaging() {
    assertSafeTarget()
    rmSync(targetDir, { recursive: true, force: true })
    mkdirSync(targetDir, { recursive: true })
    for (const fileName of PHONE_PLANNER_STAGING_FILES) copyAllowlistedFile(fileName)

    const configPath = join(sourceDir, OPTIONAL_STAGING_CONFIG)
    if (existsSync(configPath)) {
        copyAllowlistedFile(OPTIONAL_STAGING_CONFIG)
    } else {
        console.warn('No src/phone-planner/firebase-staging-config.json found; staging artifact will require config before deploy.')
    }
    assertSafeArtifactFiles()
    console.log(`Built hosted phone planner staging artifact: ${targetDir}`)
}

if (require.main === module) {
    try {
        buildPhonePlannerStaging()
    } catch (error) {
        console.error(error.message || error)
        process.exitCode = 1
    }
}

module.exports = {
    FORBIDDEN_ARTIFACT_NAMES,
    FORBIDDEN_ARTIFACT_SEGMENTS,
    OPTIONAL_STAGING_CONFIG,
    PHONE_PLANNER_STAGING_FILES,
    sourceDir,
    targetDir,
    assertSafeArtifactFiles,
    buildPhonePlannerStaging
}

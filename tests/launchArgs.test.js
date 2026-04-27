import assert from 'assert/strict'
import { test } from 'node:test'
import {
    createLaunchDiagnosticFields,
    isWindowsScriptLaunchPath,
    shouldUseWindowsShellActivationForExecutable
} from '../src/main/engine.js'
import { parseLaunchArgs } from '../src/main/launchArgs.js'

test('parseLaunchArgs splits simple flags', () => {
    assert.deepEqual(parseLaunchArgs('--new-window --profile Default'), ['--new-window', '--profile', 'Default'])
})

test('parseLaunchArgs preserves quoted values with spaces', () => {
    assert.deepEqual(
        parseLaunchArgs('--user-data-dir="C:\\Users\\A Person\\Profile" "--flag=value with spaces"'),
        ['--user-data-dir=C:\\Users\\A Person\\Profile', '--flag=value with spaces']
    )
})

test('parseLaunchArgs accepts array values', () => {
    assert.deepEqual(parseLaunchArgs([' --safe-mode ', '', null, '--verbose']), ['--safe-mode', '--verbose'])
})

test('parseLaunchArgs rejects unterminated quotes', () => {
    assert.throws(() => parseLaunchArgs('"C:\\Program Files\\App'), /unterminated quote/)
})

test('Notepad shell activation is narrow and argument-free', () => {
    const expected = process.platform === 'win32'
    const windowsRoot = process.env.SystemRoot || process.env.WINDIR || 'C:\\Windows'
    assert.equal(shouldUseWindowsShellActivationForExecutable(`${windowsRoot}\\System32\\notepad.exe`, []), expected)
    assert.equal(shouldUseWindowsShellActivationForExecutable(`${windowsRoot}\\System32\\notepad.exe`, ['notes.txt']), false)
    assert.equal(shouldUseWindowsShellActivationForExecutable('C:\\Temp\\notepad.exe', []), false)
    assert.equal(shouldUseWindowsShellActivationForExecutable('C:\\Windows\\System32\\cmd.exe', []), false)
})

test('Notepad shell activation diagnostics preserve direct-launch classification', () => {
    const expected = process.platform === 'win32'
    const windowsRoot = process.env.SystemRoot || process.env.WINDIR || 'C:\\Windows'
    const appPath = `${windowsRoot}\\System32\\notepad.exe`
    const diagnostics = createLaunchDiagnosticFields({
        name: 'Notepad',
        launchSourceType: 'host-exe',
        launchMethod: 'spawn'
    }, appPath, [])

    assert.equal(diagnostics.windowsShellActivation, expected)
    assert.equal(diagnostics.launchTargetClassification, 'direct-launch-target')
    assert.match(diagnostics.launchTargetClassificationReason, /direct app process/)
    assert.deepEqual(diagnostics.launchArgs, [])

    const withArgs = createLaunchDiagnosticFields({
        name: 'Notepad',
        launchSourceType: 'host-exe',
        launchMethod: 'spawn'
    }, appPath, ['notes.txt'])
    assert.equal(withArgs.windowsShellActivation, false)
    assert.deepEqual(withArgs.launchArgs, ['notes.txt'])
})

test('Windows script launch paths are classified as unsupported executable picks', () => {
    assert.equal(isWindowsScriptLaunchPath('C:\\Scripts\\Launch.cmd'), true)
    assert.equal(isWindowsScriptLaunchPath('C:\\Scripts\\Launch.bat'), true)
    assert.equal(isWindowsScriptLaunchPath('C:\\Windows\\System32\\cmd.exe'), false)
})

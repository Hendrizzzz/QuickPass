import assert from 'assert/strict'
import { test } from 'node:test'
import {
    createAvailableAppStorageId,
    describePathKind,
    getCanonicalArchiveName,
    getCanonicalAppStorageId,
    validateCaptureSessionInput,
    validateFactoryResetInput,
    validateImportAppInput,
    validatePayloadIdsInput,
    validateQuitOptions,
    validateSaveVaultInput,
    validateWorkspaceInput
} from '../src/main/ipcValidation.js'

test('workspace validation accepts known launch path forms', () => {
    const workspace = validateWorkspaceInput({
        webTabs: [{ url: 'https://example.com', enabled: true }],
        desktopApps: [
            { name: 'USB App', path: '[USB]\\Apps\\USB_App\\app.exe', enabled: true },
            { name: 'Host App', path: 'C:\\Program Files\\Host\\host.exe', launchSourceType: 'host-exe' },
            { name: 'Host Folder', path: 'C:\\Projects', launchSourceType: 'host-folder', launchMethod: 'shell-execute' },
            { name: 'Protocol App', path: 'zoommtg:', launchSourceType: 'protocol-uri', launchMethod: 'protocol' },
            { name: 'Packaged App', path: 'shell:AppsFolder\\Microsoft.WindowsCalculator_8wekyb3d8bbwe!App', launchSourceType: 'packaged-app', launchMethod: 'packaged-app' }
        ]
    })

    assert.equal(workspace.webTabs.length, 1)
    assert.equal(workspace.desktopApps.length, 5)
    assert.equal(describePathKind(workspace.desktopApps[0].path), 'usb-macro')
    assert.equal(workspace.desktopApps[2].launchSourceType, 'host-folder')
    assert.equal(workspace.desktopApps[2].launchMethod, 'shell-execute')
    assert.equal(describePathKind(workspace.desktopApps[3].path), 'protocol')
    assert.equal(workspace.desktopApps[3].launchMethod, 'protocol')
})

test('workspace validation rejects traversal, malformed URLs, and unknown launch sources', () => {
    assert.throws(() => validateWorkspaceInput({
        desktopApps: [{ name: 'Bad', path: '[USB]\\Apps\\..\\vault.json' }]
    }), /parent-directory traversal/)

    assert.throws(() => validateWorkspaceInput({
        webTabs: [{ url: 'not a url' }]
    }), /whitespace/)

    assert.throws(() => validateWorkspaceInput({
        webTabs: [{ url: 'javascript:alert(1)' }]
    }), /http or https/)

    assert.throws(() => validateWorkspaceInput({
        webTabs: [{ url: 'localhost:99999' }]
    }), /valid web URL/)

    assert.throws(() => validateWorkspaceInput({
        webTabs: [{ url: '999.999.999.999:80' }]
    }), /valid web URL|valid IPv4/)

    assert.throws(() => validateWorkspaceInput({
        webTabs: [{ url: 'http://user:pass@example.com' }]
    }), /username or password/)

    assert.throws(() => validateWorkspaceInput({
        desktopApps: [{ name: 'Bad', path: 'C:\\Bad\\bad.exe', launchSourceType: 'surprise' }]
    }), /Unsupported launchSourceType/)
})

test('workspace validation strips untrusted renderer-supplied metadata', () => {
    const workspace = validateWorkspaceInput({
        arbitraryWorkspaceField: true,
        webTabs: [{ id: 'tab-1', url: 'https://example.com', injected: 'nope' }],
        desktopApps: [{
            id: 'app-1',
            name: 'USB App',
            path: '[USB]\\Apps\\USB_App\\app.exe',
            manifest: { safeName: 'Injected' },
            launchProfile: 'chromium-browser',
            dataProfile: { mode: 'chromium-user-data' },
            ownershipProofLevel: 'strong',
            closePolicy: 'owned-tree',
            canQuitFromOmniLaunch: true,
            closeManagedAfterSpawn: true
        }]
    })

    assert.equal('arbitraryWorkspaceField' in workspace, false)
    assert.equal('injected' in workspace.webTabs[0], false)
    assert.equal('manifest' in workspace.desktopApps[0], false)
    assert.equal('launchProfile' in workspace.desktopApps[0], false)
    assert.equal('dataProfile' in workspace.desktopApps[0], false)
    assert.equal('ownershipProofLevel' in workspace.desktopApps[0], false)
    assert.equal('closePolicy' in workspace.desktopApps[0], false)
    assert.equal('canQuitFromOmniLaunch' in workspace.desktopApps[0], false)
    assert.equal('closeManagedAfterSpawn' in workspace.desktopApps[0], false)
})

test('workspace validation enforces launch source path method consistency', () => {
    assert.throws(() => validateWorkspaceInput({
        desktopApps: [{
            name: 'Mismatch',
            path: 'C:\\Windows\\System32\\notepad.exe',
            launchSourceType: 'protocol-uri',
            launchMethod: 'protocol'
        }]
    }), /protocol URI/)

    assert.throws(() => validateWorkspaceInput({
        desktopApps: [{
            name: 'Packaged Mismatch',
            path: 'C:\\Windows\\System32\\notepad.exe',
            launchSourceType: 'packaged-app',
            launchMethod: 'packaged-app'
        }]
    }), /shell:AppsFolder/)

    assert.throws(() => validateWorkspaceInput({
        desktopApps: [{
            name: 'UNC',
            path: '\\\\server\\share\\app.exe',
            launchSourceType: 'host-exe',
            launchMethod: 'spawn'
        }]
    }), /network\/UNC/)

    assert.throws(() => validateWorkspaceInput({
        desktopApps: [{
            name: 'ShellExe',
            path: 'C:\\Windows\\System32\\notepad.exe',
            launchSourceType: 'shell-execute',
            launchMethod: 'shell-execute'
        }]
    }), /direct executable/)

    assert.throws(() => validateWorkspaceInput({
        desktopApps: [{
            name: 'FolderAsExe',
            path: 'C:\\Program Files',
            launchSourceType: 'host-exe',
            launchMethod: 'spawn'
        }]
    }), /direct executable/)

    assert.throws(() => validateWorkspaceInput({
        desktopApps: [{
            name: 'ExeAsFolder',
            path: 'C:\\Windows\\System32\\notepad.exe',
            launchSourceType: 'host-folder',
            launchMethod: 'shell-execute'
        }]
    }), /cannot be a direct executable/)

    assert.throws(() => validateWorkspaceInput({
        desktopApps: [{
            name: 'ProtocolMismatch',
            path: 'ms-settings:',
            launchSourceType: 'protocol-uri',
            launchMethod: 'protocol',
            protocolScheme: 'zoommtg'
        }]
    }), /protocolScheme/)
})

test('save vault validation normalizes security fields', () => {
    const payload = validateSaveVaultInput({
        masterPassword: 'correct horse battery staple',
        pin: '1234',
        fastBoot: true,
        workspace: { webTabs: [], desktopApps: [] }
    })

    assert.equal(payload.pin, '1234')
    assert.equal(payload.fastBoot, true)
    assert.deepEqual(payload.workspace.webTabs, [])
})

test('import validation canonicalizes display names into storage ids', () => {
    const payload = validateImportAppInput({
        sourcePath: 'C:\\Program Files\\Visual Studio Code',
        name: 'Visual Studio Code',
        exe: 'Code.exe',
        relativeExePath: 'bin\\Code.exe',
        importData: false,
        sizeMB: 100
    })

    assert.equal(payload.storageId, 'Visual_Studio_Code')
    assert.equal(payload.archiveName, 'Visual_Studio_Code.tar.zst')
    assert.equal(getCanonicalAppStorageId('A/B App'), 'A_B_App')
    assert.equal(getCanonicalArchiveName('A/B App'), 'A_B_App.tar.zst')
    assert.equal(createAvailableAppStorageId('A/B App', id => id === 'A_B_App'), 'A_B_App-2')
    assert.equal(createAvailableAppStorageId('A/B App', id => ['A_B_App', 'A_B_App-2'].includes(id)), 'A_B_App-3')
})

test('import validation rejects absolute or traversing relative exe paths', () => {
    assert.throws(() => validateImportAppInput({
        sourcePath: 'C:\\App',
        name: 'Bad',
        relativeExePath: '..\\evil.exe'
    }), /parent-directory traversal/)

    assert.throws(() => validateImportAppInput({
        sourcePath: 'C:\\App',
        name: 'Bad',
        relativeExePath: 'C:\\Windows\\notepad.exe'
    }), /relative path/)
})

test('import validation rejects non-absolute source and data paths', () => {
    assert.throws(() => validateImportAppInput({
        sourcePath: 'App',
        name: 'Bad',
        relativeExePath: 'app.exe'
    }), /absolute filesystem path/)

    assert.throws(() => validateImportAppInput({
        sourcePath: 'C:\\App',
        name: 'Bad',
        relativeExePath: 'app.exe',
        importData: true,
        dataPath: '..\\Users\\Bad'
    }), /absolute filesystem path/)

    assert.throws(() => validateImportAppInput({
        sourcePath: '\\\\server\\share\\App',
        name: 'Remote',
        relativeExePath: 'app.exe'
    }), /network\/UNC/)
})

test('cleanup and small option payloads are strict', () => {
    assert.deepEqual(validatePayloadIdsInput({ payloadIds: ['abcdef1234567890'] }), {
        payloadIds: ['abcdef1234567890']
    })
    assert.throws(() => validatePayloadIdsInput({ payloadIds: ['nope'] }), /valid payload id/)
    assert.deepEqual(validateQuitOptions({ closeApps: true }), { closeApps: true })
    assert.deepEqual(validateCaptureSessionInput({ masterPassword: 'capture-password' }), { masterPassword: 'capture-password' })
    assert.throws(() => validateCaptureSessionInput({ masterPassword: 'pw' }), /at least 8 characters/)
    assert.deepEqual(validateFactoryResetInput({
        token: '0123456789abcdef0123456789abcdef'
    }, {
        expectedToken: '0123456789abcdef0123456789abcdef'
    }), { token: '0123456789abcdef0123456789abcdef' })
    assert.throws(() => validateFactoryResetInput({ token: 'yes' }), /token/)
    assert.throws(() => validateFactoryResetInput({
        token: '0123456789abcdef0123456789abcdef'
    }, {
        expectedToken: 'fedcba9876543210fedcba9876543210'
    }), /expired/)
})

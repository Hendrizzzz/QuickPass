import assert from 'assert/strict'
import { test } from 'node:test'
import {
    createCapabilityRecord,
    createCapabilityStore,
    generateCapabilityId,
    validateCapabilityRecord,
    validateCapabilityVaultValue
} from '../src/main/capabilityStore.js'

const FIXED_NOW = '2026-04-25T00:00:00.000Z'

function bytes(hexByte) {
    return (size) => Buffer.alloc(size, hexByte)
}

function hostExeInput(overrides = {}) {
    return {
        type: 'host-exe',
        provenance: 'browse-exe',
        displayName: 'Visual Studio Code',
        launch: {
            path: 'C:\\Program Files\\Microsoft VS Code\\Code.exe'
        },
        policy: {
            allowedArgs: 'none',
            canCloseFromWipesnap: true,
            ownership: 'owned-process'
        },
        ...overrides
    }
}

function protocolInput(overrides = {}) {
    return {
        type: 'protocol-uri',
        provenance: 'protocol-scan',
        displayName: 'Settings',
        launch: {
            uri: 'ms-settings:',
            method: 'protocol'
        },
        policy: {
            allowedArgs: 'none',
            canCloseFromWipesnap: false,
            ownership: 'external'
        },
        ...overrides
    }
}

function hostFolderInput(overrides = {}) {
    return {
        type: 'host-folder',
        provenance: 'browse-folder',
        displayName: 'Projects',
        launch: {
            path: 'C:\\Projects'
        },
        policy: {
            allowedArgs: 'none',
            canCloseFromWipesnap: false,
            ownership: 'external'
        },
        ...overrides
    }
}

test('generateCapabilityId uses opaque random bytes with the expected capability id shape', () => {
    const id = generateCapabilityId({ randomBytes: bytes(0xab) })

    assert.equal(id, `cap_${'ab'.repeat(32)}`)
    assert.match(id, /^cap_[a-f0-9]{64}$/)
})

test('createCapabilityRecord generates fresh opaque ids independent of renderer-visible fields', () => {
    const input = hostExeInput({
        capabilityId: `cap_${'11'.repeat(32)}`,
        launch: {
            path: 'C:\\registry-key-looking-folder\\protocol-name\\Code.exe'
        }
    })

    const first = createCapabilityRecord(input, {
        randomBytes: bytes(0xaa),
        now: FIXED_NOW
    })
    const second = createCapabilityRecord(input, {
        randomBytes: bytes(0xbb),
        now: FIXED_NOW
    })

    assert.equal(first.capabilityId, `cap_${'aa'.repeat(32)}`)
    assert.equal(second.capabilityId, `cap_${'bb'.repeat(32)}`)
    assert.notEqual(first.capabilityId, input.capabilityId)
    assert.notEqual(first.capabilityId, second.capabilityId)
    assert.equal(first.capabilityId.includes('registry'), false)
    assert.equal(first.capabilityId.includes('protocol'), false)
    assert.equal(first.capabilityId.includes('Code'), false)
})

test('createCapabilityRecord defaults to distinct random capability ids', () => {
    const first = createCapabilityRecord(hostExeInput(), { now: FIXED_NOW })
    const second = createCapabilityRecord(hostExeInput(), { now: FIXED_NOW })

    assert.match(first.capabilityId, /^cap_[a-f0-9]{64}$/)
    assert.match(second.capabilityId, /^cap_[a-f0-9]{64}$/)
    assert.notEqual(first.capabilityId, second.capabilityId)
})

test('createCapabilityRecord uses the default runtime timestamp path', () => {
    const record = createCapabilityRecord(hostExeInput(), {
        randomBytes: bytes(0x0c)
    })

    assert.match(record.verification.lastVerifiedAt, /^\d{4}-\d{2}-\d{2}T/)
})

test('validateCapabilityRecord normalizes a strict vault capability schema', () => {
    const record = createCapabilityRecord(protocolInput(), {
        randomBytes: bytes(0x01),
        now: FIXED_NOW
    })
    const validated = validateCapabilityRecord(record)

    assert.deepEqual(validated, {
        version: 1,
        capabilityId: `cap_${'01'.repeat(32)}`,
        type: 'protocol-uri',
        provenance: 'protocol-scan',
        displayName: 'Settings',
        launch: {
            method: 'protocol',
            uri: 'ms-settings:',
            protocolScheme: 'ms-settings'
        },
        policy: {
            allowedArgs: 'none',
            canCloseFromWipesnap: false,
            ownership: 'external'
        },
        verification: {
            lastVerifiedAt: FIXED_NOW
        }
    })
})

test('capability store creates, reads, clones, and serializes encrypted-vault-shaped records', () => {
    const store = createCapabilityStore()
    const created = store.create(hostExeInput(), {
        randomBytes: bytes(0x02),
        now: FIXED_NOW
    })

    const read = store.read(created.capabilityId)
    read.launch.path = 'C:\\Windows\\System32\\notepad.exe'

    assert.equal(store.read(created.capabilityId).launch.path, 'C:\\Program Files\\Microsoft VS Code\\Code.exe')
    assert.deepEqual(store.ids(), [created.capabilityId])

    const vaultValue = store.toVaultValue()
    assert.deepEqual(Object.keys(vaultValue), ['version', 'records'])
    assert.equal('summaries' in vaultValue, false)
    assert.equal('preUnlockSummaries' in vaultValue, false)
    assert.deepEqual(vaultValue.records[created.capabilityId], created)
})

test('capability store loads valid encrypted-vault-shaped records', () => {
    const created = createCapabilityRecord(hostExeInput(), {
        randomBytes: bytes(0x03),
        now: FIXED_NOW
    })
    const vaultValue = {
        version: 1,
        records: {
            [created.capabilityId]: created
        }
    }

    const store = createCapabilityStore({ vaultValue })

    assert.deepEqual(store.require(created.capabilityId), created)
})

test('capability store fails closed for missing and malformed capability ids', () => {
    const store = createCapabilityStore()
    const missingId = `cap_${'44'.repeat(32)}`

    assert.equal(store.read(missingId), null)
    assert.throws(() => store.require(missingId), /missing, stale, or unavailable/)
    assert.throws(() => store.read('C:\\Program Files\\App\\app.exe'), /capabilityId is invalid/)
})

test('capability validation rejects malformed, summary-bearing, and overbroad records', () => {
    const record = createCapabilityRecord(hostExeInput(), {
        randomBytes: bytes(0x05),
        now: FIXED_NOW
    })

    assert.throws(() => validateCapabilityRecord({
        ...record,
        preUnlockSummary: { displayName: record.displayName }
    }), /preUnlockSummary is not supported/)

    assert.throws(() => validateCapabilityRecord({
        ...record,
        policy: {
            ...record.policy,
            allowedArgs: 'all'
        }
    }), /allowedArgs is not supported/)

    assert.throws(() => validateCapabilityRecord({
        ...record,
        launch: {
            ...record.launch,
            path: 'C:\\Program Files'
        }
    }), /direct executable/)
})

test('capability validation rejects cross-type launch authority fields', () => {
    assert.throws(() => createCapabilityRecord(hostExeInput({
        launch: {
            path: 'C:\\Program Files\\Microsoft VS Code\\Code.exe',
            protocolCommand: '"C:\\Program Files\\Handler\\handler.exe" "%1"'
        }
    }), {
        randomBytes: bytes(0x08),
        now: FIXED_NOW
    }), /protocolCommand is not supported for host-exe/)

    assert.throws(() => createCapabilityRecord(protocolInput({
        launch: {
            uri: 'ms-settings:',
            method: 'protocol',
            shortcutPath: 'C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Settings.lnk'
        }
    }), {
        randomBytes: bytes(0x09),
        now: FIXED_NOW
    }), /shortcutPath is not supported for protocol-uri/)

    assert.throws(() => createCapabilityRecord(hostFolderInput({
        launch: {
            path: 'C:\\Projects',
            registryKey: 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Example'
        }
    }), {
        randomBytes: bytes(0x0a),
        now: FIXED_NOW
    }), /registryKey is not supported for host-folder/)
})

test('vault value validation rejects tampered records instead of partially loading authority', () => {
    const record = createCapabilityRecord(hostExeInput(), {
        randomBytes: bytes(0x06),
        now: FIXED_NOW
    })
    const wrongKey = `cap_${'07'.repeat(32)}`

    assert.throws(() => validateCapabilityVaultValue({
        version: 1,
        records: {
            [wrongKey]: record
        }
    }), /record key must match/)

    assert.throws(() => createCapabilityStore({
        vaultValue: {
            version: 1,
            records: {
                [record.capabilityId]: {
                    ...record,
                    launch: {
                        ...record.launch,
                        method: 'shell-execute'
                    }
                }
            }
        }
    }), /must be spawn/)
})

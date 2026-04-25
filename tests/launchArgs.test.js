import assert from 'assert/strict'
import { test } from 'node:test'
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

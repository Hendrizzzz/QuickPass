import { readFileSync } from 'fs'
import { DatabaseSync } from 'node:sqlite'

class LocalD1PreparedStatement {
    constructor(database, sql, params = []) {
        this.database = database
        this.sql = sql
        this.params = params
    }

    bind(...params) {
        return new LocalD1PreparedStatement(this.database, this.sql, params)
    }

    run() {
        const statement = this.database.prepare(this.sql)
        const result = statement.run(...this.params)
        return {
            success: true,
            meta: {
                changes: Number(result.changes || 0),
                last_row_id: Number(result.lastInsertRowid || 0)
            },
            results: []
        }
    }

    first() {
        return this.database.prepare(this.sql).get(...this.params) || null
    }

    all() {
        return {
            success: true,
            results: this.database.prepare(this.sql).all(...this.params)
        }
    }
}

export class LocalD1Database {
    constructor() {
        this.database = new DatabaseSync(':memory:')
        this.database.exec('PRAGMA foreign_keys = ON;')
    }

    prepare(sql) {
        return new LocalD1PreparedStatement(this.database, sql)
    }

    batch(statements) {
        const results = []
        this.database.exec('BEGIN IMMEDIATE;')
        try {
            for (const statement of statements) results.push(statement.run())
            this.database.exec('COMMIT;')
            return results
        } catch (error) {
            this.database.exec('ROLLBACK;')
            throw error
        }
    }

    exec(sql) {
        this.database.exec(sql)
    }

    close() {
        this.database.close()
    }
}

export function createMigratedLocalD1Database() {
    const db = new LocalD1Database()
    const migration = readFileSync(new URL('../../cloudflare/migrations/0001_wipesnap_phone_sync.sql', import.meta.url), 'utf8')
    db.exec(migration)
    return db
}

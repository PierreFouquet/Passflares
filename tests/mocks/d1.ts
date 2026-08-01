// A real D1 implementation backed by node:sqlite, for integration tests.
//
// The hand-rolled mock in cloudflare.ts returns canned rows keyed by a substring
// of the SQL. That is fine for branch coverage, but it cannot catch the failures
// that actually matter in this codebase: a misspelled column, a broken
// ON CONFLICT clause, a JOIN that returns nothing, or a D1.batch() that isn't
// really atomic. Those are exactly the failure modes the auth_version 1 -> 2
// upgrade depends on not having, and the mock would report success either way.
//
// This shim runs the real migrations and the real SQL. Node 24 ships
// node:sqlite, so it needs no dependency.

import { DatabaseSync } from 'node:sqlite';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const migrationsDir = resolve(here, '../../migrations');

type Row = Record<string, unknown>;

/**
 * D1 statements are immutable: `stmt.bind(a)` returns a *new* statement rather
 * than mutating the original. Worker code relies on this — it prepares once and
 * binds per row into a batch array — so a shim that mutated would silently
 * collapse every statement onto the last set of arguments.
 */
class SqliteStatement {
    constructor(
        private db: DatabaseSync,
        private sql: string,
        private args: unknown[] = []
    ) {}

    bind(...args: unknown[]): SqliteStatement {
        return new SqliteStatement(this.db, this.sql, args);
    }

    async first<T = Row>(column?: string): Promise<T | null> {
        const row = this.db.prepare(this.sql).get(...(this.args as never[])) as Row | undefined;
        if (row === undefined) return null;
        return (column ? (row[column] as T) : (row as T));
    }

    async all<T = Row>(): Promise<{ results: T[]; success: boolean }> {
        const results = this.db.prepare(this.sql).all(...(this.args as never[])) as T[];
        return { results, success: true };
    }

    async run(): Promise<{ success: boolean; meta: { last_row_id: number; changes: number }; results: [] }> {
        const info = this.db.prepare(this.sql).run(...(this.args as never[]));
        return {
            success: true,
            meta: { last_row_id: Number(info.lastInsertRowid), changes: Number(info.changes) },
            results: []
        };
    }

    /** Test-only escape hatch for asserting what a statement was bound with. */
    _debug() {
        return { sql: this.sql, args: this.args };
    }
}

export interface TestD1 {
    db: DatabaseSync;
    prepare(sql: string): SqliteStatement;
    batch(statements: SqliteStatement[]): Promise<unknown[]>;
    exec(sql: string): Promise<{ results: []; success: boolean }>;
    /** Convenience for assertions: run arbitrary SQL and get rows back. */
    query<T = Row>(sql: string, ...args: unknown[]): T[];
}

/**
 * Creates an in-memory database with every migration applied, in order.
 *
 * Running the real migrations means a schema change that breaks a query fails
 * here rather than in production — the migration files are part of the test
 * fixture, not something the tests restate.
 */
export function createTestD1(): TestD1 {
    const db = new DatabaseSync(':memory:');
    db.exec('PRAGMA foreign_keys = ON;');

    for (const file of readdirSync(migrationsDir).filter(f => f.endsWith('.sql')).sort()) {
        db.exec(readFileSync(join(migrationsDir, file), 'utf8'));
    }

    return {
        db,
        prepare: (sql: string) => new SqliteStatement(db, sql),

        // D1.batch() is atomic: every statement lands or none do. The upgrade
        // path's safety rests entirely on that, so the shim has to honour it
        // rather than just looping.
        async batch(statements: SqliteStatement[]) {
            db.exec('BEGIN');
            try {
                const out: unknown[] = [];
                for (const statement of statements) out.push(await statement.run());
                db.exec('COMMIT');
                return out;
            } catch (error) {
                db.exec('ROLLBACK');
                throw error;
            }
        },

        async exec(sql: string) {
            db.exec(sql);
            return { results: [] as [], success: true };
        },

        query<T = Row>(sql: string, ...args: unknown[]): T[] {
            return db.prepare(sql).all(...(args as never[])) as T[];
        }
    };
}

/** An R2 stand-in backed by a Map, matching the subset of the API the worker uses. */
export function createTestR2() {
    const store = new Map<string, string>();
    return {
        store,
        async get(key: string) {
            const value = store.get(key);
            if (value === undefined) return null;
            return { json: async () => JSON.parse(value), text: async () => value };
        },
        async put(key: string, value: string) {
            store.set(key, value);
        },
        async delete(key: string) {
            store.delete(key);
        }
    };
}

export function createTestKV() {
    const store = new Map<string, string>();
    return {
        store,
        async get(key: string) { return store.get(key) ?? null; },
        async put(key: string, value: string) { store.set(key, value); },
        async delete(key: string) { store.delete(key); }
    };
}

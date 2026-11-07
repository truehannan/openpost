import { createRequire } from 'node:module';
import type { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

// Vite does not treat node:sqlite as a builtin, so load it via require.
const { DatabaseSync: DB } = createRequire(import.meta.url)('node:sqlite') as typeof import('node:sqlite');

/**
 * Minimal D1Database stand-in backed by real SQLite (node:sqlite), enough for
 * prepare/bind/first/all/run/batch. Runs the real migration files, so schema
 * constraints (CHECKs, unique indexes, foreign keys) are exercised for real.
 */
class Stmt {
  private params: unknown[] = [];
  constructor(
    private db: DatabaseSync,
    private sql: string,
  ) {}
  bind(...p: unknown[]) {
    this.params = p.map((v) => (v === undefined ? null : v));
    return this;
  }
  async first<T = unknown>(): Promise<T | null> {
    return ((this.db.prepare(this.sql).get(...(this.params as any[])) as T | undefined) ?? null) as T | null;
  }
  async all<T = unknown>() {
    return { results: this.db.prepare(this.sql).all(...(this.params as any[])) as T[], success: true, meta: {} };
  }
  async run() {
    const r = this.db.prepare(this.sql).run(...(this.params as any[]));
    return { success: true, meta: { changes: Number(r.changes) } };
  }
}

export function createTestDb() {
  const db = new DB(':memory:');
  db.exec('PRAGMA foreign_keys = ON');
  db.exec(readFileSync(join(__dirname, '../../migrations/0001_integration_credentials.sql'), 'utf8'));

  const d1 = {
    prepare: (sql: string) => new Stmt(db, sql),
    async batch(stmts: Stmt[]) {
      const out = [];
      for (const s of stmts) out.push(await s.run());
      return out;
    },
    exec: async (sql: string) => db.exec(sql),
  } as unknown as D1Database;

  return {
    d1,
    raw: db,
    /** Every row of every table as one string, for "no plaintext anywhere" assertions. */
    dumpAll(): string {
      const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all() as { name: string }[];
      return tables.map((t) => JSON.stringify(db.prepare(`SELECT * FROM ${t.name}`).all())).join('\n');
    },
  };
}

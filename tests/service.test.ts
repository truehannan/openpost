import { beforeEach, describe, expect, it } from 'vitest';
import { createTestDb } from './helpers/d1';
import { IntegrationCredentialService, ServiceError, accountTokenContext } from '../src/services/integration-credentials';
import { Vault } from '../src/lib/crypto';

const KEY_A = 'k7Qp2xVn9sLw4TzRb8YdHf3JmUc6AeGo1NiXtKv0PqSa5ZyWh';
const KEY_B = 'Zr3Hn8WcJd5MbT1gLy9QfXe2UaKo7VpSi4NtAx6DvEq0YhCuB';

const APP_SECRET = 'S3cretAppSecretValue0123456789ab';
const META = { app_id: '1234567890', app_secret: APP_SECRET, webhook_verify_token: 'verify-token-xyz' };

const OWNER = { userId: 'u-owner' };
const ALICE = { userId: 'u-alice' }; // admin of ws-a
const BOB = { userId: 'u-bob' }; // member of ws-a
const CAROL = { userId: 'u-carol' }; // admin of ws-b

let t: ReturnType<typeof createTestDb>;
let svc: IntegrationCredentialService;

const make = (key = KEY_A, previous?: string) =>
  new IntegrationCredentialService({ DB: t.d1, SECRET_KEY: key, SECRET_KEY_PREVIOUS: previous });

beforeEach(() => {
  t = createTestDb();
  t.raw.exec(`
    INSERT INTO workspaces (id,name) VALUES ('ws-a','A'),('ws-b','B');
    INSERT INTO users (id,email,is_app_owner) VALUES
      ('u-owner','o@x.com',1),('u-alice','a@x.com',0),('u-bob','b@x.com',0),('u-carol','c@x.com',0);
    INSERT INTO workspace_members VALUES ('ws-a','u-alice','admin'),('ws-a','u-bob','member'),('ws-b','u-carol','admin');
  `);
  svc = make();
});

const createA = (extra: Record<string, unknown> = {}) =>
  svc.create(ALICE, { scope: 'workspace', workspaceId: 'ws-a', provider: 'meta', configurationName: 'Main', credentials: META, enabled: true, ...extra } as any);

describe('encryption at rest (scenarios 1-3)', () => {
  it('stores only ciphertext; no plaintext anywhere in the database', async () => {
    await createA();
    const row = t.raw.prepare('SELECT encrypted_credentials, public_config FROM integration_credentials').get() as any;
    expect(row.encrypted_credentials.startsWith('v1.')).toBe(true);
    const dump = t.dumpAll();
    expect(dump).not.toContain(APP_SECRET);
    expect(dump).not.toContain('verify-token-xyz');
    // The identifier is intentionally visible in public_config; secrets are not.
    expect(row.public_config).toContain('1234567890');
  });

  it('API-facing views never contain secret values', async () => {
    const v = await createA();
    const json = JSON.stringify([v, await svc.list(ALICE, 'workspace', 'ws-a'), await svc.get(ALICE, v.id)]);
    expect(json).not.toContain(APP_SECRET);
    expect(json).not.toContain('verify-token-xyz');
    const secret = v.fields.find((f) => f.key === 'app_secret')!;
    expect(secret.isSet).toBe(true);
    expect(secret.display).toMatch(/^•+$/);
  });

  it('audit log records field names only', async () => {
    const v = await createA();
    await svc.update(ALICE, v.id, { credentials: { app_secret: 'NewSecretValueABCDEF0123456789zz' } });
    const log = JSON.stringify(t.raw.prepare('SELECT * FROM credential_audit_log').all());
    expect(log).toContain('app_secret');
    expect(log).not.toContain(APP_SECRET);
    expect(log).not.toContain('NewSecretValueABCDEF');
  });
});

describe('authorization and isolation (scenarios 6, 7)', () => {
  it('ordinary members cannot create, list, read or edit', async () => {
    const v = await createA();
    await expect(svc.create(BOB, { scope: 'workspace', workspaceId: 'ws-a', provider: 'meta', configurationName: 'x', credentials: META })).rejects.toMatchObject({ code: 'FORBIDDEN' });
    await expect(svc.list(BOB, 'workspace', 'ws-a')).rejects.toMatchObject({ code: 'FORBIDDEN' });
    await expect(svc.get(BOB, v.id)).rejects.toMatchObject({ code: 'FORBIDDEN' });
    await expect(svc.update(BOB, v.id, { credentials: { app_secret: 'x'.repeat(32) } })).rejects.toMatchObject({ code: 'FORBIDDEN' });
    await expect(svc.setEnabled(BOB, v.id, false)).rejects.toMatchObject({ code: 'FORBIDDEN' });
  });

  it("workspace B's admin cannot touch workspace A's configuration", async () => {
    const v = await createA();
    await expect(svc.get(CAROL, v.id)).rejects.toMatchObject({ code: 'FORBIDDEN' });
    await expect(svc.update(CAROL, v.id, { configurationName: 'hijack' })).rejects.toMatchObject({ code: 'FORBIDDEN' });
    await expect(svc.testStored(CAROL, v.id)).rejects.toMatchObject({ code: 'FORBIDDEN' });
    await expect(svc.delete(CAROL, v.id, { confirmName: 'Main' })).rejects.toMatchObject({ code: 'FORBIDDEN' });
    await expect(svc.list(CAROL, 'workspace', 'ws-a')).rejects.toMatchObject({ code: 'FORBIDDEN' });
  });

  it('only the app owner manages global configs; workspace admins cannot', async () => {
    const mk = (a: { userId: string }) => svc.create(a, { scope: 'global', provider: 'meta', configurationName: 'Shared', credentials: META });
    await expect(mk(ALICE)).rejects.toMatchObject({ code: 'FORBIDDEN' });
    await expect(mk(OWNER)).resolves.toMatchObject({ scope: 'global' });
  });

  it('a spoofed isAppOwner claim is ignored; roles come from the database', async () => {
    await expect(
      svc.create({ userId: 'u-bob', isAppOwner: true } as any, { scope: 'global', provider: 'meta', configurationName: 'x', credentials: META }),
    ).rejects.toMatchObject({ code: 'FORBIDDEN' });
  });

  it("resolution never returns another workspace's credentials", async () => {
    await createA();
    expect(await svc.getForProvider('meta', 'ws-b')).toBeNull();
    expect(await svc.getForProvider('meta')).toBeNull();
    expect((await svc.getForProvider('meta', 'ws-a'))?.credentials.app_secret).toBe(APP_SECRET);
  });
});

describe('resolution order and missing config (scenario 12)', () => {
  it('prefers workspace config, then falls back to global', async () => {
    await svc.create(OWNER, { scope: 'global', provider: 'meta', configurationName: 'Shared', credentials: { ...META, app_id: '9999999999' }, enabled: true });
    expect((await svc.getForProvider('meta', 'ws-a'))?.scope).toBe('global');
    await createA();
    const r = await svc.getForProvider('meta', 'ws-a');
    expect(r?.scope).toBe('workspace');
    expect(r?.credentials.app_id).toBe('1234567890');
    expect((await svc.getForProvider('meta', 'ws-b'))?.scope).toBe('global');
  });

  it('missing credentials produce an actionable error', async () => {
    const e = await svc.requireForProvider('tiktok', 'ws-a').catch((x) => x);
    expect(e).toBeInstanceOf(ServiceError);
    expect(e.code).toBe('CONFIG_MISSING');
    expect(e.message).toContain('Settings → Integrations → API Credentials → TikTok');
  });

  it('incomplete configs cannot be enabled and are flagged', async () => {
    const v = await svc.create(ALICE, { scope: 'workspace', workspaceId: 'ws-a', provider: 'x', configurationName: 'X', credentials: { client_id: 'abc123' }, enabled: true });
    expect(v.enabled).toBe(false);
    expect(v.statusLabel).toBe('Disabled');
    expect(v.validationStatus).toBe('incomplete');
    await expect(svc.setEnabled(ALICE, v.id, true)).rejects.toMatchObject({ code: 'CONFIG_INCOMPLETE' });
  });
});

describe('updates preserve unchanged fields (scenario 8)', () => {
  it('replaces one field and keeps the rest', async () => {
    const v = await createA();
    await svc.update(ALICE, v.id, { credentials: { graph_api_version: 'v22.0', app_secret: '', webhook_verify_token: undefined } });
    const r = await svc.getForProvider('meta', 'ws-a');
    expect(r?.credentials).toMatchObject({ app_id: '1234567890', app_secret: APP_SECRET, webhook_verify_token: 'verify-token-xyz', graph_api_version: 'v22.0' });
  });

  it('changing credentials resets validation status', async () => {
    const v = await createA();
    const fetcher = async () => new Response(JSON.stringify({ access_token: 't' }), { status: 200 });
    svc = new IntegrationCredentialService({ DB: t.d1, SECRET_KEY: KEY_A }, { fetch: fetcher });
    expect((await svc.testStored(ALICE, v.id)).validationStatus).toBe('valid');
    const after = await svc.update(ALICE, v.id, { credentials: { app_secret: 'AnotherSecretValue0123456789abcdef' } });
    expect(after.validationStatus).toBe('unvalidated');
  });
});

describe('failure modes (scenarios 4, 5)', () => {
  it('wrong SECRET_KEY fails safely, and does NOT fall through to a global config', async () => {
    await svc.create(OWNER, { scope: 'global', provider: 'meta', configurationName: 'Shared', credentials: { ...META, app_id: '9999999999' }, enabled: true });
    await createA();
    const wrong = make(KEY_B);
    await expect(wrong.getForProvider('meta', 'ws-a')).rejects.toMatchObject({ code: 'DECRYPT_FAILED' });
    await expect(make('short').getForProvider('meta', 'ws-a')).rejects.toBeDefined();
  });

  it('tampered ciphertext is rejected', async () => {
    const v = await createA();
    const row = t.raw.prepare('SELECT encrypted_credentials e FROM integration_credentials WHERE id=?').get(v.id) as any;
    const parts = row.e.split('.');
    parts[3] = (parts[3][0] === 'A' ? 'B' : 'A') + parts[3].slice(1);
    t.raw.prepare('UPDATE integration_credentials SET encrypted_credentials=? WHERE id=?').run(parts.join('.'), v.id);
    await expect(svc.getForProvider('meta', 'ws-a')).rejects.toMatchObject({ code: 'DECRYPT_FAILED' });
  });

  it('a valid ciphertext copied onto another row is rejected (context binding)', async () => {
    const a = await createA();
    const b = await svc.create(CAROL, { scope: 'workspace', workspaceId: 'ws-b', provider: 'meta', configurationName: 'B', credentials: { ...META, app_id: '5555555555' }, enabled: true });
    const aBlob = (t.raw.prepare('SELECT encrypted_credentials e FROM integration_credentials WHERE id=?').get(a.id) as any).e;
    t.raw.prepare('UPDATE integration_credentials SET encrypted_credentials=? WHERE id=?').run(aBlob, b.id);
    await expect(svc.getForProvider('meta', 'ws-b')).rejects.toMatchObject({ code: 'DECRYPT_FAILED' });
  });
});

describe('disabled integrations (scenario 9)', () => {
  it('disabled configs are not resolvable and report an actionable error', async () => {
    const v = await createA();
    await svc.setEnabled(ALICE, v.id, false);
    expect(await svc.getForProvider('meta', 'ws-a')).toBeNull();
    const e = await svc.requireForProvider('meta', 'ws-a').catch((x) => x);
    expect(e.code).toBe('CONFIG_DISABLED');
    expect(e.message).toContain('Enable it in Settings');
  });
});

describe('connections survive changes (scenario 10)', () => {
  const connect = async (configId: string) => {
    const vault = new Vault({ SECRET_KEY: KEY_A });
    t.raw
      .prepare(
        `INSERT INTO social_accounts (id, workspace_id, provider, provider_account_id, credential_config_id, encrypted_access_token, encrypted_refresh_token)
         VALUES ('acct-1','ws-a','meta','fb-1',?,?,?)`,
      )
      .run(
        configId,
        await vault.encrypt('access-token-value', 'tokens', accountTokenContext('acct-1', 'access')),
        await vault.encrypt('refresh-token-value', 'tokens', accountTokenContext('acct-1', 'refresh')),
      );
  };

  it('the account keeps using the configuration that authorised it', async () => {
    const v = await createA();
    await connect(v.id);
    await svc.create(ALICE, { scope: 'workspace', workspaceId: 'ws-a', provider: 'meta', configurationName: 'Second', credentials: { ...META, app_id: '7777777777' }, enabled: true });
    expect((await svc.getForAccount('acct-1')).configId).toBe(v.id);
    expect((await svc.getForAccount('acct-1')).credentials.app_id).toBe('1234567890');
  });

  it('changing the client ID is blocked while accounts are connected; rotating the secret is not', async () => {
    const v = await createA();
    await connect(v.id);
    expect((await svc.get(ALICE, v.id)).connectedAccountCount).toBe(1);
    await expect(svc.update(ALICE, v.id, { credentials: { app_id: '1111111111' } })).rejects.toMatchObject({ code: 'CLIENT_ID_CHANGE_BLOCKED' });
    await expect(svc.update(ALICE, v.id, { credentials: { app_secret: 'RotatedSecretValue0123456789abcdef' } })).resolves.toBeDefined();
    expect((await svc.getForAccount('acct-1')).credentials.app_secret).toBe('RotatedSecretValue0123456789abcdef');
  });

  it('disabling the configuration blocks the account until re-enabled', async () => {
    const v = await createA();
    await connect(v.id);
    await svc.setEnabled(ALICE, v.id, false);
    await expect(svc.getForAccount('acct-1')).rejects.toMatchObject({ code: 'CONFIG_DISABLED' });
    await svc.setEnabled(ALICE, v.id, true);
    await expect(svc.getForAccount('acct-1')).resolves.toBeDefined();
  });

  it('SECRET_KEY rotation re-encrypts credentials and tokens without breaking connections', async () => {
    const v = await createA();
    await connect(v.id);
    const before = t.raw.prepare('SELECT encrypted_credentials e FROM integration_credentials').get() as any;

    // Only the new key: old data is unreadable (the failure rotation exists to avoid).
    await expect(make(KEY_B).getForAccount('acct-1')).rejects.toMatchObject({ code: 'DECRYPT_FAILED' });

    const rotated = make(KEY_B, KEY_A);
    expect(await rotated.getForAccount('acct-1')).toMatchObject({ configId: v.id });
    const res = await rotated.rotateEncryption(OWNER);
    expect(res).toMatchObject({ credentials: 1, tokens: 2, failed: 0 });

    const after = t.raw.prepare('SELECT encrypted_credentials e FROM integration_credentials').get() as any;
    expect(after.e).not.toBe(before.e);

    // Previous key can now be dropped.
    const onlyNew = make(KEY_B);
    expect((await onlyNew.getForAccount('acct-1')).credentials.app_secret).toBe(APP_SECRET);
    const acct = t.raw.prepare('SELECT * FROM social_accounts').get() as any;
    expect(await new Vault({ SECRET_KEY: KEY_B }).decrypt(acct.encrypted_access_token, 'tokens', accountTokenContext('acct-1', 'access'))).toBe('access-token-value');

    // Idempotent: a second run finds nothing to do.
    expect(await rotated.rotateEncryption(OWNER)).toMatchObject({ credentials: 0, tokens: 0, failed: 0 });
    await expect(rotated.rotateEncryption(ALICE)).rejects.toMatchObject({ code: 'FORBIDDEN' });
  });
});

describe('deletion', () => {
  it('requires the exact name and refuses while accounts are connected', async () => {
    const v = await createA();
    await expect(svc.delete(ALICE, v.id, { confirmName: 'nope' })).rejects.toMatchObject({ code: 'VALIDATION' });
    t.raw
      .prepare(`INSERT INTO social_accounts (id, workspace_id, provider, provider_account_id, credential_config_id, encrypted_access_token) VALUES ('a','ws-a','meta','p',?,'x')`)
      .run(v.id);
    await expect(svc.delete(ALICE, v.id, { confirmName: 'Main' })).rejects.toMatchObject({ code: 'CONFIG_IN_USE' });
    t.raw.prepare('DELETE FROM social_accounts').run();
    await svc.delete(ALICE, v.id, { confirmName: 'Main' });
    expect(await svc.list(ALICE, 'workspace', 'ws-a')).toEqual([]);
  });

  it('rejects duplicate names within the same scope', async () => {
    await createA();
    await expect(createA()).rejects.toMatchObject({ code: 'CONFLICT' });
  });
});

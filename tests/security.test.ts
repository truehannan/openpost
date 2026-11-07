/**
 * Section 9 of the amendment, one `describe` per numbered scenario, driven through
 * the real HTTP app and a real SQLite database (not mocks of our own code).
 */
import { beforeEach, describe, expect, it } from 'vitest';
import { createTestDb } from './helpers/d1';
import { createApp } from '../src/app';
import { mintSession } from '../src/auth';
import { hmacSha256, toHex } from '../src/lib/crypto';

const KEY_A = 'k7Qp2xVn9sLw4TzRb8YdHf3JmUc6AeGo1NiXtKv0PqSa5ZyWh';
const KEY_B = 'Zr3Hn8WcJd5MbT1gLy9QfXe2UaKo7VpSi4NtAx6DvEq0YhCuB';

const APP_SECRET = 'S3cretAppSecretValue0123456789ab';
const VERIFY = 'verify-token-xyz';
const ACCESS = 'ACCESS-TOKEN-PLAINTEXT-111';
const REFRESH = 'REFRESH-TOKEN-PLAINTEXT-222';
const ALL_SECRETS = [APP_SECRET, VERIFY, ACCESS, REFRESH];
const META = { app_id: '1234567890', app_secret: APP_SECRET, webhook_verify_token: VERIFY };
const GLOBAL_META = { app_id: '9999999999', app_secret: 'GlobalAppSecretValue0123456789ab', webhook_verify_token: 'global-verify' };

let t: ReturnType<typeof createTestDb>;
let env: any;
let sent: any[];

const stub = async (url: string) => {
  if (url.includes('/oauth/access_token')) return new Response(JSON.stringify({ access_token: ACCESS, refresh_token: REFRESH, expires_in: 3600 }), { status: 200 });
  if (url.includes('/me?')) return new Response(JSON.stringify({ id: 'fb-1', name: 'Page' }), { status: 200 });
  return new Response(JSON.stringify({ error: 'stub' }), { status: 400 });
};
const app = createApp({ fetch: stub });

const mkEnv = (key = KEY_A, previous?: string, db: D1Database = t.d1) => ({
  DB: db, SECRET_KEY: key, SECRET_KEY_PREVIOUS: previous, APP_URL: 'https://app.test',
  WEBHOOK_QUEUE: { send: async (m: any) => void sent.push(m) },
});
const tok = (user: string, key = KEY_A) => mintSession(key, user);

async function call(method: string, path: string, user?: string, body?: unknown, opts: { env?: any; key?: string } = {}) {
  const headers: Record<string, string> = {};
  if (user) headers.authorization = `Bearer ${await tok(user, opts.key ?? KEY_A)}`;
  if (body !== undefined) headers['content-type'] = 'application/json';
  return app.request(`https://app.test${path}`, { method, headers, body: body !== undefined ? JSON.stringify(body) : undefined }, opts.env ?? env);
}
const json = async (r: Response) => (await r.json()) as any;

async function createMeta(user = 'alice', ws = 'ws-a', creds: any = META, name = 'Main') {
  const r = await call('POST', `/api/workspaces/${ws}/integrations`, user, { provider: 'meta', configurationName: name, credentials: creds, enabled: true });
  expect(r.status).toBe(201);
  return (await json(r)).integration as { id: string };
}

/** Full OAuth round trip over HTTP; returns the connected account id. */
async function connect(user = 'alice', ws = 'ws-a', key = KEY_A, e = env) {
  const start = await json(await call('POST', `/api/workspaces/${ws}/oauth/meta/start`, user, {}, { env: e, key }));
  const state = new URL(start.authorizeUrl).searchParams.get('state')!;
  const r = await app.request(`https://app.test/oauth/callback/meta?code=abc&state=${state}`, { headers: { cookie: `session=${await tok(user, key)}` } }, e);
  expect(r.headers.get('location')).toContain('connected=meta');
  return decodeURIComponent(r.headers.get('location')!.split('account=')[1]!);
}

beforeEach(() => {
  t = createTestDb();
  sent = [];
  t.raw.exec(`
    INSERT INTO workspaces (id,name) VALUES ('ws-a','A'),('ws-b','B');
    INSERT INTO users (id,email,is_app_owner) VALUES ('owner','o@x.com',1),('alice','a@x.com',0),('bob','b@x.com',0),('carol','c@x.com',0);
    INSERT INTO workspace_members VALUES ('ws-a','alice','admin'),('ws-a','bob','member'),('ws-b','carol','admin');
  `);
  env = mkEnv();
});

describe('1. Credentials are encrypted before database insertion', () => {
  it('no statement sent to the database ever carries a plaintext secret', async () => {
    const seen: string[] = [];
    const spy = {
      ...t.d1,
      prepare(sql: string) {
        const st: any = (t.d1 as any).prepare(sql);
        const bind = st.bind.bind(st);
        st.bind = (...p: unknown[]) => { seen.push(JSON.stringify([sql, ...p])); return bind(...p); };
        return st;
      },
    } as unknown as D1Database;
    const e = mkEnv(KEY_A, undefined, spy);

    const r = await call('POST', '/api/workspaces/ws-a/integrations', 'alice', { provider: 'meta', configurationName: 'Main', credentials: META, enabled: true }, { env: e });
    const id = (await json(r)).integration.id;
    await call('PATCH', `/api/integrations/${id}`, 'alice', { credentials: { app_secret: 'AnotherSecretValue0123456789abcdef' } }, { env: e });
    await connect('alice', 'ws-a', KEY_A, e);

    const inserts = seen.filter((s) => /INSERT INTO integration_credentials|UPDATE integration_credentials|INSERT INTO social_accounts|INSERT INTO oauth_states/.test(s));
    expect(inserts.length).toBeGreaterThanOrEqual(4);
    for (const s of seen) for (const secret of [...ALL_SECRETS, 'AnotherSecretValue0123456789abcdef']) expect(s).not.toContain(secret);
    expect(seen.some((s) => s.includes('"v1.'))).toBe(true); // ciphertext envelopes were what got written
  });
});

describe('2. Database inspection never reveals plaintext credentials', () => {
  it('after create, update, connect, webhook traffic and rotation, no table holds any secret', async () => {
    const { id } = await createMeta();
    await call('PATCH', `/api/integrations/${id}`, 'alice', { credentials: { graph_api_version: 'v22.0' } });
    await connect();
    const hook = (await json(await call('POST', `/api/integrations/${id}/webhook/enable`, 'alice'))).webhook;
    const body = JSON.stringify({ object: 'page' });
    await app.request(new URL(hook.callbackUrl).href, { method: 'POST', body, headers: { 'x-hub-signature-256': `sha256=${toHex(await hmacSha256(APP_SECRET, body))}` } }, env);
    await call('POST', '/api/admin/rotate-encryption', 'owner');

    const dump = t.dumpAll();
    for (const secret of ALL_SECRETS) expect(dump).not.toContain(secret);
    // Only identifiers are mirrored outside the encrypted blob.
    const pub = (t.raw.prepare('SELECT public_config p FROM integration_credentials').get() as any).p;
    expect(JSON.parse(pub).fields).toEqual({ app_id: '1234567890', graph_api_version: 'v22.0' });
    // Webhook log keeps a hash, not the payload.
    expect(dump).not.toContain('"object":"page"');
  });
});

describe('3. API responses never expose decrypted credentials', () => {
  it('every response across the API surface is free of secrets, masked where relevant', async () => {
    const { id } = await createMeta();
    const acct = await connect();
    const out: string[] = [];
    const grab = async (p: Promise<Response>) => out.push(await (await p).text());

    await grab(call('GET', '/api/me', 'alice'));
    await grab(call('GET', '/api/integrations/providers', 'alice'));
    await grab(call('GET', '/api/workspaces/ws-a/integrations', 'alice'));
    await grab(call('GET', '/api/workspaces/ws-a/integrations/availability', 'alice'));
    await grab(call('GET', '/api/workspaces/ws-a/accounts', 'alice'));
    await grab(call('GET', '/api/workspaces/ws-a/accounts', 'bob'));
    await grab(call('GET', `/api/integrations/${id}`, 'alice'));
    await grab(call('PATCH', `/api/integrations/${id}`, 'alice', { credentials: { app_secret: 'x' } })); // validation error
    await grab(call('POST', `/api/integrations/${id}/test`, 'alice'));
    await grab(call('POST', `/api/integrations/${id}/webhook/enable`, 'alice'));
    await grab(call('GET', `/api/integrations/${id}/webhook`, 'alice'));
    await grab(call('GET', `/api/integrations/${id}`, 'bob')); // 403
    await grab(call('POST', '/api/admin/rotate-encryption', 'owner'));
    await grab(call('DELETE', `/api/integrations/${id}`, 'alice', { confirmName: 'Main' })); // CONFIG_IN_USE error
    await grab(call('DELETE', `/api/accounts/${acct}`, 'alice'));

    const all = out.join('\n');
    for (const secret of ALL_SECRETS) expect(all).not.toContain(secret);
    expect(all).toContain('••••');
  });
});

describe('4. Invalid encryption keys prevent credential access safely', () => {
  it('a different SECRET_KEY cannot read credentials, tokens, or fall back to the shared app', async () => {
    await call('POST', '/api/admin/integrations', 'owner', { provider: 'meta', configurationName: 'Shared', credentials: GLOBAL_META, enabled: true });
    await createMeta();
    const acct = await connect();
    const wrong = mkEnv(KEY_B);

    const start = await call('POST', '/api/workspaces/ws-a/oauth/meta/start', 'alice', {}, { env: wrong, key: KEY_B });
    expect(start.status).toBe(500);
    const b = await json(start);
    expect(b.error.code).toBe('DECRYPT_FAILED');
    expect(JSON.stringify(b)).not.toContain(APP_SECRET);
    expect(JSON.stringify(b)).not.toContain(GLOBAL_META.app_secret); // did not silently use the shared app instead

    const { OAuthService } = await import('../src/services/oauth');
    await expect(new OAuthService(wrong as any, { fetch: stub }).getAccessToken(acct)).rejects.toMatchObject({ code: 'DECRYPT_FAILED' });
  });

  it('a missing or weak SECRET_KEY is refused with an actionable message', async () => {
    for (const bad of [undefined, 'short', 'a'.repeat(64)]) {
      const r = await app.request('https://app.test/api/me', { headers: { authorization: `Bearer ${await tok('alice')}` } }, { ...mkEnv(), SECRET_KEY: bad });
      expect(r.status).toBe(503);
      expect(JSON.stringify(await json(r))).toMatch(/SECRET_KEY/);
    }
  });

  it('sessions signed under one key are not accepted under another', async () => {
    const r = await call('GET', '/api/me', 'alice', undefined, { env: mkEnv(KEY_B), key: KEY_A });
    expect(r.status).toBe(401);
  });
});

describe('5. Tampered ciphertext is rejected', () => {
  const flip = (blob: string) => {
    const p = blob.split('.');
    const c = p[3]!;
    p[3] = c.slice(0, 5) + (c[5] === 'A' ? 'B' : 'A') + c.slice(6); // change one ciphertext character
    return p.join('.');
  };

  it('tampered app credentials: OAuth start fails closed; webhook is not enqueued', async () => {
    const { id } = await createMeta();
    const hook = (await json(await call('POST', `/api/integrations/${id}/webhook/enable`, 'alice'))).webhook;
    const blob = (t.raw.prepare('SELECT encrypted_credentials e FROM integration_credentials').get() as any).e;
    t.raw.prepare('UPDATE integration_credentials SET encrypted_credentials = ?').run(flip(blob));

    const start = await call('POST', '/api/workspaces/ws-a/oauth/meta/start', 'alice', {});
    expect(start.status).toBe(500);
    expect((await json(start)).error.code).toBe('DECRYPT_FAILED');

    const body = '{}';
    const r = await app.request(new URL(hook.callbackUrl).href, { method: 'POST', body, headers: { 'x-hub-signature-256': `sha256=${toHex(await hmacSha256(APP_SECRET, body))}` } }, env);
    expect(r.status).toBe(500);
    expect(sent).toHaveLength(0);
  });

  it('tampered access token is never returned', async () => {
    await createMeta();
    const acct = await connect();
    const row = t.raw.prepare('SELECT encrypted_access_token a FROM social_accounts').get() as any;
    t.raw.prepare('UPDATE social_accounts SET encrypted_access_token = ?').run(flip(row.a));
    const { OAuthService } = await import('../src/services/oauth');
    await expect(new OAuthService(env, { fetch: stub }).getAccessToken(acct)).rejects.toBeDefined();
  });

  it('a valid blob moved to a different row or column is rejected (context binding)', async () => {
    await createMeta();
    await createMeta('carol', 'ws-b', { ...META, app_id: '5555555555' }, 'B');
    const blobA = (t.raw.prepare("SELECT encrypted_credentials e FROM integration_credentials WHERE workspace_id = 'ws-a'").get() as any).e;
    // Copy A's perfectly valid ciphertext onto B's row.
    t.raw.prepare("UPDATE integration_credentials SET encrypted_credentials = ? WHERE workspace_id = 'ws-b'").run(blobA);
    const r = await call('POST', '/api/workspaces/ws-b/oauth/meta/start', 'carol', {});
    expect(r.status).toBe(500);
  });
});

describe('6. Workspace A cannot retrieve Workspace B\'s credentials', () => {
  it('is enforced on every route and in resolution', async () => {
    const { id } = await createMeta();
    for (const [m, p, b] of [
      ['GET', `/api/integrations/${id}`], ['PATCH', `/api/integrations/${id}`, { configurationName: 'x' }],
      ['POST', `/api/integrations/${id}/test`], ['POST', `/api/integrations/${id}/disable`],
      ['DELETE', `/api/integrations/${id}`, { confirmName: 'Main' }], ['GET', `/api/integrations/${id}/webhook`],
      ['GET', '/api/workspaces/ws-a/integrations'], ['POST', '/api/workspaces/ws-a/oauth/meta/start', {}],
      ['GET', '/api/workspaces/ws-a/accounts'],
    ] as Array<[string, string, unknown?]>) {
      expect((await call(m, p, 'carol', b)).status, `${m} ${p}`).toBe(403);
    }
    // B has no app of its own and there is no shared one: A's is not used.
    const r = await call('POST', '/api/workspaces/ws-b/oauth/meta/start', 'carol', {});
    expect(r.status).toBe(424);
    expect((await json(r)).error.code).toBe('CONFIG_MISSING');
  });

  it('an account row pointing at another workspace\'s configuration cannot use it', async () => {
    const { id } = await createMeta();
    t.raw.prepare(`INSERT INTO social_accounts (id, workspace_id, provider, provider_account_id, credential_config_id, encrypted_access_token) VALUES ('rogue','ws-b','meta','x',?,'x')`).run(id);
    const { IntegrationCredentialService } = await import('../src/services/integration-credentials');
    await expect(new IntegrationCredentialService(env).getForAccount('rogue')).rejects.toMatchObject({ code: 'FORBIDDEN' });
  });
});

describe('7. Ordinary workspace members cannot edit credentials', () => {
  it('members are refused on all write and read routes', async () => {
    const { id } = await createMeta();
    for (const [m, p, b] of [
      ['POST', '/api/workspaces/ws-a/integrations', { provider: 'meta', configurationName: 'n', credentials: META }],
      ['PATCH', `/api/integrations/${id}`, { credentials: { app_secret: 'x'.repeat(32) } }],
      ['POST', `/api/integrations/${id}/enable`], ['POST', `/api/integrations/${id}/disable`],
      ['POST', `/api/integrations/${id}/test`], ['DELETE', `/api/integrations/${id}`, { confirmName: 'Main' }],
      ['POST', `/api/integrations/${id}/webhook/rotate-key`], ['GET', '/api/workspaces/ws-a/integrations'],
    ] as Array<[string, string, unknown?]>) {
      expect((await call(m, p, 'bob', b)).status, `${m} ${p}`).toBe(403);
    }
    expect((await call('POST', '/api/admin/integrations', 'alice', { provider: 'meta', configurationName: 'g', credentials: META })).status).toBe(403);
    // nothing changed
    expect((t.raw.prepare('SELECT COUNT(*) n FROM integration_credentials').get() as any).n).toBe(1);
  });
});

describe('8. Credential updates preserve unchanged fields', () => {
  it('only submitted fields change', async () => {
    const { id } = await createMeta();
    await call('PATCH', `/api/integrations/${id}`, 'alice', { credentials: { graph_api_version: 'v22.0', app_secret: '', webhook_verify_token: '' } });
    const { IntegrationCredentialService } = await import('../src/services/integration-credentials');
    const c = await new IntegrationCredentialService(env).getForProvider('meta', 'ws-a');
    expect(c?.credentials).toMatchObject({ ...META, graph_api_version: 'v22.0' });
  });
});

describe('9. Disabled integrations cannot start OAuth or be used for API calls', () => {
  it('blocks OAuth start, OAuth completion, token use (the publishing gate) and webhooks', async () => {
    const { id } = await createMeta();
    const acct = await connect();
    const hook = (await json(await call('POST', `/api/integrations/${id}/webhook/enable`, 'alice'))).webhook;

    // A flow started before disabling cannot be completed afterwards.
    const pending = await json(await call('POST', '/api/workspaces/ws-a/oauth/meta/start', 'alice', {}));
    await call('POST', `/api/integrations/${id}/disable`, 'alice');

    const start = await call('POST', '/api/workspaces/ws-a/oauth/meta/start', 'alice', {});
    expect(start.status).toBe(424);
    expect((await json(start)).error.code).toBe('CONFIG_DISABLED');

    const state = new URL(pending.authorizeUrl).searchParams.get('state');
    const cb = await app.request(`https://app.test/oauth/callback/meta?code=c&state=${state}`, { headers: { cookie: `session=${await tok('alice')}` } }, env);
    expect(cb.headers.get('location')).toContain('error=CONFIG_DISABLED');

    const { OAuthService } = await import('../src/services/oauth');
    await expect(new OAuthService(env, { fetch: stub }).getAccessToken(acct)).rejects.toMatchObject({ code: 'CONFIG_DISABLED' });

    const body = '{}';
    const wh = await app.request(new URL(hook.callbackUrl).href, { method: 'POST', body, headers: { 'x-hub-signature-256': `sha256=${toHex(await hmacSha256(APP_SECRET, body))}` } }, env);
    expect(wh.status).toBe(403);
    expect(sent).toHaveLength(0);
  });
});

describe('10. Credential rotation does not silently invalidate existing connections', () => {
  it('rotating SECRET_KEY via the previous-key window keeps accounts working', async () => {
    await createMeta();
    const acct = await connect();
    const { OAuthService } = await import('../src/services/oauth');

    // Deploy new key + old key side by side: still readable, nothing re-encrypted yet.
    const dual = mkEnv(KEY_B, KEY_A);
    expect(await new OAuthService(dual as any, { fetch: stub }).getAccessToken(acct)).toBe(ACCESS);

    // Owner runs rotation (session now signed with the new key).
    const r = await call('POST', '/api/admin/rotate-encryption', 'owner', undefined, { env: dual, key: KEY_B });
    expect((await json(r)).result).toMatchObject({ credentials: 1, tokens: 2, failed: 0 });

    // Old key removed: connection still works, same account id and configuration.
    const only = mkEnv(KEY_B);
    expect(await new OAuthService(only as any, { fetch: stub }).getAccessToken(acct)).toBe(ACCESS);
    const accounts = (await json(await call('GET', '/api/workspaces/ws-a/accounts', 'alice', undefined, { env: only, key: KEY_B }))).accounts;
    expect(accounts).toHaveLength(1);
    expect(accounts[0]).toMatchObject({ id: acct, status: 'active' });
  });

  it('rotating the app secret in place keeps the connection; changing the client ID is blocked', async () => {
    const { id } = await createMeta();
    const acct = await connect();
    expect((await call('PATCH', `/api/integrations/${id}`, 'alice', { credentials: { app_secret: 'RotatedSecretValue0123456789abcdef' } })).status).toBe(200);
    expect((await json(await call('GET', '/api/workspaces/ws-a/accounts', 'alice'))).accounts[0]).toMatchObject({ id: acct, status: 'active' });
    const blocked = await call('PATCH', `/api/integrations/${id}`, 'alice', { credentials: { app_id: '1111111111' } });
    expect(blocked.status).toBe(409);
    expect((await json(blocked)).error.code).toBe('CLIENT_ID_CHANGE_BLOCKED');
  });

  it('adding a second configuration does not re-point existing accounts', async () => {
    const { id } = await createMeta();
    const acct = await connect();
    await createMeta('alice', 'ws-a', { ...META, app_id: '7777777777' }, 'Second');
    const accounts = (await json(await call('GET', '/api/workspaces/ws-a/accounts', 'alice'))).accounts;
    expect(accounts.find((a: any) => a.id === acct).credentialConfigId).toBe(id);
  });
});

describe('11. Webhook verification uses the correct provider configuration', () => {
  it('maps by URL key only, per provider, and never confuses token with signing secret', async () => {
    const a = await createMeta();
    const bCfg = await createMeta('carol', 'ws-b', { app_id: '2222222222', app_secret: 'WorkspaceBSecretValue0123456789cd', webhook_verify_token: 'verify-b' }, 'B');
    const hookA = (await json(await call('POST', `/api/integrations/${a.id}/webhook/enable`, 'alice'))).webhook;
    const hookB = (await json(await call('POST', `/api/integrations/${bCfg.id}/webhook/enable`, 'carol'))).webhook;
    const body = JSON.stringify({ x: 1 });
    const sig = async (secret: string) => `sha256=${toHex(await hmacSha256(secret, body))}`;
    const post = async (url: string, secret: string, extra: Record<string, string> = {}) =>
      app.request(new URL(url).href, { method: 'POST', body, headers: { 'x-hub-signature-256': await sig(secret), ...extra } }, env);

    expect((await post(hookA.callbackUrl, 'WorkspaceBSecretValue0123456789cd')).status).toBe(401); // B's secret on A's URL
    expect((await post(hookA.callbackUrl, VERIFY)).status).toBe(401); // verification token is not a signing secret
    expect((await post(hookA.callbackUrl, APP_SECRET, { 'x-workspace-id': 'ws-b' })).status).toBe(200);
    expect((await post(hookB.callbackUrl, 'WorkspaceBSecretValue0123456789cd')).status).toBe(200);
    expect(sent.map((m) => m.workspaceId)).toEqual(['ws-a', 'ws-b']); // derived from the config, not the request

    // Provider in the URL must match the configuration that owns the key.
    expect((await post(hookA.callbackUrl.replace('/meta/', '/tiktok/'), APP_SECRET)).status).toBe(404);
    // GET handshake: token of the right config only; signing secret is not a valid token.
    const hs = (u: string, tkn: string) => app.request(`${new URL(u).href}?hub.mode=subscribe&hub.verify_token=${tkn}&hub.challenge=ok`, {}, env);
    expect((await (await hs(hookA.callbackUrl, VERIFY)).text())).toBe('ok');
    expect((await hs(hookA.callbackUrl, 'verify-b')).status).toBe(403);
    expect((await hs(hookA.callbackUrl, APP_SECRET)).status).toBe(403);
  });
});

describe('12. Missing credentials produce actionable configuration errors', () => {
  it('tells the admin exactly where to go', async () => {
    for (const [provider, label] of [['meta', 'Meta'], ['linkedin', 'LinkedIn'], ['x', 'X'], ['google', 'YouTube / Google'], ['tiktok', 'TikTok']]) {
      const r = await call('POST', `/api/workspaces/ws-a/oauth/${provider}/start`, 'alice', {});
      expect(r.status).toBe(424);
      const e = (await json(r)).error;
      expect(e.code).toBe('CONFIG_MISSING');
      expect(e.message).toContain(`Settings → Integrations → API Credentials → ${label}`);
    }
  });

  it('incomplete, disabled, and invalid-input cases each explain the fix', async () => {
    const draft = await json(await call('POST', '/api/workspaces/ws-a/integrations', 'alice', { provider: 'x', configurationName: 'X', credentials: { client_id: 'abc123' }, enabled: true }));
    expect(draft.integration.statusLabel).toBe('Disabled');
    expect(draft.integration.validationStatus).toBe('incomplete');
    const en = await call('POST', `/api/integrations/${draft.integration.id}/enable`, 'alice');
    expect(en.status).toBe(424);
    expect((await json(en)).error.message).toContain('required fields');

    const bad = await call('POST', '/api/workspaces/ws-a/integrations', 'alice', { provider: 'meta', configurationName: 'M', credentials: { app_id: 'abc' } });
    expect(bad.status).toBe(422);
    expect(JSON.stringify((await json(bad)).error.details)).toContain('App ID');
  });
});

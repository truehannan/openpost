import { beforeEach, describe, expect, it } from 'vitest';
import { createTestDb } from './helpers/d1';
import { createApp } from '../src/app';
import { mintSession } from '../src/auth';
import { hmacSha256, toHex } from '../src/lib/crypto';

const KEY = 'k7Qp2xVn9sLw4TzRb8YdHf3JmUc6AeGo1NiXtKv0PqSa5ZyWh';
const APP_SECRET = 'S3cretAppSecretValue0123456789ab';
const VERIFY = 'verify-token-xyz';
const META = { app_id: '1234567890', app_secret: APP_SECRET, webhook_verify_token: VERIFY };

let t: ReturnType<typeof createTestDb>;
let env: any;
let sent: any[];
const outbound: string[] = [];
// Providers are never contacted for real: every outbound call is recorded and answered with a 400.
const app = createApp({
  fetch: async (url) => {
    outbound.push(url);
    return new Response(JSON.stringify({ error: { message: 'stub' } }), { status: 400 });
  },
});

const tokens: Record<string, string> = {};
const call = (method: string, path: string, user?: string, body?: unknown, extra: Record<string, string> = {}) =>
  app.request(
    `https://app.test${path}`,
    {
      method,
      headers: {
        ...(user ? { authorization: `Bearer ${tokens[user]}` } : {}),
        ...(body !== undefined ? { 'content-type': 'application/json' } : {}),
        ...extra,
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    },
    env,
  );

beforeEach(async () => {
  t = createTestDb();
  sent = [];
  t.raw.exec(`
    INSERT INTO workspaces (id,name) VALUES ('ws-a','A'),('ws-b','B');
    INSERT INTO users (id,email,is_app_owner) VALUES ('owner','o@x.com',1),('alice','a@x.com',0),('bob','b@x.com',0),('carol','c@x.com',0);
    INSERT INTO workspace_members VALUES ('ws-a','alice','admin'),('ws-a','bob','member'),('ws-b','carol','admin');
  `);
  env = { DB: t.d1, SECRET_KEY: KEY, APP_URL: 'https://app.test', WEBHOOK_QUEUE: { send: async (m: any) => void sent.push(m) } };
  for (const u of ['owner', 'alice', 'bob', 'carol']) tokens[u] = await mintSession(KEY, u);
});

const createMeta = async () => {
  const r = await call('POST', '/api/workspaces/ws-a/integrations', 'alice', {
    provider: 'meta', configurationName: 'Main', credentials: META, enabled: true,
  });
  return { r, body: (await r.clone().json()) as any };
};

describe('authentication and hardening', () => {
  it('requires a valid session', async () => {
    expect((await call('GET', '/api/workspaces/ws-a/integrations')).status).toBe(401);
    expect((await call('GET', '/api/workspaces/ws-a/integrations', undefined, undefined, { authorization: 'Bearer junk' })).status).toBe(401);
    const forged = (await mintSession('Zr3Hn8WcJd5MbT1gLy9QfXe2UaKo7VpSi4NtAx6DvEq0YhCuB', 'alice'));
    expect((await app.request('https://app.test/api/workspaces/ws-a/integrations', { headers: { authorization: `Bearer ${forged}` } }, env)).status).toBe(401);
  });

  it('expired sessions are rejected', async () => {
    const old = await mintSession(KEY, 'alice', -10);
    expect((await app.request('https://app.test/api/workspaces/ws-a/integrations', { headers: { authorization: `Bearer ${old}` } }, env)).status).toBe(401);
  });

  it('blocks cross-origin and non-JSON writes (CSRF)', async () => {
    const body = { provider: 'meta', configurationName: 'x', credentials: META };
    expect((await call('POST', '/api/workspaces/ws-a/integrations', 'alice', body, { origin: 'https://evil.test' })).status).toBe(403);
    const r = await app.request('https://app.test/api/workspaces/ws-a/integrations', {
      method: 'POST', headers: { authorization: `Bearer ${tokens.alice}`, 'content-type': 'text/plain' }, body: JSON.stringify(body),
    }, env);
    expect(r.status).toBe(415);
    expect((await call('POST', '/api/workspaces/ws-a/integrations', 'alice', body, { origin: 'https://app.test' })).status).toBe(201);
  });

  it('a missing or weak SECRET_KEY yields an actionable 503, not a crash', async () => {
    const r = await app.request('https://app.test/api/integrations/providers', { headers: { authorization: `Bearer ${tokens.alice}` } }, { ...env, SECRET_KEY: undefined });
    expect(r.status).toBe(503);
    expect(JSON.stringify(await r.json())).toContain('wrangler secret put SECRET_KEY');
  });
});

describe('responses never expose secrets (scenario 3)', () => {
  it('create, list, get, update, test, webhook and error responses contain no secret values', async () => {
    const { r, body } = await createMeta();
    expect(r.status).toBe(201);
    const id = body.integration.id;
    const outputs: string[] = [JSON.stringify(body)];
    const grab = async (p: Response | Promise<Response>) => outputs.push(await (await p).text());

    await grab(call('GET', '/api/workspaces/ws-a/integrations', 'alice'));
    await grab(call('GET', `/api/integrations/${id}`, 'alice'));
    await grab(call('PATCH', `/api/integrations/${id}`, 'alice', { credentials: { graph_api_version: 'v22.0' } }));
    await grab(call('POST', `/api/integrations/${id}/test`, 'alice')); // provider rejects: must report invalid, not leak
    expect(outbound.length).toBeGreaterThan(0);
    await grab(call('POST', `/api/integrations/${id}/webhook/enable`, 'alice'));
    await grab(call('GET', `/api/integrations/${id}/webhook`, 'alice'));
    await grab(call('GET', `/api/integrations/${id}`, 'bob')); // forbidden body
    await grab(call('PATCH', `/api/integrations/${id}`, 'alice', { credentials: { app_secret: 'bad' } })); // validation error body
    await grab(call('GET', '/api/integrations/providers', 'alice'));

    const all = outputs.join('\n');
    for (const secret of [APP_SECRET, VERIFY]) expect(all).not.toContain(secret);
    expect(all).toContain('••••');
  });

  it('masks secrets and shows identifiers; update preserves unchanged fields', async () => {
    const { body } = await createMeta();
    const f = Object.fromEntries(body.integration.fields.map((x: any) => [x.key, x]));
    expect(f.app_id.display).toBe('1234567890');
    expect(f.app_secret.display).toMatch(/^•+$/);
    const up = await (await call('PATCH', `/api/integrations/${body.integration.id}`, 'alice', { credentials: { app_secret: '', graph_api_version: 'v22.0' } })).json() as any;
    expect(up.integration.fields.find((x: any) => x.key === 'app_secret').isSet).toBe(true);
    expect(up.integration.fields.find((x: any) => x.key === 'graph_api_version').display).toBe('v22.0');
  });

  it('the database holds no plaintext after the whole flow', async () => {
    await createMeta();
    expect(t.dumpAll()).not.toContain(APP_SECRET);
    expect(t.dumpAll()).not.toContain(VERIFY);
  });
});

describe('authorization over HTTP (scenarios 6, 7)', () => {
  it('members get 403 on every credential route', async () => {
    const { body } = await createMeta();
    const id = body.integration.id;
    const attempts: Array<[string, string, unknown?]> = [
      ['GET', '/api/workspaces/ws-a/integrations'],
      ['POST', '/api/workspaces/ws-a/integrations', { provider: 'meta', configurationName: 'n', credentials: META }],
      ['GET', `/api/integrations/${id}`],
      ['PATCH', `/api/integrations/${id}`, { configurationName: 'n' }],
      ['POST', `/api/integrations/${id}/test`],
      ['POST', `/api/integrations/${id}/disable`],
      ['DELETE', `/api/integrations/${id}`, { confirmName: 'Main' }],
      ['GET', `/api/integrations/${id}/webhook`],
      ['POST', '/api/workspaces/ws-a/oauth/meta/start', {}],
    ];
    for (const [m, p, b] of attempts) expect((await call(m, p, 'bob', b)).status, `${m} ${p}`).toBe(403);
  });

  it("another workspace's admin gets 403, and the app owner gets no implicit access to workspace configs", async () => {
    const { body } = await createMeta();
    const id = body.integration.id;
    for (const u of ['carol', 'owner']) {
      expect((await call('GET', `/api/integrations/${id}`, u)).status).toBe(403);
      expect((await call('PATCH', `/api/integrations/${id}`, u, { configurationName: 'x' })).status).toBe(403);
    }
  });

  it('global integrations: app owner only', async () => {
    const payload = { provider: 'meta', configurationName: 'Shared', credentials: META };
    expect((await call('POST', '/api/admin/integrations', 'alice', payload)).status).toBe(403);
    expect((await call('GET', '/api/admin/integrations', 'alice')).status).toBe(403);
    expect((await call('POST', '/api/admin/integrations', 'owner', payload)).status).toBe(201);
    expect((await call('POST', '/api/admin/rotate-encryption', 'alice')).status).toBe(403);
    expect((await call('POST', '/api/admin/rotate-encryption', 'owner')).status).toBe(200);
  });

  it('availability is visible to members but reveals no configuration', async () => {
    await createMeta();
    const r = await call('GET', '/api/workspaces/ws-a/integrations/availability', 'bob');
    expect(await r.json()).toEqual({ availability: { meta: 'workspace', linkedin: 'none', x: 'none', google: 'none', tiktok: 'none' } });
    expect((await call('GET', '/api/workspaces/ws-a/integrations/availability', 'carol')).status).toBe(403);
  });
});

describe('lifecycle', () => {
  it('enable/disable/delete with confirmation, and actionable errors', async () => {
    const { body } = await createMeta();
    const id = body.integration.id;
    expect(((await (await call('POST', `/api/integrations/${id}/disable`, 'alice')).json()) as any).integration.statusLabel).toBe('Disabled');
    expect((await call('DELETE', `/api/integrations/${id}`, 'alice', { confirmName: 'wrong' })).status).toBe(422);
    expect((await call('DELETE', `/api/integrations/${id}`, 'alice', { confirmName: 'Main' })).status).toBe(200);
    const start = await call('POST', '/api/workspaces/ws-a/oauth/meta/start', 'alice', {});
    expect(start.status).toBe(424);
    expect(JSON.stringify(await start.json())).toContain('Settings → Integrations → API Credentials → Meta');
  });

  it('OAuth start returns an authorize URL built from the stored app, without secrets', async () => {
    await createMeta();
    const r = await call('POST', '/api/workspaces/ws-a/oauth/meta/start', 'alice', {});
    const j = (await r.json()) as any;
    expect(r.status).toBe(200);
    expect(j.authorizeUrl).toContain('client_id=1234567890');
    expect(j.authorizeUrl).not.toContain(APP_SECRET);
  });
});

describe('provider-facing endpoints', () => {
  it('OAuth callback always redirects to a fixed destination and reports failures by code only', async () => {
    const noSession = await app.request('https://app.test/oauth/callback/meta?code=c&state=s', {}, env);
    expect(noSession.status).toBe(302);
    expect(noSession.headers.get('location')).toBe('https://app.test/settings/integrations?error=UNAUTHENTICATED');

    const badState = await app.request('https://app.test/oauth/callback/meta?code=c&state=nope', { headers: { cookie: `session=${tokens.alice}` } }, env);
    expect(badState.headers.get('location')).toBe('https://app.test/settings/integrations?error=VALIDATION&provider=meta');

    const bogus = await app.request('https://app.test/oauth/callback/evil?code=c&state=s', {}, env);
    expect(bogus.headers.get('location')?.startsWith('https://app.test/settings/integrations')).toBe(true);
  });

  it('webhooks work end to end through HTTP with provider-specific verification', async () => {
    const { body } = await createMeta();
    const id = body.integration.id;
    const wh = ((await (await call('POST', `/api/integrations/${id}/webhook/enable`, 'alice')).json()) as any).webhook;
    const path = new URL(wh.callbackUrl).pathname;

    const hs = await app.request(`https://app.test${path}?hub.mode=subscribe&hub.verify_token=${VERIFY}&hub.challenge=hello`, {}, env);
    expect(await hs.text()).toBe('hello');

    const payload = JSON.stringify({ object: 'page' });
    const sig = `sha256=${toHex(await hmacSha256(APP_SECRET, payload))}`;
    const ok = await app.request(`https://app.test${path}`, { method: 'POST', body: payload, headers: { 'x-hub-signature-256': sig } }, env);
    expect(ok.status).toBe(200);
    expect(sent[0]).toMatchObject({ workspaceId: 'ws-a', provider: 'meta' });

    const bad = await app.request(`https://app.test${path}`, { method: 'POST', body: payload, headers: { 'x-hub-signature-256': 'sha256=00' } }, env);
    expect(bad.status).toBe(401);

    const status = (await (await call('GET', `/api/integrations/${id}/webhook`, 'alice')).json()) as any;
    expect(status.webhook.subscriptionStatus).toBe('active');
    expect(status.webhook.recentEvents.map((e: any) => e.status)).toEqual(expect.arrayContaining(['accepted', 'rejected']));
  });
});

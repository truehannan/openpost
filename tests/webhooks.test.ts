import { beforeEach, describe, expect, it } from 'vitest';
import { createTestDb } from './helpers/d1';
import { IntegrationCredentialService } from '../src/services/integration-credentials';
import { WebhookService } from '../src/services/webhooks';
import { hmacSha256, toHex } from '../src/lib/crypto';

const KEY = 'k7Qp2xVn9sLw4TzRb8YdHf3JmUc6AeGo1NiXtKv0PqSa5ZyWh';
const SECRET_A = 'AppSecretForWorkspaceA0123456789ab';
const SECRET_B = 'AppSecretForWorkspaceB0123456789cd';
const VERIFY_A = 'verify-token-for-a';
const ALICE = { userId: 'u-alice' };
const CAROL = { userId: 'u-carol' };
const BOB = { userId: 'u-bob' };

let t: ReturnType<typeof createTestDb>;
let creds: IntegrationCredentialService;
let hooks: WebhookService;
let sent: any[];
let idA: string;
let idB: string;

const keyOf = (id: string) => (t.raw.prepare('SELECT webhook_key k FROM webhook_subscriptions WHERE credential_config_id=?').get(id) as any).k as string;
const sign = async (secret: string, body: string) => `sha256=${toHex(await hmacSha256(secret, body))}`;
const hdr = (h: Record<string, string>) => new Headers(h);

beforeEach(async () => {
  t = createTestDb();
  sent = [];
  t.raw.exec(`
    INSERT INTO workspaces (id,name) VALUES ('ws-a','A'),('ws-b','B');
    INSERT INTO users (id,email,is_app_owner) VALUES ('u-alice','a@x.com',0),('u-carol','c@x.com',0),('u-bob','b@x.com',0);
    INSERT INTO workspace_members VALUES ('ws-a','u-alice','admin'),('ws-b','u-carol','admin'),('ws-a','u-bob','member');
  `);
  const env = { DB: t.d1, SECRET_KEY: KEY, APP_URL: 'https://app.test', WEBHOOK_QUEUE: { send: async (m: any) => void sent.push(m) } as any };
  creds = new IntegrationCredentialService(env);
  hooks = new WebhookService(env, { credentials: creds });
  idA = (await creds.create(ALICE, { scope: 'workspace', workspaceId: 'ws-a', provider: 'meta', configurationName: 'A', credentials: { app_id: '1111111111', app_secret: SECRET_A, webhook_verify_token: VERIFY_A }, enabled: true })).id;
  idB = (await creds.create(CAROL, { scope: 'workspace', workspaceId: 'ws-b', provider: 'meta', configurationName: 'B', credentials: { app_id: '2222222222', app_secret: SECRET_B, webhook_verify_token: 'verify-b' }, enabled: true })).id;
  await hooks.enable(ALICE, idA);
  await hooks.enable(CAROL, idB);
});

describe('dashboard-facing status', () => {
  it('issues a callback URL and reports which field is the token vs the signing secret', async () => {
    const s = await hooks.status(ALICE, idA);
    expect(s.callbackUrl).toBe(`https://app.test/webhooks/meta/${keyOf(idA)}`);
    expect(s.subscriptionStatus).toBe('pending');
    expect(s.verifyTokenField).toBe('webhook_verify_token');
    expect(s.signingSecretField).toBe('app_secret');
    expect(s.verifyTokenConfigured).toBe(true);
    expect(JSON.stringify(s)).not.toContain(SECRET_A);
    expect(JSON.stringify(s)).not.toContain(VERIFY_A);
  });

  it('enable is idempotent, rotate changes the URL, and authz is enforced', async () => {
    const u1 = (await hooks.enable(ALICE, idA)).callbackUrl;
    expect(u1).toBe((await hooks.status(ALICE, idA)).callbackUrl);
    const u2 = (await hooks.rotateKey(ALICE, idA)).callbackUrl;
    expect(u2).not.toBe(u1);
    await expect(hooks.status(BOB, idA)).rejects.toMatchObject({ code: 'FORBIDDEN' });
    await expect(hooks.enable(CAROL, idA)).rejects.toMatchObject({ code: 'FORBIDDEN' });
  });

  it('refuses providers without webhook support', async () => {
    const li = await creds.create(ALICE, { scope: 'workspace', workspaceId: 'ws-a', provider: 'linkedin', configurationName: 'L', credentials: { client_id: 'abc123', client_secret: 'x'.repeat(20) } });
    await expect(hooks.enable(ALICE, li.id)).rejects.toMatchObject({ code: 'VALIDATION' });
  });
});

describe('GET handshake (scenario 11: correct provider configuration)', () => {
  const q = (o: Record<string, string>) => new URLSearchParams(o);

  it('Meta echoes the challenge for the right verification token and marks the subscription active', async () => {
    const r = await hooks.handleVerification('meta', keyOf(idA), q({ 'hub.mode': 'subscribe', 'hub.verify_token': VERIFY_A, 'hub.challenge': 'CHALLENGE-42' }));
    expect(r).toMatchObject({ status: 200, body: 'CHALLENGE-42' });
    expect((await hooks.status(ALICE, idA)).subscriptionStatus).toBe('active');
  });

  it('rejects another configuration\'s token and the signing secret (they are not interchangeable)', async () => {
    const k = keyOf(idA);
    for (const token of ['verify-b', SECRET_A, '']) {
      const r = await hooks.handleVerification('meta', k, q({ 'hub.mode': 'subscribe', 'hub.verify_token': token, 'hub.challenge': 'c' }));
      expect(r.status).toBe(403);
    }
    expect((await hooks.status(ALICE, idA)).lastError).toContain('mismatch');
  });

  it('unknown key, wrong provider in the URL, and disabled configs are refused', async () => {
    const ok = q({ 'hub.mode': 'subscribe', 'hub.verify_token': VERIFY_A, 'hub.challenge': 'c' });
    expect((await hooks.handleVerification('meta', 'x'.repeat(32), ok)).status).toBe(404);
    expect((await hooks.handleVerification('tiktok', keyOf(idA), ok)).status).toBe(404);
    await creds.setEnabled(ALICE, idA, false);
    expect((await hooks.handleVerification('meta', keyOf(idA), ok)).status).toBe(403);
  });

  it('X answers a CRC with an HMAC using the API Key Secret', async () => {
    const x = await creds.create(ALICE, { scope: 'workspace', workspaceId: 'ws-a', provider: 'x', configurationName: 'X', credentials: { client_id: 'xclient123', client_secret: 'c'.repeat(30), api_key_secret: 'consumer-secret-value' }, enabled: true });
    await hooks.enable(ALICE, x.id);
    const r = await hooks.handleVerification('x', keyOf(x.id), q({ crc_token: 'abc' }));
    const expected = btoa(String.fromCharCode(...(await hmacSha256('consumer-secret-value', 'abc'))));
    expect(JSON.parse(r.body)).toEqual({ response_token: `sha256=${expected}` });
  });
});

describe('POST events', () => {
  const body = JSON.stringify({ object: 'page', entry: [{ id: '1' }] });

  it('accepts a correctly signed event, enqueues it with a server-derived workspace, and logs it', async () => {
    const r = await hooks.handleEvent('meta', keyOf(idA), body, hdr({ 'x-hub-signature-256': await sign(SECRET_A, body) }));
    expect(r.status).toBe(200);
    expect(sent).toHaveLength(1);
    expect(sent[0]).toMatchObject({ configId: idA, provider: 'meta', workspaceId: 'ws-a', body });
    const s = await hooks.status(ALICE, idA);
    expect(s.lastEventAt).toBeTruthy();
    expect(s.recentEvents[0]).toMatchObject({ status: 'accepted', signatureValid: true });
  });

  it('verifies against the configuration the URL key belongs to, not another workspace\'s', async () => {
    // Signed with B's secret but sent to A's URL: must fail.
    const r = await hooks.handleEvent('meta', keyOf(idA), body, hdr({ 'x-hub-signature-256': await sign(SECRET_B, body) }));
    expect(r.status).toBe(401);
    expect(sent).toHaveLength(0);
    // Signed with B's secret and sent to B's URL: accepted and attributed to ws-b.
    const ok = await hooks.handleEvent('meta', keyOf(idB), body, hdr({ 'x-hub-signature-256': await sign(SECRET_B, body) }));
    expect(ok.status).toBe(200);
    expect(sent[0].workspaceId).toBe('ws-b');
  });

  it('ignores client-supplied workspace identifiers', async () => {
    const h = hdr({ 'x-hub-signature-256': await sign(SECRET_A, body), 'x-workspace-id': 'ws-b' });
    await hooks.handleEvent('meta', keyOf(idA), body, h);
    expect(sent[0].workspaceId).toBe('ws-a');
  });

  it('the verification token is not accepted as a signing secret', async () => {
    const r = await hooks.handleEvent('meta', keyOf(idA), body, hdr({ 'x-hub-signature-256': await sign(VERIFY_A, body) }));
    expect(r.status).toBe(401);
  });

  it('rejects missing, malformed and tampered signatures, and logs each', async () => {
    const k = keyOf(idA);
    const good = await sign(SECRET_A, body);
    for (const [b, h] of [
      [body, {}],
      [body, { 'x-hub-signature-256': 'sha256=zz' }],
      [body, { 'x-hub-signature-256': 'md5=abcd' }],
      [body + ' ', { 'x-hub-signature-256': good }],
    ] as const) {
      expect((await hooks.handleEvent('meta', k, b, hdr(h as any))).status).toBe(401);
    }
    expect(sent).toHaveLength(0);
    const s = await hooks.status(ALICE, idA);
    expect(s.recentEvents.filter((e) => e.status === 'rejected')).toHaveLength(4);
    expect(s.lastError).toBeTruthy();
  });

  it('disabled integrations reject events; oversized payloads are refused', async () => {
    await creds.setEnabled(ALICE, idA, false);
    expect((await hooks.handleEvent('meta', keyOf(idA), body, hdr({ 'x-hub-signature-256': await sign(SECRET_A, body) }))).status).toBe(403);
    await creds.setEnabled(ALICE, idA, true);
    const big = 'x'.repeat(100_001);
    expect((await hooks.handleEvent('meta', keyOf(idA), big, hdr({}))).status).toBe(413);
  });

  it('stores a payload hash, never the payload', async () => {
    await hooks.handleEvent('meta', keyOf(idA), body, hdr({ 'x-hub-signature-256': await sign(SECRET_A, body) }));
    expect(JSON.stringify(t.raw.prepare('SELECT * FROM webhook_events').all())).not.toContain('"entry"');
  });

  it('TikTok uses its own timestamped scheme and rejects stale timestamps', async () => {
    const tk = await creds.create(ALICE, { scope: 'workspace', workspaceId: 'ws-a', provider: 'tiktok', configurationName: 'T', credentials: { client_key: 'awkey12345', client_secret: 'tiktok-secret-value-123' }, enabled: true });
    await hooks.enable(ALICE, tk.id);
    const mk = async (ts: number) => `t=${ts},s=${toHex(await hmacSha256('tiktok-secret-value-123', `${ts}.${body}`))}`;
    const now = Math.floor(Date.now() / 1000);
    expect((await hooks.handleEvent('tiktok', keyOf(tk.id), body, hdr({ 'tiktok-signature': await mk(now) }))).status).toBe(200);
    expect((await hooks.handleEvent('tiktok', keyOf(tk.id), body, hdr({ 'tiktok-signature': await mk(now - 3600) }))).status).toBe(401);
  });
});

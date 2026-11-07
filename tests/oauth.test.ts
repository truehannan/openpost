import { beforeEach, describe, expect, it } from 'vitest';
import { createTestDb } from './helpers/d1';
import { IntegrationCredentialService } from '../src/services/integration-credentials';
import { OAuthService } from '../src/services/oauth';

const KEY = 'k7Qp2xVn9sLw4TzRb8YdHf3JmUc6AeGo1NiXtKv0PqSa5ZyWh';
const APP_SECRET = 'S3cretAppSecretValue0123456789ab';
const META = { app_id: '1234567890', app_secret: APP_SECRET };
const ALICE = { userId: 'u-alice' }; // admin ws-a
const BOB = { userId: 'u-bob' }; // member ws-a

let t: ReturnType<typeof createTestDb>;
let calls: Array<{ url: string; init?: RequestInit }>;
let respond: (url: string, init?: RequestInit) => Response;

const fetcher = async (url: string, init?: RequestInit) => {
  calls.push({ url, init });
  return respond(url, init);
};
const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status });

let creds: IntegrationCredentialService;
let oauth: OAuthService;
let configId: string;

beforeEach(async () => {
  t = createTestDb();
  calls = [];
  t.raw.exec(`
    INSERT INTO workspaces (id,name) VALUES ('ws-a','A'),('ws-b','B');
    INSERT INTO users (id,email,is_app_owner) VALUES ('u-owner','o@x.com',1),('u-alice','a@x.com',0),('u-bob','b@x.com',0);
    INSERT INTO workspace_members VALUES ('ws-a','u-alice','admin'),('ws-a','u-bob','member');
  `);
  const env = { DB: t.d1, SECRET_KEY: KEY, APP_URL: 'https://app.test' };
  creds = new IntegrationCredentialService(env, { fetch: fetcher });
  oauth = new OAuthService(env, { fetch: fetcher, credentials: creds });
  configId = (await creds.create(ALICE, { scope: 'workspace', workspaceId: 'ws-a', provider: 'meta', configurationName: 'Main', credentials: META, enabled: true })).id;
  respond = (url) => {
    if (url.includes('/oauth/access_token')) return json(200, { access_token: 'ACCESS-TOKEN-1', expires_in: 3600 });
    if (url.includes('/me?')) return json(200, { id: 'fb-123', name: 'My Page' });
    return json(404, {});
  };
});

const stateOf = (authorizeUrl: string) => new URL(authorizeUrl).searchParams.get('state')!;

describe('OAuth start', () => {
  it('uses the resolved app, a fresh state, and the registered redirect URI', async () => {
    const { authorizeUrl } = await oauth.start(ALICE, 'ws-a', 'meta');
    const u = new URL(authorizeUrl);
    expect(u.host).toBe('www.facebook.com');
    expect(u.searchParams.get('client_id')).toBe('1234567890');
    expect(u.searchParams.get('redirect_uri')).toBe('https://app.test/oauth/callback/meta');
    expect(authorizeUrl).not.toContain(APP_SECRET);
    expect(stateOf(authorizeUrl).length).toBeGreaterThan(30);
  });

  it('only owners/admins can start; members cannot', async () => {
    await expect(oauth.start(BOB, 'ws-a', 'meta')).rejects.toMatchObject({ code: 'FORBIDDEN' });
  });

  it('a disabled integration cannot start OAuth (scenario 9)', async () => {
    await creds.setEnabled(ALICE, configId, false);
    await expect(oauth.start(ALICE, 'ws-a', 'meta')).rejects.toMatchObject({ code: 'CONFIG_DISABLED' });
  });

  it('missing integration gives an actionable error (scenario 12)', async () => {
    const e = await oauth.start(ALICE, 'ws-a', 'tiktok').catch((x) => x);
    expect(e.code).toBe('CONFIG_MISSING');
    expect(e.message).toContain('Settings → Integrations → API Credentials → TikTok');
  });

  it('PKCE providers store the verifier encrypted and send only the challenge', async () => {
    await creds.create(ALICE, {
      scope: 'workspace', workspaceId: 'ws-a', provider: 'x', configurationName: 'X',
      credentials: { client_id: 'xclient123', client_secret: 'x'.repeat(30) }, enabled: true,
    });
    const { authorizeUrl } = await oauth.start(ALICE, 'ws-a', 'x');
    const u = new URL(authorizeUrl);
    expect(u.searchParams.get('code_challenge_method')).toBe('S256');
    expect(u.searchParams.get('code_challenge')).toBeTruthy();
    const row = t.raw.prepare('SELECT encrypted_code_verifier v FROM oauth_states').get() as any;
    expect(row.v.startsWith('v1.')).toBe(true);
  });
});

describe('OAuth callback', () => {
  it('exchanges the code and stores only encrypted tokens (steps 4-7)', async () => {
    const { authorizeUrl } = await oauth.start(ALICE, 'ws-a', 'meta');
    const acct = await oauth.handleCallback('u-alice', 'meta', { code: 'AUTHCODE', state: stateOf(authorizeUrl) });

    expect(acct).toMatchObject({ provider: 'meta', providerAccountId: 'fb-123', status: 'active', credentialConfigId: configId });
    expect(JSON.stringify(acct)).not.toContain('ACCESS-TOKEN-1');
    expect(t.dumpAll()).not.toContain('ACCESS-TOKEN-1');
    expect(t.dumpAll()).not.toContain(APP_SECRET);

    const tokenCall = calls.find((c) => c.url.includes('/oauth/access_token'))!;
    expect(String(tokenCall.init?.body)).toContain('code=AUTHCODE');
    expect(await oauth.getAccessToken(acct.id)).toBe('ACCESS-TOKEN-1');
  });

  it('state is single-use (replay is rejected)', async () => {
    const state = stateOf((await oauth.start(ALICE, 'ws-a', 'meta')).authorizeUrl);
    await oauth.handleCallback('u-alice', 'meta', { code: 'c', state });
    await expect(oauth.handleCallback('u-alice', 'meta', { code: 'c', state })).rejects.toMatchObject({ code: 'VALIDATION' });
  });

  it('rejects unknown, expired, cross-provider and cross-user state', async () => {
    await expect(oauth.handleCallback('u-alice', 'meta', { code: 'c', state: 'nope' })).rejects.toMatchObject({ code: 'VALIDATION' });

    const s1 = stateOf((await oauth.start(ALICE, 'ws-a', 'meta')).authorizeUrl);
    t.raw.prepare('UPDATE oauth_states SET expires_at = ? WHERE state = ?').run(new Date(Date.now() - 1000).toISOString(), s1);
    await expect(oauth.handleCallback('u-alice', 'meta', { code: 'c', state: s1 })).rejects.toMatchObject({ code: 'VALIDATION' });

    const s2 = stateOf((await oauth.start(ALICE, 'ws-a', 'meta')).authorizeUrl);
    await expect(oauth.handleCallback('u-alice', 'tiktok', { code: 'c', state: s2 })).rejects.toMatchObject({ code: 'VALIDATION' });

    const s3 = stateOf((await oauth.start(ALICE, 'ws-a', 'meta')).authorizeUrl);
    await expect(oauth.handleCallback('u-bob', 'meta', { code: 'c', state: s3 })).rejects.toMatchObject({ code: 'FORBIDDEN' });
    expect(calls.filter((c) => c.url.includes('/oauth/access_token'))).toHaveLength(0);
  });

  it('refuses to finish if the integration was disabled mid-flow', async () => {
    const state = stateOf((await oauth.start(ALICE, 'ws-a', 'meta')).authorizeUrl);
    await creds.setEnabled(ALICE, configId, false);
    await expect(oauth.handleCallback('u-alice', 'meta', { code: 'c', state })).rejects.toMatchObject({ code: 'CONFIG_DISABLED' });
  });

  it('PKCE verifier is sent on exchange', async () => {
    await creds.create(ALICE, {
      scope: 'workspace', workspaceId: 'ws-a', provider: 'x', configurationName: 'X',
      credentials: { client_id: 'xclient123', client_secret: 'x'.repeat(30) }, enabled: true,
    });
    respond = (url) =>
      url.includes('oauth2/token') ? json(200, { access_token: 'XT-ACCESS-VALUE-555', refresh_token: 'XR-REFRESH-VALUE-777', expires_in: 7200 })
      : url.includes('users/me') ? json(200, { data: { id: 'x-1', username: 'me' } }) : json(404, {});
    const state = stateOf((await oauth.start(ALICE, 'ws-a', 'x')).authorizeUrl);
    await oauth.handleCallback('u-alice', 'x', { code: 'c', state });
    const body = String(calls.find((c) => c.url.includes('oauth2/token'))!.init?.body);
    expect(body).toContain('code_verifier=');
    expect(t.dumpAll()).not.toContain('XR-REFRESH-VALUE-777');
    expect(t.dumpAll()).not.toContain('XT-ACCESS-VALUE-555');
  });

  it('reconnecting the same account updates it in place, keeping its id', async () => {
    const a1 = await oauth.handleCallback('u-alice', 'meta', { code: 'c', state: stateOf((await oauth.start(ALICE, 'ws-a', 'meta')).authorizeUrl) });
    const a2 = await oauth.handleCallback('u-alice', 'meta', { code: 'c', state: stateOf((await oauth.start(ALICE, 'ws-a', 'meta')).authorizeUrl) });
    expect(a2.id).toBe(a1.id);
    expect(await oauth.listAccounts(ALICE, 'ws-a')).toHaveLength(1);
  });
});

describe('use, refresh and revocation', () => {
  const connectX = async () => {
    await creds.create(ALICE, {
      scope: 'workspace', workspaceId: 'ws-a', provider: 'x', configurationName: 'X',
      credentials: { client_id: 'xclient123', client_secret: 'x'.repeat(30) }, enabled: true,
    });
    respond = (url) =>
      url.includes('oauth2/token') ? json(200, { access_token: 'XT-OLD', refresh_token: 'XR-OLD', expires_in: 60 })
      : url.includes('users/me') ? json(200, { data: { id: 'x-1', username: 'me' } }) : json(404, {});
    const state = stateOf((await oauth.start(ALICE, 'ws-a', 'x')).authorizeUrl);
    return oauth.handleCallback('u-alice', 'x', { code: 'c', state });
  };

  it('refreshes automatically when near expiry', async () => {
    const acct = await connectX(); // expires in 60s, inside the 5 minute skew
    respond = (url, init) => {
      expect(String(init?.body)).toContain('grant_type=refresh_token');
      return json(200, { access_token: 'XT-NEW', expires_in: 7200 });
    };
    expect(await oauth.getAccessToken(acct.id)).toBe('XT-NEW');
    // refresh token is retained when the provider does not rotate it
    const row = t.raw.prepare('SELECT encrypted_refresh_token r FROM social_accounts WHERE id=?').get(acct.id) as any;
    expect(row.r).toBeTruthy();
  });

  it('a dead refresh token marks the account revoked, and it stays unusable', async () => {
    const acct = await connectX();
    respond = () => json(400, { error: 'invalid_grant' });
    await expect(oauth.getAccessToken(acct.id)).rejects.toBeDefined();
    expect((await oauth.listAccounts(ALICE, 'ws-a'))[0]).toMatchObject({ status: 'revoked' });
    await expect(oauth.getAccessToken(acct.id)).rejects.toMatchObject({ code: 'VALIDATION' });
  });

  it('a transient failure marks error, not revoked', async () => {
    const acct = await connectX();
    respond = () => json(500, { error: 'server_error' });
    await expect(oauth.getAccessToken(acct.id)).rejects.toBeDefined();
    expect((await oauth.listAccounts(ALICE, 'ws-a'))[0]).toMatchObject({ status: 'error' });
  });

  it('disabling the integration blocks token use; members can list but not disconnect', async () => {
    const acct = await oauth.handleCallback('u-alice', 'meta', { code: 'c', state: stateOf((await oauth.start(ALICE, 'ws-a', 'meta')).authorizeUrl) });
    await creds.setEnabled(ALICE, configId, false);
    await expect(oauth.getAccessToken(acct.id)).rejects.toMatchObject({ code: 'CONFIG_DISABLED' });
    expect(await oauth.listAccounts(BOB, 'ws-a')).toHaveLength(1);
    await expect(oauth.disconnect(BOB, acct.id)).rejects.toMatchObject({ code: 'FORBIDDEN' });
    await oauth.disconnect(ALICE, acct.id);
    expect(await oauth.listAccounts(ALICE, 'ws-a')).toHaveLength(0);
  });

  it('listing is token-free and workspace-scoped', async () => {
    await oauth.handleCallback('u-alice', 'meta', { code: 'c', state: stateOf((await oauth.start(ALICE, 'ws-a', 'meta')).authorizeUrl) });
    expect(JSON.stringify(await oauth.listAccounts(ALICE, 'ws-a'))).not.toContain('ACCESS-TOKEN');
    await expect(oauth.listAccounts({ userId: 'u-owner' }, 'ws-a')).rejects.toMatchObject({ code: 'FORBIDDEN' });
  });
});

import { describe, expect, it } from 'vitest';
import { PROVIDERS, checkCredentials, missingRequired } from '../src/services/integration-credentials/providers';
import { maskCredentials, mergeCredentials, publicFieldsOf } from '../src/services/integration-credentials/mask';
import { validateCredentials } from '../src/services/integration-credentials/validate';

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

describe('provider schemas', () => {
  it('are provider-specific, not one shared form', () => {
    const keys = (p: keyof typeof PROVIDERS) => PROVIDERS[p].fields.map((f) => f.key).join(',');
    expect(keys('meta')).toContain('app_id');
    expect(keys('tiktok')).toContain('client_key');
    expect(keys('x')).toContain('api_key_secret');
    expect(new Set(Object.keys(PROVIDERS).map((p) => keys(p as any))).size).toBe(5);
  });

  it('keeps Meta verification token and signing secret distinct', () => {
    const w = PROVIDERS.meta.webhook;
    expect(w.verifyTokenField).toBe('webhook_verify_token');
    expect(w.signingSecretField).toBe('app_secret');
    expect(w.verifyTokenField).not.toBe(w.signingSecretField);
  });

  it('rejects unknown fields and bad formats, applies defaults', () => {
    const r = checkCredentials('meta', { app_id: 'abc', app_secret: 'x', bogus: '1' });
    expect(r.errors.map((e) => e.field).sort()).toEqual(['app_id', 'app_secret', 'bogus']);
    const ok = checkCredentials('meta', { app_id: '1234567890', app_secret: 'a'.repeat(32) });
    expect(ok.errors).toEqual([]);
    expect(ok.values.graph_api_version).toBe('v21.0');
  });

  it('reports incomplete configuration', () => {
    expect(missingRequired('x', { client_id: 'abc' })).toEqual(['client_secret']);
  });
});

describe('masking', () => {
  const creds = { app_id: '123456789', app_secret: 'supersecretvalue1234', graph_api_version: 'v21.0' };

  it('shows identifiers, masks secrets with a fixed-length mask', () => {
    const m = maskCredentials('meta', creds);
    const secret = m.find((f) => f.key === 'app_secret')!;
    expect(m.find((f) => f.key === 'app_id')!.display).toBe('123456789');
    expect(secret.display).not.toContain('super');
    expect(secret.display).toBe(maskCredentials('meta', { ...creds, app_secret: 'x'.repeat(60) }).find((f) => f.key === 'app_secret')!.display);
    expect(JSON.stringify(m)).not.toContain('supersecretvalue1234');
  });

  it('mirrors only non-secret fields to public_config', () => {
    const pub = publicFieldsOf('meta', creds);
    expect(pub).toEqual({ app_id: '123456789', graph_api_version: 'v21.0' });
  });

  it('merge preserves unchanged fields and clears only on explicit null', () => {
    const a = mergeCredentials(creds, { app_secret: '', app_id: undefined, graph_api_version: 'v22.0' });
    expect(a.merged.app_secret).toBe(creds.app_secret);
    expect(a.merged.graph_api_version).toBe('v22.0');
    expect(a.changed).toEqual(['graph_api_version']);
    const b = mergeCredentials({ ...creds, config_id: '9' }, { config_id: null });
    expect('config_id' in b.merged).toBe(false);
  });
});

describe('validation probes', () => {
  const metaCreds = { app_id: '1234567890', app_secret: 'a'.repeat(32), graph_api_version: 'v21.0' };

  it('incomplete credentials never hit the network', async () => {
    let called = false;
    const r = await validateCredentials('meta', { app_id: '1' }, async () => {
      called = true;
      return json(200, {});
    });
    expect(r.status).toBe('incomplete');
    expect(called).toBe(false);
  });

  it('meta: valid, invalid, and inconclusive', async () => {
    expect((await validateCredentials('meta', metaCreds, async () => json(200, { access_token: 't' }))).status).toBe('valid');
    expect((await validateCredentials('meta', metaCreds, async () => json(400, { error: {} }))).status).toBe('invalid');
    expect((await validateCredentials('meta', metaCreds, async () => json(500, {}))).status).toBe('unvalidated');
  });

  it('network failure is inconclusive, never valid, and never echoes secrets', async () => {
    const r = await validateCredentials('meta', metaCreds, async () => {
      throw new Error(`boom ${metaCreds.app_secret}`);
    });
    expect(r.status).toBe('unvalidated');
    expect(r.message).not.toContain(metaCreds.app_secret);
  });

  it('google probe distinguishes invalid_client from invalid_grant', async () => {
    const g = { client_id: 'abc123.apps.googleusercontent.com', client_secret: 'a'.repeat(24) };
    expect((await validateCredentials('google', g, async () => json(401, { error: 'invalid_client' }))).status).toBe('invalid');
    expect((await validateCredentials('google', g, async () => json(400, { error: 'invalid_grant' }))).status).toBe('valid');
  });

  it('tiktok: valid and invalid', async () => {
    const t = { client_key: 'awkey12345', client_secret: 'a'.repeat(24) };
    expect((await validateCredentials('tiktok', t, async () => json(200, { access_token: 'x' }))).status).toBe('valid');
    expect((await validateCredentials('tiktok', t, async () => json(400, { error: 'invalid_client' }))).status).toBe('invalid');
  });
});

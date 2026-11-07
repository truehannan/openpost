import { Hono, type Context } from 'hono';
import type { Env } from './types';
import { CryptoError, assertSecretKey } from './lib/crypto';
import { extractToken, verifySession } from './auth';
import {
  IntegrationCredentialService,
  PROVIDERS,
  PROVIDER_IDS,
  ServiceError,
  isProviderId,
  type Scope,
} from './services/integration-credentials';
import { OAuthService } from './services/oauth';
import { WebhookService } from './services/webhooks';

type AppEnv = { Bindings: Env; Variables: { userId: string } };

const MAX_JSON_BYTES = 64 * 1024;


async function readJson(c: Context<AppEnv>): Promise<Record<string, any>> {
  const len = Number(c.req.header('content-length') ?? 0);
  if (len > MAX_JSON_BYTES) throw new ServiceError('VALIDATION', 'Request body too large.');
  const raw = await c.req.text();
  if (!raw) return {};
  if (raw.length > MAX_JSON_BYTES) throw new ServiceError('VALIDATION', 'Request body too large.');
  try {
    const v = JSON.parse(raw);
    if (v === null || typeof v !== 'object' || Array.isArray(v)) throw new Error();
    return v;
  } catch {
    throw new ServiceError('VALIDATION', 'Request body must be a JSON object.');
  }
}

export interface AppDeps {
  /** Outbound HTTP to providers. Defaults to global fetch; tests inject a stub. */
  fetch?: (input: string, init?: RequestInit) => Promise<Response>;
}

export function createApp(deps: AppDeps = {}) {
  const app = new Hono<AppEnv>();
  const svc = (c: Context<AppEnv>) => new IntegrationCredentialService(c.env, { fetch: deps.fetch });
  const oauth = (c: Context<AppEnv>) => new OAuthService(c.env, { fetch: deps.fetch, credentials: svc(c) });
  const hooks = (c: Context<AppEnv>) => new WebhookService(c.env, { credentials: svc(c) });

  // ---------------------------------------------------------------- errors
  app.onError((err, c) => {
    if (err instanceof ServiceError) {
      return c.json({ error: { code: err.code, message: err.message, details: err.details } }, err.status as any);
    }
    if (err instanceof CryptoError) {
      return c.json({ error: { code: 'SECRET_KEY_INVALID', message: err.message } }, 503);
    }
    // Log the error class only: messages from lower layers are not guaranteed secret-free.
    console.error('Unhandled error:', err?.name ?? 'Error');
    return c.json({ error: { code: 'INTERNAL', message: 'Unexpected error.' } }, 500);
  });

  app.notFound((c) => c.json({ error: { code: 'NOT_FOUND', message: 'Not found.' } }, 404));

  // -------------------------------------------------- API auth + hardening
  app.use('/api/*', async (c, next) => {
    try {
      assertSecretKey(c.env.SECRET_KEY);
    } catch (e) {
      return c.json({ error: { code: 'SECRET_KEY_INVALID', message: (e as Error).message } }, 503);
    }

    // CSRF: a browser cross-site request carries a foreign Origin or a non-JSON content type.
    if (!['GET', 'HEAD', 'OPTIONS'].includes(c.req.method)) {
      const origin = c.req.header('origin');
      if (origin && c.env.APP_URL && origin !== new URL(c.env.APP_URL).origin) {
        return c.json({ error: { code: 'FORBIDDEN', message: 'Cross-origin request blocked.' } }, 403);
      }
      const ct = c.req.header('content-type');
      if (ct && !ct.toLowerCase().startsWith('application/json')) {
        return c.json({ error: { code: 'VALIDATION', message: 'Content-Type must be application/json.' } }, 415);
      }
    }

    const userId = await verifySession(c.env.SECRET_KEY, extractToken(c.req.raw));
    if (!userId) return c.json({ error: { code: 'UNAUTHENTICATED', message: 'Sign in required.' } }, 401);
    c.set('userId', userId);

    await next();
    c.header('Cache-Control', 'no-store');
    c.header('X-Content-Type-Options', 'nosniff');
  });

  const actor = (c: Context<AppEnv>) => ({ userId: c.get('userId') });

  // Who am I, and which workspaces can I see (drives the dashboard's scope selector).
  app.get('/api/me', async (c) => {
    const userId = c.get('userId');
    const u = await c.env.DB.prepare('SELECT id, email, is_app_owner FROM users WHERE id = ?')
      .bind(userId)
      .first<{ id: string; email: string; is_app_owner: number }>();
    if (!u) return c.json({ error: { code: 'UNAUTHENTICATED', message: 'Sign in required.' } }, 401);
    const ws = await c.env.DB.prepare(
      `SELECT w.id, w.name, m.role FROM workspace_members m JOIN workspaces w ON w.id = m.workspace_id
        WHERE m.user_id = ? ORDER BY w.name`,
    )
      .bind(userId)
      .all<{ id: string; name: string; role: string }>();
    return c.json({ userId: u.id, email: u.email, isAppOwner: u.is_app_owner === 1, workspaces: ws.results ?? [] });
  });

  // ----------------------------------------------- provider metadata (forms)
  app.get('/api/integrations/providers', (c) => {
    const redirectBase = (c.env.APP_URL ?? '').replace(/\/+$/, '');
    return c.json({
      providers: PROVIDER_IDS.map((id) => {
        const p = PROVIDERS[id];
        return {
          id,
          label: p.label,
          fields: p.fields.map((f) => ({
            key: f.key,
            label: f.label,
            secret: f.secret,
            required: f.required,
            help: f.help ?? null,
            patternHint: f.patternHint ?? null,
            default: f.default ?? null,
          })),
          requiredPermissions: p.requiredPermissions,
          webhook: {
            supported: p.webhook.supported,
            verifyTokenField: p.webhook.verifyTokenField ?? null,
            signingSecretField: p.webhook.signingSecretField ?? null,
            note: p.webhook.note ?? null,
          },
          oauthRedirectUri: `${redirectBase}/oauth/callback/${id}`,
        };
      }),
    });
  });

  // ------------------------------------------------------ global (app owner)
  app.get('/api/admin/integrations', async (c) =>
    c.json({ integrations: await svc(c).list(actor(c), 'global') }),
  );
  app.post('/api/admin/integrations', async (c) => {
    const b = await readJson(c);
    const v = await svc(c).create(actor(c), {
      scope: 'global',
      provider: b.provider,
      configurationName: b.configurationName,
      credentials: b.credentials ?? {},
      enabled: b.enabled === true,
    });
    return c.json({ integration: v }, 201);
  });
  app.post('/api/admin/rotate-encryption', async (c) =>
    c.json({ result: await svc(c).rotateEncryption(actor(c)) }),
  );

  // ------------------------------------------------------------- workspace
  app.get('/api/workspaces/:ws/integrations', async (c) =>
    c.json({ integrations: await svc(c).list(actor(c), 'workspace' as Scope, c.req.param('ws')) }),
  );
  app.post('/api/workspaces/:ws/integrations', async (c) => {
    const b = await readJson(c);
    const v = await svc(c).create(actor(c), {
      scope: 'workspace',
      workspaceId: c.req.param('ws'),
      provider: b.provider,
      configurationName: b.configurationName,
      credentials: b.credentials ?? {},
      enabled: b.enabled === true,
    });
    return c.json({ integration: v }, 201);
  });
  app.get('/api/workspaces/:ws/integrations/availability', async (c) =>
    c.json({ availability: await svc(c).availability(actor(c), c.req.param('ws')) }),
  );
  app.get('/api/workspaces/:ws/accounts', async (c) =>
    c.json({ accounts: await oauth(c).listAccounts(actor(c), c.req.param('ws')) }),
  );
  app.post('/api/workspaces/:ws/oauth/:provider/start', async (c) => {
    const b = await readJson(c);
    const r = await oauth(c).start(actor(c), c.req.param('ws'), c.req.param('provider'), {
      configId: typeof b.configId === 'string' ? b.configId : undefined,
    });
    return c.json(r);
  });
  app.delete('/api/accounts/:id', async (c) => {
    await oauth(c).disconnect(actor(c), c.req.param('id'));
    return c.json({ ok: true });
  });

  // -------------------------------------------------- configuration by id
  app.get('/api/integrations/:id', async (c) => c.json({ integration: await svc(c).get(actor(c), c.req.param('id')) }));
  app.patch('/api/integrations/:id', async (c) => {
    const b = await readJson(c);
    const v = await svc(c).update(actor(c), c.req.param('id'), {
      configurationName: b.configurationName,
      credentials: b.credentials,
      allowClientIdChange: b.allowClientIdChange === true,
    });
    return c.json({ integration: v });
  });
  app.post('/api/integrations/:id/test', async (c) =>
    c.json({ integration: await svc(c).testStored(actor(c), c.req.param('id')) }),
  );
  app.post('/api/integrations/:id/enable', async (c) =>
    c.json({ integration: await svc(c).setEnabled(actor(c), c.req.param('id'), true) }),
  );
  app.post('/api/integrations/:id/disable', async (c) =>
    c.json({ integration: await svc(c).setEnabled(actor(c), c.req.param('id'), false) }),
  );
  app.delete('/api/integrations/:id', async (c) => {
    const b = await readJson(c);
    await svc(c).delete(actor(c), c.req.param('id'), { confirmName: String(b.confirmName ?? '') });
    return c.json({ ok: true });
  });

  // --------------------------------------------------------------- webhooks
  app.get('/api/integrations/:id/webhook', async (c) =>
    c.json({ webhook: await hooks(c).status(actor(c), c.req.param('id')) }),
  );
  app.post('/api/integrations/:id/webhook/enable', async (c) =>
    c.json({ webhook: await hooks(c).enable(actor(c), c.req.param('id')) }),
  );
  app.post('/api/integrations/:id/webhook/rotate-key', async (c) =>
    c.json({ webhook: await hooks(c).rotateKey(actor(c), c.req.param('id')) }),
  );

  // ------------------------------------------------------------- dashboard
  // Static page + external script/style only, so the CSP can forbid inline code entirely.
  const CSP = [
    "default-src 'none'",
    "script-src 'self'",
    "style-src 'self'",
    "connect-src 'self'",
    "img-src 'self' data:",
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'",
  ].join('; ');

  app.get('/settings/integrations', async (c) => {
    if (!c.env.ASSETS) {
      return c.text('Dashboard assets are not configured (missing ASSETS binding).', 500);
    }
    const res = await c.env.ASSETS.fetch(new Request(new URL('/dashboard.html', c.req.url)));
    return new Response(res.body, {
      status: res.status,
      headers: {
        'content-type': 'text/html; charset=utf-8',
        'content-security-policy': CSP,
        'cache-control': 'no-store',
        'x-content-type-options': 'nosniff',
        'referrer-policy': 'no-referrer',
        'x-frame-options': 'DENY',
      },
    });
  });

  // ===================== provider-facing (not behind API session auth) =====================

  // OAuth redirect target. Needs the browser's session cookie to bind the flow to the user.
  app.get('/oauth/callback/:provider', async (c) => {
    const provider = c.req.param('provider');
    const base = (c.env.APP_URL ?? '').replace(/\/+$/, '');
    // Fixed destination: never redirect to a client-supplied URL.
    const dest = (q: string) => c.redirect(`${base}/settings/integrations?${q}`, 302);
    if (!isProviderId(provider)) return dest('error=VALIDATION');
    try {
      assertSecretKey(c.env.SECRET_KEY);
      const userId = await verifySession(c.env.SECRET_KEY, extractToken(c.req.raw));
      if (!userId) return dest('error=UNAUTHENTICATED');
      const q = new URL(c.req.url).searchParams;
      const acct = await oauth(c).handleCallback(userId, provider, {
        code: q.get('code'),
        state: q.get('state'),
        error: q.get('error'),
      });
      return dest(`connected=${provider}&account=${encodeURIComponent(acct.id)}`);
    } catch (e) {
      const code = e instanceof ServiceError ? e.code : e instanceof CryptoError ? 'SECRET_KEY_INVALID' : 'INTERNAL';
      return dest(`error=${code}&provider=${provider}`);
    }
  });

  // Webhook endpoints: the signature is the authentication; the URL key picks the configuration.
  const sendHook = (r: { status: number; body: string; contentType: string }) =>
    new Response(r.body, { status: r.status, headers: { 'content-type': r.contentType, 'cache-control': 'no-store' } });

  app.get('/webhooks/:provider/:key', async (c) =>
    sendHook(await hooks(c).handleVerification(c.req.param('provider'), c.req.param('key'), new URL(c.req.url).searchParams)),
  );
  app.post('/webhooks/:provider/:key', async (c) => {
    // Raw text: the signature is computed over the exact bytes received.
    const raw = await c.req.text();
    return sendHook(await hooks(c).handleEvent(c.req.param('provider'), c.req.param('key'), raw, c.req.raw.headers));
  });

  return app;
}

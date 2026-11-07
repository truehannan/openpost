import type { Env, ProviderId } from '../types';
import { b64urlEncode, base64ToBytes, hexToBytes, hmacSha256, sha256Hex, timingSafeEqual } from '../lib/crypto';
import {
  IntegrationCredentialService,
  PROVIDERS,
  ServiceError,
  isProviderId,
  type Actor,
  type DecryptedProviderCredentials,
} from './integration-credentials';

export type WebhookEnv = Pick<Env, 'DB' | 'SECRET_KEY' | 'SECRET_KEY_PREVIOUS' | 'APP_URL' | 'WEBHOOK_QUEUE'>;

const MAX_BODY_BYTES = 100_000; // queue messages are limited; provider payloads are small
const TIKTOK_TOLERANCE_SEC = 300;
const enc = new TextEncoder();

export interface WebhookResponse {
  status: number;
  body: string;
  contentType: 'text/plain' | 'application/json';
}

const text = (status: number, body: string): WebhookResponse => ({ status, body, contentType: 'text/plain' });

export interface WebhookQueueMessage {
  configId: string;
  provider: ProviderId;
  /** Derived from the stored configuration, never from the request. Null for global (shared-app) configs. */
  workspaceId: string | null;
  receivedAt: string;
  body: string;
}

/**
 * Incoming requests are mapped to a configuration ONLY by the unguessable
 * per-configuration key in the URL path. No workspace ID, header or query
 * parameter from the request is trusted for that purpose.
 */
export class WebhookService {
  private creds: IntegrationCredentialService;

  constructor(
    private env: WebhookEnv,
    deps: { credentials?: IntegrationCredentialService } = {},
  ) {
    this.creds = deps.credentials ?? new IntegrationCredentialService(env);
  }

  callbackUrl(provider: ProviderId, key: string): string {
    return `${(this.env.APP_URL ?? '').replace(/\/+$/, '')}/webhooks/${provider}/${key}`;
  }

  // ------------------------------------------------------- dashboard-facing

  /** Issue (or return) the callback URL for a configuration. Idempotent. */
  async enable(actor: Actor, configId: string) {
    const cfg = await this.creds.get(actor, configId); // authorization + existence
    const spec = PROVIDERS[cfg.provider].webhook;
    if (!spec.supported) throw new ServiceError('VALIDATION', `${cfg.providerLabel} webhooks are not supported by this integration.`);

    const existing = await this.env.DB.prepare('SELECT id FROM webhook_subscriptions WHERE credential_config_id = ?')
      .bind(configId)
      .first();
    if (!existing) {
      await this.env.DB.prepare(
        "INSERT INTO webhook_subscriptions (id, credential_config_id, webhook_key, status) VALUES (?, ?, ?, 'pending')",
      )
        .bind(crypto.randomUUID(), configId, b64urlEncode(crypto.getRandomValues(new Uint8Array(24))))
        .run();
    }
    return this.status(actor, configId);
  }

  /** Replace the callback URL key (e.g. if the URL leaked). The provider must be re-pointed afterwards. */
  async rotateKey(actor: Actor, configId: string) {
    await this.creds.get(actor, configId);
    await this.env.DB.prepare(
      "UPDATE webhook_subscriptions SET webhook_key = ?, status = 'pending', last_error = NULL WHERE credential_config_id = ?",
    )
      .bind(b64urlEncode(crypto.getRandomValues(new Uint8Array(24))), configId)
      .run();
    return this.status(actor, configId);
  }

  async status(actor: Actor, configId: string) {
    const cfg = await this.creds.get(actor, configId);
    const spec = PROVIDERS[cfg.provider].webhook;
    const sub = await this.env.DB.prepare('SELECT * FROM webhook_subscriptions WHERE credential_config_id = ?')
      .bind(configId)
      .first<{ webhook_key: string; status: string; last_event_at: string | null; last_error: string | null }>();
    const events = await this.env.DB.prepare(
      `SELECT id, received_at, signature_valid, status, error FROM webhook_events
        WHERE credential_config_id = ? ORDER BY received_at DESC, rowid DESC LIMIT 25`,
    )
      .bind(configId)
      .all<{ id: string; received_at: string; signature_valid: number; status: string; error: string | null }>();

    const verifyTokenConfigured = spec.verifyTokenField
      ? cfg.fields.find((f) => f.key === spec.verifyTokenField)?.isSet ?? false
      : null;

    return {
      supported: spec.supported,
      note: spec.note ?? null,
      callbackUrl: sub ? this.callbackUrl(cfg.provider, sub.webhook_key) : null,
      subscriptionStatus: sub?.status ?? 'inactive',
      // These describe WHICH field plays which role; values are never returned.
      verifyTokenField: spec.verifyTokenField ?? null,
      verifyTokenConfigured,
      signingSecretField: spec.signingSecretField ?? null,
      lastEventAt: sub?.last_event_at ?? null,
      lastError: sub?.last_error ?? null,
      recentEvents: (events.results ?? []).map((e) => ({
        id: e.id,
        receivedAt: e.received_at,
        signatureValid: e.signature_valid === 1,
        status: e.status,
        error: e.error,
      })),
    };
  }

  // ------------------------------------------------------ provider-facing

  private async resolve(provider: string, key: string) {
    if (!isProviderId(provider) || !/^[A-Za-z0-9_-]{20,64}$/.test(key)) return null;
    const sub = await this.env.DB.prepare('SELECT * FROM webhook_subscriptions WHERE webhook_key = ?')
      .bind(key)
      .first<{ id: string; credential_config_id: string }>();
    if (!sub) return null;
    const row = await this.env.DB.prepare('SELECT provider, enabled FROM integration_credentials WHERE id = ?')
      .bind(sub.credential_config_id)
      .first<{ provider: string; enabled: number }>();
    // The key must belong to a configuration of the provider named in the URL.
    if (!row || row.provider !== provider) return null;
    return { sub, enabled: row.enabled === 1, provider: provider as ProviderId, configId: sub.credential_config_id };
  }

  private async note(configId: string, ok: boolean, error: string | null) {
    await this.env.DB.prepare(
      `UPDATE webhook_subscriptions
          SET last_error = ?, status = CASE WHEN ? = 1 THEN 'active' ELSE status END,
              last_event_at = CASE WHEN ? = 1 THEN datetime('now') ELSE last_event_at END
        WHERE credential_config_id = ?`,
    )
      .bind(ok ? null : error, ok ? 1 : 0, ok ? 1 : 0, configId)
      .run();
  }

  private async log(configId: string, provider: ProviderId, sigValid: boolean, status: string, error: string | null, body: string) {
    await this.env.DB.prepare(
      `INSERT INTO webhook_events (id, credential_config_id, provider, signature_valid, status, error, payload_hash)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    )
      .bind(crypto.randomUUID(), configId, provider, sigValid ? 1 : 0, status, error, await sha256Hex(body))
      .run();
  }

  /** GET: subscription handshake. Meta echoes a challenge; X answers a CRC. */
  async handleVerification(provider: string, key: string, query: URLSearchParams): Promise<WebhookResponse> {
    const r = await this.resolve(provider, key);
    if (!r) return text(404, 'Not found');
    if (!r.enabled) return text(403, 'Integration disabled');

    let app: DecryptedProviderCredentials | null;
    try {
      app = await this.creds.getInternal(r.configId, { requireEnabled: true });
    } catch {
      await this.note(r.configId, false, 'Stored credentials could not be decrypted.');
      return text(500, 'Configuration error');
    }
    if (!app) return text(403, 'Integration disabled');
    const spec = PROVIDERS[r.provider].webhook;

    if (spec.scheme === 'meta-sha256') {
      const token = app.credentials[spec.verifyTokenField!];
      if (!token) {
        await this.note(r.configId, false, 'Webhook verification token is not configured.');
        return text(403, 'Verification token not configured');
      }
      const supplied = query.get('hub.verify_token') ?? '';
      const okMode = query.get('hub.mode') === 'subscribe';
      if (!okMode || !timingSafeEqual(enc.encode(supplied), enc.encode(token))) {
        await this.note(r.configId, false, 'Webhook handshake failed: verification token mismatch.');
        return text(403, 'Verification failed');
      }
      await this.note(r.configId, true, null);
      return text(200, query.get('hub.challenge') ?? '');
    }

    if (spec.scheme === 'x-crc-sha256') {
      const crc = query.get('crc_token');
      const secret = app.credentials[spec.signingSecretField!];
      if (!crc || !secret) {
        await this.note(r.configId, false, 'CRC check failed: missing crc_token or API Key Secret.');
        return text(400, 'Bad request');
      }
      const sig = await hmacSha256(secret, crc);
      let bin = '';
      for (const b of sig) bin += String.fromCharCode(b);
      await this.note(r.configId, true, null);
      return { status: 200, contentType: 'application/json', body: JSON.stringify({ response_token: `sha256=${btoa(bin)}` }) };
    }
    return text(404, 'Not found');
  }

  /** POST: verify the signature with the provider-specific scheme, log, then enqueue. */
  async handleEvent(provider: string, key: string, rawBody: string, headers: Headers): Promise<WebhookResponse> {
    const r = await this.resolve(provider, key);
    if (!r) return text(404, 'Not found');
    if (rawBody.length > MAX_BODY_BYTES) {
      await this.log(r.configId, r.provider, false, 'rejected', 'Payload too large', '');
      return text(413, 'Payload too large');
    }
    if (!r.enabled) {
      await this.log(r.configId, r.provider, false, 'rejected', 'Integration disabled', rawBody);
      return text(403, 'Integration disabled');
    }

    let app: DecryptedProviderCredentials | null;
    try {
      app = await this.creds.getInternal(r.configId, { requireEnabled: true });
    } catch {
      await this.log(r.configId, r.provider, false, 'error', 'Stored credentials could not be decrypted', rawBody);
      await this.note(r.configId, false, 'Stored credentials could not be decrypted.');
      return text(500, 'Configuration error');
    }
    if (!app) return text(403, 'Integration disabled');

    const verdict = await this.verifySignature(r.provider, app, rawBody, headers);
    if (!verdict.ok) {
      await this.log(r.configId, r.provider, false, 'rejected', verdict.reason, rawBody);
      await this.note(r.configId, false, verdict.reason);
      return text(401, 'Invalid signature');
    }

    const msg: WebhookQueueMessage = {
      configId: r.configId,
      provider: r.provider,
      workspaceId: app.workspaceId,
      receivedAt: new Date().toISOString(),
      body: rawBody,
    };
    try {
      await this.env.WEBHOOK_QUEUE.send(msg);
    } catch {
      await this.log(r.configId, r.provider, true, 'error', 'Failed to enqueue event', rawBody);
      return text(503, 'Try again');
    }
    await this.log(r.configId, r.provider, true, 'accepted', null, rawBody);
    await this.note(r.configId, true, null);
    return text(200, 'OK');
  }

  private async verifySignature(
    provider: ProviderId,
    app: DecryptedProviderCredentials,
    body: string,
    headers: Headers,
  ): Promise<{ ok: true } | { ok: false; reason: string }> {
    const spec = PROVIDERS[provider].webhook;
    const secret = spec.signingSecretField ? app.credentials[spec.signingSecretField] : undefined;
    if (!secret) return { ok: false, reason: 'Signing secret is not configured for this integration.' };
    const header = headers.get(spec.signatureHeader ?? '') ?? '';
    const bad = { ok: false as const, reason: 'Signature verification failed.' };

    switch (spec.scheme) {
      case 'meta-sha256': {
        const supplied = header.startsWith('sha256=') ? hexToBytes(header.slice(7)) : null;
        if (!supplied) return bad;
        return timingSafeEqual(supplied, await hmacSha256(secret, body)) ? { ok: true } : bad;
      }
      case 'x-crc-sha256': {
        const supplied = header.startsWith('sha256=') ? base64ToBytes(header.slice(7)) : null;
        if (!supplied) return bad;
        return timingSafeEqual(supplied, await hmacSha256(secret, body)) ? { ok: true } : bad;
      }
      case 'tiktok-ts-sha256': {
        const parts = Object.fromEntries(header.split(',').map((p) => p.trim().split('=') as [string, string]));
        const ts = Number(parts.t);
        const supplied = parts.s ? hexToBytes(parts.s) : null;
        if (!supplied || !Number.isFinite(ts)) return bad;
        if (Math.abs(Date.now() / 1000 - ts) > TIKTOK_TOLERANCE_SEC) {
          return { ok: false, reason: 'Signature timestamp outside the allowed window.' };
        }
        return timingSafeEqual(supplied, await hmacSha256(secret, `${parts.t}.${body}`)) ? { ok: true } : bad;
      }
      default:
        return { ok: false, reason: 'Webhooks are not supported for this provider.' };
    }
  }
}

import { PROVIDERS, missingRequired, type ProviderCredentials } from './providers';
import type { ProviderId, ValidationStatus } from '../../types';

export interface ValidationResult {
  status: ValidationStatus;
  /** Safe to show in the UI and store in `last_error`. Never contains credential values. */
  message: string;
  checkedRemotely: boolean;
}

type Fetcher = (input: string, init?: RequestInit) => Promise<Response>;

/**
 * Best-effort live checks. Each probe asks the provider's token endpoint
 * something that is guaranteed to fail for business reasons (bad code) but
 * distinguishes "your app credentials are wrong" from "your app is fine".
 *
 * NOTE: provider error shapes change. These probes are written from the
 * providers' documented OAuth behaviour but are not guaranteed against live
 * APIs; a network failure or unrecognised response yields `unvalidated`
 * (inconclusive), never a false `valid`.
 */
export async function validateCredentials(
  provider: ProviderId,
  creds: ProviderCredentials,
  fetcher: Fetcher = fetch,
): Promise<ValidationResult> {
  const missing = missingRequired(provider, creds);
  if (missing.length) {
    const labels = PROVIDERS[provider].fields.filter((f) => missing.includes(f.key)).map((f) => f.label);
    return {
      status: 'incomplete',
      message: `Missing required fields: ${labels.join(', ')}`,
      checkedRemotely: false,
    };
  }

  try {
    switch (provider) {
      case 'meta':
        return await probeMeta(creds, fetcher);
      case 'tiktok':
        return await probeTikTok(creds, fetcher);
      case 'google':
        return await probeOAuthCode(
          PROVIDERS.google.oauth.tokenUrl,
          creds.client_id!,
          creds.client_secret!,
          'form-body',
          fetcher,
        );
      case 'linkedin':
        return await probeOAuthCode(
          PROVIDERS.linkedin.oauth.tokenUrl,
          creds.client_id!,
          creds.client_secret!,
          'form-body',
          fetcher,
        );
      case 'x':
        return await probeOAuthCode(
          PROVIDERS.x.oauth.tokenUrl,
          creds.client_id!,
          creds.client_secret!,
          'basic-auth',
          fetcher,
        );
    }
  } catch {
    return {
      status: 'unvalidated',
      message: 'Could not reach the provider to verify these credentials. Try again shortly.',
      checkedRemotely: false,
    };
  }
}

async function probeMeta(c: ProviderCredentials, f: Fetcher): Promise<ValidationResult> {
  const version = c.graph_api_version || 'v21.0';
  const url =
    `https://graph.facebook.com/${version}/oauth/access_token` +
    `?client_id=${encodeURIComponent(c.app_id!)}` +
    `&client_secret=${encodeURIComponent(c.app_secret!)}` +
    `&grant_type=client_credentials`;
  const res = await f(url, { method: 'GET' });
  const body = (await res.json().catch(() => ({}))) as { access_token?: string; error?: { message?: string } };
  if (res.ok && body.access_token) {
    return { status: 'valid', message: 'Meta accepted the App ID and App Secret.', checkedRemotely: true };
  }
  if (res.status === 400 || res.status === 401) {
    return {
      status: 'invalid',
      message: 'Meta rejected the App ID or App Secret. Check both values in the Meta developer dashboard.',
      checkedRemotely: true,
    };
  }
  return inconclusive();
}

async function probeTikTok(c: ProviderCredentials, f: Fetcher): Promise<ValidationResult> {
  const res = await f(PROVIDERS.tiktok.oauth.tokenUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_key: c.client_key!,
      client_secret: c.client_secret!,
      grant_type: 'client_credentials',
    }),
  });
  const body = (await res.json().catch(() => ({}))) as { access_token?: string; error?: string };
  if (res.ok && body.access_token) {
    return { status: 'valid', message: 'TikTok accepted the Client Key and Client Secret.', checkedRemotely: true };
  }
  if (body.error === 'invalid_client' || res.status === 401) {
    return {
      status: 'invalid',
      message: 'TikTok rejected the Client Key or Client Secret.',
      checkedRemotely: true,
    };
  }
  return inconclusive();
}

/**
 * Sends an authorization_code exchange with a deliberately bogus code.
 * - `invalid_client` / 401 => credentials wrong.
 * - `invalid_grant` (or similar code-specific error) => client authenticated, code was bad => credentials fine.
 */
async function probeOAuthCode(
  tokenUrl: string,
  clientId: string,
  clientSecret: string,
  mode: 'form-body' | 'basic-auth',
  f: Fetcher,
): Promise<ValidationResult> {
  const params = new URLSearchParams({
    grant_type: 'authorization_code',
    code: 'credential-validation-probe',
    redirect_uri: 'https://invalid.example/validate',
  });
  const headers: Record<string, string> = { 'content-type': 'application/x-www-form-urlencoded' };
  if (mode === 'basic-auth') {
    headers.authorization = `Basic ${btoa(`${clientId}:${clientSecret}`)}`;
    params.set('client_id', clientId);
    params.set('code_verifier', 'probe');
  } else {
    params.set('client_id', clientId);
    params.set('client_secret', clientSecret);
  }

  const res = await f(tokenUrl, { method: 'POST', headers, body: params });
  const body = (await res.json().catch(() => ({}))) as { error?: string };
  const err = (body.error ?? '').toLowerCase();

  if (err === 'invalid_client' || err === 'invalid_client_id' || res.status === 401) {
    return {
      status: 'invalid',
      message: 'The provider rejected the client ID or client secret.',
      checkedRemotely: true,
    };
  }
  if (err === 'invalid_grant' || err === 'invalid_request' || err === 'unauthorized_client') {
    return {
      status: 'valid',
      message: 'The provider authenticated the client credentials.',
      checkedRemotely: true,
    };
  }
  return inconclusive();
}

function inconclusive(): ValidationResult {
  return {
    status: 'unvalidated',
    message: 'The provider returned an unexpected response, so these credentials could not be confirmed.',
    checkedRemotely: true,
  };
}

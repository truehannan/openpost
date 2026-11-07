import type { ProviderId } from '../../types';

/**
 * Provider-specific credential schemas. Each provider declares exactly the
 * fields it needs; nothing is forced into a shared form.
 *
 * `secret: true`  -> stored encrypted, shown only as a mask after saving.
 * `secret: false` -> an identifier (App ID, Client ID). Still stored inside the
 *                    encrypted blob, but also mirrored to `public_config` so the
 *                    UI can show it without decrypting.
 */
export interface FieldSpec {
  key: string;
  label: string;
  secret: boolean;
  required: boolean;
  help?: string;
  /** Format check applied on save. Deliberately loose: providers change formats. */
  pattern?: RegExp;
  patternHint?: string;
  default?: string;
}

/**
 * How incoming webhooks are authenticated. Verification tokens and signing
 * secrets are different things and are modelled separately.
 */
export interface WebhookSpec {
  supported: boolean;
  /** Field holding a handshake/verification token echoed back during subscription. */
  verifyTokenField?: string;
  /** Field whose value is the HMAC key used to sign event payloads. */
  signingSecretField?: string;
  signatureHeader?: string;
  scheme?: 'meta-sha256' | 'x-crc-sha256' | 'tiktok-ts-sha256' | 'linkedin-sha256';
  note?: string;
}

export interface ProviderSpec {
  id: ProviderId;
  label: string;
  fields: FieldSpec[];
  /** Permissions/scopes the app needs approved in the provider's developer console. */
  requiredPermissions: string[];
  webhook: WebhookSpec;
  oauth: {
    authorizeUrl: string;
    tokenUrl: string;
    usesPkce: boolean;
    clientIdField: string;
    clientSecretField: string;
    defaultScopes: string[];
  };
}

const idPattern = /^[A-Za-z0-9._-]{3,200}$/;

export const PROVIDERS: Record<ProviderId, ProviderSpec> = {
  meta: {
    id: 'meta',
    label: 'Meta (Facebook / Instagram)',
    fields: [
      { key: 'app_id', label: 'App ID', secret: false, required: true, pattern: /^\d{5,25}$/, patternHint: 'Numeric App ID' },
      { key: 'app_secret', label: 'App Secret', secret: true, required: true, pattern: /^[A-Za-z0-9]{16,64}$/, patternHint: 'Alphanumeric App Secret' },
      { key: 'graph_api_version', label: 'Graph API version', secret: false, required: true, default: 'v21.0', pattern: /^v\d{1,2}\.\d$/, patternHint: 'For example v21.0' },
      { key: 'webhook_verify_token', label: 'Webhook verification token', secret: true, required: false, help: 'Any string you choose; Meta echoes it during webhook subscription. Not the signing secret.' },
      { key: 'config_id', label: 'Facebook Login for Business config ID', secret: false, required: false },
    ],
    requiredPermissions: [
      'pages_show_list',
      'pages_manage_posts',
      'pages_read_engagement',
      'pages_messaging',
      'instagram_basic',
      'instagram_content_publish',
      'instagram_manage_comments',
    ],
    webhook: {
      supported: true,
      verifyTokenField: 'webhook_verify_token',
      signingSecretField: 'app_secret', // X-Hub-Signature-256 is HMAC-SHA256 with the App Secret
      signatureHeader: 'x-hub-signature-256',
      scheme: 'meta-sha256',
      note: 'Verification token is used only for the GET handshake. POST payloads are signed with the App Secret.',
    },
    oauth: {
      authorizeUrl: 'https://www.facebook.com/{version}/dialog/oauth',
      tokenUrl: 'https://graph.facebook.com/{version}/oauth/access_token',
      usesPkce: false,
      clientIdField: 'app_id',
      clientSecretField: 'app_secret',
      defaultScopes: ['pages_show_list', 'pages_manage_posts', 'pages_read_engagement'],
    },
  },

  linkedin: {
    id: 'linkedin',
    label: 'LinkedIn',
    fields: [
      { key: 'client_id', label: 'Client ID', secret: false, required: true, pattern: idPattern },
      { key: 'client_secret', label: 'Client Secret', secret: true, required: true, pattern: /^[A-Za-z0-9=_-]{8,128}$/ },
    ],
    requiredPermissions: ['w_member_social', 'r_liteprofile / openid profile', 'w_organization_social (company pages)'],
    webhook: {
      supported: false,
      note: 'LinkedIn event delivery depends on the approved API products; enable only if your app has access.',
    },
    oauth: {
      authorizeUrl: 'https://www.linkedin.com/oauth/v2/authorization',
      tokenUrl: 'https://www.linkedin.com/oauth/v2/accessToken',
      usesPkce: false,
      clientIdField: 'client_id',
      clientSecretField: 'client_secret',
      defaultScopes: ['openid', 'profile', 'w_member_social'],
    },
  },

  x: {
    id: 'x',
    label: 'X',
    fields: [
      { key: 'client_id', label: 'OAuth 2.0 Client ID', secret: false, required: true, pattern: idPattern },
      { key: 'client_secret', label: 'OAuth 2.0 Client Secret', secret: true, required: true, pattern: /^[A-Za-z0-9_-]{16,128}$/ },
      { key: 'api_key', label: 'API Key (consumer key)', secret: false, required: false, help: 'Needed for Account Activity webhooks and OAuth 1.0a media upload.' },
      { key: 'api_key_secret', label: 'API Key Secret', secret: true, required: false, help: 'Signs Account Activity webhook payloads and CRC responses.' },
      { key: 'bearer_token', label: 'App Bearer Token', secret: true, required: false },
    ],
    requiredPermissions: ['tweet.read', 'tweet.write', 'users.read', 'offline.access'],
    webhook: {
      supported: true,
      signingSecretField: 'api_key_secret',
      signatureHeader: 'x-twitter-webhooks-signature',
      scheme: 'x-crc-sha256',
      note: 'X uses a CRC challenge (GET) and signs payloads with the API Key Secret. No separate verification token.',
    },
    oauth: {
      authorizeUrl: 'https://twitter.com/i/oauth2/authorize',
      tokenUrl: 'https://api.twitter.com/2/oauth2/token',
      usesPkce: true,
      clientIdField: 'client_id',
      clientSecretField: 'client_secret',
      defaultScopes: ['tweet.read', 'tweet.write', 'users.read', 'offline.access'],
    },
  },

  google: {
    id: 'google',
    label: 'YouTube / Google',
    fields: [
      { key: 'client_id', label: 'OAuth Client ID', secret: false, required: true, pattern: /^[\w.-]+\.apps\.googleusercontent\.com$/, patternHint: 'Ends with .apps.googleusercontent.com' },
      { key: 'client_secret', label: 'OAuth Client Secret', secret: true, required: true, pattern: /^[A-Za-z0-9_-]{16,128}$/ },
      { key: 'api_key', label: 'API Key (optional)', secret: true, required: false, help: 'For public YouTube Data API reads that do not need user consent.' },
      { key: 'project_id', label: 'Google Cloud project ID', secret: false, required: false },
    ],
    requiredPermissions: [
      'https://www.googleapis.com/auth/youtube.upload',
      'https://www.googleapis.com/auth/youtube.readonly',
    ],
    webhook: {
      supported: false,
      note: 'YouTube push notifications use WebSub with a per-subscription secret managed at subscription time.',
    },
    oauth: {
      authorizeUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
      tokenUrl: 'https://oauth2.googleapis.com/token',
      usesPkce: true,
      clientIdField: 'client_id',
      clientSecretField: 'client_secret',
      defaultScopes: [
        'https://www.googleapis.com/auth/youtube.upload',
        'https://www.googleapis.com/auth/youtube.readonly',
      ],
    },
  },

  tiktok: {
    id: 'tiktok',
    label: 'TikTok',
    fields: [
      { key: 'client_key', label: 'Client Key', secret: false, required: true, pattern: idPattern },
      { key: 'client_secret', label: 'Client Secret', secret: true, required: true, pattern: /^[A-Za-z0-9_-]{16,128}$/ },
    ],
    requiredPermissions: ['user.info.basic', 'video.publish', 'video.upload'],
    webhook: {
      supported: true,
      signingSecretField: 'client_secret',
      signatureHeader: 'tiktok-signature',
      scheme: 'tiktok-ts-sha256',
      note: 'Payloads are signed with the Client Secret using a timestamped HMAC. There is no separate verification token.',
    },
    oauth: {
      authorizeUrl: 'https://www.tiktok.com/v2/auth/authorize/',
      tokenUrl: 'https://open.tiktokapis.com/v2/oauth/token/',
      usesPkce: false, // web apps authenticate the code exchange with the client secret
      clientIdField: 'client_key',
      clientSecretField: 'client_secret',
      defaultScopes: ['user.info.basic', 'video.publish', 'video.upload'],
    },
  },
};

export const PROVIDER_IDS = Object.keys(PROVIDERS) as ProviderId[];

export function isProviderId(v: unknown): v is ProviderId {
  return typeof v === 'string' && v in PROVIDERS;
}

export function getProvider(id: string): ProviderSpec {
  if (!isProviderId(id)) throw new Error(`Unknown provider: ${id}`);
  return PROVIDERS[id];
}

export type ProviderCredentials = Record<string, string>;

export interface FieldError {
  field: string;
  message: string;
}

/**
 * Normalize and validate a credential object against its provider schema.
 * Unknown fields are rejected; defaults are applied; whitespace is trimmed.
 * `partial` allows omitting required fields and skips defaults (updates that merge
 * with existing values). `allowIncomplete` allows omitting required fields but still
 * applies defaults (saving a draft that shows as "Configuration incomplete").
 */
export function checkCredentials(
  provider: ProviderId,
  input: Record<string, unknown>,
  opts: { partial?: boolean; allowIncomplete?: boolean } = {},
): { values: ProviderCredentials; errors: FieldError[] } {
  const spec = PROVIDERS[provider];
  const known = new Map(spec.fields.map((f) => [f.key, f]));
  const errors: FieldError[] = [];
  const values: ProviderCredentials = {};

  for (const k of Object.keys(input)) {
    if (!known.has(k)) errors.push({ field: k, message: 'Unknown field for this provider' });
  }

  for (const f of spec.fields) {
    const raw = input[f.key];
    if (raw === undefined || raw === null || raw === '') {
      if (f.default !== undefined && !opts.partial) values[f.key] = f.default;
      else if (f.required && !opts.partial && !opts.allowIncomplete) errors.push({ field: f.key, message: `${f.label} is required` });
      continue;
    }
    if (typeof raw !== 'string') {
      errors.push({ field: f.key, message: `${f.label} must be a string` });
      continue;
    }
    const v = raw.trim();
    if (v.length > 2048) {
      errors.push({ field: f.key, message: `${f.label} is too long` });
      continue;
    }
    if (f.pattern && !f.pattern.test(v)) {
      errors.push({ field: f.key, message: `${f.label} looks invalid${f.patternHint ? `: ${f.patternHint}` : ''}` });
      continue;
    }
    values[f.key] = v;
  }
  return { values, errors };
}

/** Which required fields are still missing (drives "Configuration incomplete"). */
export function missingRequired(provider: ProviderId, values: ProviderCredentials): string[] {
  return PROVIDERS[provider].fields.filter((f) => f.required && !values[f.key]).map((f) => f.key);
}

/**
 * Envelope encryption for credentials and tokens.
 *
 * - SECRET_KEY is imported as HKDF input keying material, never used directly.
 * - Separate AES-256-GCM subkeys are derived per purpose via HKDF-SHA256.
 * - Every encryption uses a fresh random 96-bit IV.
 * - Context (AAD) binds a ciphertext to its row/purpose, so a valid blob
 *   copied to another row or purpose fails authentication.
 * - Envelope format is versioned and carries a key id, enabling rotation.
 *
 * Envelope string:  v<version>.<kid>.<iv b64url>.<ciphertext||tag b64url>
 * (WebCrypto AES-GCM appends the 128-bit auth tag to the ciphertext.)
 */

export const ENCRYPTION_VERSION = 1;

export type KeyPurpose =
  | 'credentials'      // provider app credentials
  | 'tokens'           // per-account access/refresh tokens
  | 'oauth-verifier'   // PKCE verifiers
  | 'session-signing'; // HMAC signing (derived separately, never shares keys)

const enc = new TextEncoder();
const dec = new TextDecoder();

export class CryptoError extends Error {
  constructor(
    public code:
      | 'KEY_MISSING'
      | 'KEY_WEAK'
      | 'MALFORMED'
      | 'UNSUPPORTED_VERSION'
      | 'UNKNOWN_KEY'
      | 'AUTH_FAILED',
    message: string,
  ) {
    super(message);
    this.name = 'CryptoError';
  }
}

// ---------- encoding helpers ----------

export function b64urlEncode(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function b64urlDecode(str: string): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9_-]*$/.test(str)) {
    throw new CryptoError('MALFORMED', 'Invalid base64url');
  }
  const pad = str.length % 4 === 0 ? '' : '='.repeat(4 - (str.length % 4));
  const bin = atob(str.replace(/-/g, '+').replace(/_/g, '/') + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function toHex(bytes: ArrayBuffer | Uint8Array): string {
  const u = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  return Array.from(u, (b) => b.toString(16).padStart(2, '0')).join('');
}

export async function sha256Hex(data: string | Uint8Array<ArrayBuffer>): Promise<string> {
  const buf = typeof data === 'string' ? enc.encode(data) : data;
  return toHex(await crypto.subtle.digest('SHA-256', buf));
}

/** Constant-time comparison for secrets, tokens and signatures. */
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

// ---------- SECRET_KEY handling ----------

/**
 * Accepts either a base64/base64url/hex string that decodes to >= 32 bytes,
 * or any string of >= 32 characters. Generate one with:
 *   openssl rand -base64 48
 */
function parseSecretKey(secret: string | undefined): Uint8Array<ArrayBuffer> {
  if (!secret) {
    throw new CryptoError(
      'KEY_MISSING',
      'SECRET_KEY is not configured. Run: npx wrangler secret put SECRET_KEY',
    );
  }
  const trimmed = secret.trim();
  if (trimmed.length < 32) {
    throw new CryptoError(
      'KEY_WEAK',
      'SECRET_KEY must be at least 32 characters. Generate one with: openssl rand -base64 48',
    );
  }
  // Reject trivially low-entropy values like "aaaa...".
  if (new Set(trimmed).size < 8) {
    throw new CryptoError('KEY_WEAK', 'SECRET_KEY has too little entropy.');
  }
  return enc.encode(trimmed);
}

const HKDF_SALT = enc.encode('social-platform/credential-vault/hkdf-salt/v1');

interface DerivedKey {
  kid: string;
  key: CryptoKey;
}

/** Derive an AES-256-GCM key for a purpose, plus a short non-secret key id. */
async function deriveKey(secret: string | undefined, purpose: KeyPurpose): Promise<DerivedKey> {
  const ikm = await crypto.subtle.importKey('raw', parseSecretKey(secret), 'HKDF', false, [
    'deriveKey',
    'deriveBits',
  ]);
  const info = enc.encode(`purpose:${purpose}:v${ENCRYPTION_VERSION}`);

  const key = await crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: HKDF_SALT, info },
    ikm,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );

  // Key id: derived from a separate HKDF label, so it reveals nothing about the key.
  const kidBits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: HKDF_SALT, info: enc.encode(`kid:${purpose}`) },
    ikm,
    48,
  );
  return { kid: toHex(kidBits), key };
}

/** HMAC-SHA256 signing key, derived separately from the encryption keys. */
export async function deriveSigningKey(secret: string | undefined): Promise<CryptoKey> {
  const ikm = await crypto.subtle.importKey('raw', parseSecretKey(secret), 'HKDF', false, [
    'deriveBits',
  ]);
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: HKDF_SALT,
      info: enc.encode(`purpose:session-signing:v${ENCRYPTION_VERSION}`),
    },
    ikm,
    256,
  );
  return crypto.subtle.importKey('raw', bits, { name: 'HMAC', hash: 'SHA-256' }, false, [
    'sign',
    'verify',
  ]);
}

// ---------- vault ----------

export interface VaultKeys {
  SECRET_KEY: string | undefined;
  SECRET_KEY_PREVIOUS?: string | undefined;
}

export class Vault {
  constructor(private keys: VaultKeys) {}

  /**
   * Encrypt a string. `context` is authenticated but not stored, so decrypt
   * must supply the identical value (e.g. `credentials:<row id>`).
   */
  async encrypt(plaintext: string, purpose: KeyPurpose, context: string): Promise<string> {
    const { kid, key } = await deriveKey(this.keys.SECRET_KEY, purpose);
    const iv = crypto.getRandomValues(new Uint8Array(12)); // 96-bit, per operation
    const ct = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: enc.encode(context), tagLength: 128 },
      key,
      enc.encode(plaintext),
    );
    return `v${ENCRYPTION_VERSION}.${kid}.${b64urlEncode(iv)}.${b64urlEncode(new Uint8Array(ct))}`;
  }

  async decrypt(envelope: string, purpose: KeyPurpose, context: string): Promise<string> {
    const parts = envelope.split('.');
    if (parts.length !== 4) throw new CryptoError('MALFORMED', 'Malformed ciphertext envelope');
    const [ver, kid, ivB64, ctB64] = parts as [string, string, string, string];

    if (ver !== `v${ENCRYPTION_VERSION}`) {
      throw new CryptoError('UNSUPPORTED_VERSION', `Unsupported encryption version: ${ver}`);
    }

    const iv = b64urlDecode(ivB64);
    if (iv.length !== 12) throw new CryptoError('MALFORMED', 'Invalid IV length');
    const ct = b64urlDecode(ctB64);
    if (ct.length < 16) throw new CryptoError('MALFORMED', 'Ciphertext too short');

    // Pick the key whose id matches; this makes rotation deterministic and
    // turns a wrong SECRET_KEY into a clear error instead of a generic failure.
    const candidates: Array<string | undefined> = [this.keys.SECRET_KEY, this.keys.SECRET_KEY_PREVIOUS];
    let chosen: DerivedKey | null = null;
    for (const secret of candidates) {
      if (!secret) continue;
      const d = await deriveKey(secret, purpose);
      if (d.kid === kid) {
        chosen = d;
        break;
      }
    }
    if (!chosen) {
      throw new CryptoError(
        'UNKNOWN_KEY',
        'Credentials were encrypted with a different SECRET_KEY than the one configured.',
      );
    }

    try {
      const pt = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv, additionalData: enc.encode(context), tagLength: 128 },
        chosen.key,
        ct,
      );
      return dec.decode(pt);
    } catch {
      // Deliberately generic: tamper, wrong context, or wrong purpose.
      throw new CryptoError('AUTH_FAILED', 'Ciphertext failed authentication');
    }
  }

  /** True when the envelope was written with a key other than the current SECRET_KEY. */
  async needsRotation(envelope: string, purpose: KeyPurpose): Promise<boolean> {
    const kid = envelope.split('.')[1];
    const current = await deriveKey(this.keys.SECRET_KEY, purpose);
    return kid !== current.kid;
  }
}

/** HMAC-SHA256 of `data` keyed by a secret string. Used for webhook signature checks. */
export async function hmacSha256(secret: string, data: string): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, enc.encode(data)));
}

export function hexToBytes(hex: string): Uint8Array | null {
  if (!/^([0-9a-fA-F]{2})+$/.test(hex)) return null;
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function base64ToBytes(b64: string): Uint8Array | null {
  try {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

/** Throws a CryptoError with an actionable message when SECRET_KEY is missing or weak. */
export function assertSecretKey(secret: string | undefined): void {
  parseSecretKey(secret);
}

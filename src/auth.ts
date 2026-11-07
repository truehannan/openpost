import { b64urlDecode, b64urlEncode, deriveSigningKey } from './lib/crypto';

/**
 * Minimal signed-session stand-in so the credential API is secure and testable
 * on its own. If the host platform already has authentication, replace
 * `resolveUserId` in the route layer with it; the services only need a userId.
 *
 * Tokens are signed with an HMAC key derived from SECRET_KEY under a
 * separate HKDF purpose, so they share no key material with the encryption keys.
 *
 * Format: base64url(JSON{u,e}) . base64url(HMAC-SHA256)
 */
const enc = new TextEncoder();
const dec = new TextDecoder();

export async function mintSession(secretKey: string, userId: string, ttlSeconds = 60 * 60 * 12): Promise<string> {
  const payload = b64urlEncode(enc.encode(JSON.stringify({ u: userId, e: Math.floor(Date.now() / 1000) + ttlSeconds })));
  const key = await deriveSigningKey(secretKey);
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, enc.encode(payload)));
  return `${payload}.${b64urlEncode(sig)}`;
}

export async function verifySession(secretKey: string, token: string | null | undefined): Promise<string | null> {
  if (!token) return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  try {
    const key = await deriveSigningKey(secretKey);
    // subtle.verify compares in constant time.
    const ok = await crypto.subtle.verify('HMAC', key, b64urlDecode(parts[1]!), enc.encode(parts[0]!));
    if (!ok) return null;
    const { u, e } = JSON.parse(dec.decode(b64urlDecode(parts[0]!))) as { u?: string; e?: number };
    if (typeof u !== 'string' || typeof e !== 'number' || e < Date.now() / 1000) return null;
    return u;
  } catch {
    return null;
  }
}

/** Reads `Authorization: Bearer <token>` or a `session` cookie. */
export function extractToken(req: Request): string | null {
  const h = req.headers.get('authorization');
  if (h?.toLowerCase().startsWith('bearer ')) return h.slice(7).trim();
  const cookie = req.headers.get('cookie');
  if (!cookie) return null;
  for (const part of cookie.split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === 'session') return v.join('=');
  }
  return null;
}

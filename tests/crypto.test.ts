import { describe, expect, it } from 'vitest';
import { CryptoError, Vault, b64urlDecode, b64urlEncode } from '../src/lib/crypto';

const KEY_A = 'k7Qp2xVn9sLw4TzRb8YdHf3JmUc6AeGo1NiXtKv0PqSa5ZyWh';
const KEY_B = 'Zr3Hn8WcJd5MbT1gLy9QfXe2UaKo7VpSi4NtAx6DvEq0YhCuB';

const vault = (secret = KEY_A, previous?: string) =>
  new Vault({ SECRET_KEY: secret, SECRET_KEY_PREVIOUS: previous });

describe('Vault', () => {
  it('round-trips and never leaves plaintext in the envelope', async () => {
    const v = vault();
    const env = await v.encrypt('super-secret-app-secret', 'credentials', 'ctx:1');
    expect(env.startsWith('v1.')).toBe(true);
    expect(env).not.toContain('super-secret');
    expect(await v.decrypt(env, 'credentials', 'ctx:1')).toBe('super-secret-app-secret');
  });

  it('uses a unique IV for every encryption', async () => {
    const v = vault();
    const ivs = new Set<string>();
    for (let i = 0; i < 50; i++) {
      const env = await v.encrypt('same', 'credentials', 'c');
      ivs.add(env.split('.')[2]!);
      expect(b64urlDecode(env.split('.')[2]!).length).toBe(12);
    }
    expect(ivs.size).toBe(50);
  });

  it('rejects tampered ciphertext', async () => {
    const v = vault();
    const env = await v.encrypt('secret', 'credentials', 'c');
    const parts = env.split('.');
    const ct = b64urlDecode(parts[3]!);
    ct[0] = ct[0]! ^ 0x01;
    parts[3] = b64urlEncode(ct);
    await expect(v.decrypt(parts.join('.'), 'credentials', 'c')).rejects.toMatchObject({
      code: 'AUTH_FAILED',
    });
  });

  it('rejects a swapped IV', async () => {
    const v = vault();
    const env = await v.encrypt('secret', 'credentials', 'c');
    const parts = env.split('.');
    parts[2] = b64urlEncode(crypto.getRandomValues(new Uint8Array(12)));
    await expect(v.decrypt(parts.join('.'), 'credentials', 'c')).rejects.toMatchObject({
      code: 'AUTH_FAILED',
    });
  });

  it('binds ciphertext to its context (row) and purpose', async () => {
    const v = vault();
    const env = await v.encrypt('secret', 'credentials', 'credentials:row-1');
    await expect(v.decrypt(env, 'credentials', 'credentials:row-2')).rejects.toMatchObject({
      code: 'AUTH_FAILED',
    });
    await expect(v.decrypt(env, 'tokens', 'credentials:row-1')).rejects.toBeInstanceOf(CryptoError);
  });

  it('fails safely with the wrong SECRET_KEY', async () => {
    const env = await vault(KEY_A).encrypt('secret', 'credentials', 'c');
    await expect(vault(KEY_B).decrypt(env, 'credentials', 'c')).rejects.toMatchObject({
      code: 'UNKNOWN_KEY',
    });
  });

  it('rejects malformed envelopes and unsupported versions', async () => {
    const v = vault();
    await expect(v.decrypt('garbage', 'credentials', 'c')).rejects.toMatchObject({ code: 'MALFORMED' });
    await expect(v.decrypt('v9.a.b.c', 'credentials', 'c')).rejects.toMatchObject({
      code: 'UNSUPPORTED_VERSION',
    });
  });

  it('refuses missing or weak SECRET_KEY with an actionable message', async () => {
    await expect(new Vault({ SECRET_KEY: undefined }).encrypt('x', 'credentials', 'c')).rejects.toMatchObject({
      code: 'KEY_MISSING',
    });
    await expect(vault('short').encrypt('x', 'credentials', 'c')).rejects.toMatchObject({ code: 'KEY_WEAK' });
    await expect(vault('a'.repeat(64)).encrypt('x', 'credentials', 'c')).rejects.toMatchObject({
      code: 'KEY_WEAK',
    });
  });

  it('supports rotation via SECRET_KEY_PREVIOUS and flags old envelopes', async () => {
    const old = await vault(KEY_A).encrypt('secret', 'credentials', 'c');
    const rotated = vault(KEY_B, KEY_A);
    expect(await rotated.decrypt(old, 'credentials', 'c')).toBe('secret');
    expect(await rotated.needsRotation(old, 'credentials')).toBe(true);
    const fresh = await rotated.encrypt('secret', 'credentials', 'c');
    expect(await rotated.needsRotation(fresh, 'credentials')).toBe(false);
  });
});

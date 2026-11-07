/**
 * Authenticated-encryption contexts (AES-GCM additional data). A ciphertext is
 * only decryptable with the exact context it was written with, so a blob copied
 * to another row, column or provider fails authentication.
 *
 * Phase 5 (OAuth/token storage) must use these helpers.
 */
export const credentialContext = (id: string, provider: string) => `credentials:${id}:${provider}`;
export const accountTokenContext = (accountId: string, kind: 'access' | 'refresh') =>
  `account-token:${accountId}:${kind}`;
export const oauthVerifierContext = (state: string) => `oauth-verifier:${state}`;

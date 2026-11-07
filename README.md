# Dashboard-managed API credentials

Social-platform provider credentials (Meta, LinkedIn, X, YouTube/Google, TikTok) are entered and managed in the
dashboard at **Settings → Integrations → API Credentials**, encrypted with AES-256-GCM, and stored in D1.
**`SECRET_KEY` is the only secret you configure in Cloudflare.** Nothing in `wrangler.jsonc`, `.env` or Worker
variables holds a provider credential, token or webhook secret.

## Setup

Requires Node 22.5+ (the test suite uses `node:sqlite`).

```bash
npm install
npx wrangler d1 create social-platform          # put the id in wrangler.jsonc -> d1_databases[0].database_id
npm run db:migrate:remote
openssl rand -base64 48 | npx wrangler secret put SECRET_KEY
# set APP_URL in wrangler.jsonc vars to your real origin, then:
npm run deploy
```

Then open `/settings/integrations`, add a provider configuration, and register the **OAuth redirect URI** shown on
each provider card (`<APP_URL>/oauth/callback/<provider>`) in that provider's developer console.

## Authentication (read this)

`src/auth.ts` is a minimal signed-session stand-in so this module is secure and testable on its own. If your platform
already authenticates users, replace the `verifySession` call in `src/app.ts` with yours; the services only need a
`userId`. Roles are **always re-read from the database**; no role or admin flag from the request is trusted.
The migration creates minimal `users`, `workspaces`, `workspace_members` tables; point them at your real ones.

## How it works

| Concern | Where |
|---|---|
| AES-256-GCM, HKDF subkeys per purpose, versioned envelope, key id | `src/lib/crypto.ts` |
| Per-provider field schemas, validation, webhook scheme per provider | `src/services/integration-credentials/providers.ts` |
| Masking, merge-on-update (blank = keep) | `.../mask.ts` |
| Live credential probes | `.../validate.ts` |
| CRUD, scope resolution, authz, audit, key rotation | `.../service.ts` |
| OAuth (state, PKCE, encrypted tokens, refresh, revoke) | `src/services/oauth.ts` |
| Webhooks (handshake, signature checks, logs, queue) | `src/services/webhooks.ts` |
| HTTP API + CSP-protected dashboard route | `src/app.ts`, `public/` |

**Resolution order** (`getForProvider`): this workspace's enabled configuration, then the enabled global one. Another
workspace's configuration is never considered. A configuration that cannot be decrypted raises an error; it never
falls through to the next scope.

**Connected accounts are pinned** to the configuration that authorised them (`social_accounts.credential_config_id`).
Adding or editing configurations does not re-point them. Changing the OAuth client ID of a configuration with live
connections is blocked unless explicitly confirmed, because their tokens were issued to the old app.

**Anything that calls a provider on behalf of an account must go through `OAuthService.getAccessToken(accountId)`.**
It resolves the pinned app, refuses if the integration is disabled, and refreshes near expiry. There is no publishing
module in this repository; that call is the gate it should use.

## Rotating SECRET_KEY

1. `wrangler secret put SECRET_KEY_PREVIOUS` with the **old** value, then `wrangler secret put SECRET_KEY` with the new one.
2. As the app owner, `POST /api/admin/rotate-encryption`. It re-encrypts app credentials and account tokens,
   keeps every id and link, and is safe to re-run.
3. Confirm the response shows `"failed": 0`, then `wrangler secret delete SECRET_KEY_PREVIOUS`.

Because the session-signing key is derived from `SECRET_KEY` (separately from the encryption keys), rotating it signs
everyone out when using the stand-in `auth.ts`. Hosts with their own auth are unaffected.
Losing `SECRET_KEY` without a previous copy makes stored credentials unrecoverable by design; users re-enter them.

## Webhooks

Each configuration gets an unguessable callback URL (`/webhooks/<provider>/<key>`); the key alone selects the
configuration. Meta's verification token (GET handshake) and the App Secret (POST signature) are separate fields.
X signs with the API Key Secret; TikTok with the Client Secret over `timestamp.body`. Verified events are queued on
`WEBHOOK_QUEUE` as `{configId, provider, workspaceId, receivedAt, body}`; you still need a queue consumer.

## Known limits

- Provider **probe and identity endpoints** (credential tests, "who is this account" calls, token refresh shapes) follow
  the providers' documented OAuth behaviour but were not run against live APIs. Verify each before launch.
- Webhook **subscription is manual**: paste the callback URL into the provider console. Status turns `active` after the
  first successful handshake or signed event. Automated subscription via provider APIs is not implemented.
- The dashboard was tested in jsdom against the real app and database, not in a real browser.
- Audit events are written but there is no read endpoint or screen for them. Webhook delivery logs are not pruned.
- Global (platform) configurations are usable by every workspace that lacks its own; there is no per-workspace policy.
- Only workspace owners/admins can connect or disconnect accounts.

## Tests

`npm test` (126 tests). `tests/security.test.ts` maps one `describe` per scenario in section 9 of the amendment.

import type { Env, ProviderId } from '../types';
import { Vault, b64urlEncode } from '../lib/crypto';
import {
  IntegrationCredentialService,
  PROVIDERS,
  ServiceError,
  accountTokenContext,
  oauthVerifierContext,
  isProviderId,
  type Actor,
  type DecryptedProviderCredentials,
} from './integration-credentials';

export type OAuthEnv = Pick<Env, 'DB' | 'SECRET_KEY' | 'SECRET_KEY_PREVIOUS' | 'APP_URL'>;
type Fetcher = (input: string, init?: RequestInit) => Promise<Response>;

const STATE_TTL_MS = 10 * 60 * 1000;
const REFRESH_SKEW_MS = 5 * 60 * 1000;
const enc = new TextEncoder();

interface TokenSet {
  access_token: string;
  refresh_token?: string;
  expires_in?: number;
  scope?: string;
}

export interface AccountView {
  id: string;
  provider: ProviderId;
  providerAccountId: string;
  displayName: string | null;
  status: 'active' | 'expired' | 'revoked' | 'error';
  tokenExpiresAt: string | null;
  lastError: string | null;
  credentialConfigId: string;
}

/**
 * Provider endpoints below follow each provider's documented OAuth 2.0 shape,
 * but they have not been exercised against the live APIs from this codebase.
 * Identity lookups in particular should be confirmed per provider before launch.
 */
export class OAuthService {
  private vault: Vault;
  private creds: IntegrationCredentialService;

  constructor(
    private env: OAuthEnv,
    private deps: { fetch?: Fetcher; credentials?: IntegrationCredentialService } = {},
  ) {
    this.vault = new Vault({ SECRET_KEY: env.SECRET_KEY, SECRET_KEY_PREVIOUS: env.SECRET_KEY_PREVIOUS });
    this.creds = deps.credentials ?? new IntegrationCredentialService(env, { fetch: deps.fetch });
  }

  private get f(): Fetcher {
    return this.deps.fetch ?? fetch;
  }

  redirectUri(provider: ProviderId): string {
    const base = (this.env.APP_URL ?? '').replace(/\/+$/, '');
    return `${base}/oauth/callback/${provider}`;
  }

  private async role(userId: string, workspaceId: string): Promise<string | null> {
    const r = await this.env.DB.prepare('SELECT role FROM workspace_members WHERE workspace_id = ? AND user_id = ?')
      .bind(workspaceId, userId)
      .first<{ role: string }>();
    return r?.role ?? null;
  }

  private async requireManager(userId: string, workspaceId: string) {
    const role = await this.role(userId, workspaceId);
    if (role !== 'owner' && role !== 'admin') {
      throw new ServiceError('FORBIDDEN', 'Only workspace owners and admins can connect or disconnect accounts.');
    }
  }

  // ------------------------------------------------------------------ start

  /** Steps 1-2: resolve the provider app, then start the flow. */
  async start(actor: Actor, workspaceId: string, provider: string, opts: { configId?: string } = {}) {
    if (!isProviderId(provider)) throw new ServiceError('VALIDATION', 'Unknown provider.');
    await this.requireManager(actor.userId, workspaceId);

    // Throws an actionable error when nothing is configured, or when it is disabled.
    const app = await this.creds.requireForProvider(provider, workspaceId, opts);
    const spec = PROVIDERS[provider];

    const state = b64urlEncode(crypto.getRandomValues(new Uint8Array(32)));
    let verifier: string | null = null;
    let challenge: string | null = null;
    if (spec.oauth.usesPkce) {
      verifier = b64urlEncode(crypto.getRandomValues(new Uint8Array(48)));
      challenge = b64urlEncode(new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(verifier))));
    }

    await this.env.DB.prepare(
      `INSERT INTO oauth_states (state, workspace_id, user_id, provider, credential_config_id, encrypted_code_verifier, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    )
      .bind(
        state,
        workspaceId,
        actor.userId,
        provider,
        app.configId,
        verifier ? await this.vault.encrypt(verifier, 'oauth-verifier', oauthVerifierContext(state)) : null,
        new Date(Date.now() + STATE_TTL_MS).toISOString(),
      )
      .run();

    return { authorizeUrl: this.buildAuthorizeUrl(provider, app, state, challenge), expiresInSeconds: STATE_TTL_MS / 1000 };
  }

  private buildAuthorizeUrl(provider: ProviderId, app: DecryptedProviderCredentials, state: string, challenge: string | null) {
    const spec = PROVIDERS[provider];
    const c = app.credentials;
    const base = spec.oauth.authorizeUrl.replace('{version}', c.graph_api_version ?? 'v21.0');
    const p = new URLSearchParams();
    const redirect = this.redirectUri(provider);
    const scopes = spec.oauth.defaultScopes;

    switch (provider) {
      case 'meta':
        p.set('client_id', c.app_id!);
        p.set('redirect_uri', redirect);
        p.set('state', state);
        p.set('response_type', 'code');
        p.set('scope', scopes.join(','));
        if (c.config_id) p.set('config_id', c.config_id);
        break;
      case 'tiktok':
        p.set('client_key', c.client_key!);
        p.set('response_type', 'code');
        p.set('scope', scopes.join(','));
        p.set('redirect_uri', redirect);
        p.set('state', state);
        break;
      case 'google':
        p.set('client_id', c.client_id!);
        p.set('redirect_uri', redirect);
        p.set('response_type', 'code');
        p.set('scope', scopes.join(' '));
        p.set('state', state);
        p.set('access_type', 'offline');
        p.set('prompt', 'consent');
        break;
      default: // linkedin, x
        p.set('response_type', 'code');
        p.set('client_id', c.client_id!);
        p.set('redirect_uri', redirect);
        p.set('scope', scopes.join(' '));
        p.set('state', state);
    }
    if (challenge) {
      p.set('code_challenge', challenge);
      p.set('code_challenge_method', 'S256');
    }
    return `${base}?${p.toString()}`;
  }

  // --------------------------------------------------------------- callback

  /** Steps 3-7: validate state (+PKCE), exchange the code, encrypt and store tokens. */
  async handleCallback(
    sessionUserId: string,
    provider: string,
    query: { code?: string | null; state?: string | null; error?: string | null },
  ): Promise<AccountView> {
    if (!isProviderId(provider)) throw new ServiceError('VALIDATION', 'Unknown provider.');
    if (!query.state) throw new ServiceError('VALIDATION', 'Missing OAuth state.');

    // Single use: consume the state before doing anything else, so replays fail.
    const st = await this.env.DB.prepare('SELECT * FROM oauth_states WHERE state = ?').bind(query.state).first<{
      state: string;
      workspace_id: string;
      user_id: string;
      provider: string;
      credential_config_id: string;
      encrypted_code_verifier: string | null;
      expires_at: string;
    }>();
    await this.env.DB.prepare('DELETE FROM oauth_states WHERE state = ?').bind(query.state).run();

    if (!st) throw new ServiceError('VALIDATION', 'This connection attempt is invalid or was already used. Start again.');
    if (Date.parse(st.expires_at) < Date.now()) throw new ServiceError('VALIDATION', 'This connection attempt expired. Start again.');
    if (st.provider !== provider) throw new ServiceError('VALIDATION', 'OAuth state does not match this provider.');
    if (st.user_id !== sessionUserId) throw new ServiceError('FORBIDDEN', 'This connection attempt belongs to a different user.');
    await this.requireManager(sessionUserId, st.workspace_id);

    if (query.error) throw new ServiceError('VALIDATION', `The provider declined the connection (${query.error}).`);
    if (!query.code) throw new ServiceError('VALIDATION', 'Missing authorization code.');

    // The app that STARTED the flow must still be enabled and must be the one used to finish it.
    const app = await this.creds.getInternal(st.credential_config_id, { requireEnabled: true });
    if (!app) {
      throw new ServiceError('CONFIG_DISABLED', 'The integration used for this connection was disabled or removed. Enable it and try again.');
    }

    const verifier = st.encrypted_code_verifier
      ? await this.vault.decrypt(st.encrypted_code_verifier, 'oauth-verifier', oauthVerifierContext(st.state))
      : undefined;

    const tokens = await this.tokenRequest(provider, app, {
      grant_type: 'authorization_code',
      code: query.code,
      redirect_uri: this.redirectUri(provider),
      ...(verifier ? { code_verifier: verifier } : {}),
    });
    const identity = await this.fetchIdentity(provider, app, tokens.access_token);
    return this.saveAccount(st.workspace_id, provider, app.configId, identity, tokens);
  }

  private async saveAccount(
    workspaceId: string,
    provider: ProviderId,
    configId: string,
    identity: { id: string; name: string | null },
    tokens: TokenSet,
  ): Promise<AccountView> {
    const existing = await this.env.DB.prepare(
      'SELECT id FROM social_accounts WHERE workspace_id = ? AND provider = ? AND provider_account_id = ?',
    )
      .bind(workspaceId, provider, identity.id)
      .first<{ id: string }>();
    const id = existing?.id ?? crypto.randomUUID();

    const access = await this.vault.encrypt(tokens.access_token, 'tokens', accountTokenContext(id, 'access'));
    const refresh = tokens.refresh_token
      ? await this.vault.encrypt(tokens.refresh_token, 'tokens', accountTokenContext(id, 'refresh'))
      : null;
    const expires = tokens.expires_in ? new Date(Date.now() + tokens.expires_in * 1000).toISOString() : null;

    if (existing) {
      await this.env.DB.prepare(
        `UPDATE social_accounts
            SET display_name = ?, credential_config_id = ?, encrypted_access_token = ?,
                encrypted_refresh_token = COALESCE(?, encrypted_refresh_token),
                token_expires_at = ?, scopes = ?, status = 'active', last_error = NULL, updated_at = datetime('now')
          WHERE id = ?`,
      )
        .bind(identity.name, configId, access, refresh, expires, tokens.scope ?? null, id)
        .run();
    } else {
      await this.env.DB.prepare(
        `INSERT INTO social_accounts
           (id, workspace_id, provider, provider_account_id, display_name, credential_config_id,
            encrypted_access_token, encrypted_refresh_token, token_expires_at, scopes)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
        .bind(id, workspaceId, provider, identity.id, identity.name, configId, access, refresh, expires, tokens.scope ?? null)
        .run();
    }
    return this.view(id);
  }

  // ----------------------------------------------------- provider HTTP calls

  private clientAuth(
    provider: ProviderId,
    app: DecryptedProviderCredentials,
  ): { headers?: Record<string, string>; body: Record<string, string> } {
    const c = app.credentials;
    switch (provider) {
      case 'meta':
        return { body: { client_id: c.app_id!, client_secret: c.app_secret! } };
      case 'tiktok':
        return { body: { client_key: c.client_key!, client_secret: c.client_secret! } };
      case 'x':
        return {
          headers: { authorization: `Basic ${btoa(`${c.client_id}:${c.client_secret}`)}` },
          body: { client_id: c.client_id! },
        };
      default:
        return { body: { client_id: c.client_id!, client_secret: c.client_secret! } };
    }
  }

  private async tokenRequest(
    provider: ProviderId,
    app: DecryptedProviderCredentials,
    params: Record<string, string>,
  ): Promise<TokenSet> {
    const auth = this.clientAuth(provider, app);
    const url = PROVIDERS[provider].oauth.tokenUrl.replace('{version}', app.credentials.graph_api_version ?? 'v21.0');
    const res = await this.f(url, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json', ...(auth.headers ?? {}) },
      body: new URLSearchParams({ ...params, ...auth.body }),
    });
    const body = (await res.json().catch(() => ({}))) as TokenSet & { error?: string | { message?: string; type?: string } };
    if (!res.ok || !body.access_token) {
      const code = typeof body.error === 'string' ? body.error : 'request_failed';
      const e = new ServiceError('VALIDATION', `The provider rejected the token request (${code}).`, { providerError: code, status: res.status });
      throw e;
    }
    return body;
  }

  private async fetchIdentity(provider: ProviderId, app: DecryptedProviderCredentials, accessToken: string) {
    const v = app.credentials.graph_api_version ?? 'v21.0';
    const urls: Record<ProviderId, string> = {
      meta: `https://graph.facebook.com/${v}/me?fields=id,name`,
      linkedin: 'https://api.linkedin.com/v2/userinfo',
      x: 'https://api.twitter.com/2/users/me',
      google: 'https://www.googleapis.com/youtube/v3/channels?part=snippet&mine=true',
      tiktok: 'https://open.tiktokapis.com/v2/user/info/?fields=open_id,display_name',
    };
    const res = await this.f(urls[provider], { headers: { authorization: `Bearer ${accessToken}` } });
    const j = (await res.json().catch(() => ({}))) as any;
    let id: string | undefined;
    let name: string | null = null;
    switch (provider) {
      case 'meta': id = j.id; name = j.name ?? null; break;
      case 'linkedin': id = j.sub; name = j.name ?? null; break;
      case 'x': id = j.data?.id; name = j.data?.username ?? null; break;
      case 'google': id = j.items?.[0]?.id; name = j.items?.[0]?.snippet?.title ?? null; break;
      case 'tiktok': id = j.data?.user?.open_id; name = j.data?.user?.display_name ?? null; break;
    }
    if (!res.ok || !id) {
      throw new ServiceError('VALIDATION', 'Connected, but the provider did not return an account identity. Check the app has the required permissions.');
    }
    return { id: String(id), name };
  }

  // ------------------------------------------------- use, refresh, revocation

  private async loadAccount(accountId: string) {
    const a = await this.env.DB.prepare('SELECT * FROM social_accounts WHERE id = ?').bind(accountId).first<{
      id: string;
      workspace_id: string;
      provider: ProviderId;
      encrypted_access_token: string;
      encrypted_refresh_token: string | null;
      token_expires_at: string | null;
      status: AccountView['status'];
      credential_config_id: string;
    }>();
    if (!a) throw new ServiceError('NOT_FOUND', 'Connected account not found.');
    return a;
  }

  /**
   * INTERNAL, backend only. Returns a usable access token, refreshing first when
   * it is near expiry. Always resolves the app via the account's pinned
   * configuration, and refuses if that integration is disabled.
   */
  async getAccessToken(accountId: string): Promise<string> {
    let a = await this.loadAccount(accountId);
    if (a.status === 'revoked') throw new ServiceError('VALIDATION', 'This account was disconnected or revoked. Reconnect it.');
    await this.creds.getForAccount(accountId); // enforces "disabled integrations cannot be used"

    const expMs = a.token_expires_at ? Date.parse(a.token_expires_at) : null;
    if (expMs !== null && expMs - Date.now() < REFRESH_SKEW_MS) {
      await this.refresh(accountId);
      a = await this.loadAccount(accountId);
    }
    return this.vault.decrypt(a.encrypted_access_token, 'tokens', accountTokenContext(a.id, 'access'));
  }

  /** Refresh where the provider supports it. Meta uses a long-lived-token exchange instead. */
  async refresh(accountId: string): Promise<AccountView> {
    const a = await this.loadAccount(accountId);
    const app = await this.creds.getForAccount(accountId);

    const fail = async (status: 'expired' | 'revoked' | 'error', msg: string): Promise<never> => {
      await this.env.DB.prepare("UPDATE social_accounts SET status = ?, last_error = ?, updated_at = datetime('now') WHERE id = ?")
        .bind(status, msg, accountId)
        .run();
      throw new ServiceError('VALIDATION', msg);
    };

    try {
      let tokens: TokenSet;
      if (a.provider === 'meta') {
        const current = await this.vault.decrypt(a.encrypted_access_token, 'tokens', accountTokenContext(a.id, 'access'));
        tokens = await this.tokenRequest('meta', app, { grant_type: 'fb_exchange_token', fb_exchange_token: current });
      } else {
        if (!a.encrypted_refresh_token) {
          return await fail('expired', 'The access token expired and this provider did not issue a refresh token. Reconnect the account.');
        }
        const rt = await this.vault.decrypt(a.encrypted_refresh_token, 'tokens', accountTokenContext(a.id, 'refresh'));
        tokens = await this.tokenRequest(a.provider, app, { grant_type: 'refresh_token', refresh_token: rt });
      }
      await this.saveAccountTokens(a.id, tokens);
      return this.view(a.id);
    } catch (e) {
      if (e instanceof ServiceError && e.code === 'VALIDATION' && (e.details as any)?.providerError) {
        const perr = (e.details as any).providerError as string;
        // invalid_grant / invalid_token: the user revoked access or the refresh token is dead.
        const permanent = ['invalid_grant', 'invalid_token', 'invalid_client'].includes(perr);
        return await fail(permanent ? 'revoked' : 'error', permanent ? 'Access was revoked or has expired. Reconnect the account.' : 'Token refresh failed. It will be retried.');
      }
      throw e;
    }
  }

  private async saveAccountTokens(accountId: string, tokens: TokenSet) {
    const access = await this.vault.encrypt(tokens.access_token, 'tokens', accountTokenContext(accountId, 'access'));
    const refresh = tokens.refresh_token
      ? await this.vault.encrypt(tokens.refresh_token, 'tokens', accountTokenContext(accountId, 'refresh'))
      : null;
    await this.env.DB.prepare(
      `UPDATE social_accounts
          SET encrypted_access_token = ?, encrypted_refresh_token = COALESCE(?, encrypted_refresh_token),
              token_expires_at = ?, status = 'active', last_error = NULL, updated_at = datetime('now')
        WHERE id = ?`,
    )
      .bind(access, refresh, tokens.expires_in ? new Date(Date.now() + tokens.expires_in * 1000).toISOString() : null, accountId)
      .run();
  }

  /** Removes the stored tokens by deleting the account row. */
  async disconnect(actor: Actor, accountId: string): Promise<void> {
    const a = await this.loadAccount(accountId);
    await this.requireManager(actor.userId, a.workspace_id);
    await this.env.DB.prepare('DELETE FROM social_accounts WHERE id = ?').bind(accountId).run();
  }

  // ------------------------------------------------------------------ views

  private async view(id: string): Promise<AccountView> {
    const r = await this.env.DB.prepare(
      `SELECT id, provider, provider_account_id, display_name, status, token_expires_at, last_error, credential_config_id
         FROM social_accounts WHERE id = ?`,
    )
      .bind(id)
      .first<any>();
    return {
      id: r.id,
      provider: r.provider,
      providerAccountId: r.provider_account_id,
      displayName: r.display_name,
      status: r.status,
      tokenExpiresAt: r.token_expires_at,
      lastError: r.last_error,
      credentialConfigId: r.credential_config_id,
    };
  }

  /** Token-free listing for the dashboard. */
  async listAccounts(actor: Actor, workspaceId: string): Promise<AccountView[]> {
    if (!(await this.role(actor.userId, workspaceId))) throw new ServiceError('FORBIDDEN', 'You are not a member of this workspace.');
    const rs = await this.env.DB.prepare(
      `SELECT id FROM social_accounts WHERE workspace_id = ? ORDER BY created_at`,
    )
      .bind(workspaceId)
      .all<{ id: string }>();
    return Promise.all((rs.results ?? []).map((r) => this.view(r.id)));
  }
}


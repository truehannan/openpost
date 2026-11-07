import type { Env, ProviderId, ValidationStatus } from '../../types';
import { Vault, ENCRYPTION_VERSION, CryptoError } from '../../lib/crypto';
import { PROVIDERS, checkCredentials, isProviderId, missingRequired, type ProviderCredentials } from './providers';
import { maskCredentials, mergeCredentials, publicFieldsOf, setSecretFieldNames, type MaskedField } from './mask';
import { validateCredentials, type ValidationResult } from './validate';
import { ServiceError } from './errors';
import { accountTokenContext, credentialContext } from './contexts';

export type ServiceEnv = Pick<Env, 'DB' | 'SECRET_KEY' | 'SECRET_KEY_PREVIOUS'>;
export type Scope = 'global' | 'workspace';

interface Row {
  id: string;
  workspace_id: string | null;
  provider: ProviderId;
  configuration_name: string;
  encrypted_credentials: string;
  encryption_version: number;
  public_config: string;
  enabled: number;
  validation_status: ValidationStatus;
  last_validated_at: string | null;
  last_error: string | null;
  created_by: string | null;
  created_at: string;
  updated_at: string;
}

/** What the API and dashboard may see. Never contains a secret value. */
export interface ConfigView {
  id: string;
  scope: Scope;
  workspaceId: string | null;
  provider: ProviderId;
  providerLabel: string;
  configurationName: string;
  enabled: boolean;
  validationStatus: ValidationStatus;
  statusLabel: 'Disabled' | 'Connected' | 'Configuration incomplete' | 'Invalid credentials' | 'Not yet tested';
  lastValidatedAt: string | null;
  lastError: string | null;
  fields: MaskedField[];
  requiredPermissions: string[];
  connectedAccountCount: number;
  createdAt: string;
  updatedAt: string;
}

/** Internal only. Decrypted values must never be serialised into an API response. */
export interface DecryptedProviderCredentials {
  configId: string;
  scope: Scope;
  workspaceId: string | null;
  provider: ProviderId;
  configurationName: string;
  credentials: ProviderCredentials;
}

export interface CreateCredentialInput {
  scope: Scope;
  workspaceId?: string;
  provider: ProviderId;
  configurationName: string;
  credentials: Record<string, unknown>;
  enabled?: boolean;
}

export interface UpdateCredentialInput {
  configurationName?: string;
  /** Omitted/empty fields keep their stored value; explicit null clears an optional field. */
  credentials?: Record<string, string | null | undefined>;
  /** Required to change the OAuth client identifier while accounts are connected. */
  allowClientIdChange?: boolean;
}

export interface Actor {
  /** Only userId is trusted. Roles are always re-read from the database. */
  userId: string;
}

type Fetcher = (input: string, init?: RequestInit) => Promise<Response>;

const PROVIDER_NAME_LABELS: Record<ProviderId, string> = {
  meta: 'Meta',
  linkedin: 'LinkedIn',
  x: 'X',
  google: 'YouTube / Google',
  tiktok: 'TikTok',
};

export class IntegrationCredentialService {
  private vault: Vault;

  constructor(
    private env: ServiceEnv,
    private deps: { fetch?: Fetcher } = {},
  ) {
    this.vault = new Vault({ SECRET_KEY: env.SECRET_KEY, SECRET_KEY_PREVIOUS: env.SECRET_KEY_PREVIOUS });
  }

  // ------------------------------------------------------------------ authz

  private async isAppOwner(userId: string): Promise<boolean> {
    const r = await this.env.DB.prepare('SELECT is_app_owner FROM users WHERE id = ?').bind(userId).first<{
      is_app_owner: number;
    }>();
    return r?.is_app_owner === 1;
  }

  private async workspaceRole(userId: string, workspaceId: string): Promise<string | null> {
    const r = await this.env.DB.prepare('SELECT role FROM workspace_members WHERE workspace_id = ? AND user_id = ?')
      .bind(workspaceId, userId)
      .first<{ role: string }>();
    return r?.role ?? null;
  }

  /**
   * Global configs: application owner only.
   * Workspace configs: that workspace's owner/admin only (app ownership grants nothing here).
   */
  private async authorize(actor: Actor, scope: Scope, workspaceId: string | null): Promise<void> {
    if (scope === 'global') {
      if (!(await this.isAppOwner(actor.userId))) {
        throw new ServiceError('FORBIDDEN', 'Only the application owner can manage global integrations.');
      }
      return;
    }
    if (!workspaceId) throw new ServiceError('VALIDATION', 'workspaceId is required for workspace-scoped integrations.');
    const role = await this.workspaceRole(actor.userId, workspaceId);
    if (role !== 'owner' && role !== 'admin') {
      throw new ServiceError('FORBIDDEN', 'Only workspace owners and admins can manage integration credentials.');
    }
  }

  private scopeOf(row: Row): Scope {
    return row.workspace_id ? 'workspace' : 'global';
  }

  private async loadRow(id: string): Promise<Row> {
    const row = await this.env.DB.prepare('SELECT * FROM integration_credentials WHERE id = ?').bind(id).first<Row>();
    if (!row) throw new ServiceError('NOT_FOUND', 'Integration configuration not found.');
    return row;
  }

  /** Load + authorize. Unauthorized callers get NOT_FOUND-equivalent FORBIDDEN, never row contents. */
  private async loadAuthorized(actor: Actor, id: string): Promise<Row> {
    const row = await this.loadRow(id);
    await this.authorize(actor, this.scopeOf(row), row.workspace_id);
    return row;
  }

  // -------------------------------------------------------------- crypto I/O

  private async decryptRow(row: Row): Promise<ProviderCredentials> {
    try {
      const json = await this.vault.decrypt(
        row.encrypted_credentials,
        'credentials',
        credentialContext(row.id, row.provider),
      );
      return JSON.parse(json) as ProviderCredentials;
    } catch (e) {
      if (e instanceof CryptoError) {
        throw new ServiceError(
          'DECRYPT_FAILED',
          e.code === 'UNKNOWN_KEY'
            ? 'Stored credentials were encrypted with a different SECRET_KEY than the one configured. Restore the original key (or set it as SECRET_KEY_PREVIOUS) and retry.'
            : 'Stored credentials failed integrity checks and cannot be used. Re-enter them in the dashboard.',
        );
      }
      throw e;
    }
  }

  private encryptFor(id: string, provider: ProviderId, creds: ProviderCredentials): Promise<string> {
    return this.vault.encrypt(JSON.stringify(creds), 'credentials', credentialContext(id, provider));
  }

  private publicConfigJson(provider: ProviderId, creds: ProviderCredentials): string {
    return JSON.stringify({
      fields: publicFieldsOf(provider, creds),
      secretsSet: setSecretFieldNames(provider, creds),
    });
  }

  // ------------------------------------------------------------------- audit

  private async audit(
    action: string,
    actorUserId: string | null,
    row: Pick<Row, 'id' | 'workspace_id'>,
    changedFields?: string[],
  ): Promise<void> {
    await this.env.DB.prepare(
      `INSERT INTO credential_audit_log (id, credential_config_id, workspace_id, actor_user_id, action, changed_fields)
       VALUES (?, ?, ?, ?, ?, ?)`,
    )
      .bind(
        crypto.randomUUID(),
        row.id,
        row.workspace_id,
        actorUserId,
        action,
        changedFields ? JSON.stringify(changedFields) : null,
      )
      .run();
  }

  // ------------------------------------------------------------------- views

  private statusLabel(row: Row): ConfigView['statusLabel'] {
    if (!row.enabled) return 'Disabled';
    switch (row.validation_status) {
      case 'valid':
        return 'Connected';
      case 'incomplete':
        return 'Configuration incomplete';
      case 'invalid':
        return 'Invalid credentials';
      default:
        return 'Not yet tested';
    }
  }

  /** Builds a masked view from non-secret metadata only; no decryption needed. */
  private async toView(row: Row): Promise<ConfigView> {
    const meta = JSON.parse(row.public_config || '{}') as { fields?: Record<string, string>; secretsSet?: string[] };
    const spec = PROVIDERS[row.provider];
    const fields = maskCredentials(row.provider, {
      ...(meta.fields ?? {}),
      // Placeholder values only to flip isSet; maskCredentials never returns them for secret fields.
      ...Object.fromEntries((meta.secretsSet ?? []).map((k) => [k, '1'])),
    });
    const count = await this.env.DB.prepare(
      "SELECT COUNT(*) AS n FROM social_accounts WHERE credential_config_id = ? AND status != 'revoked'",
    )
      .bind(row.id)
      .first<{ n: number }>();
    return {
      id: row.id,
      scope: this.scopeOf(row),
      workspaceId: row.workspace_id,
      provider: row.provider,
      providerLabel: spec.label,
      configurationName: row.configuration_name,
      enabled: row.enabled === 1,
      validationStatus: row.validation_status,
      statusLabel: this.statusLabel(row),
      lastValidatedAt: row.last_validated_at,
      lastError: row.last_error,
      fields,
      requiredPermissions: spec.requiredPermissions,
      connectedAccountCount: count?.n ?? 0,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }

  // ------------------------------------------------------------ public CRUD

  async list(actor: Actor, scope: Scope, workspaceId?: string): Promise<ConfigView[]> {
    await this.authorize(actor, scope, workspaceId ?? null);
    const rs =
      scope === 'global'
        ? await this.env.DB.prepare(
            'SELECT * FROM integration_credentials WHERE workspace_id IS NULL ORDER BY provider, created_at',
          ).all<Row>()
        : await this.env.DB.prepare(
            'SELECT * FROM integration_credentials WHERE workspace_id = ? ORDER BY provider, created_at',
          )
            .bind(workspaceId!)
            .all<Row>();
    return Promise.all((rs.results ?? []).map((r) => this.toView(r)));
  }

  async get(actor: Actor, id: string): Promise<ConfigView> {
    return this.toView(await this.loadAuthorized(actor, id));
  }

  async create(actor: Actor, input: CreateCredentialInput): Promise<ConfigView> {
    await this.authorize(actor, input.scope, input.workspaceId ?? null);
    if (!isProviderId(input.provider)) throw new ServiceError('VALIDATION', 'Unknown provider.');
    const name = (input.configurationName ?? '').trim();
    if (!name || name.length > 80) {
      throw new ServiceError('VALIDATION', 'Configuration name is required (max 80 characters).');
    }

    const { values, errors } = checkCredentials(input.provider, input.credentials, { allowIncomplete: true });
    if (errors.length) throw new ServiceError('VALIDATION', 'Some credential fields are invalid.', errors);

    const missing = missingRequired(input.provider, values);
    const id = crypto.randomUUID();
    const encrypted = await this.encryptFor(id, input.provider, values);
    const status: ValidationStatus = missing.length ? 'incomplete' : 'unvalidated';
    const wantsEnabled = input.enabled === true && !missing.length;

    try {
      await this.env.DB.prepare(
        `INSERT INTO integration_credentials
           (id, workspace_id, provider, configuration_name, encrypted_credentials, encryption_version,
            public_config, enabled, validation_status, created_by)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
        .bind(
          id,
          input.scope === 'workspace' ? input.workspaceId! : null,
          input.provider,
          name,
          encrypted,
          ENCRYPTION_VERSION,
          this.publicConfigJson(input.provider, values),
          wantsEnabled ? 1 : 0,
          status,
          actor.userId,
        )
        .run();
    } catch (e) {
      if (String(e).toLowerCase().includes('unique')) {
        throw new ServiceError('CONFLICT', `A ${PROVIDER_NAME_LABELS[input.provider]} configuration named "${name}" already exists here.`);
      }
      throw e;
    }

    const row = await this.loadRow(id);
    await this.audit('create', actor.userId, row, Object.keys(values));
    return this.toView(row);
  }

  async update(actor: Actor, id: string, input: UpdateCredentialInput): Promise<ConfigView> {
    const row = await this.loadAuthorized(actor, id);
    const spec = PROVIDERS[row.provider];
    const existing = await this.decryptRow(row);

    // Validate only the fields being changed, then merge with what is stored.
    const incoming = Object.fromEntries(
      Object.entries(input.credentials ?? {}).filter(([, v]) => v !== undefined && v !== null && v !== ''),
    );
    const { values: cleaned, errors } = checkCredentials(row.provider, incoming, { partial: true });
    if (errors.length) throw new ServiceError('VALIDATION', 'Some credential fields are invalid.', errors);

    const clears = Object.fromEntries(
      Object.entries(input.credentials ?? {}).filter(([k, v]) => v === null && spec.fields.some((f) => f.key === k && !f.required)),
    ) as Record<string, null>;

    const { merged, changed } = mergeCredentials(existing, { ...cleaned, ...clears });

    // Changing the OAuth client identifier invalidates tokens issued to existing connections.
    const idField = spec.oauth.clientIdField;
    if (changed.includes(idField) && !input.allowClientIdChange) {
      const n = await this.env.DB.prepare(
        "SELECT COUNT(*) AS n FROM social_accounts WHERE credential_config_id = ? AND status != 'revoked'",
      )
        .bind(row.id)
        .first<{ n: number }>();
      if ((n?.n ?? 0) > 0) {
        throw new ServiceError(
          'CLIENT_ID_CHANGE_BLOCKED',
          `Changing the ${spec.fields.find((f) => f.key === idField)?.label ?? 'client ID'} would break ${n!.n} connected account(s), because their tokens were issued to the current app. Create a new configuration instead, or confirm the change explicitly.`,
        );
      }
    }

    const name = input.configurationName !== undefined ? input.configurationName.trim() : row.configuration_name;
    if (!name || name.length > 80) throw new ServiceError('VALIDATION', 'Configuration name is required (max 80 characters).');
    const nameChanged = name !== row.configuration_name;

    if (!changed.length && !nameChanged) return this.toView(row); // nothing to do

    const missing = missingRequired(row.provider, merged);
    let status: ValidationStatus = row.validation_status;
    let enabled = row.enabled;
    if (changed.length) {
      status = missing.length ? 'incomplete' : 'unvalidated'; // credentials changed: previous validation no longer applies
      if (missing.length) enabled = 0;
    }

    const encrypted = changed.length ? await this.encryptFor(row.id, row.provider, merged) : row.encrypted_credentials;
    try {
      await this.env.DB.prepare(
        `UPDATE integration_credentials
            SET configuration_name = ?, encrypted_credentials = ?, encryption_version = ?, public_config = ?,
                enabled = ?, validation_status = ?, last_error = ?, updated_at = datetime('now')
          WHERE id = ?`,
      )
        .bind(
          name,
          encrypted,
          ENCRYPTION_VERSION,
          changed.length ? this.publicConfigJson(row.provider, merged) : row.public_config,
          enabled,
          status,
          changed.length ? null : row.last_error,
          row.id,
        )
        .run();
    } catch (e) {
      if (String(e).toLowerCase().includes('unique')) {
        throw new ServiceError('CONFLICT', `A configuration named "${name}" already exists here.`);
      }
      throw e;
    }

    const fresh = await this.loadRow(id);
    await this.audit('update', actor.userId, fresh, [...changed, ...(nameChanged ? ['configuration_name'] : [])]);
    return this.toView(fresh);
  }

  async setEnabled(actor: Actor, id: string, enabled: boolean): Promise<ConfigView> {
    const row = await this.loadAuthorized(actor, id);
    if (enabled && row.validation_status === 'incomplete') {
      throw new ServiceError('CONFIG_INCOMPLETE', 'Fill in all required fields before enabling this integration.');
    }
    await this.env.DB.prepare("UPDATE integration_credentials SET enabled = ?, updated_at = datetime('now') WHERE id = ?")
      .bind(enabled ? 1 : 0, id)
      .run();
    const fresh = await this.loadRow(id);
    await this.audit(enabled ? 'enable' : 'disable', actor.userId, fresh);
    return this.toView(fresh);
  }

  /**
   * Requires the caller to retype the configuration name. Refuses while social
   * accounts still reference the configuration, so connections are never orphaned.
   */
  async delete(actor: Actor, id: string, opts: { confirmName: string }): Promise<void> {
    const row = await this.loadAuthorized(actor, id);
    if ((opts?.confirmName ?? '') !== row.configuration_name) {
      throw new ServiceError('VALIDATION', 'Type the configuration name exactly to confirm deletion.');
    }
    const n = await this.env.DB.prepare('SELECT COUNT(*) AS n FROM social_accounts WHERE credential_config_id = ?')
      .bind(id)
      .first<{ n: number }>();
    if ((n?.n ?? 0) > 0) {
      throw new ServiceError(
        'CONFIG_IN_USE',
        `${n!.n} connected account(s) still use this configuration. Disconnect them first, or disable the integration instead.`,
      );
    }
    await this.env.DB.prepare('DELETE FROM integration_credentials WHERE id = ?').bind(id).run();
    await this.audit('delete', actor.userId, row);
  }

  // -------------------------------------------------------------- validation

  /** Pure check of a credential set (spec's `validate`). Does not touch storage. */
  async validate(provider: string, credentials: ProviderCredentials): Promise<ValidationResult> {
    if (!isProviderId(provider)) throw new ServiceError('VALIDATION', 'Unknown provider.');
    return validateCredentials(provider, credentials, this.deps.fetch);
  }

  /** Test a saved configuration and record the outcome. Decryption stays server-side. */
  async testStored(actor: Actor, id: string): Promise<ConfigView> {
    const row = await this.loadAuthorized(actor, id);
    const creds = await this.decryptRow(row);
    const result = await validateCredentials(row.provider, creds, this.deps.fetch);
    const stamp = result.status === 'valid' ? "datetime('now')" : 'last_validated_at';
    await this.env.DB.prepare(
      `UPDATE integration_credentials
          SET validation_status = ?, last_error = ?, last_validated_at = ${stamp}, updated_at = datetime('now')
        WHERE id = ?`,
    )
      .bind(result.status, result.status === 'valid' ? null : result.message, id)
      .run();
    const fresh = await this.loadRow(id);
    await this.audit('validate', actor.userId, fresh);
    return this.toView(fresh);
  }

  // ------------------------------------------------- internal retrieval only

  /**
   * Resolution order:
   *   1. An enabled configuration owned by THIS workspace.
   *   2. An enabled global (application-level) configuration.
   * Another workspace's configuration is never considered. A configuration that
   * exists but cannot be decrypted raises an error rather than silently falling
   * through to the next scope.
   *
   * INTERNAL: returns decrypted secrets. Never serialise the result.
   */
  async getForProvider(
    provider: string,
    workspaceId?: string,
    opts: { configId?: string } = {},
  ): Promise<DecryptedProviderCredentials | null> {
    if (!isProviderId(provider)) throw new ServiceError('VALIDATION', 'Unknown provider.');

    const pick = async (ws: string | null): Promise<Row | null> => {
      const clauses = ws
        ? 'workspace_id = ?'
        : 'workspace_id IS NULL';
      const params: unknown[] = ws ? [provider, ws] : [provider];
      let sql = `SELECT * FROM integration_credentials WHERE provider = ? AND ${clauses} AND enabled = 1`;
      if (opts.configId) {
        sql += ' AND id = ?';
        params.push(opts.configId);
      }
      sql += " ORDER BY CASE validation_status WHEN 'valid' THEN 0 ELSE 1 END, created_at LIMIT 1";
      return this.env.DB.prepare(sql).bind(...params).first<Row>();
    };

    let row: Row | null = null;
    if (workspaceId) row = await pick(workspaceId);
    if (!row) row = await pick(null);
    if (!row) return null;

    return {
      configId: row.id,
      scope: this.scopeOf(row),
      workspaceId: row.workspace_id,
      provider: row.provider,
      configurationName: row.configuration_name,
      credentials: await this.decryptRow(row),
    };
  }

  /** Like getForProvider but throws an actionable error when nothing usable exists. */
  async requireForProvider(
    provider: string,
    workspaceId?: string,
    opts: { configId?: string } = {},
  ): Promise<DecryptedProviderCredentials> {
    const found = await this.getForProvider(provider, workspaceId, opts);
    if (found) return found;

    const label = isProviderId(provider) ? PROVIDER_NAME_LABELS[provider] : provider;
    const disabled = isProviderId(provider)
      ? await this.env.DB.prepare(
          'SELECT 1 AS x FROM integration_credentials WHERE provider = ? AND enabled = 0 AND (workspace_id IS NULL OR workspace_id = ?) LIMIT 1',
        )
          .bind(provider, workspaceId ?? '')
          .first()
      : null;
    if (disabled) {
      throw new ServiceError(
        'CONFIG_DISABLED',
        `The ${label} integration is disabled. Enable it in Settings → Integrations → API Credentials → ${label}.`,
      );
    }
    throw new ServiceError(
      'CONFIG_MISSING',
      `No ${label} integration is configured. Add your ${label} API credentials in Settings → Integrations → API Credentials → ${label}${workspaceId ? ', or ask the application owner to enable a shared one' : ''}.`,
    );
  }

  /**
   * Credentials for the app that authorised an existing connected account.
   * Used for token refresh and publishing, so editing or adding configurations
   * never re-points an existing connection. Refuses disabled configurations.
   */
  async getForAccount(accountId: string): Promise<DecryptedProviderCredentials> {
    const acct = await this.env.DB.prepare(
      'SELECT workspace_id, credential_config_id FROM social_accounts WHERE id = ?',
    )
      .bind(accountId)
      .first<{ workspace_id: string; credential_config_id: string }>();
    if (!acct) throw new ServiceError('NOT_FOUND', 'Connected account not found.');

    const row = await this.loadRow(acct.credential_config_id);
    // A workspace account may only use its own workspace's config or a global one.
    if (row.workspace_id && row.workspace_id !== acct.workspace_id) {
      throw new ServiceError('FORBIDDEN', 'This account references a configuration it is not allowed to use.');
    }
    if (!row.enabled) {
      const label = PROVIDER_NAME_LABELS[row.provider];
      throw new ServiceError(
        'CONFIG_DISABLED',
        `The ${label} integration used by this account is disabled. Enable it in Settings → Integrations → API Credentials → ${label}.`,
      );
    }
    return {
      configId: row.id,
      scope: this.scopeOf(row),
      workspaceId: row.workspace_id,
      provider: row.provider,
      configurationName: row.configuration_name,
      credentials: await this.decryptRow(row),
    };
  }

  /**
   * Credentials for a specific configuration, by id (webhook verification,
   * OAuth callback). Returns null when missing, or disabled if requireEnabled.
   * INTERNAL: returns decrypted secrets. Never serialise the result.
   */
  async getInternal(
    configId: string,
    opts: { requireEnabled?: boolean } = {},
  ): Promise<DecryptedProviderCredentials | null> {
    const row = await this.env.DB.prepare('SELECT * FROM integration_credentials WHERE id = ?')
      .bind(configId)
      .first<Row>();
    if (!row) return null;
    if (opts.requireEnabled && !row.enabled) return null;
    return {
      configId: row.id,
      scope: this.scopeOf(row),
      workspaceId: row.workspace_id,
      provider: row.provider,
      configurationName: row.configuration_name,
      credentials: await this.decryptRow(row),
    };
  }

  // ---------------------------------------------------------------- rotation

  /**
   * Re-encrypt everything with the current SECRET_KEY. Run after setting
   * SECRET_KEY to the new value and SECRET_KEY_PREVIOUS to the old one.
   * IDs and relationships are untouched, so connected accounts keep working.
   * Rows are rewritten one at a time and only after a successful decrypt, so
   * an interrupted run is safe to repeat.
   */
  async rotateEncryption(actor: Actor): Promise<{ credentials: number; tokens: number; failed: number }> {
    await this.authorize(actor, 'global', null);
    let credentials = 0;
    let tokens = 0;
    let failed = 0;

    const creds = await this.env.DB.prepare('SELECT * FROM integration_credentials').all<Row>();
    for (const row of creds.results ?? []) {
      try {
        if (!(await this.vault.needsRotation(row.encrypted_credentials, 'credentials'))) continue;
        const plain = await this.decryptRow(row);
        await this.env.DB.prepare(
          "UPDATE integration_credentials SET encrypted_credentials = ?, encryption_version = ?, updated_at = datetime('now') WHERE id = ?",
        )
          .bind(await this.encryptFor(row.id, row.provider, plain), ENCRYPTION_VERSION, row.id)
          .run();
        await this.audit('rotate', actor.userId, row);
        credentials++;
      } catch {
        failed++;
      }
    }

    const accts = await this.env.DB.prepare(
      'SELECT id, encrypted_access_token, encrypted_refresh_token FROM social_accounts',
    ).all<{ id: string; encrypted_access_token: string; encrypted_refresh_token: string | null }>();
    for (const a of accts.results ?? []) {
      try {
        const reEnc = async (blob: string | null, kind: 'access' | 'refresh') => {
          if (!blob || !(await this.vault.needsRotation(blob, 'tokens'))) return blob;
          const ctx = accountTokenContext(a.id, kind);
          const plain = await this.vault.decrypt(blob, 'tokens', ctx);
          tokens++;
          return this.vault.encrypt(plain, 'tokens', ctx);
        };
        const access = await reEnc(a.encrypted_access_token, 'access');
        const refresh = await reEnc(a.encrypted_refresh_token, 'refresh');
        await this.env.DB.prepare(
          'UPDATE social_accounts SET encrypted_access_token = ?, encrypted_refresh_token = ? WHERE id = ?',
        )
          .bind(access, refresh, a.id)
          .run();
      } catch {
        failed++;
      }
    }
    return { credentials, tokens, failed };
  }

  // --------------------------------------------------- non-sensitive summary

  /**
   * For any workspace member: which provider apps are usable for this
   * workspace, and from which scope. Reveals no configuration details.
   */
  async availability(
    actor: Actor,
    workspaceId: string,
  ): Promise<Record<ProviderId, 'workspace' | 'global' | 'none'>> {
    if (!(await this.workspaceRole(actor.userId, workspaceId))) {
      throw new ServiceError('FORBIDDEN', 'You are not a member of this workspace.');
    }
    const out = {} as Record<ProviderId, 'workspace' | 'global' | 'none'>;
    for (const p of Object.keys(PROVIDERS) as ProviderId[]) {
      const ws = await this.env.DB.prepare(
        'SELECT 1 AS x FROM integration_credentials WHERE provider = ? AND workspace_id = ? AND enabled = 1 LIMIT 1',
      )
        .bind(p, workspaceId)
        .first();
      if (ws) {
        out[p] = 'workspace';
        continue;
      }
      const gl = await this.env.DB.prepare(
        'SELECT 1 AS x FROM integration_credentials WHERE provider = ? AND workspace_id IS NULL AND enabled = 1 LIMIT 1',
      )
        .bind(p)
        .first();
      out[p] = gl ? 'global' : 'none';
    }
    return out;
  }
}

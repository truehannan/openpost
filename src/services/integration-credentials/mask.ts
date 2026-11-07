import { PROVIDERS, type ProviderCredentials } from './providers';
import type { ProviderId } from '../../types';

export interface MaskedField {
  key: string;
  label: string;
  secret: boolean;
  /** Plain value for identifiers, fixed-length bullets for secrets, null when unset. */
  display: string | null;
  isSet: boolean;
}

/**
 * Secrets are masked with a FIXED-length string so the mask leaks neither the
 * secret's length nor any of its characters.
 */
const SECRET_MASK = '••••••••••••••••';

export function maskCredentials(provider: ProviderId, values: ProviderCredentials): MaskedField[] {
  return PROVIDERS[provider].fields.map((f) => {
    const v = values[f.key];
    const isSet = typeof v === 'string' && v.length > 0;
    return {
      key: f.key,
      label: f.label,
      secret: f.secret,
      display: !isSet ? null : f.secret ? SECRET_MASK : v!,
      isSet,
    };
  });
}

/** Non-secret identifiers only; this is what gets mirrored into `public_config`. */
export function publicFieldsOf(provider: ProviderId, values: ProviderCredentials): Record<string, string> {
  const out: Record<string, string> = {};
  for (const f of PROVIDERS[provider].fields) {
    if (!f.secret && values[f.key]) out[f.key] = values[f.key]!;
  }
  return out;
}

/** Which secret fields are set, by name only. Safe for the API and the audit log. */
export function setSecretFieldNames(provider: ProviderId, values: ProviderCredentials): string[] {
  return PROVIDERS[provider].fields.filter((f) => f.secret && values[f.key]).map((f) => f.key);
}

/**
 * Merge an update into existing credentials. Omitted or empty fields keep their
 * stored value (so the UI can leave masked inputs blank). An explicit `null`
 * clears an optional field.
 */
export function mergeCredentials(
  existing: ProviderCredentials,
  update: Record<string, string | null | undefined>,
): { merged: ProviderCredentials; changed: string[] } {
  const merged: ProviderCredentials = { ...existing };
  const changed: string[] = [];
  for (const [k, v] of Object.entries(update)) {
    if (v === undefined || v === '') continue;
    if (v === null) {
      if (k in merged) {
        delete merged[k];
        changed.push(k);
      }
      continue;
    }
    if (merged[k] !== v) {
      merged[k] = v;
      changed.push(k);
    }
  }
  return { merged, changed };
}

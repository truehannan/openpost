export interface Env {
  // The ONLY mandatory secret. Set via `wrangler secret put SECRET_KEY`.
  SECRET_KEY: string;

  // Only set temporarily while rotating SECRET_KEY, so existing ciphertext
  // stays readable until it has been re-encrypted. Remove afterwards.
  SECRET_KEY_PREVIOUS?: string;

  // Non-sensitive runtime configuration.
  APP_ENV?: string;
  APP_URL?: string;

  // Infrastructure bindings.
  DB: D1Database;
  MEDIA: R2Bucket;
  PUBLISH_QUEUE: Queue;
  AUTOMATION_QUEUE: Queue;
  WEBHOOK_QUEUE: Queue;
  NOTIFICATION_QUEUE: Queue;
  REALTIME?: DurableObjectNamespace;

  // Static dashboard files (public/). Not a secret; a Workers Assets binding.
  ASSETS?: Fetcher;
}

export type ProviderId = 'meta' | 'linkedin' | 'x' | 'google' | 'tiktok';

export type ValidationStatus = 'unvalidated' | 'incomplete' | 'valid' | 'invalid';

/** Authenticated caller, populated by the app's auth layer. */
export interface Actor {
  userId: string;
  isAppOwner: boolean;
  /** Role in the workspace being acted on, if any. */
  workspaceRole?: 'owner' | 'admin' | 'member';
}

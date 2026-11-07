export type ServiceErrorCode =
  | 'FORBIDDEN'
  | 'NOT_FOUND'
  | 'VALIDATION'
  | 'CONFLICT'
  | 'CONFIG_MISSING'
  | 'CONFIG_DISABLED'
  | 'CONFIG_INCOMPLETE'
  | 'CONFIG_IN_USE'
  | 'CLIENT_ID_CHANGE_BLOCKED'
  | 'DECRYPT_FAILED';

const STATUS: Record<ServiceErrorCode, number> = {
  FORBIDDEN: 403,
  NOT_FOUND: 404,
  VALIDATION: 422,
  CONFLICT: 409,
  CONFIG_MISSING: 424,
  CONFIG_DISABLED: 424,
  CONFIG_INCOMPLETE: 424,
  CONFIG_IN_USE: 409,
  CLIENT_ID_CHANGE_BLOCKED: 409,
  DECRYPT_FAILED: 500,
};

/** Error messages are user-safe: they never contain credential values. */
export class ServiceError extends Error {
  readonly status: number;
  constructor(
    public readonly code: ServiceErrorCode,
    message: string,
    public readonly details?: unknown,
  ) {
    super(message);
    this.name = 'ServiceError';
    this.status = STATUS[code];
  }
}

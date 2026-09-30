export class AuditValidationError extends Error {
  override readonly name = "AuditValidationError";
  constructor(
    message: string,
    readonly details: unknown = undefined,
  ) {
    super(message);
  }
}

/** Same client-supplied `id` was appended before with different content. */
export class AuditConflictError extends Error {
  override readonly name = "AuditConflictError";
}

/** Append could not be completed (for example the chain-race retry budget was exhausted). Nothing was acknowledged. */
export class AuditAppendError extends Error {
  override readonly name = "AuditAppendError";
}

export class AuditExportError extends Error {
  override readonly name = "AuditExportError";
}

export class WormOverwriteError extends Error {
  override readonly name = "WormOverwriteError";
}

export class WormNotFoundError extends Error {
  override readonly name = "WormNotFoundError";
}

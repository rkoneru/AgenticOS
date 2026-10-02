/** Process exit codes of `axis` (documented in docs/spec/cli.md). */
export const EXIT = {
  OK: 0,
  /** Any other failure: API error, validation failure, network, feature not yet available. */
  ERROR: 1,
  /** Bad command line. */
  USAGE: 2,
  /** Missing, invalid or insufficient credentials (401/403 forbidden, unreadable config). */
  AUTH: 3,
  /** The policy gate denied the request. */
  POLICY_DENIED: 4,
  /** A human approval is pending, or a wait timed out. */
  APPROVAL_PENDING: 5,
} as const;

export type ExitCode = (typeof EXIT)[keyof typeof EXIT];

/** A failure the CLI reports as one clean line (plus hints), with an exit code. */
export class CliError extends Error {
  constructor(
    message: string,
    readonly exitCode: ExitCode = EXIT.ERROR,
    readonly hints: readonly string[] = [],
  ) {
    super(message);
    this.name = "CliError";
  }
}

export class UsageError extends CliError {
  constructor(message: string, hints: readonly string[] = []) {
    super(message, EXIT.USAGE, hints);
    this.name = "UsageError";
  }
}

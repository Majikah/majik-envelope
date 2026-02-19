/* -------------------------------
 * Error Types
 * ------------------------------- */

export class MajikEnvelopeError extends Error {
  constructor(
    message: string,
    public readonly cause?: unknown,
  ) {
    super(message);
    this.name = "MajikEnvelopeError";
  }
}

export type EnvelopeErrorCode =
  | "INVALID_INPUT"
  | "FORMAT_ERROR"
  | "VALIDATION_ERROR";

export class MessageEnvelopeError extends Error {
  readonly code: EnvelopeErrorCode;
  readonly raw?: string;

  constructor(code: EnvelopeErrorCode, message: string, raw?: string) {
    super(message);
    this.name = "MessageEnvelopeError";
    this.code = code;
    this.raw = raw;
  }
}

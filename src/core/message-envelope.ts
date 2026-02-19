/**
 * MessageEnvelope.ts
 *
 * LEGACY binary envelope parser.
 *
 * This class is now a thin wrapper around raw binary envelope blobs.
 * It extracts version bytes, fingerprints, and JSON payloads but does NOT
 * perform encryption or decryption — that's MajikEnvelope's job.
 *
 * Kept for backward compatibility with existing scanner infrastructure.
 * New code should use MajikEnvelope directly.
 */

import { MessageEnvelopeError } from "./error";
import type { EnvelopePayload, SinglePayload, GroupKey } from "./types";
import { base64ToArrayBuffer, arrayBufferToBase64 } from "./utils";

/* -------------------------------
 * Constants
 * ------------------------------- */

const ENVELOPE_PREFIX = "~*$MJKMSG";
const ENVELOPE_REGEX = /^~\*\$MJKMSG:([A-Za-z0-9+/=]+)$/;

const MAX_ENVELOPE_LENGTH = 16_384; // raw string
const MAX_PAYLOAD_BYTES = 12_288; // decoded binary

/* -------------------------------
 * Error Types
 * ------------------------------- */

/* -------------------------------
 * MessageEnvelope
 * ------------------------------- */

export class MessageEnvelope {
  /** Raw decoded encrypted payload */
  readonly encryptedBlob: ArrayBuffer;

  static readonly PREFIX = ENVELOPE_PREFIX;
  static readonly DEFAULT_FINGERPRINT_LENGTH = 32;

  constructor(blob: ArrayBuffer) {
    this.encryptedBlob = blob;
  }

  get raw(): ArrayBuffer {
    return this.encryptedBlob;
  }

  /** Quick validation without throwing */
  static tryFromString(raw: unknown): {
    envelope?: MessageEnvelope;
    error?: MessageEnvelopeError;
  } {
    try {
      return { envelope: MessageEnvelope.fromMatchedString(raw) };
    } catch (err) {
      return { error: err as MessageEnvelopeError };
    }
  }

  static isEnvelopeCandidate(input: unknown): boolean {
    return (
      typeof input === "string" &&
      input.length <= MAX_ENVELOPE_LENGTH &&
      ENVELOPE_REGEX.test(input.trim())
    );
  }

  /**
   * Get the envelope version byte.
   * Returns 1, 2, or 3 (v3 = post-quantum ML-KEM).
   */
  getVersion(): number {
    const view = new Uint8Array(this.encryptedBlob);
    if (view.length < 1) {
      throw new MessageEnvelopeError(
        "VALIDATION_ERROR",
        "Encrypted blob too short to contain version byte",
      );
    }
    return view[0];
  }

  /* -------------------------------
   * Factory
   * ------------------------------- */

  static fromMatchedString(raw: unknown): MessageEnvelope {
    if (typeof raw !== "string") {
      throw new MessageEnvelopeError(
        "INVALID_INPUT",
        "Envelope input must be a string",
      );
    }

    const trimmed = raw.trim();

    if (trimmed.length > MAX_ENVELOPE_LENGTH) {
      throw new MessageEnvelopeError(
        "VALIDATION_ERROR",
        "Envelope exceeds maximum allowed length",
        raw,
      );
    }

    const match = ENVELOPE_REGEX.exec(trimmed);
    if (!match) {
      throw new MessageEnvelopeError(
        "FORMAT_ERROR",
        `Invalid envelope format. Expected ${ENVELOPE_PREFIX}:<base64>`,
        raw,
      );
    }

    let decoded: ArrayBuffer;
    try {
      decoded = base64ToArrayBuffer(match[1]);
    } catch {
      throw new MessageEnvelopeError(
        "VALIDATION_ERROR",
        "Base64 payload failed to decode",
        raw,
      );
    }

    if (decoded.byteLength === 0) {
      throw new MessageEnvelopeError(
        "VALIDATION_ERROR",
        "Decoded payload is empty",
        raw,
      );
    }

    if (decoded.byteLength > MAX_PAYLOAD_BYTES) {
      throw new MessageEnvelopeError(
        "VALIDATION_ERROR",
        "Decoded payload exceeds size limit",
        raw,
      );
    }

    return new MessageEnvelope(decoded);
  }

  /* -------------------------------
   * Extract Fingerprint
   * ------------------------------- */

  extractFingerprint(
    fingerprintLength = MessageEnvelope.DEFAULT_FINGERPRINT_LENGTH,
  ): string {
    const view = new Uint8Array(this.encryptedBlob);
    if (view.length < 1 + fingerprintLength) {
      throw new MessageEnvelopeError(
        "VALIDATION_ERROR",
        "Encrypted blob too short to contain fingerprint",
      );
    }

    const fingerprintBytes = view.slice(1, 1 + fingerprintLength);
    const ab = fingerprintBytes.buffer.slice(
      fingerprintBytes.byteOffset,
      fingerprintBytes.byteOffset + fingerprintBytes.length,
    );

    return arrayBufferToBase64(ab);
  }

  /* -------------------------------
   * Extract Encrypted Payload
   * ------------------------------- */

  /**
   * Extract and parse the JSON payload from the binary blob.
   * Works for v1, v2, and v3 envelopes — the JSON structure is parsed
   * as-is without validation beyond basic well-formedness.
   *
   * Type discrimination (v1 vs v2 vs v3) is done by the caller using
   * type guards from types.ts.
   */
  extractEncryptedPayload(): EnvelopePayload {
    const view = new Uint8Array(this.encryptedBlob);
    const versionLength = 1;
    const fingerprintLength = MessageEnvelope.DEFAULT_FINGERPRINT_LENGTH;

    if (view.length < versionLength + fingerprintLength + 1) {
      throw new MessageEnvelopeError(
        "VALIDATION_ERROR",
        "Encrypted blob too short to contain payload",
      );
    }

    const payloadBytes = view.slice(versionLength + fingerprintLength);
    const payloadText = new TextDecoder().decode(payloadBytes);

    let parsed: EnvelopePayload;
    try {
      parsed = JSON.parse(payloadText);
    } catch {
      throw new MessageEnvelopeError(
        "VALIDATION_ERROR",
        "Failed to parse encrypted payload JSON",
      );
    }

    // Basic validation: ensure it looks like an envelope payload
    if (!parsed.iv || !parsed.ciphertext) {
      throw new MessageEnvelopeError(
        "VALIDATION_ERROR",
        "Payload missing required fields (iv, ciphertext)",
      );
    }

    // Note: We do NOT validate v3-specific fields here (mlKemCiphertext, etc.)
    // because this class is format-agnostic. Type discrimination happens
    // upstream in MajikEnvelope or the caller.

    return parsed;
  }

  /* -------------------------------
   * Multi-Recipient Helpers
   * ------------------------------- */

  /**
   * Returns the ephemeral encrypted key for a given fingerprint.
   * Works for v2 (X25519) and v3 (ML-KEM) group messages.
   */
  getRecipientKey(fingerprint: string): GroupKey | undefined {
    const payload = this.extractEncryptedPayload();

    if ("keys" in payload) {
      return payload.keys.find((k) => k.fingerprint === fingerprint);
    }

    return undefined;
  }

  getSingleRecipientPayload(): SinglePayload | undefined {
    const payload = this.extractEncryptedPayload();
    return "keys" in payload ? undefined : (payload as SinglePayload);
  }

  /**
   * Checks if this envelope contains a key for the given fingerprint.
   */
  hasRecipient(fingerprint: string): boolean {
    return !!this.getRecipientKey(fingerprint);
  }

  isGroup(): boolean {
    const payload = this.extractEncryptedPayload();
    return "keys" in payload;
  }

  isSingle(): boolean {
    return !this.isGroup();
  }

  /**
   * Check if this is a v3 (post-quantum ML-KEM) envelope.
   */
  isPostQuantum(): boolean {
    return this.getVersion() === 3;
  }
}

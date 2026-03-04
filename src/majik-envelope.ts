import {
  aesGcmEncrypt,
  aesGcmDecrypt,
  generateRandomBytes,
  IV_LENGTH,
  mlKemEncapsulate,
  mlKemDecapsulate,
} from "./core/crypto/crypto-provider";
import {
  arrayBufferToBase64,
  arrayToBase64,
  base64ToArrayBuffer,
} from "./core/utils";
import { MajikCompressor } from "./core/compressor/majik-compressor";
import type {
  EnvelopePayload,
  GroupKey,
  GroupPayload,
  MajikEnvelopeJSON,
  SinglePayload,
} from "./core/types";
import { MajikEnvelopeError } from "./core/error";

// ─── Constants ────────────────────────────────────────────────────────────────

const PREFIX = "~*$MJKMSG";
const PREFIX_REGEX = /^~\*\$MJKMSG:([A-Za-z0-9+/=]+)$/;
const VERSION = 3;
const FINGERPRINT_LEN = 32; // SHA-256 = 32 bytes
const ML_KEM_PK_LEN = 1184; // ML-KEM-768 public key
const ML_KEM_SK_LEN = 2400; // ML-KEM-768 secret key
const ML_KEM_CT_LEN = 1088; // ML-KEM-768 ciphertext
const AES_KEY_LEN = 32;

// ─── Public Interfaces ────────────────────────────────────────────────────────

/** Any account or contact that can receive an encrypted message. */
export interface MajikRecipient {
  fingerprint: string; // base64 SHA-256 of X25519 public key (for lookup)
  mlKemPublicKey: Uint8Array; // 1184 bytes — ML-KEM-768 public key
}

/** The decrypting account's private ML-KEM key. */
export interface MajikIdentity {
  fingerprint: string; // used to find this identity's key entry in group envelopes
  mlKemSecretKey: Uint8Array; // 2400 bytes — ML-KEM-768 secret key
}

export interface EncryptOptions {
  plaintext: string;
  recipients: MajikRecipient[]; // 1 = solo, 2+ = group
  senderFingerprint?: string; // required for group (stored as envelope fingerprint)
  compress?: boolean; // default: true
}

/**
 * MajikEnvelope
 * ----------------
 *
 * Post-quantum envelope encryption for Majik Message.
 * ML-KEM-768 (FIPS-203) exclusively. No legacy paths.
 *
 * Two methods:
 *   MajikEnvelope.encrypt(options) → MajikEnvelope
 *   envelope.decrypt(identity)     → string
 *
 * Single vs group is automatic — driven by recipients.length.
 * Compression is transparent — always applied, always stripped on decrypt.
 *
 * Binary format
 * [1 byte: version=3][32 bytes: fingerprint][N bytes: JSON payload]
 *
 * Scanner string
 *   ~*$MJKMSG:<base64 of binary>
 *
 * Single payload
 *   { iv, ciphertext, mlKemCipherText }
 *   → sharedSecret = decapsulate(mlKemCipherText, secretKey)
 *   → plaintext    = AES-GCM-decrypt(sharedSecret, iv, ciphertext)
 *
 * Group payload
 *   { iv, ciphertext, keys: [{ fingerprint, mlKemCipherText, encryptedAesKey }] }
 *   → sharedSecret   = decapsulate(mlKemCipherText, secretKey)
 *   → aesKey         = encryptedAesKey XOR sharedSecret
 *   → plaintext      = AES-GCM-decrypt(aesKey, iv, ciphertext)
 */
export class MajikEnvelope {
  private readonly _fingerprint: string;
  private readonly _payload: EnvelopePayload;
  private _plaintext?: string;

  private constructor(
    fingerprint: string,
    payload: EnvelopePayload,
    plaintext?: string,
  ) {
    this._fingerprint = fingerprint;
    this._payload = payload;
    this._plaintext = plaintext;
  }

  // ── Getters ───────────────────────────────────────────────────────────────

  get fingerprint(): string {
    return this._fingerprint;
  }
  get plaintext(): string | undefined {
    return this._plaintext;
  }
  get isGroup(): boolean {
    return "keys" in this._payload;
  }
  get isSingle(): boolean {
    return !this.isGroup;
  }
  get version(): 3 {
    return VERSION;
  }

  // ── ENCRYPT ───────────────────────────────────────────────────────────────

  /**
   * Encrypt plaintext for one or more recipients.
   *
   * Single  (1 recipient):
   *   Encapsulate → 32-byte sharedSecret used directly as AES-GCM key.
   *   Result: { iv, ciphertext, mlKemCipherText }
   *
   * Group (2+ recipients):
   *   Generate random 32-byte AES key → encrypt message once.
   *   Per recipient: encapsulate → encryptedAesKey = aesKey XOR sharedSecret.
   *   Result: { iv, ciphertext, keys: [...] }
   *
   * @throws MajikEnvelopeError on empty plaintext, missing recipients, bad key sizes
   */
  static async encrypt(options: EncryptOptions): Promise<MajikEnvelope> {
    const {
      plaintext,
      recipients,
      senderFingerprint,
      compress = true,
    } = options;

    // ── Validation ───────────────────────────────────────────────────────
    if (!plaintext?.trim()) {
      throw new MajikEnvelopeError("Plaintext cannot be empty");
    }
    if (!recipients?.length) {
      throw new MajikEnvelopeError("At least one recipient is required");
    }
    if (recipients.length > 1 && !senderFingerprint) {
      throw new MajikEnvelopeError(
        "senderFingerprint is required for group messages",
      );
    }
    for (const r of recipients) {
      if (r.mlKemPublicKey.length !== ML_KEM_PK_LEN) {
        throw new MajikEnvelopeError(
          `Recipient "${r.fingerprint}": mlKemPublicKey must be ${ML_KEM_PK_LEN} bytes (got ${r.mlKemPublicKey.length})`,
        );
      }
    }

    try {
      // ── Compress ─────────────────────────────────────────────────────
      const message = compress
        ? ((await MajikCompressor.compress("plaintext", plaintext)) as string)
        : plaintext;

      const encoded = new TextEncoder().encode(message);

      let payload: EnvelopePayload;
      let envelopeFingerprint: string;

      if (recipients.length === 1) {
        // ── Single ─────────────────────────────────────────────────────
        const r = recipients[0];
        const { sharedSecret, cipherText: mlKemCT } = mlKemEncapsulate(
          r.mlKemPublicKey,
        );

        const iv = generateRandomBytes(IV_LENGTH);
        const ciphertext = aesGcmEncrypt(sharedSecret, iv, encoded);

        payload = {
          iv: arrayToBase64(iv),
          ciphertext: arrayToBase64(ciphertext),
          mlKemCipherText: arrayToBase64(mlKemCT),
        } satisfies SinglePayload;

        envelopeFingerprint = r.fingerprint;
      } else {
        // ── Group ────────────────────────────────────────────────────
        const aesKey = generateRandomBytes(AES_KEY_LEN);
        const iv = generateRandomBytes(IV_LENGTH);
        const ciphertext = aesGcmEncrypt(aesKey, iv, encoded);

        const keys: GroupKey[] = recipients.map((r) => {
          const { sharedSecret, cipherText: mlKemCT } = mlKemEncapsulate(
            r.mlKemPublicKey,
          );

          // One-time-pad: safe because sharedSecret is 32 uniformly random bytes
          const encryptedAesKey = new Uint8Array(AES_KEY_LEN);
          for (let i = 0; i < AES_KEY_LEN; i++) {
            encryptedAesKey[i] = aesKey[i] ^ sharedSecret[i];
          }

          return {
            fingerprint: r.fingerprint,
            mlKemCipherText: arrayToBase64(mlKemCT),
            encryptedAesKey: arrayToBase64(encryptedAesKey),
          };
        });

        payload = {
          iv: arrayToBase64(iv),
          ciphertext: arrayToBase64(ciphertext),
          keys,
        } satisfies GroupPayload;

        envelopeFingerprint = senderFingerprint!;
      }

      return new MajikEnvelope(envelopeFingerprint, payload);
    } catch (err) {
      if (err instanceof MajikEnvelopeError) throw err;
      throw new MajikEnvelopeError("Encryption failed", err);
    }
  }

  // ── DECRYPT ───────────────────────────────────────────────────────────────

  /**
   * Decrypt this envelope with the holder's ML-KEM secret key.
   *
   * Single:  decapsulate → sharedSecret → AES-GCM key → plaintext.
   * Group: find key entry by fingerprint → decapsulate → XOR to recover
   *        group AES key → AES-GCM decrypt → plaintext.
   *
   * Decompression is applied automatically if the payload is compressed.
   *
   * Note: ML-KEM decapsulation never throws on wrong key — it returns a
   * garbage shared secret, which causes AES-GCM authentication to fail.
   * That surfaces here as a MajikEnvelopeError.
   *
   * @throws MajikEnvelopeError on wrong key, missing key entry, or corrupted data
   */
  async decrypt(identity: MajikIdentity): Promise<string> {
    if (identity.mlKemSecretKey.length !== ML_KEM_SK_LEN) {
      throw new MajikEnvelopeError(
        `mlKemSecretKey must be ${ML_KEM_SK_LEN} bytes (got ${identity.mlKemSecretKey.length})`,
      );
    }

    try {
      let plain: Uint8Array | null;

      if (this.isSingle) {
        // ── Single ─────────────────────────────────────────────────────
        const p = this._payload as SinglePayload;
        const mlKemCT = new Uint8Array(base64ToArrayBuffer(p.mlKemCipherText));
        const sharedSecret = mlKemDecapsulate(mlKemCT, identity.mlKemSecretKey);
        const iv = new Uint8Array(base64ToArrayBuffer(p.iv));
        const ciphertext = new Uint8Array(base64ToArrayBuffer(p.ciphertext));
        plain = aesGcmDecrypt(sharedSecret, iv, ciphertext);
      } else {
        // ── Group ────────────────────────────────────────────────────
        const p = this._payload as GroupPayload;
        const entry = p.keys.find(
          (k) => k.fingerprint === identity.fingerprint,
        );

        if (!entry) {
          throw new MajikEnvelopeError(
            `No key entry found for fingerprint "${identity.fingerprint}"`,
          );
        }

        const mlKemCT = new Uint8Array(
          base64ToArrayBuffer(entry.mlKemCipherText),
        );
        const sharedSecret = mlKemDecapsulate(mlKemCT, identity.mlKemSecretKey);
        const encAesKey = new Uint8Array(
          base64ToArrayBuffer(entry.encryptedAesKey),
        );

        // Recover group AES key: aesKey = encryptedAesKey XOR sharedSecret
        const aesKey = new Uint8Array(AES_KEY_LEN);
        for (let i = 0; i < AES_KEY_LEN; i++) {
          aesKey[i] = encAesKey[i] ^ sharedSecret[i];
        }

        const iv = new Uint8Array(base64ToArrayBuffer(p.iv));
        const ciphertext = new Uint8Array(base64ToArrayBuffer(p.ciphertext));
        plain = aesGcmDecrypt(aesKey, iv, ciphertext);
      }

      if (!plain) {
        throw new MajikEnvelopeError(
          "Decryption failed — wrong key or corrupted envelope",
        );
      }

      let result = new TextDecoder().decode(plain);

      // Decompress transparently
      if (result.startsWith("mjkcmp:")) {
        result = (await MajikCompressor.decompress(
          "plaintext",
          result,
        )) as string;
      }

      this._plaintext = result;
      return result;
    } catch (err) {
      if (err instanceof MajikEnvelopeError) throw err;
      throw new MajikEnvelopeError("Decryption failed", err);
    }
  }

  // ── SERIALIZATION ─────────────────────────────────────────────────────────

  /** Scanner string: ~*$MJKMSG:<base64> */
  toScannerString(): string {
    return `${PREFIX}:${arrayBufferToBase64(this.toBinary())}`;
  }

  /** Binary: [1-byte version][32-byte fingerprint][JSON payload bytes] */
  toBinary(): ArrayBuffer {
    const version = new Uint8Array([VERSION]);
    const fingerprint = new Uint8Array(base64ToArrayBuffer(this._fingerprint));
    const payloadJson = new TextEncoder().encode(JSON.stringify(this._payload));

    const out = new Uint8Array(
      version.length + fingerprint.length + payloadJson.length,
    );
    out.set(version, 0);
    out.set(fingerprint, version.length);
    out.set(payloadJson, version.length + fingerprint.length);

    return out.buffer as ArrayBuffer;
  }

  /** JSON — for storage (EnvelopeCache, IDB). */
  toJSON(): MajikEnvelopeJSON {
    return {
      version: VERSION,
      fingerprint: this._fingerprint,
      payload: this._payload,
      plaintext: this._plaintext,
    };
  }

  // ── PARSING ───────────────────────────────────────────────────────────────

  /** Parse from scanner string: ~*$MJKMSG:<base64> */
  static fromScannerString(str: string): MajikEnvelope {
    const match = PREFIX_REGEX.exec(str.trim());
    if (!match) {
      throw new MajikEnvelopeError(
        `Invalid format — expected ${PREFIX}:<base64>`,
      );
    }
    try {
      return MajikEnvelope.fromBinary(base64ToArrayBuffer(match[1]));
    } catch (err) {
      if (err instanceof MajikEnvelopeError) throw err;
      throw new MajikEnvelopeError("Failed to parse scanner string", err);
    }
  }

  /** Parse from binary blob. */
  static fromBinary(blob: ArrayBuffer): MajikEnvelope {
    const view = new Uint8Array(blob);

    if (view.length < 1 + FINGERPRINT_LEN + 1) {
      throw new MajikEnvelopeError("Binary envelope too short");
    }

    const version = view[0];
    if (version !== VERSION) {
      throw new MajikEnvelopeError(
        `Unsupported envelope version: ${version}. Only v3 (ML-KEM) is supported.`,
      );
    }

    const fpBytes = view.slice(1, 1 + FINGERPRINT_LEN);
    const fingerprint = arrayBufferToBase64(
      fpBytes.buffer.slice(
        fpBytes.byteOffset,
        fpBytes.byteOffset + fpBytes.length,
      ),
    );

    let payload: EnvelopePayload;
    try {
      payload = JSON.parse(
        new TextDecoder().decode(view.slice(1 + FINGERPRINT_LEN)),
      );
    } catch {
      throw new MajikEnvelopeError("Failed to parse envelope payload JSON");
    }

    MajikEnvelope._assertPayload(payload);
    return new MajikEnvelope(fingerprint, payload);
  }

  /** Restore from stored JSON. */
  static fromJSON(json: MajikEnvelopeJSON): MajikEnvelope {
    if (json.version !== VERSION) {
      throw new MajikEnvelopeError(
        `Cannot load v${json.version} envelope — only v3 (ML-KEM) is supported`,
      );
    }
    MajikEnvelope._assertPayload(json.payload);
    return new MajikEnvelope(json.fingerprint, json.payload, json.plaintext);
  }

  // ── PRIVATE: Payload validation ───────────────────────────────────────────

  private static _assertPayload(p: unknown): asserts p is EnvelopePayload {
    if (typeof p !== "object" || !p) {
      throw new MajikEnvelopeError("Payload must be an object");
    }

    const payload = p as Record<string, unknown>;

    if (
      typeof payload.iv !== "string" ||
      typeof payload.ciphertext !== "string"
    ) {
      throw new MajikEnvelopeError(
        "Payload missing required fields: iv, ciphertext",
      );
    }

    if ("keys" in payload) {
      // Group
      if (!Array.isArray(payload.keys) || payload.keys.length === 0) {
        throw new MajikEnvelopeError(
          "Group payload has empty or invalid keys array",
        );
      }
      for (const k of payload.keys as unknown[]) {
        const entry = k as Record<string, unknown>;
        if (
          typeof entry.fingerprint !== "string" ||
          typeof entry.mlKemCipherText !== "string" ||
          typeof entry.encryptedAesKey !== "string"
        ) {
          throw new MajikEnvelopeError(
            "Group key entry missing required fields: fingerprint, mlKemCipherText, encryptedAesKey",
          );
        }
      }
    } else {
      // Single
      if (typeof payload.mlKemCipherText !== "string") {
        throw new MajikEnvelopeError("Single payload missing mlKemCipherText");
      }
    }
  }
}

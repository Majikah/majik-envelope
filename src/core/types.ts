/**
 * types.ts — @majikah/majik-envelope
 *
 * ML-KEM-768 (v3) envelope types only.
 * v1 (X25519 solo) and v2 (X25519 group) have been removed.
 */

/** ISO 8601 timestamp string, e.g. `"2026-07-11T00:00:00.000Z"`. */
export type ISODateString = string;

/** Base64-encoded public key material. Safe to store, log, or transmit. */
export type MajikKeyAddress = string;

/** Base64-encoded SHA-256 digest of a MajikKey's X25519 public key. Doubles as the account `id`. */
export type MajikKeyFingerprint = string;

export type ED25519PublicKey = string;
export type MLKEM768PublicKey = string;
export type MLDSA87PublicKey = string;
export type BitcoinPublicKey = string;

export type ED25519RawPublicKey = Uint8Array;
export type MLKEM768RawPublicKey = Uint8Array;
export type MLDSA87RawPublicKey = Uint8Array;
export type BitcoinRawPublicKey = Uint8Array;

export interface X25519RawKey {
  raw: Uint8Array;
}

// ─── Single Payload ─────────────────────────────────────────────────────────────

/**
 * Single-recipient envelope payload.
 * The ML-KEM shared secret is used directly as the AES-256-GCM key.
 */
export interface SinglePayload {
  iv: string; // base64, 12 bytes
  ciphertext: string; // base64, AES-256-GCM ciphertext
  mlKemCipherText: string; // base64, 1088 bytes (ML-KEM-768 ciphertext)
}

// ─── Group Payload ────────────────────────────────────────────────────────────

/**
 * Per-recipient key entry in a group envelope.
 * encryptedAesKey = groupAesKey XOR mlKemSharedSecret (32-byte XOR one-time-pad).
 */
export interface GroupKey {
  fingerprint: MajikKeyFingerprint; // base64 SHA-256 — used to find this entry during decryption
  mlKemCipherText: string; // base64, 1088 bytes (ML-KEM-768 ciphertext for this recipient)
  encryptedAesKey: string; // base64, 32 bytes (aesKey XOR sharedSecret)
}

/**
 * Multi-recipient envelope payload.
 * Message is encrypted once with a random AES key.
 * Each recipient gets their own ML-KEM encapsulation of that AES key.
 */
export interface GroupPayload {
  iv: string; // base64, 12 bytes
  ciphertext: string; // base64, AES-256-GCM ciphertext
  keys: GroupKey[]; // one entry per recipient
}

// ─── Union ────────────────────────────────────────────────────────────────────

export type EnvelopePayload = SinglePayload | GroupPayload;

// ─── Type Guards ──────────────────────────────────────────────────────────────

export function isSinglePayload(p: EnvelopePayload): p is SinglePayload {
  return "mlKemCipherText" in p && !("keys" in p);
}

export function isGroupPayload(p: EnvelopePayload): p is GroupPayload {
  return "keys" in p && Array.isArray((p as GroupPayload).keys);
}

// ─── MajikEnvelope JSON ───────────────────────────────────────────────────────

export interface MajikEnvelopeJSON {
  version: 3;
  fingerprint: MajikKeyFingerprint;
  payload: EnvelopePayload;
  plaintext?: string;
}
// ─── Shared API Types ─────────────────────────────────────────────────────────

export interface MAJIK_API_RESPONSE {
  success: boolean;
  message: string;
  data?: unknown;
}

export interface MnemonicJSON {
  id: string;
  seed: string[];
  phrase?: string;
}



/**
 * Safe, serializable snapshot of a MajikKey — what `toJSON()` / `toString()` produce.
 *
 * Every `encrypted*` field is an AES-256-GCM ciphertext (IV + ciphertext,
 * base64-encoded) protected by a passphrase-derived Argon2id key (or legacy
 * PBKDF2, see `kdfVersion`). None of these fields ever contain raw private
 * key material — this shape is safe to persist in a database, localStorage,
 * or anywhere else at rest.
 *
 * Load one of these back into a live instance with `MajikKey.fromJSON()`.
 */
export interface MajikKeyJSON {
  /** Account identifier. Equal to `fingerprint` for accounts created by this library. */
  id: MajikKeyFingerprint;
  /** Human-readable, user-editable account name. */
  label: string;
  /** X25519 public key, base64. */
  publicKey: MajikKeyAddress; // base64
  /** SHA-256 fingerprint of `publicKey`. Stable identity anchor for the account. */
  fingerprint: MajikKeyFingerprint;
  /** AES-256-GCM-encrypted X25519 private key (IV + ciphertext), base64. Requires the passphrase to decrypt. */
  encryptedPrivateKey: string; // base64
  /** Random salt used to derive the passphrase-based encryption key. Shared across all key types on this account. */
  salt: string; // base64
  /**
   * Encrypted, mnemonic-verification blob (base64 JSON). Decryptable only with
   * the original mnemonic — used internally to verify a supplied mnemonic
   * before `importFromMnemonicBackup()` re-derives the full identity. Not a
   * general-purpose backup of the private key.
   */
  backup: string; // base64
  /** Account creation time, ISO 8601. */
  timestamp: ISODateString; // ISO 8601
  /** KDF used for every `encrypted*` field on this account: `1` = legacy PBKDF2 (read-only), `2` = Argon2id (current). Defaults to `1` if omitted. */
  kdfVersion?: number;

  /** ML-KEM-768 (FIPS-203) public key, base64. Post-quantum key encapsulation. */
  mlKemPublicKey?: MLKEM768PublicKey;
  /** AES-256-GCM-encrypted ML-KEM-768 secret key, base64. */
  encryptedMlKemSecretKey?: string;

  /** Ed25519 public key, base64. Classical signing — same keypair the X25519 identity key is converted from. */
  edPublicKey?: ED25519PublicKey;
  /** AES-256-GCM-encrypted Ed25519 secret key, base64. */
  encryptedEdSecretKey?: string;
  /** ML-DSA-87 (FIPS-204) public key, base64. Post-quantum signing. */
  mlDsaPublicKey?: MLDSA87PublicKey;
  /** AES-256-GCM-encrypted ML-DSA-87 secret key, base64. */
  encryptedMlDsaSecretKey?: string;

  /** @experimental secp256k1 Bitcoin public key, base64. Domain-separated BIP-32/84 derivation by default — see `MajikKeyBitcoinNamespace`. */
  btcPublicKey?: BitcoinPublicKey;
  /** @experimental AES-256-GCM-encrypted Bitcoin private key, base64. */
  encryptedBtcSecretKey?: string;

  /** BIP-39 wordlist language the original mnemonic was generated/validated against. Defaults to `"en"`. */
  mnemonicLanguage?: string;
}

export interface MajikKeyMetadata {
  id: string;
  fingerprint: string;
  label: string;
  timestamp: Date;
  isLocked: boolean;
  kdfVersion: number;
  hasMlKem: boolean;
}

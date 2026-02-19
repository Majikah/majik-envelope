/**
 * types.ts — @majikah/majik-envelope
 *
 * ML-KEM-768 (v3) envelope types only.
 * v1 (X25519 solo) and v2 (X25519 group) have been removed.
 */

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
  fingerprint: string; // base64 SHA-256 — used to find this entry during decryption
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
  fingerprint: string;
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

export interface MajikKeyJSON {
  id: string;
  label: string;
  publicKey: string;
  fingerprint: string;
  encryptedPrivateKey: string;
  salt: string;
  backup: string;
  timestamp: string;
  kdfVersion: number;
  mlKemPublicKey?: string;
  encryptedMlKemSecretKey?: string;
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

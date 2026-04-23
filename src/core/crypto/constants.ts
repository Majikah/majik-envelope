export const KEY_ALGO = { name: "ECDH", namedCurve: "X25519" } as const;

export const MAJIK_SALT = "MajikMessageSalt";
export const MAJIK_MNEMONIC_SALT = "MajikMessageMnemonicSalt";

/**
 * KDF version identifiers.
 * Stored alongside every encrypted private key blob so the correct
 * derivation function is always used on decryption.
 */
export const KDF_VERSION = {
  PBKDF2: 1, // legacy — read-only support for existing accounts
  ARGON2ID: 2, // current — all new accounts and re-encryptions
} as const;

export type KDF_VERSION = (typeof KDF_VERSION)[keyof typeof KDF_VERSION];

/**
 * Argon2id parameters.
 *
 * PASSPHRASE (protecting the private key at rest):
 *   m=65536 (64 MB) 
 *   t=3  — 3 passes
 *   p=4  — 4 parallel lanes
 *
 */
export const ARGON2_PARAMS = {
  PASSPHRASE: {
    m: 65536, // memory in KB (128 MB)
    t: 3, // time cost (passes)
    p: 4, // parallelism (lanes)
    dkLen: 32, // output length in bytes (256-bit AES key)
  },
  MNEMONIC: {
    m: 65536, // 64 MB
    t: 3,
    p: 2,
    dkLen: 32,
  },
} as const;

export type ARGON2_PARAMS = (typeof ARGON2_PARAMS)[keyof typeof ARGON2_PARAMS];

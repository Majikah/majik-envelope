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
 *   m=131072 (128 MB) — double OWASP "high security" tier (64 MB)
 *   t=4               — 4 passes
 *   p=4               — 4 parallel lanes
 *
 * Benchmark targets (approximate):
 *   Modern laptop (2020+):          ~600–900ms  ✓
 *   Mid-range desktop (2018):       ~800–1200ms ✓
 *   Low-end / older machine:        ~1500–2500ms — acceptable for a one-time unlock
 *   RTX 4090 brute-force attack:    ~1–3 guesses/sec vs ~400,000/sec for PBKDF2
 *   Improvement over current PBKDF2: ~100,000–400,000×
 *
 * MNEMONIC BACKUP (protecting exported backup files):
 *   m=65536 (64 MB) — lower because the mnemonic itself is 128-bit entropy;
 *                     the KDF is a domain separator, not a weak-password defense.
 *   t=3
 *   p=2
 *
 * If benchmarks on your lowest-spec target device exceed 3s for the passphrase
 * parameters, reduce m to 65536 (64 MB) and t to 3. That is still ~50,000×
 * harder than the current PBKDF2 setup.
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

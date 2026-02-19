# Majik Envelope

[![Developed by Zelijah](https://img.shields.io/badge/Developed%20by-Zelijah-red?logo=github&logoColor=white)](https://thezelijah.world) ![GitHub Sponsors](https://img.shields.io/github/sponsors/jedlsf?style=plastic&label=Sponsors&link=https%3A%2F%2Fgithub.com%2Fsponsors%2Fjedlsf)

**Majik Envelope** is the core cryptographic engine of the [Majik Message](https://github.com/Majikah/majik-message) platform. It provides a post-quantum secure "envelope" format that handles message encryption, multi-recipient key encapsulation, and transparent compression using NIST-standardized algorithms.

![npm](https://img.shields.io/npm/v/@majikah/majik-envelope) ![npm downloads](https://img.shields.io/npm/dm/@majikah/majik-envelope) ![npm bundle size](https://img.shields.io/bundlephobia/min/%40majikah%2Fmajik-envelope) [![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) ![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue)


---
- [Majik Envelope](#majik-envelope)
  - [Overview](#overview)
    - [Key Features](#key-features)
  - [Installation](#installation)
  - [Usage Guide](#usage-guide)
    - [Encrypting a Message (Single Recipient)](#encrypting-a-message-single-recipient)
    - [Encrypting for a Group (2+ Recipients)](#encrypting-for-a-group-2-recipients)
    - [Decrypting an Envelope](#decrypting-an-envelope)
  - [Technical Specifications Reference](#technical-specifications-reference)
    - [1. Cryptographic Stack (Envelope)](#1-cryptographic-stack-envelope)
    - [2. Binary Structure \& Framing](#2-binary-structure--framing)
      - [Internal Binary Layout (Decoded Base64):](#internal-binary-layout-decoded-base64)
    - [3. Primitive Parameters](#3-primitive-parameters)
    - [4. Encryption Logic Flows](#4-encryption-logic-flows)
      - [A. Single-Recipient (Direct)](#a-single-recipient-direct)
      - [B. Multi-Recipient (Group)](#b-multi-recipient-group)
    - [5. Implementation Notes](#5-implementation-notes)
  - [Related Projects](#related-projects)
    - [Majik Message](#majik-message)
    - [Majik Key](#majik-key)
  - [Contributing](#contributing)
  - [License](#license)
  - [Author](#author)
  - [About the Developer](#about-the-developer)
  - [Contact](#contact)


---

## Overview

Majik Envelope implements **Envelope Format**, which exclusively uses **ML-KEM-768 (FIPS-203)** for post-quantum security. It abstracts away the complexity of managing shared secrets, AES-GCM initialization vectors, and multi-recipient key wrapping, allowing developers to focus on sending secure messages.

---

### Key Features

- **Post-Quantum Security**: Exclusively uses ML-KEM-768 for key encapsulation.
- **Hybrid Encryption**: Combines ML-KEM shared secrets with AES-256-GCM for high-speed content encryption.
- **Group Messaging**: Native support for 1-to-many encryption using a single-ciphertext, multi-key-wrap approach.
- **Transparent Compression**: Built-in Zstd and Gzip support via `MajikCompressor` to reduce message size.
- **Strict Format**: Binary-backed envelopes with a standardized Base64 string representation (`~*$MJKMSG:`).

---


## Installation

```bash
npm install @majikah/majik-envelope

```

---

## Usage Guide

### Encrypting a Message (Single Recipient)

The library automatically chooses between "Single" and "Group" logic based on the number of recipients.

```ts
import { MajikEnvelope } from "@majikah/majik-envelope";

const envelope = await MajikEnvelope.encrypt({
  plaintext: "Hello, this is a quantum-safe secret.",
  recipients: [{
    fingerprint: "recipient_fingerprint_base64",
    mlKemPublicKey: recipientPublicKeyBytes // Uint8Array (1184 bytes)
  }],
  compress: true // Default is true
});

// Convert to the scanner-ready string
const secretString = envelope.toString(); 
// Output: ~*$MJKMSG:AbC123...


```

### Encrypting for a Group (2+ Recipients)

For group messages, a senderFingerprint is required for metadata.

```ts
import { MajikEnvelope } from "@majikah/majik-envelope";

const groupEnvelope = await MajikEnvelope.encrypt({
  plaintext: "Secret group meeting at midnight.",
  senderFingerprint: "my_fingerprint_base64",
  recipients: [
    { fingerprint: "alice_fp", mlKemPublicKey: alicePk },
    { fingerprint: "bob_fp", mlKemPublicKey: bobPk }
  ]
});

// Convert to the scanner-ready string
const secretString = groupEnvelope.toString(); 
// Output: ~*$MJKMSG:AbC123...


```


### Decrypting an Envelope

To decrypt, you simply provide the recipient's identity (their private ML-KEM key and fingerprint).

```ts
import { MajikEnvelope } from "@majikah/majik-envelope";

const identity = {
  fingerprint: "my_fingerprint_base64",
  mlKemSecretKey: mySecretKeyBytes // Uint8Array (2400 bytes)
};

try {
  // Option 1: Decrypt from an existing instance
  const decrypted = await envelope.decrypt(identity);
  
  // Option 2: Parse from a string first
  const parsedEnvelope = MajikEnvelope.fromString("~*$MJKMSG:...");
  const text = await parsedEnvelope.decrypt(identity);
  
  console.log(text); // "Hello, this is a quantum-safe secret."
} catch (error) {
  console.error("Decryption failed: Unauthorized or tampered message.");
}

```

---

## Technical Specifications Reference

### 1. Cryptographic Stack (Envelope)
Majik Envelope is designed to be **Post-Quantum Secure (PQS)** by default, moving away from classical ECC for key encapsulation.

| Component | Primitive | Implementation / Standard |
| :--- | :--- | :--- |
| **Key Encapsulation (KEM)** | ML-KEM-768 | FIPS-203 (formerly Kyber) |
| **Symmetric Encryption** | AES-256-GCM | NIST SP 800-38D |
| **Hashing / Fingerprinting**| SHA-256 | FIPS 180-4 |
| **Key Derivation (KDF)** | Argon2id | OWASP Recommended (v2 accounts) |
| **Compression** | Zstd / Gzip | `@bokuweb/zstd-wasm` / `fflate` |


### 2. Binary Structure & Framing
The library produces a "Scanner-Ready" string. This is a Base64-encoded binary blob prefixed with a protocol identifier.

**Format:** `~*$MJKMSG:<Base64_Payload>`

#### Internal Binary Layout (Decoded Base64):
| Offset (Bytes) | Length | Field | Description |
| :--- | :--- | :--- | :--- |
| `0` | 1 | **Version** | Set to `0x03` for current PQ format. |
| `1` | 32 | **Fingerprint** | SHA-256 of the recipient (Single) or Sender (Group). |
| `33` | Variable | **Payload** | UTF-8 JSON string containing IVs and ciphertexts. |


### 3. Primitive Parameters
| Parameter | Value | Description |
| :--- | :--- | :--- |
| `ML_KEM_PK_LEN` | 1184 bytes | ML-KEM-768 Public Key size. |
| `ML_KEM_SK_LEN` | 2400 bytes | ML-KEM-768 Secret Key size. |
| `ML_KEM_CT_LEN` | 1088 bytes | ML-KEM-768 Ciphertext (encapsulation). |
| `AES_KEY_LEN` | 32 bytes | 256-bit symmetric key. |
| `IV_LENGTH` | 12 bytes | Standard GCM Initialization Vector length. |


### 4. Encryption Logic Flows

#### A. Single-Recipient (Direct)
1. **Compress**: Plaintext is compressed using Zstd (or Gzip fallback).
2. **Encapsulate**: Generate a `sharedSecret` (32b) and `mlKemCipherText` (1088b) using the recipient's Public Key.
3. **Encrypt**: Encrypt the compressed data via AES-256-GCM using the `sharedSecret` as the key.
4. **Pack**: Encode the `iv`, `ciphertext`, and `mlKemCipherText` into a `SinglePayload` JSON object.

#### B. Multi-Recipient (Group)
1. **Compress**: Plaintext is compressed.
2. **Key Generation**: Generate a random 32-byte `masterAesKey`.
3. **Encrypt**: Encrypt the compressed data via AES-256-GCM using the `masterAesKey`.
4. **Wrap Keys**: For **each** recipient:
   - Perform ML-KEM encapsulation to get a unique `sharedSecret`.
   - `encryptedAesKey = masterAesKey XOR sharedSecret`.
   - Store the recipient's `fingerprint`, `mlKemCipherText`, and `encryptedAesKey`.
5. **Pack**: Encode the `iv`, `ciphertext`, and the array of `keys` into a `GroupPayload` JSON object.


### 5. Implementation Notes
- **Authentication**: AES-GCM provides AEAD (Authenticated Encryption with Associated Data). If a message is tampered with or the wrong key is used, decryption will throw an "Auth tag mismatch" error.
- **Quantum Resistance**: Because the symmetric key is derived via ML-KEM-768, the message remains secure even against future Shor's algorithm-based attacks that would break RSA or Elliptic Curve (X25519) systems.
- **Graceful Degradation**: The `MajikCompressor` automatically handles decompression by identifying the `mjkcmp` magic header, ensuring compatibility even if compression settings change.


---

## Related Projects

### [Majik Message](https://message.majikah.solutions)
Secure messaging platform using Majik Keys

![npm](https://img.shields.io/npm/v/@majikah/majik-message) ![npm downloads](https://img.shields.io/npm/dm/@majikah/majik-message) ![npm bundle size](https://img.shields.io/bundlephobia/min/%40majikah%2Fmajik-message) [![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) ![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue)

[Read more about Majik Message here](https://majikah.solutions/products/majik-message)

[![Majik Message Thumbnail](https://github.com/user-attachments/assets/d433c6b8-1841-4fa1-a6da-b348029d1dbe)](https://message.majikah.solutions)

> Click the image to try Majik Message live.

[Read Docs](https://majikah.solutions/products/majik-message/docs)


Also available on [Microsoft Store](https://apps.microsoft.com/detail/9pmjgvzzjspn) for free.

[Official Repository](https://github.com/Majikah/majik-message)
[SDK Library](https://www.npmjs.com/package/@majikah/majik-message)

---

### [Majik Key](https://majikah.solutions/sdk/majik-key)
**Majik Key** is a seed phrase account library for creating, managing, and parsing mnemonic-based cryptographic accounts (Majik Keys). Generate deterministic key pairs from BIP39 seed phrases with simple, developer-friendly APIs. Now supports ML-KEM-768 post-quantum key derivation alongside X25519.

![npm](https://img.shields.io/npm/v/@majikah/majik-key) ![npm downloads](https://img.shields.io/npm/dm/@majikah/majik-key) ![npm bundle size](https://img.shields.io/bundlephobia/min/%40majikah%2Fmajik-key) [![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) ![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue)

[Read Docs](https://majikah.solutions/sdk/majik-key/docs)
[Official Repository](https://github.com/Majikah/majik-key)
[SDK Library](https://www.npmjs.com/package/@majikah/majik-key)

---

## Contributing

If you want to contribute or help extend support to more platforms, reach out via email. All contributions are welcome!  

---

## License

[Apache-2.0](LICENSE) — free for personal and commercial use.

---
## Author

Made with 💙 by [@thezelijah](https://github.com/jedlsf)

## About the Developer

- **Developer**: Josef Elijah Fabian
- **GitHub**: [https://github.com/jedlsf](https://github.com/jedlsf)
- **Project Repository**: [https://github.com/Majikah/majik-envelope](https://github.com/Majikah/majik-envelope)

---

## Contact

- **Business Email**: [business@thezelijah.world](mailto:business@thezelijah.world)
- **Official Website**: [https://www.thezelijah.world](https://www.thezelijah.world)

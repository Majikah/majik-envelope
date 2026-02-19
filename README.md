# Majik Key

[![Developed by Zelijah](https://img.shields.io/badge/Developed%20by-Zelijah-red?logo=github&logoColor=white)](https://thezelijah.world) ![GitHub Sponsors](https://img.shields.io/github/sponsors/jedlsf?style=plastic&label=Sponsors&link=https%3A%2F%2Fgithub.com%2Fsponsors%2Fjedlsf)

**Majik Key** is a seed phrase account library for creating, managing, and parsing mnemonic-based cryptographic accounts (Majik Keys). Generate deterministic key pairs from BIP39 seed phrases with simple, developer-friendly APIs.

![npm](https://img.shields.io/npm/v/@majikah/majik-key) ![npm downloads](https://img.shields.io/npm/dm/@majikah/majik-key) ![npm bundle size](https://img.shields.io/bundlephobia/min/%40majikah%2Fmajik-key) [![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) ![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue)



---
- [Majik Key](#majik-key)
  - [Overview](#overview)
    - [What is a Majik Key?](#what-is-a-majik-key)
    - [Use Cases](#use-cases)
  - [Features](#features)
    - [Security First](#security-first)
    - [BIP39 Compliance](#bip39-compliance)
    - [Developer Friendly](#developer-friendly)
    - [Import/Export](#importexport)
    - [Interoperability](#interoperability)
  - [Installation](#installation)
  - [Quick Start](#quick-start)
  - [API Reference](#api-reference)
    - [Static Methods](#static-methods)
      - [`MajikKey.create(mnemonic, passphrase, label?)`](#majikkeycreatemnemonic-passphrase-label)
      - [`MajikKey.fromJSON(json)`](#majikkeyfromjsonjson)
      - [`MajikKey.fromMnemonicJSON(mnemonicJson, passphrase, label?)`](#majikkeyfrommnemonicjsonmnemonicjson-passphrase-label)
      - [`MajikKey.importFromMnemonicBackup(backup, mnemonic, passphrase, label?)`](#majikkeyimportfrommnemonicbackupbackup-mnemonic-passphrase-label)
      - [`MajikKey.generateMnemonic(strength?)`](#majikkeygeneratemnemonicstrength)
      - [`MajikKey.validateMnemonic(mnemonic)`](#majikkeyvalidatemnemonicmnemonic)
    - [Instance Methods](#instance-methods)
      - [`unlock(passphrase)`](#unlockpassphrase)
      - [`lock()`](#lock)
      - [`verify(passphrase)`](#verifypassphrase)
      - [`updateLabel(newLabel)`](#updatelabelnewlabel)
      - [`updatePassphrase(currentPassphrase, newPassphrase)`](#updatepassphrasecurrentpassphrase-newpassphrase)
      - [`getPrivateKey()`](#getprivatekey)
      - [`getPrivateKeyBase64()`](#getprivatekeybase64)
      - [`toJSON()`](#tojson)
      - [`toString(pretty?)`](#tostringpretty)
      - [`toMnemonicJSON(mnemonic, passphrase?)`](#tomnemonicjsonmnemonic-passphrase)
      - [`exportMnemonicBackup(mnemonic)`](#exportmnemonicbackupmnemonic)
      - [`toContact()`](#tocontact)
      - [`toMajikMessageIdentity(user, options?)`](#tomajikmessageidentityuser-options)
    - [Getters](#getters)
      - [`id: string`](#id-string)
      - [`fingerprint: string`](#fingerprint-string)
      - [`publicKey: CryptoKey | { raw: Uint8Array }`](#publickey-cryptokey---raw-uint8array-)
      - [`publicKeyBase64: string`](#publickeybase64-string)
      - [`label: string`](#label-string)
      - [`backup: string`](#backup-string)
      - [`timestamp: Date`](#timestamp-date)
      - [`isLocked: boolean`](#islocked-boolean)
      - [`isUnlocked: boolean`](#isunlocked-boolean)
      - [`metadata: MajikKeyMetadata`](#metadata-majikkeymetadata)
  - [Usage Examples](#usage-examples)
    - [Example 1: Create and Manage a Key](#example-1-create-and-manage-a-key)
    - [Example 2: Lock/Unlock Pattern](#example-2-lockunlock-pattern)
    - [Example 3: Backup and Recovery](#example-3-backup-and-recovery)
    - [Example 4: Update Passphrase](#example-4-update-passphrase)
    - [Example 5: Verify Passphrase](#example-5-verify-passphrase)
  - [Integration with Majik Message](#integration-with-majik-message)
    - [Importing to Majik Message](#importing-to-majik-message)
    - [Converting to Majik Message Identity](#converting-to-majik-message-identity)
  - [Security Considerations](#security-considerations)
    - [Best Practices](#best-practices)
    - [Security Features](#security-features)
    - [What NOT to Do](#what-not-to-do)
    - [What TO Do](#what-to-do)
    - [Tips \& Reminders](#tips--reminders)
      - [For Developers](#for-developers)
      - [For Users](#for-users)
  - [Related Projects](#related-projects)
    - [Majik Message](#majik-message)
  - [Contributing](#contributing)
  - [License](#license)
  - [Author](#author)
  - [About the Developer](#about-the-developer)
  - [Contact](#contact)


---

## Overview

**Majik Key** is a comprehensive library for managing seed phrase-based cryptographic accounts. It provides a secure, intuitive way to create, store, and manage mnemonic-based identities with built-in encryption, backup, and recovery features.

### What is a Majik Key?

A Majik Key is a seed phrase account that:
- Derives cryptographic key pairs from BIP39 mnemonic phrases
- Encrypts private keys at rest with a user-defined passphrase
- Supports secure backup and recovery via mnemonic encryption
- Provides locked/unlocked state management for enhanced security
- Is fully compatible with **Majik Message** and other Majikah products

### Use Cases

- **Majik Message Integration**: Create seed phrase accounts that can be imported directly into Majik Message
- **Cryptographic Identity Management**: Manage multiple identities with deterministic key derivation
- **Secure Messaging**: Generate signing keys for end-to-end encrypted communication
- **Blockchain Applications**: Create wallet-like accounts from mnemonic phrases
- **Majikah Ecosystem**: Use across all Majikah products and services

---

## Features

### Security First
- **Encrypted at Rest**: Private keys are encrypted with PBKDF2-derived keys (200,000 iterations)
- **AES-GCM Encryption**: Industry-standard authenticated encryption
- **Locked/Unlocked States**: Private keys only exist in memory when explicitly unlocked
- **Per-Identity Salts**: Each account uses a unique salt for encryption

### BIP39 Compliance
- **Standard Mnemonic Generation**: Generate 12 or 24-word seed phrases
- **Mnemonic Validation**: Built-in BIP39 validation
- **Deterministic Key Derivation**: Same mnemonic always produces the same keys

### Developer Friendly
- **TypeScript Support**: Full type definitions included
- **Simple API**: Intuitive CRUD operations
- **Error Handling**: Comprehensive error messages with `MajikKeyError`
- **Method Chaining**: Fluent API for common operations

### Import/Export
- **JSON Serialization**: Safe storage format (no private keys exposed)
- **Mnemonic Backup**: Export/import encrypted backups using mnemonic phrases
- **MnemonicJSON Format**: Compatible format for seed phrase storage

### Interoperability
- **Majik Message Compatible**: Seamlessly import/export to Majik Message
- **Majik Contact Integration**: Convert keys to contact format
- **Majikah Ecosystem**: Works across all Majikah products

---

## Installation

```bash
# Using npm
npm install @majikah/majik-key

```

---

## Quick Start

```ts
import { MajikKey } from '@majikah/majik-key';

// Generate a new mnemonic
const mnemonic = MajikKey.generateMnemonic(); // 12 words
console.log('Save this mnemonic:', mnemonic);

// Create a new Majik Key (unlocked state)
const key = await MajikKey.create(
  mnemonic,
  'my-secure-passphrase',
  'My First Key'
);

console.log('Key ID:', key.id);
console.log('Fingerprint:', key.fingerprint);
console.log('Is Unlocked:', key.isUnlocked); // true

// Lock the key (clear private keys from memory)
key.lock();
console.log('Is Locked:', key.isLocked); // true

// Unlock when needed
await key.unlock('my-secure-passphrase');
console.log('Is Unlocked:', key.isUnlocked); // true

// Access private key (only when unlocked)
const privateKey = key.getPrivateKey();
const privateKeyBase64 = key.getPrivateKeyBase64();

// Save to storage (private keys never included)
const json = key.toJSON();
localStorage.setItem('myKey', JSON.stringify(json));

// Load from storage (locked state)
const loadedKey = MajikKey.fromJSON(json);
await loadedKey.unlock('my-secure-passphrase');
```

---

## API Reference

### Static Methods

#### `MajikKey.create(mnemonic, passphrase, label?)`
Create a new Majik Key from a mnemonic phrase.

**Parameters:**
- `mnemonic: string` - BIP39 mnemonic phrase (12-24 words)
- `passphrase: string` - Passphrase to encrypt the private key at rest
- `label?: string` - Optional label for the key

**Returns:** `Promise<MajikKey>` - A new unlocked MajikKey instance

**Example:**
```ts
const mnemonic = 'witch collapse practice feed shame open despair creek road again ice least';
const key = await MajikKey.create(mnemonic, 'my-password', 'Personal Account');

```

---

#### `MajikKey.fromJSON(json)`
Load a Majik Key from JSON (locked state).

**Parameters:**
- `json: MajikKeyJSON | string` - JSON object or string

**Returns:** `MajikKey` - A locked MajikKey instance

**Example:**
```ts
const json = localStorage.getItem('myKey');
const key = MajikKey.fromJSON(json);
await key.unlock('my-password');
```

---

#### `MajikKey.fromMnemonicJSON(mnemonicJson, passphrase, label?)`
Create a Majik Key from MnemonicJSON format.

**Parameters:**
- `mnemonicJson: MnemonicJSON | string` - MnemonicJSON object or string
- `passphrase: string` - Passphrase to encrypt the key at rest
- `label?: string` - Optional label for the key

**Returns:** `Promise<MajikKey>` - A new unlocked MajikKey instance

**Example:**
```ts
const mnemonicData = {
  id: 'backup-id',
  seed: ['word1', 'word2', ...],
  phrase: 'optional-encryption-phrase'
};

const key = await MajikKey.fromMnemonicJSON(mnemonicData, 'my-password');
```

---

#### `MajikKey.importFromMnemonicBackup(backup, mnemonic, passphrase, label?)`
Import a Majik Key from a mnemonic-encrypted backup.

**Parameters:**
- `backup: string` - Base64-encoded backup string
- `mnemonic: string` - The mnemonic phrase used to encrypt the backup
- `passphrase: string` - Passphrase to encrypt the imported key
- `label?: string` - Optional label for the key

**Returns:** `Promise<MajikKey>` - A new unlocked MajikKey instance

**Example:**
```ts
const backupString = 'eT8xY2F...'; // From exportMnemonicBackup()
const key = await MajikKey.importFromMnemonicBackup(
  backupString,
  mnemonic,
  'new-password',
  'Restored Account'
);
```

---

#### `MajikKey.generateMnemonic(strength?)`
Generate a new BIP39 mnemonic phrase.

**Parameters:**
- `strength?: 128 | 256` - Entropy strength (128 = 12 words, 256 = 24 words). Default: 128

**Returns:** `string` - A new mnemonic phrase

**Example:**
```ts
const mnemonic12 = MajikKey.generateMnemonic();      // 12 words
const mnemonic24 = MajikKey.generateMnemonic(256);   // 24 words
```

---

#### `MajikKey.validateMnemonic(mnemonic)`
Validate a BIP39 mnemonic phrase.

**Parameters:**
- `mnemonic: string` - Mnemonic phrase to validate

**Returns:** `boolean` - true if valid, false otherwise

**Example:**
```ts
const isValid = MajikKey.validateMnemonic('witch collapse practice...');
```

---

### Instance Methods

#### `unlock(passphrase)`
Unlock the Majik Key by decrypting the private key.

**Parameters:**
- `passphrase: string` - Passphrase to decrypt the private key

**Returns:** `Promise<this>` - This instance for chaining

**Throws:** `MajikKeyError` if passphrase is incorrect or key is already unlocked

**Example:**
```ts
await key.unlock('my-password');
```

---

#### `lock()`
Lock the Majik Key by clearing private keys from memory.

**Returns:** `this` - This instance for chaining

**Example:**
```ts
key.lock();
```

---

#### `verify(passphrase)`
Verify that a passphrase can decrypt the private key.

**Parameters:**
- `passphrase: string` - Passphrase to verify

**Returns:** `Promise<boolean>` - true if valid, false otherwise

**Example:**
```ts
const isValid = await key.verify('my-password');
```

---

#### `updateLabel(newLabel)`
Update the label of the Majik Key.

**Parameters:**
- `newLabel: string` - New label value

**Returns:** `this` - This instance for chaining

**Example:**
```ts
key.updateLabel('Work Account');
```

---

#### `updatePassphrase(currentPassphrase, newPassphrase)`
Change the passphrase used to encrypt the private key.

**Parameters:**
- `currentPassphrase: string` - Current passphrase
- `newPassphrase: string` - New passphrase

**Returns:** `Promise<this>` - This instance for chaining

**Throws:** `MajikKeyError` if current passphrase is incorrect

**Example:**
```ts
await key.updatePassphrase('old-password', 'new-password');
```

---

#### `getPrivateKey()`
Get the private key (only when unlocked).

**Returns:** `CryptoKey | { raw: Uint8Array }` - The private key

**Throws:** `MajikKeyError` if the key is locked

**Example:**
```ts
const privateKey = key.getPrivateKey();
```

---

#### `getPrivateKeyBase64()`
Get the private key as base64 (only when unlocked).

**Returns:** `string` - The private key in base64 format

**Throws:** `MajikKeyError` if the key is locked

**Example:**
```ts
const privateKeyBase64 = key.getPrivateKeyBase64();
```

---

#### `toJSON()`
Export to JSON format (safe for storage).

**Returns:** `MajikKeyJSON` - JSON representation (private keys never included)

**Example:**
```ts
const json = key.toJSON();
localStorage.setItem('myKey', JSON.stringify(json));
```

---

#### `toString(pretty?)`
Export to JSON string.

**Parameters:**
- `pretty?: boolean` - Whether to pretty-print. Default: false

**Returns:** `string` - JSON string representation

**Example:**
```ts
const jsonString = key.toString(true);
```

---

#### `toMnemonicJSON(mnemonic, passphrase?)`
Export to MnemonicJSON format.

**Parameters:**
- `mnemonic: string` - The BIP39 mnemonic phrase
- `passphrase?: string` - Optional passphrase

**Returns:** `MnemonicJSON` - MnemonicJSON object

**Throws:** `MajikKeyError` if the key is locked

**Example:**
```ts
const mnemonicData = key.toMnemonicJSON(mnemonic, 'encryption-phrase');
```

---

#### `exportMnemonicBackup(mnemonic)`
Export a mnemonic-encrypted backup.

**Parameters:**
- `mnemonic: string` - The original mnemonic phrase

**Returns:** `Promise<string>` - Base64-encoded backup string

**Throws:** `MajikKeyError` if the key is locked

**Example:**
```ts
const backup = await key.exportMnemonicBackup(mnemonic);
```

---

#### `toContact()`
Create a MajikContact from this Majik Key.

**Returns:** `MajikContact` - A MajikContact instance

**Example:**
```ts
const contact = key.toContact();
```

---

#### `toMajikMessageIdentity(user, options?)`
Convert to MajikMessageIdentity for use in Majik Message.

**Parameters:**
- `user: MajikUser` - MajikUser instance
- `options?: { label?: string, restricted?: boolean }` - Optional configuration

**Returns:** `Promise<MajikMessageIdentity>` - MajikMessageIdentity instance

**Example:**
```ts
const identity = await key.toMajikMessageIdentity(user, {
  label: 'My Account',
  restricted: false
});
```

---

### Getters

#### `id: string`
The unique identifier (fingerprint).

#### `fingerprint: string`
The cryptographic fingerprint.

#### `publicKey: CryptoKey | { raw: Uint8Array }`
The public key.

#### `publicKeyBase64: string`
The public key in base64 format.

#### `label: string`
The user-defined label.

#### `backup: string`
The mnemonic backup identifier.

#### `timestamp: Date`
The creation timestamp.

#### `isLocked: boolean`
Whether the key is currently locked.

#### `isUnlocked: boolean`
Whether the key is currently unlocked.

#### `metadata: MajikKeyMetadata`
Safe metadata object (no sensitive data).

**Example:**
```ts
console.log(key.metadata);
// {
//   id: 'fingerprint-id',
//   fingerprint: 'fingerprint-id',
//   label: 'My Key',
//   timestamp: Date,
//   isLocked: false
// }
```

---

## Usage Examples

### Example 1: Create and Manage a Key

```ts
import { MajikKey } from '@majikah/majik-key';

async function createKey() {
  // Generate mnemonic
  const mnemonic = MajikKey.generateMnemonic();
  console.log('🔑 Save this mnemonic safely:', mnemonic);

  // Create key
  const key = await MajikKey.create(
    mnemonic,
    'secure-passphrase',
    'Personal Account'
  );

  console.log('✅ Key created!');
  console.log('ID:', key.id);
  console.log('Fingerprint:', key.fingerprint);
  console.log('Label:', key.label);

  // Save to storage
  const json = key.toJSON();
  localStorage.setItem('myKey', JSON.stringify(json));

  return { key, mnemonic };
}

createKey();
```

---

### Example 2: Lock/Unlock Pattern

```ts
import { MajikKey } from '@majikah/majik-key';

async function secureLockPattern() {
  const json = localStorage.getItem('myKey');
  const key = MajikKey.fromJSON(json);

  // Key is locked by default when loaded from JSON
  console.log('Locked:', key.isLocked); // true

  try {
    // This will throw an error
    const privateKey = key.getPrivateKey();
  } catch (error) {
    console.log('❌ Cannot access private key when locked');
  }

  // Unlock to use private key
  await key.unlock('secure-passphrase');
  console.log('Unlocked:', key.isUnlocked); // true

  // Now we can access private keys
  const privateKey = key.getPrivateKey();
  const privateKeyBase64 = key.getPrivateKeyBase64();

  // Use the key for cryptographic operations
  // ...

  // Lock again when done
  key.lock();
  console.log('🔒 Key locked again');
}

secureLockPattern();
```

---

### Example 3: Backup and Recovery

```ts
import { MajikKey } from '@majikah/majik-key';

async function backupAndRecover() {
  const mnemonic = MajikKey.generateMnemonic();
  const key = await MajikKey.create(mnemonic, 'password123', 'Original Key');

  //Download as Blob JSON File

  const jsonData = await key.toMnemonicJSON(mnemonic, 'password123');
  const jsonString = JSON.stringify(jsonData);
  const blob = new Blob([jsonString], {
    type: "application/json;charset=utf-8",
  });
  downloadBlob(
    blob,
    "json",
    `${label} | ${key.id} | SEED KEY`,
  );



  // Later... recover from backup

  //Parse the downloaded JSON into this object
  const jsonData: MnemonicJSON = {
    id: "abc123",
    seed: ["word1", "word2", ...],
    phrase: 'password123',
  };

  const recoveredKey = await MajikKey.importFromMnemonicBackup(
    jsonData.id,
    seedArrayToString(jsonData.seed),
    jsonData.phrase,
    'Recovered Key'
  );

  console.log('✅ Key recovered!');
  console.log('Same fingerprint:', key.fingerprint === recoveredKey.fingerprint);
}

backupAndRecover();
```


---

### Example 4: Update Passphrase

```ts
import { MajikKey } from '@majikah/majik-key';

async function changePassphrase() {
  const json = localStorage.getItem('myKey');
  const key = MajikKey.fromJSON(json);

  // Must unlock first
  await key.unlock('old-password');

  // Change passphrase
  await key.updatePassphrase('old-password', 'new-secure-password');
  console.log('✅ Passphrase updated!');

  // Save updated key
  localStorage.setItem('myKey', JSON.stringify(key.toJSON()));

  // Verify new passphrase works
  key.lock();
  await key.unlock('new-secure-password');
  console.log('✅ New passphrase verified!');
}

changePassphrase();
```

---

### Example 5: Verify Passphrase

```ts
import { MajikKey } from '@majikah/majik-key';

async function verifyPassphrase() {
  const json = localStorage.getItem('myKey');
  const key = MajikKey.fromJSON(json);

  // Verify without unlocking
  const isValid = await key.verify('user-entered-password');

  if (isValid) {
    console.log('✅ Passphrase is correct');
    await key.unlock('user-entered-password');
    // Proceed with operations...
  } else {
    console.log('❌ Invalid passphrase');
    // Show error to user
  }
}

verifyPassphrase();
```

---

## Integration with Majik Message

Majik Key is fully compatible with **Majik Message** as its seed phrase account implementation. Keys created with Majik Key can be directly imported into Majik Message.

### Importing to Majik Message

```ts
import { MajikKey } from '@majikah/majik-key';

async function importToMajikMessage() {
  // Create or load a Majik Key
  const mnemonic = MajikKey.generateMnemonic();
  const key = await MajikKey.create(mnemonic, 'password', 'Message Account');

  // Export to MnemonicJSON format for Majik Message
  const mnemonicData = key.toMnemonicJSON(mnemonic, 'password');
  const jsonString = JSON.stringify(mnemonicData);

  // Download this blob as a JSON locally
  const blob = new Blob([jsonString], {
    type: "application/json;charset=utf-8",
  });

  // This mnemonicData can be imported directly into Majik Message
  // as a seed phrase account
  console.log('Import the saved JSON to Majik Message:', mnemonicData);
}
```

### Converting to Majik Message Identity

```ts
import { MajikKey } from '@majikah/majik-key';
import { MajikUser } from '@thezelijah/majik-user';

async function createMessageIdentity() {
  const mnemonic = MajikKey.generateMnemonic();
  const key = await MajikKey.create(mnemonic, 'password', 'Message Identity');

  // Create/parse a MajikUser instance
  const user = new MajikUser({
    username: 'myusername',
    // ... other user properties
  });

  // Convert to Majik Message Identity
  const identity = await key.toMajikMessageIdentity(user, {
    label: 'My Message Account',
    restricted: false
  });

  console.log('Majik Message Identity created:', identity);
}
```

---

## Security Considerations

### Best Practices

1. **Never expose mnemonics**: Treat mnemonic phrases like passwords. Never log, transmit, or store them unencrypted.

2. **Use strong passphrases**: Choose passphrases with high entropy (mix of letters, numbers, symbols).

3. **Lock when not in use**: Always lock keys when private key access is not needed.

4. **Secure storage**: Store JSON exports in secure locations (encrypted databases, secure storage APIs).

5. **Backup mnemonics**: Store mnemonic phrases in multiple secure locations (password manager, paper backup, hardware wallet).

### Security Features

- **PBKDF2 Key Derivation**: 200,000 iterations with SHA-256
- **AES-GCM Encryption**: Authenticated encryption with random IVs
- **Per-Identity Salts**: Unique salt for each key prevents rainbow table attacks
- **No Private Key Exposure**: Private keys never included in JSON exports
- **Memory Management**: Private keys cleared from memory when locked

### What NOT to Do

❌ **DON'T** store mnemonics in code or version control  
❌ **DON'T** transmit mnemonics over insecure channels  
❌ **DON'T** use weak passphrases like "password123"  
❌ **DON'T** share mnemonics or passphrases with anyone  
❌ **DON'T** screenshot or photograph mnemonics  

### What TO Do

✅ **DO** use password managers for mnemonic storage  
✅ **DO** write mnemonics on paper and store securely  
✅ **DO** use hardware security modules when possible  
✅ **DO** test recovery procedures before relying on them  
✅ **DO** keep multiple encrypted backups in different locations  

---

### Tips & Reminders

#### For Developers

- **Remember**: Always validate user input before creating or unlocking keys.

- **Security**: Never log sensitive data (mnemonics, private keys, passphrases) in production.

- **Performance**: Lock keys when not in use to free memory and reduce attack surface.

- **Testing**: Test backup/recovery procedures in development before deploying to production.

- **Dependencies**: Keep `@scure/bip39` and other crypto dependencies up to date.

#### For Users

- **Backup**: Always keep multiple backups of your mnemonic phrase in secure locations.

- **Passphrase**: Use a strong, unique passphrase for each Majik Key.

- **Recovery**: Test your ability to recover keys from backups before you need to.

- **Organization**: Use meaningful labels to identify different keys.
- **Loss Prevention**: Losing your mnemonic phrase means permanent loss of access to your key.

---

## Related Projects

### [Majik Message](https://message.majikah.solutions)
Secure messaging platform using Majik Keys

[Read more about Majik Message here](https://majikah.solutions/products/majik-message)

[![Majik Message Thumbnail](https://gydzizwxtftlmsdaiouw.supabase.co/storage/v1/object/public/bucket-majikah-public/main/Majikah_MajikMessage_SocialCard.webp)](https://message.majikah.solutions)

> Click the image to try Majik Message live.

[Read Docs](https://majikah.solutions/products/majik-message/docs)


Also available on [Microsoft Store](https://apps.microsoft.com/detail/9pmjgvzzjspn) for free.

[Official Repository](https://github.com/Majikah/majik-message)
[SDK Library](https://www.npmjs.com/package/@majikah/majik-message)

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
- **Project Repository**: [https://github.com/jedlsf/majik-key](https://github.com/jedlsf/majik-key)

---

## Contact

- **Business Email**: [business@thezelijah.world](mailto:business@thezelijah.world)
- **Official Website**: [https://www.thezelijah.world](https://www.thezelijah.world)

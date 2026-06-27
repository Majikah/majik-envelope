// majik-envelope.test.ts
//
// These tests exercise MajikEnvelope against real post-quantum cryptography
// (@noble/post-quantum ML-KEM-768) and real AES-256-GCM. We avoid mocking the
// core crypto layer so that real encapsulation/decapsulation cycles are verified,
// ensuring the underlying 32-byte shared secrets properly flow into the AES
// symmetric ciphers.

import { Buffer } from "node:buffer";

import { describe, it, expect, vi, beforeAll } from "vitest";
import { MajikEnvelope } from "../src/majik-envelope";
import { generateMlKemKeypair } from "../src/core/crypto/crypto-provider";
import { MajikEnvelopeError } from "../src/core/error";
import type { MajikIdentity, MajikRecipient } from "../src/majik-envelope";
import type { MajikContact } from "@majikah/majik-contact";

const CRYPTO_TIMEOUT = 30_000;

// ── MOCK DEPENDENCIES ────────────────────────────────────────────────────────

vi.mock("../src/core/compressor/majik-compressor", () => ({
  MajikCompressor: {
    compress: vi.fn(async (type: string, text: string) => `mjkcmp:${text}`),
    decompress: vi.fn(async (type: string, text: string) =>
      text.replace(/^mjkcmp:/, ""),
    ),
  },
}));

// Quick Base64 utility to generate valid mock fingerprints and keys
function dummyBase64String(length: number): string {
  const bytes = new Uint8Array(length).fill(1);
  return Buffer.from(bytes).toString("base64");
}

// ── TEST HELPERS ─────────────────────────────────────────────────────────────

interface TestUser {
  recipient: MajikRecipient;
  identity: MajikIdentity;
}

/** Generates a real ML-KEM-768 keypair for use in test envelopes */
function createTestUser(name: string): TestUser {
  const keys = generateMlKemKeypair();

  // Real fingerprints in MajikMessage are 32-byte Base64 strings (SHA-256)
  // We MUST use valid base64 here, otherwise MajikEnvelope.toBinary() will throw.
  const fingerprintBytes = new Uint8Array(32).fill(name.charCodeAt(0));
  const fingerprint = Buffer.from(fingerprintBytes).toString("base64");

  return {
    recipient: { fingerprint, mlKemPublicKey: keys.publicKey },
    identity: { fingerprint, mlKemSecretKey: keys.secretKey },
  };
}

// ── TEST SUITE ───────────────────────────────────────────────────────────────

describe("MajikEnvelope Class Unit Tests", () => {
  let alice: TestUser;
  let bob: TestUser;
  let charlie: TestUser;

  const DUMMY_PLAINTEXT = "Hello, post-quantum world! This message is secret.";

  beforeAll(() => {
    // Generate real ML-KEM keypairs for test actors
    alice = createTestUser("alice");
    bob = createTestUser("bob");
    charlie = createTestUser("charlie");
  });

  // ── 1. VALIDATION & ERROR HANDLING ──────────────────────────────────────────
  describe("Validation & Errors", () => {
    it("should reject encryption with empty plaintext", async () => {
      await expect(
        MajikEnvelope.encrypt({
          plaintext: "   ",
          recipients: [alice.recipient],
        }),
      ).rejects.toThrow(MajikEnvelopeError);
    });

    it("should reject encryption with no recipients", async () => {
      await expect(
        MajikEnvelope.encrypt({
          plaintext: DUMMY_PLAINTEXT,
          recipients: [],
        }),
      ).rejects.toThrow(MajikEnvelopeError);
    });

    it("should reject group encryption without a sender fingerprint", async () => {
      await expect(
        MajikEnvelope.encrypt({
          plaintext: DUMMY_PLAINTEXT,
          recipients: [alice.recipient, bob.recipient],
          // Missing senderFingerprint
        }),
      ).rejects.toThrow(/senderFingerprint is required for group messages/);
    });

    it("should reject recipients with invalid ML-KEM public key lengths", async () => {
      const invalidRecipient: MajikRecipient = {
        fingerprint: dummyBase64String(32),
        mlKemPublicKey: new Uint8Array(10), // Expected 1184
      };

      await expect(
        MajikEnvelope.encrypt({
          plaintext: DUMMY_PLAINTEXT,
          recipients: [invalidRecipient],
        }),
      ).rejects.toThrow(/mlKemPublicKey must be 1184 bytes/);
    });
  });

  // ── 2. SINGLE RECIPIENT TESTS ──────────────────────────────────────────────
  describe("Single Recipient (1-to-1 Encryption)", () => {
    let singleEnvelope: MajikEnvelope;

    it(
      "should correctly encrypt for a single recipient",
      async () => {
        singleEnvelope = await MajikEnvelope.encrypt({
          plaintext: DUMMY_PLAINTEXT,
          recipients: [alice.recipient],
        });

        expect(singleEnvelope).toBeInstanceOf(MajikEnvelope);
        expect(singleEnvelope.isSingle).toBe(true);
        expect(singleEnvelope.isGroup).toBe(false);
        expect(singleEnvelope.version).toBe(3);
        expect(singleEnvelope.fingerprint).toBe(alice.recipient.fingerprint);
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "should successfully decrypt using the recipient's ML-KEM secret key",
      async () => {
        const decryptedText = await singleEnvelope.decrypt(alice.identity);
        expect(decryptedText).toBe(DUMMY_PLAINTEXT);

        // Check plaintext cache property
        expect(singleEnvelope.plaintext).toBe(DUMMY_PLAINTEXT);
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "should fail to decrypt if provided the wrong identity/secret key",
      async () => {
        // Bob tries to decrypt Alice's message. ML-KEM decapsulate will return
        // garbage, causing the AES-GCM auth tag verification to fail and throw.
        await expect(singleEnvelope.decrypt(bob.identity)).rejects.toThrow(
          MajikEnvelopeError,
        );
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "should handle encryption/decryption when compression is explicitly bypassed",
      async () => {
        const uncompressedEnvelope = await MajikEnvelope.encrypt({
          plaintext: DUMMY_PLAINTEXT,
          recipients: [alice.recipient],
          compress: false,
        });

        const decryptedText = await uncompressedEnvelope.decrypt(
          alice.identity,
        );
        expect(decryptedText).toBe(DUMMY_PLAINTEXT);
      },
      CRYPTO_TIMEOUT,
    );
  });

  // ── 3. GROUP RECIPIENT TESTS ───────────────────────────────────────────────
  describe("Multi-Recipient (Group Encryption)", () => {
    let groupEnvelope: MajikEnvelope;
    // Base64 32-byte equivalent string so serialization doesn't throw
    const SENDER_FP = dummyBase64String(32);

    it(
      "should correctly encrypt for multiple recipients via AES one-time-pad mapping",
      async () => {
        groupEnvelope = await MajikEnvelope.encrypt({
          plaintext: DUMMY_PLAINTEXT,
          recipients: [alice.recipient, bob.recipient],
          senderFingerprint: SENDER_FP,
        });

        expect(groupEnvelope).toBeInstanceOf(MajikEnvelope);
        expect(groupEnvelope.isSingle).toBe(false);
        expect(groupEnvelope.isGroup).toBe(true);
        expect(groupEnvelope.fingerprint).toBe(SENDER_FP);

        // Verify internal structure flags
        const json = groupEnvelope.toJSON();
        expect("keys" in json.payload).toBe(true);
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "should decrypt successfully for Recipient A (Alice)",
      async () => {
        const decryptedText = await groupEnvelope.decrypt(alice.identity);
        expect(decryptedText).toBe(DUMMY_PLAINTEXT);
      },
      CRYPTO_TIMEOUT,
    );

    it(
      "should decrypt successfully for Recipient B (Bob)",
      async () => {
        const decryptedText = await groupEnvelope.decrypt(bob.identity);
        expect(decryptedText).toBe(DUMMY_PLAINTEXT);
      },
      CRYPTO_TIMEOUT,
    );

    it("should throw an error if an unlisted identity attempts to decrypt", async () => {
      // Charlie is not in the group payload `keys` array
      await expect(groupEnvelope.decrypt(charlie.identity)).rejects.toThrow(
        /No key entry found for fingerprint/,
      );
    });
  });

  // ── 4. SERIALIZATION & PARSING ─────────────────────────────────────────────
  describe("Serialization, Parsing, and Transport Formats", () => {
    let originalEnvelope: MajikEnvelope;

    beforeAll(async () => {
      originalEnvelope = await MajikEnvelope.encrypt({
        plaintext: "Serialization Test Payload",
        recipients: [alice.recipient],
      });
    });

    it("should cleanly execute string round-trips via Scanner Strings", async () => {
      const scannerString = originalEnvelope.toScannerString();

      expect(typeof scannerString).toBe("string");
      expect(scannerString.startsWith("~*$MJKMSG:")).toBe(true);

      const parsedEnvelope = MajikEnvelope.fromScannerString(scannerString);

      expect(parsedEnvelope).toBeInstanceOf(MajikEnvelope);
      expect(parsedEnvelope.fingerprint).toBe(originalEnvelope.fingerprint);

      const decrypted = await parsedEnvelope.decrypt(alice.identity);
      expect(decrypted).toBe("Serialization Test Payload");
    });

    it("should compile to and parse from raw Binary arrays", async () => {
      const binaryBlob = originalEnvelope.toBinary();

      expect(binaryBlob).toBeInstanceOf(ArrayBuffer);

      const parsedEnvelope = MajikEnvelope.fromBinary(binaryBlob);

      expect(parsedEnvelope.version).toBe(3);
      expect(parsedEnvelope.isSingle).toBe(true);

      const decrypted = await parsedEnvelope.decrypt(alice.identity);
      expect(decrypted).toBe("Serialization Test Payload");
    });

    it("should export to standard JSON primitives via toJSON", async () => {
      const jsonOutput = originalEnvelope.toJSON();

      expect(jsonOutput.version).toBe(3);
      expect(jsonOutput.fingerprint).toBe(originalEnvelope.fingerprint);
      expect(jsonOutput.payload).toBeDefined();

      const parsedEnvelope = MajikEnvelope.fromJSON(jsonOutput);
      expect(parsedEnvelope.fingerprint).toBe(originalEnvelope.fingerprint);
    });

    it("should throw an error if parsing a tampered or legacy scanner string", () => {
      expect(() =>
        MajikEnvelope.fromScannerString("~*$BAD_PREFIX:abcd"),
      ).toThrow(MajikEnvelopeError);

      const legacyV2Blob = new Uint8Array([
        2,
        ...new Array(32).fill(0),
        ...new TextEncoder().encode("{}"),
      ]);
      expect(() => MajikEnvelope.fromBinary(legacyV2Blob.buffer)).toThrow(
        /Unsupported envelope version: 2/,
      );
    });
  });

  // ── 5. CONTACT & RECIPIENT HELPERS ──────────────────────────────────────────
  describe("Contact Helper Mappers", () => {
    it("should map a valid MajikContact to a MajikRecipient", async () => {
      const mockContact = {
        fingerprint: dummyBase64String(32),
        mlKey: dummyBase64String(1184),
      } as MajikContact;

      const recipient =
        await MajikEnvelope.buildMajikRecipientFromContact(mockContact);

      expect(recipient.fingerprint).toBe(mockContact.fingerprint);
      expect(recipient.mlKemPublicKey.length).toBe(1184);
    });

    it("should build and deduplicate multiple recipients from contacts", async () => {
      const mockContacts = [
        { fingerprint: "fp-1", mlKey: dummyBase64String(1184) } as MajikContact,
        { fingerprint: "fp-2", mlKey: dummyBase64String(1184) } as MajikContact,
        { fingerprint: "fp-1", mlKey: dummyBase64String(1184) } as MajikContact, // Duplicate
      ];

      const recipients =
        await MajikEnvelope.buildMajikRecipientsFromContacts(mockContacts);

      expect(recipients.length).toBe(2);
      expect(recipients[0].fingerprint).toBe("fp-1");
      expect(recipients[1].fingerprint).toBe("fp-2");
    });

    it("should throw an error if a contact lacks an ML-KEM key", async () => {
      const mockContactWithoutKey = {
        fingerprint: dummyBase64String(32),
        mlKey: "",
      } as MajikContact;

      await expect(
        MajikEnvelope.buildMajikRecipientFromContact(mockContactWithoutKey),
      ).rejects.toThrow(MajikEnvelopeError);
    });
  });
});

import * as jose from "jose";
import {
  KEY_EXPORT_ALG,
  KEY_EXPORT_CONTENT_TYPE,
  KEY_EXPORT_ENC,
  KEY_EXPORT_P2C,
  KEY_EXPORT_VERSION,
  KeyExportDocument,
  KeyExportService,
} from "./key-export.service";
import { SignatureType } from "../types/key-types.enum";
import { KeyType } from "../types/key-format.enum";
import { KeyException } from "../types/custom-exceptions";

describe("KeyExportService", () => {
  const service = new KeyExportService();
  const passphrase = "correct-horse-battery";
  const document: KeyExportDocument = {
    version: KEY_EXPORT_VERSION,
    id: "did:web:example.com#key",
    signatureType: SignatureType.ED25519_2020,
    keyType: KeyType.MULTIKEY,
    publicKey: "z6MkPublic",
    privateKey: "z1PrivateSecretKeyMaterial",
  };

  it("round-trips a document and publishes the passphrase KDF parameters", async () => {
    const exportedKey = await service.encrypt(document, passphrase);
    expect(exportedKey).not.toContain(document.privateKey);
    expect(jose.decodeProtectedHeader(exportedKey)).toMatchObject({
      alg: KEY_EXPORT_ALG,
      enc: KEY_EXPORT_ENC,
      cty: KEY_EXPORT_CONTENT_TYPE,
      p2c: KEY_EXPORT_P2C,
      signatureType: document.signatureType,
      keyType: document.keyType,
    });
    await expect(service.decrypt(exportedKey, passphrase)).resolves.toEqual(
      document
    );
  });

  it("rejects a wrong passphrase", async () => {
    const exportedKey = await service.encrypt(document, passphrase);
    await expect(
      service.decrypt(exportedKey, "wrong-passphrase-value")
    ).rejects.toBeInstanceOf(KeyException);
  });

  it("rejects a tampered ciphertext", async () => {
    const exportedKey = await service.encrypt(document, passphrase);
    const parts = exportedKey.split(".");
    const ciphertext = parts[3];
    // The last base64url character can change without changing the decoded
    // bytes. Flip the first character so the ciphertext itself changes.
    parts[3] = (ciphertext.startsWith("A") ? "B" : "A") + ciphertext.slice(1);
    await expect(service.decrypt(parts.join("."), passphrase)).rejects.toThrow(
      "Failed to decrypt exported key"
    );
  });

  it("rejects a JWE that uses a different iteration count", async () => {
    const exportedKey = await new jose.CompactEncrypt(
      new TextEncoder().encode(JSON.stringify(document))
    )
      .setProtectedHeader({
        alg: KEY_EXPORT_ALG,
        enc: KEY_EXPORT_ENC,
        cty: KEY_EXPORT_CONTENT_TYPE,
      })
      .setKeyManagementParameters({ p2c: 2048 })
      .encrypt(new TextEncoder().encode(passphrase));

    await expect(service.decrypt(exportedKey, passphrase)).rejects.toThrow(
      "Unsupported exported key format"
    );
  });

  it("rejects a short passphrase", async () => {
    await expect(service.encrypt(document, "too-short")).rejects.toThrow(
      "Passphrase must be"
    );
  });
});

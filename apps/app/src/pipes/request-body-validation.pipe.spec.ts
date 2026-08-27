import { RequestBodyValidationPipe } from "./request-body-validation.pipe";
import { GenerateRequestDto, SignRequestDto } from "../types/request.dto";
import { EncryptedPayloadDto } from "../types/encrypted-payload.dto";

describe("RequestBodyValidationPipe", () => {
  const pipe = new RequestBodyValidationPipe(GenerateRequestDto);
  const bodyMeta = { type: "body" as const, metatype: Object, data: "" };

  it("rejects empty generate body", async () => {
    await expect(pipe.transform({}, bodyMeta)).rejects.toMatchObject({
      response: { statusCode: 400 },
    });
  });

  it("accepts a valid generate body", async () => {
    const result = await pipe.transform(
      {
        secrets: ["secret1"],
        identifier: "test-key",
        signatureType: "Ed25519",
        keyType: "JsonWebKey",
      },
      bodyMeta
    );
    expect(result).toBeInstanceOf(GenerateRequestDto);
  });

  it("rejects invalid keyType", async () => {
    await expect(
      pipe.transform(
        {
          secrets: ["secret1"],
          identifier: "test-key",
          signatureType: "Ed25519",
          keyType: "INVALID_TYPE",
        },
        bodyMeta
      )
    ).rejects.toMatchObject({ response: { statusCode: 400 } });
  });

  it("rejects unknown fields on plain body", async () => {
    await expect(
      pipe.transform(
        {
          secrets: ["secret1"],
          identifier: "test-key",
          signatureType: "Ed25519",
          keyType: "JsonWebKey",
          maliciousField: "x",
        },
        bodyMeta
      )
    ).rejects.toMatchObject({ response: { statusCode: 400 } });
  });

  it("validates encrypted payload shape", async () => {
    const result = await pipe.transform(
      { encryptedData: "abc" },
      bodyMeta
    );
    expect(result).toBeInstanceOf(EncryptedPayloadDto);
  });

  it("rejects empty encryptedData", async () => {
    await expect(
      pipe.transform({ encryptedData: "" }, bodyMeta)
    ).rejects.toMatchObject({ response: { statusCode: 400 } });
  });

  describe("signing key reference", () => {
    const signPipe = new RequestBodyValidationPipe(SignRequestDto);

    it("accepts an optional string keyReference", async () => {
      const result = await signPipe.transform(
        {
          secrets: ["secret1"],
          identifier: "public-key",
          keyReference: "stored-key",
        },
        bodyMeta
      );

      expect(result).toBeInstanceOf(SignRequestDto);
    });

    it("rejects a non-string keyReference", async () => {
      await expect(
        signPipe.transform(
          {
            secrets: ["secret1"],
            identifier: "public-key",
            keyReference: 123,
          },
          bodyMeta
        )
      ).rejects.toMatchObject({ response: { statusCode: 400 } });
    });
  });
});

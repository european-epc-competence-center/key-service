import { Test, TestingModule } from "@nestjs/testing";
import { INestApplication, ValidationPipe } from "@nestjs/common";
import request from "supertest";
import { AppModule } from "./../src/app.module";

describe("Input Validation (e2e)", () => {
  let app: INestApplication;

  beforeEach(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    
    // Apply the same global validation pipe as in main.ts
    app.useGlobalPipes(
      new ValidationPipe({
        whitelist: true,
        forbidNonWhitelisted: true,
        transform: true,
        disableErrorMessages: false,
        validationError: {
          target: false,
          value: false,
        },
        stopAtFirstError: false,
      })
    );
    
    await app.init();
  });

  afterEach(async () => {
    await app.close();
  });

  describe("POST /generate - Input Validation", () => {
    it("should reject empty body", () => {
      return request(app.getHttpServer())
        .post("/generate")
        .send({})
        .expect(400);
    });

    it("should reject missing secrets field", () => {
      return request(app.getHttpServer())
        .post("/generate")
        .send({
          identifier: "test-key",
          signatureType: "Ed25519",
          keyType: "JsonWebKey",
        })
        .expect(400);
    });

    it("should reject missing identifier field", () => {
      return request(app.getHttpServer())
        .post("/generate")
        .send({
          secrets: ["secret1"],
          signatureType: "Ed25519",
          keyType: "JsonWebKey",
        })
        .expect(400);
    });

    it("should reject missing signatureType field", () => {
      return request(app.getHttpServer())
        .post("/generate")
        .send({
          secrets: ["secret1"],
          identifier: "test-key",
          keyType: "JsonWebKey",
        })
        .expect(400);
    });

    it("should reject missing keyType field", () => {
      return request(app.getHttpServer())
        .post("/generate")
        .send({
          secrets: ["secret1"],
          identifier: "test-key",
          signatureType: "Ed25519",
        })
        .expect(400);
    });

    it("should reject invalid signatureType", () => {
      return request(app.getHttpServer())
        .post("/generate")
        .send({
          secrets: ["secret1"],
          identifier: "test-key",
          signatureType: "INVALID_TYPE",
          keyType: "JsonWebKey",
        })
        .expect(400);
    });

    it("should reject invalid keyType", () => {
      return request(app.getHttpServer())
        .post("/generate")
        .send({
          secrets: ["secret1"],
          identifier: "test-key",
          signatureType: "Ed25519",
          keyType: "INVALID_TYPE",
        })
        .expect(400);
    });

    it("should reject empty secrets array", () => {
      return request(app.getHttpServer())
        .post("/generate")
        .send({
          secrets: [],
          identifier: "test-key",
          signatureType: "Ed25519",
          keyType: "JsonWebKey",
        })
        .expect(400);
    });

    it("should reject too many secrets (> 10)", () => {
      return request(app.getHttpServer())
        .post("/generate")
        .send({
          secrets: Array(11).fill("secret"),
          identifier: "test-key",
          signatureType: "Ed25519",
          keyType: "JsonWebKey",
        })
        .expect(400);
    });

    it("should reject identifier with invalid characters", () => {
      return request(app.getHttpServer())
        .post("/generate")
        .send({
          secrets: ["secret1"],
          identifier: "test@key#invalid!",
          signatureType: "Ed25519",
          keyType: "JsonWebKey",
        })
        .expect(400);
    });

    it("should reject identifier that is too long", () => {
      return request(app.getHttpServer())
        .post("/generate")
        .send({
          secrets: ["secret1"],
          identifier: "a".repeat(501), // Max is 500
          signatureType: "Ed25519",
          keyType: "JsonWebKey",
        })
        .expect(400);
    });

    it("should reject secret that is too long", () => {
      return request(app.getHttpServer())
        .post("/generate")
        .send({
          secrets: ["a".repeat(1001)], // Max is 1000
          identifier: "test-key",
          signatureType: "Ed25519",
          keyType: "JsonWebKey",
        })
        .expect(400);
    });

    it("should reject non-array secrets", () => {
      return request(app.getHttpServer())
        .post("/generate")
        .send({
          secrets: "not-an-array",
          identifier: "test-key",
          signatureType: "Ed25519",
          keyType: "JsonWebKey",
        })
        .expect(400);
    });

    it("should reject extra/unknown fields (whitelist protection)", () => {
      return request(app.getHttpServer())
        .post("/generate")
        .send({
          secrets: ["secret1"],
          identifier: "test-key",
          signatureType: "Ed25519",
          keyType: "JsonWebKey",
          maliciousField: "hacker-payload",
        })
        .expect(400);
    });
  });

  describe("POST /sign/vc/:type - Input Validation", () => {
    const validVC = {
      "@context": ["https://www.w3.org/2018/credentials/v1"],
      type: ["VerifiableCredential"],
      issuer: "did:example:123",
      credentialSubject: {
        id: "did:example:456",
      },
    };

    it("should reject empty body", () => {
      return request(app.getHttpServer())
        .post("/sign/vc/jwt")
        .send({})
        .expect(400);
    });

    it("should reject missing verifiable field", () => {
      return request(app.getHttpServer())
        .post("/sign/vc/jwt")
        .send({
          secrets: ["secret1"],
          identifier: "test-key",
        })
        .expect(400);
    });

    it("should reject missing secrets field", () => {
      return request(app.getHttpServer())
        .post("/sign/vc/jwt")
        .send({
          verifiable: validVC,
          identifier: "test-key",
        })
        .expect(400);
    });

    it("should reject missing identifier field", () => {
      return request(app.getHttpServer())
        .post("/sign/vc/jwt")
        .send({
          verifiable: validVC,
          secrets: ["secret1"],
        })
        .expect(400);
    });

    it("should reject invalid sign type in URL param", () => {
      return request(app.getHttpServer())
        .post("/sign/vc/invalid-type")
        .send({
          verifiable: validVC,
          secrets: ["secret1"],
          identifier: "test-key",
        })
        .expect(400);
    });

    it("should reject extra/unknown fields", () => {
      return request(app.getHttpServer())
        .post("/sign/vc/jwt")
        .send({
          verifiable: validVC,
          secrets: ["secret1"],
          identifier: "test-key",
          maliciousField: "hacker-payload",
        })
        .expect(400);
    });
  });
});

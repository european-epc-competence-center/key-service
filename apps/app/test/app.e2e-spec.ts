import { Test, TestingModule } from "@nestjs/testing";
import { INestApplication } from "@nestjs/common";
import request from "supertest";
import { AppModule } from "./../src/app.module";

describe("AppController (e2e)", () => {
  let app: INestApplication;

  beforeEach(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    await app.init();
  });

  afterEach(async () => {
    await app.close();
  });

  it("GET /health", () => {
    return request(app.getHttpServer()).get("/health").expect(200);
  });

  it("POST /export then POST /import stores the key under new secrets", async () => {
    const secrets = ["e2e-export-secret"];
    const importedSecrets = ["e2e-import-secret"];
    const passphrase = "e2e-export-passphrase";
    const identifier = `e2e-export-${Date.now()}`;
    const importedId = `${identifier}-copy`;

    const generated = await request(app.getHttpServer())
      .post("/generate")
      .send({
        secrets,
        identifier,
        signatureType: "Ed25519",
        keyType: "Multikey",
      })
      .expect(201);

    const exported = await request(app.getHttpServer())
      .post("/export")
      .send({
        secrets,
        identifier: generated.body.id,
        passphrase,
      })
      .expect(201);

    expect(exported.body.exportedKey).toEqual(expect.any(String));
    expect(exported.body.exportedKey).not.toContain(
      generated.body.publicKeyMultibase
    );

    const imported = await request(app.getHttpServer())
      .post("/import")
      .send({
        secrets: importedSecrets,
        passphrase,
        exportedKey: exported.body.exportedKey,
        identifier: importedId,
      })
      .expect(201);

    expect(imported.body.publicKeyMultibase).toBe(
      generated.body.publicKeyMultibase
    );
    expect(imported.body.id).toBe(importedId);

    const signed = await request(app.getHttpServer())
      .post("/sign/raw")
      .send({
        secrets: importedSecrets,
        identifier: importedId,
        data: Buffer.from("hello").toString("base64"),
      })
      .expect(201);

    expect(signed.body.signature).toEqual(expect.any(String));

    await request(app.getHttpServer())
      .post("/delete")
      .send({ secrets, identifier: generated.body.id })
      .expect(201);
    await request(app.getHttpServer())
      .post("/delete")
      .send({ secrets: importedSecrets, identifier: importedId })
      .expect(201);
  });
});

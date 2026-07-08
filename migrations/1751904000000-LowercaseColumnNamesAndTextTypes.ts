import { MigrationInterface, QueryRunner } from "typeorm";

export class LowercaseColumnNamesAndTextTypes1751904000000
  implements MigrationInterface
{
  name = "LowercaseColumnNamesAndTextTypes1751904000000";

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP INDEX IF EXISTS "IDX_keys_created_at"`);
    await queryRunner.query(`DROP INDEX IF EXISTS "IDX_keys_identifier"`);
    await queryRunner.query(`DROP INDEX IF EXISTS "IDX_keys_type_signature"`);
    await queryRunner.query(
      `ALTER TABLE "keys" DROP CONSTRAINT IF EXISTS "UQ_keys_identifier_type_signature"`
    );

    await queryRunner.query(
      `ALTER TABLE "keys" RENAME COLUMN "keyType" TO "keytype"`
    );
    await queryRunner.query(
      `ALTER TABLE "keys" RENAME COLUMN "signatureType" TO "signaturetype"`
    );
    await queryRunner.query(
      `ALTER TABLE "keys" RENAME COLUMN "encryptedPrivateKey" TO "encryptedprivatekey"`
    );
    await queryRunner.query(
      `ALTER TABLE "keys" RENAME COLUMN "encryptedPublicKey" TO "encryptedpublickey"`
    );
    await queryRunner.query(
      `ALTER TABLE "keys" RENAME COLUMN "createdAt" TO "createdat"`
    );

    await queryRunner.query(
      `ALTER TABLE "keys" ALTER COLUMN "identifier" TYPE text`
    );
    await queryRunner.query(
      `ALTER TABLE "keys" ALTER COLUMN "keytype" TYPE text`
    );
    await queryRunner.query(
      `ALTER TABLE "keys" ALTER COLUMN "signaturetype" TYPE text`
    );

    await queryRunner.query(
      `CREATE INDEX "IDX_keys_identifier" ON "keys" ("identifier")`
    );
    await queryRunner.query(
      `CREATE INDEX "IDX_keys_created_at" ON "keys" ("createdat")`
    );
    await queryRunner.query(
      `CREATE INDEX "IDX_keys_type_signature" ON "keys" ("keytype", "signaturetype")`
    );
    await queryRunner.query(
      `ALTER TABLE "keys" ADD CONSTRAINT "UQ_keys_identifier_type_signature" UNIQUE ("identifier", "keytype", "signaturetype")`
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP INDEX IF EXISTS "IDX_keys_created_at"`);
    await queryRunner.query(`DROP INDEX IF EXISTS "IDX_keys_identifier"`);
    await queryRunner.query(`DROP INDEX IF EXISTS "IDX_keys_type_signature"`);
    await queryRunner.query(
      `ALTER TABLE "keys" DROP CONSTRAINT IF EXISTS "UQ_keys_identifier_type_signature"`
    );

    await queryRunner.query(
      `ALTER TABLE "keys" ALTER COLUMN "identifier" TYPE character varying(255)`
    );
    await queryRunner.query(
      `ALTER TABLE "keys" ALTER COLUMN "keytype" TYPE character varying(50)`
    );
    await queryRunner.query(
      `ALTER TABLE "keys" ALTER COLUMN "signaturetype" TYPE character varying(50)`
    );

    await queryRunner.query(
      `ALTER TABLE "keys" RENAME COLUMN "keytype" TO "keyType"`
    );
    await queryRunner.query(
      `ALTER TABLE "keys" RENAME COLUMN "signaturetype" TO "signatureType"`
    );
    await queryRunner.query(
      `ALTER TABLE "keys" RENAME COLUMN "encryptedprivatekey" TO "encryptedPrivateKey"`
    );
    await queryRunner.query(
      `ALTER TABLE "keys" RENAME COLUMN "encryptedpublickey" TO "encryptedPublicKey"`
    );
    await queryRunner.query(
      `ALTER TABLE "keys" RENAME COLUMN "createdat" TO "createdAt"`
    );

    await queryRunner.query(
      `CREATE INDEX "IDX_keys_identifier" ON "keys" ("identifier")`
    );
    await queryRunner.query(
      `CREATE INDEX "IDX_keys_created_at" ON "keys" ("createdAt")`
    );
  }
}

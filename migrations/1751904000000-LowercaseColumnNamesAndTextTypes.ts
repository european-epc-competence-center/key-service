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
      `ALTER TABLE "keys" RENAME COLUMN "keyType" TO "key_type"`
    );
    await queryRunner.query(
      `ALTER TABLE "keys" RENAME COLUMN "signatureType" TO "signature_type"`
    );
    await queryRunner.query(
      `ALTER TABLE "keys" RENAME COLUMN "encryptedPrivateKey" TO "encrypted_private_key"`
    );
    await queryRunner.query(
      `ALTER TABLE "keys" RENAME COLUMN "encryptedPublicKey" TO "encrypted_public_key"`
    );
    await queryRunner.query(
      `ALTER TABLE "keys" RENAME COLUMN "createdAt" TO "created_at"`
    );

    await queryRunner.query(
      `ALTER TABLE "keys" ALTER COLUMN "identifier" TYPE text`
    );
    await queryRunner.query(
      `ALTER TABLE "keys" ALTER COLUMN "key_type" TYPE text`
    );
    await queryRunner.query(
      `ALTER TABLE "keys" ALTER COLUMN "signature_type" TYPE text`
    );

    await queryRunner.query(
      `CREATE INDEX "IDX_keys_identifier" ON "keys" ("identifier")`
    );
    await queryRunner.query(
      `CREATE INDEX "IDX_keys_created_at" ON "keys" ("created_at")`
    );
    await queryRunner.query(
      `CREATE INDEX "IDX_keys_type_signature" ON "keys" ("key_type", "signature_type")`
    );
    await queryRunner.query(
      `ALTER TABLE "keys" ADD CONSTRAINT "UQ_keys_identifier_type_signature" UNIQUE ("identifier", "key_type", "signature_type")`
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
      `ALTER TABLE "keys" ALTER COLUMN "key_type" TYPE character varying(50)`
    );
    await queryRunner.query(
      `ALTER TABLE "keys" ALTER COLUMN "signature_type" TYPE character varying(50)`
    );

    await queryRunner.query(
      `ALTER TABLE "keys" RENAME COLUMN "key_type" TO "keyType"`
    );
    await queryRunner.query(
      `ALTER TABLE "keys" RENAME COLUMN "signature_type" TO "signatureType"`
    );
    await queryRunner.query(
      `ALTER TABLE "keys" RENAME COLUMN "encrypted_private_key" TO "encryptedPrivateKey"`
    );
    await queryRunner.query(
      `ALTER TABLE "keys" RENAME COLUMN "encrypted_public_key" TO "encryptedPublicKey"`
    );
    await queryRunner.query(
      `ALTER TABLE "keys" RENAME COLUMN "created_at" TO "createdAt"`
    );

    await queryRunner.query(
      `CREATE INDEX "IDX_keys_identifier" ON "keys" ("identifier")`
    );
    await queryRunner.query(
      `CREATE INDEX "IDX_keys_created_at" ON "keys" ("createdAt")`
    );
  }
}

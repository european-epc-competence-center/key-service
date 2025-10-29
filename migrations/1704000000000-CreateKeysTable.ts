import { MigrationInterface, QueryRunner } from "typeorm";

export class CreateKeysTable1704000000000 implements MigrationInterface {
  name = "CreateKeysTable1704000000000";

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
            CREATE TABLE "keys" (
                "id" uuid NOT NULL DEFAULT uuid_generate_v4(),
                "identifier" character varying(255) NOT NULL,
                "keyType" character varying(50) NOT NULL,
                "signatureType" character varying(50) NOT NULL,
                "encryptedPrivateKey" text NOT NULL,
                "encryptedPublicKey" text NOT NULL,
                "createdAt" TIMESTAMP NOT NULL DEFAULT now(),
                CONSTRAINT "PK_keys_id" PRIMARY KEY ("id")
            )
        `);

    // Create index on identifier for fast lookups (non-unique since same identifier can have multiple keys)
    await queryRunner.query(`
            CREATE INDEX "IDX_keys_identifier" ON "keys" ("identifier")
        `);

    // Add index on createdAt for time-based queries
    await queryRunner.query(`
            CREATE INDEX "IDX_keys_created_at" ON "keys" ("createdAt")
        `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP INDEX "IDX_keys_created_at"`);
    await queryRunner.query(`DROP INDEX "IDX_keys_identifier"`);
    await queryRunner.query(`DROP TABLE "keys"`);
  }
}

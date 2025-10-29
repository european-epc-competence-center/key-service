import { TypeOrmModuleOptions } from "@nestjs/typeorm";
import { EncryptedKey } from "../src/key-services/entities/encrypted-key.entity";

export const testDatabaseConfig: TypeOrmModuleOptions = {
  type: "postgres",
  host: process.env.TEST_DB_HOST || "localhost",
  port: parseInt(process.env.TEST_DB_PORT || "5433"),
  username: process.env.TEST_DB_USERNAME || "postgres",
  password: process.env.TEST_DB_PASSWORD || "postgres",
  database: process.env.TEST_DB_NAME || "key_service_test",
  entities: [EncryptedKey],
  synchronize: true, // Auto-create tables for tests
  dropSchema: true, // Clean schema on each test run
  logging: false,
  ssl: false,
};

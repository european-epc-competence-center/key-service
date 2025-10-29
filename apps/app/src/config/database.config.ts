import { TypeOrmModuleOptions } from "@nestjs/typeorm";
import { DataSourceOptions } from "typeorm";
import { EncryptedKey } from "../key-services/entities/encrypted-key.entity";

// Shared base configuration for both NestJS and TypeORM CLI
export const baseDbConfig: DataSourceOptions = {
  type: "postgres",
  host: process.env.DB_HOST || "localhost",
  port: parseInt(process.env.DB_PORT || "5432"),
  username: process.env.DB_USERNAME || "postgres",
  password: process.env.DB_PASSWORD || "postgres",
  database: process.env.DB_NAME || "key_service",
  entities: [EncryptedKey],
  logging: process.env.NODE_ENV !== "production",
  ssl: process.env.DB_SSL === "true" ? { rejectUnauthorized: false } : false,
};

// NestJS runtime configuration
export const databaseConfig: TypeOrmModuleOptions = {
  ...baseDbConfig,
  // Development: auto-sync schema changes
  synchronize: process.env.NODE_ENV !== "production",
  // Production: run migrations automatically on startup
  migrationsRun: process.env.NODE_ENV === "production",
  migrations:
    process.env.NODE_ENV === "production" ? ["dist/migrations/[0-9]*.js"] : [],
};

// TypeORM CLI configuration (for migrations)
export const cliDbConfig: DataSourceOptions = {
  ...baseDbConfig,
  migrations: ["migrations/[0-9]*.ts"],
  synchronize: false, // Never auto-sync when using CLI
};

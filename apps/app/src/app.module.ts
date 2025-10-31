import { Module } from "@nestjs/common";
import { TypeOrmModule } from "@nestjs/typeorm";
import { AppController } from "./app.controller";
import { AppService } from "./app.service";
import { JwtSigningService } from "./signing-services/jwt-signing.service";
import { DataIntegritySigningService } from "./signing-services/data-integrity-signing.service";
import { KeyService } from "./key-services/key.service";
import { SecretService } from "./key-services/secret.service";
import { KeyStorageService } from "./key-services/key-storage.service";
import { FailedAttemptsCacheService } from "./key-services/failed-attempts-cache.service";
import { PayloadEncryptionService } from "./key-services/payload-encryption.service";
import { DocumentLoaderService } from "./utils/document-loader.service";
import { EncryptedKey } from "./key-services/entities/encrypted-key.entity";
import { databaseConfig } from "./config/database.config";
import { HealthModule } from "./health/health.module";

@Module({
  imports: [
    TypeOrmModule.forRoot(databaseConfig),
    TypeOrmModule.forFeature([EncryptedKey]),
    HealthModule,
  ],
  controllers: [AppController],
  providers: [
    AppService,
    JwtSigningService,
    DataIntegritySigningService,
    KeyService,
    SecretService,
    KeyStorageService,
    FailedAttemptsCacheService,
    PayloadEncryptionService,
    DocumentLoaderService,
  ],
})
export class AppModule {}

import { NestFactory } from "@nestjs/core";
import { ValidationPipe } from "@nestjs/common";
import { AppModule } from "./app.module";
import { GlobalExceptionFilter } from "./filters/global-exception.filter";
import { getAppVersion } from "./utils/version.util";
import { corsConfig } from "./config/cors.config";

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const version = getAppVersion();
  const port = process.env.port ?? 3000;

  console.log(`🚀 Starting key-service v${version}`);

  // Configure CORS based on environment settings
  if (corsConfig.enabled) {
    if (corsConfig.options) {
      app.enableCors(corsConfig.options);
      console.log(`🔒 CORS enabled with restricted origins: ${corsConfig.options.origin}`);
    } else {
      app.enableCors();
      console.log(`⚠️  CORS enabled with ALL origins allowed (not recommended for production)`);
    }
  } else {
    console.log(`🚫 CORS disabled`);
  }

  // Apply global exception filter
  app.useGlobalFilters(new GlobalExceptionFilter());

  // Enable global input validation with security settings
  app.useGlobalPipes(
    new ValidationPipe({
      // Strip properties that don't have decorators
      whitelist: true,
      // Throw an error if non-whitelisted properties are present
      forbidNonWhitelisted: true,
      // Automatically transform payloads to DTO instances
      transform: true,
      // Disable implicit type conversion for better security
      disableErrorMessages: false,
      // Return detailed validation error messages
      validationError: {
        target: false, // Don't expose the target object in error messages
        value: false, // Don't expose the rejected value in error messages
      },
      // Stop validation on first error for performance
      stopAtFirstError: false,
    })
  );
  console.log(`🔒 Input validation enabled with security settings`);

  await app.listen(port);
  console.log(`✅ key-service v${version} is running on port ${port}`);
}
bootstrap();

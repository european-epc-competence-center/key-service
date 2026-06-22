import { NestFactory } from "@nestjs/core";
import { ValidationPipe } from "@nestjs/common";
import type { IncomingMessage, ServerResponse } from "http";
import type { TLSSocket } from "tls";
import { AppModule } from "./app.module";
import { GlobalExceptionFilter } from "./filters/global-exception.filter";
import { getAppVersion } from "./utils/version.util";
import { corsConfig } from "./config/cors.config";
import { buildHttpTlsConfig, describeHttpTlsConfig } from "./config/http-tls.config";

const HEALTH_PATHS = new Set(["/health", "/health/liveness", "/health/readiness"]);

function isHealthPath(url: string | undefined): boolean {
  if (!url) {
    return false;
  }
  return HEALTH_PATHS.has(url.split("?")[0] ?? "");
}

function configureInternalMtlsGate(
  app: Awaited<ReturnType<typeof NestFactory.create>>,
  mtlsEnabled: boolean
): void {
  if (!mtlsEnabled) {
    return;
  }

  app.use((req: IncomingMessage, res: ServerResponse, next: () => void) => {
    if (isHealthPath(req.url)) {
      next();
      return;
    }

    const socket = req.socket as TLSSocket;
    if (!socket.authorized) {
      res.statusCode = 401;
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify({ message: "Client certificate required" }));
      return;
    }

    next();
  });
}

async function bootstrap() {
  const httpTls = buildHttpTlsConfig();
  const app = await NestFactory.create(
    AppModule,
    httpTls.enabled ? { httpsOptions: httpTls.httpsOptions } : {}
  );
  configureInternalMtlsGate(app, httpTls.mtls);
  const version = getAppVersion();
  const port = process.env.port ?? 3000;

  console.log(`🚀 Starting key-service v${version}`);
  console.log(`🔐 Internal HTTP transport: ${describeHttpTlsConfig(httpTls)}`);

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

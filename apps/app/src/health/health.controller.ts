import { Controller, Get } from "@nestjs/common";
import {
  HealthCheck,
  HealthCheckService,
  TypeOrmHealthIndicator,
} from "@nestjs/terminus";
import { getAppVersion } from "../utils/version.util";

interface ExtendedHealthResponse {
  status: string;
  info?: any;
  error?: any;
  details: any;
  service: {
    name: string;
    version: string;
  };
}

@Controller("health")
export class HealthController {
  private readonly serviceName = "key-service";
  private readonly serviceVersion =
    process.env.SERVICE_VERSION || getAppVersion();

  constructor(
    private health: HealthCheckService,
    private db: TypeOrmHealthIndicator
  ) {}

  @Get()
  @HealthCheck()
  async check(): Promise<ExtendedHealthResponse> {
    const healthResult = await this.health.check([
      () => this.db.pingCheck("database"),
    ]);
    return this.addServiceInfo(healthResult);
  }

  @Get("liveness")
  @HealthCheck()
  async checkLiveness(): Promise<ExtendedHealthResponse> {
    // Basic liveness check - just returns 200 if the application is running
    const healthResult = await this.health.check([]);
    return this.addServiceInfo(healthResult);
  }

  @Get("readiness")
  @HealthCheck()
  async checkReadiness(): Promise<ExtendedHealthResponse> {
    // Readiness check - ensures database is available before serving traffic
    const healthResult = await this.health.check([
      () => this.db.pingCheck("database"),
    ]);
    return this.addServiceInfo(healthResult);
  }

  private addServiceInfo(healthResult: any): ExtendedHealthResponse {
    return {
      ...healthResult,
      service: {
        name: this.serviceName,
        version: this.serviceVersion,
      },
    };
  }
}

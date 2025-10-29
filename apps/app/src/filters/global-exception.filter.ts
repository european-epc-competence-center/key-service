import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
} from "@nestjs/common";
import { GenericApiResponse } from "../types/generic-api-response.interface";
import { logError } from "../utils/log/logger";
import { getAppVersion } from "../utils/version.util";

@Catch()
export class GlobalExceptionFilter implements ExceptionFilter {
  private readonly serviceName = "key-service";
  private readonly serviceVersion =
    process.env.SERVICE_VERSION || getAppVersion();

  catch(exception: unknown, host: ArgumentsHost): void {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse();
    const request = ctx.getRequest();

    let status: HttpStatus;
    let message: string;
    let type: string;

    if (exception instanceof HttpException) {
      status = exception.getStatus();
      const exceptionResponse = exception.getResponse();

      if (typeof exceptionResponse === "string") {
        message = exceptionResponse;
      } else if (
        typeof exceptionResponse === "object" &&
        exceptionResponse !== null
      ) {
        const responseObj = exceptionResponse as any;
        message = responseObj.message || responseObj.error || exception.message;
      } else {
        message = exception.message;
      }

      type = exception.constructor.name;
    } else if (exception instanceof Error) {
      status = HttpStatus.INTERNAL_SERVER_ERROR;
      message = exception.message || "Internal server error";
      type = exception.constructor.name;
    } else {
      status = HttpStatus.INTERNAL_SERVER_ERROR;
      message = "Unknown error occurred";
      type = "UnknownError";
    }

    // Log the error
    logError(`Error ${status}: ${message}`, {
      type,
      path: request.url,
      method: request.method,
      stack: exception instanceof Error ? exception.stack : undefined,
    });

    const errorResponse: GenericApiResponse = {
      timestamp: new Date().toISOString(),
      status: HttpStatus[status],
      statusCode: status,
      type,
      message,
      path: request.url,
      artifact: this.serviceName,
      version: this.serviceVersion,
    };

    response.status(status).json(errorResponse);
  }
}

import { HttpException, HttpStatus } from "@nestjs/common";

export class KeyException extends HttpException {
  constructor(message: string, status: HttpStatus = HttpStatus.BAD_REQUEST) {
    super(message, status);
    this.name = "KeyException";
  }
}

export class SigningException extends HttpException {
  constructor(
    message: string,
    status: HttpStatus = HttpStatus.INTERNAL_SERVER_ERROR
  ) {
    super(message, status);
    this.name = "SigningException";
  }
}

export class ValidationException extends HttpException {
  constructor(message: string, status: HttpStatus = HttpStatus.BAD_REQUEST) {
    super(message, status);
    this.name = "ValidationException";
  }
}

export class UnsupportedException extends HttpException {
  constructor(message: string, status: HttpStatus = HttpStatus.BAD_REQUEST) {
    super(message, status);
    this.name = "UnsupportedException";
  }
}

export class ConfigurationException extends HttpException {
  constructor(
    message: string,
    status: HttpStatus = HttpStatus.INTERNAL_SERVER_ERROR
  ) {
    super(message, status);
    this.name = "ConfigurationException";
  }
}

export class TooManyFailedAttemptsException extends HttpException {
  constructor(message: string, cooldownPeriodSeconds: number) {
    super(
      `${message}. Please try again after ${Math.ceil(
        cooldownPeriodSeconds / 60
      )} minutes.`,
      HttpStatus.TOO_MANY_REQUESTS
    );
    this.name = "TooManyFailedAttemptsException";
  }
}

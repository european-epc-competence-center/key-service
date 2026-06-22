import { logError } from "./log/logger";

type JoseErrorShape = Error & {
  code?: string;
  claim?: string;
  reason?: string;
  payload?: unknown;
  cause?: unknown;
  details?: unknown;
};

type SigningErrorAnalysis = {
  summaryMessage?: string;
  structuredDetails?: unknown;
  logContext: Record<string, unknown>;
};

/**
 * Builds a human-readable SigningException message from signing library errors
 * (@digitalbazaar/vc / jsonld, jose, and generic Error).
 */
export function formatSigningError(error: unknown): string {
  if (!(error instanceof Error)) {
    return "Failed to sign: Unknown error";
  }

  const { summaryMessage, structuredDetails } = analyzeSigningError(error);

  if (structuredDetails === undefined) {
    return summaryMessage
      ? `Failed to sign: ${summaryMessage}`
      : "Failed to sign: Unknown error";
  }

  const detailsText = formatErrorDetails(structuredDetails);

  if (summaryMessage) {
    return `Failed to sign: ${summaryMessage}\nDetails: ${detailsText}`;
  }

  const nestedEventMessage = extractNestedEventMessage(structuredDetails);
  if (nestedEventMessage) {
    return `Failed to sign: ${nestedEventMessage}\nDetails: ${detailsText}`;
  }

  const joseCode = extractJoseCode(structuredDetails);
  if (joseCode) {
    return `Failed to sign: ${joseCode}\nDetails: ${detailsText}`;
  }

  return `Failed to sign: ${detailsText}`;
}

/** Logs full signing error context for operators (richer than the API exception message). */
export function logSigningError(error: unknown): void {
  const { summaryMessage, logContext } = analyzeSigningError(error);
  const prefix = summaryMessage
    ? `Signing failed: ${summaryMessage}`
    : "Signing failed";
  logError(prefix, logContext);
}

function analyzeSigningError(error: unknown): SigningErrorAnalysis {
  if (!(error instanceof Error)) {
    return { logContext: { error: String(error) } };
  }

  const err = error as JoseErrorShape;
  const logContext: Record<string, unknown> = {
    name: err.name,
    message: err.message,
    stack: err.stack,
  };

  let structuredDetails: unknown | undefined;

  if (err.details !== undefined && err.details !== null) {
    structuredDetails = err.details;
    logContext.details = err.details;
  } else {
    const joseDetails = buildJoseDetails(err);
    if (joseDetails) {
      structuredDetails = joseDetails;
      Object.assign(logContext, joseDetails);
      if (err.payload !== undefined) {
        logContext.payload = err.payload;
      }
    } else if (typeof err.code === "string") {
      logContext.code = err.code;
    }
  }

  if (err.cause !== undefined) {
    logContext.cause = formatCauseForLog(err.cause);
  }

  return {
    summaryMessage: err.message?.trim() || undefined,
    structuredDetails,
    logContext,
  };
}

function buildJoseDetails(
  error: JoseErrorShape
): Record<string, unknown> | undefined {
  if (typeof error.code !== "string" || !error.code.startsWith("ERR_J")) {
    return undefined;
  }

  const details: Record<string, unknown> = { code: error.code };

  if (typeof error.claim === "string" && error.claim !== "unspecified") {
    details.claim = error.claim;
  }
  if (typeof error.reason === "string" && error.reason !== "unspecified") {
    details.reason = error.reason;
  }
  if (error.cause instanceof Error) {
    details.cause = `${error.cause.name}: ${error.cause.message}`;
  }

  return details;
}

function formatCauseForLog(cause: unknown): unknown {
  if (cause instanceof Error) {
    return {
      name: cause.name,
      message: cause.message,
      stack: cause.stack,
    };
  }
  return cause;
}

function formatErrorDetails(details: unknown): string {
  if (typeof details === "string") {
    return details;
  }
  return JSON.stringify(details, null, 2);
}

function extractNestedEventMessage(details: unknown): string | undefined {
  if (typeof details !== "object" || details === null) {
    return undefined;
  }

  const event = (details as { event?: { message?: string } }).event;
  const message = event?.message?.trim();
  return message || undefined;
}

function extractJoseCode(details: unknown): string | undefined {
  if (typeof details !== "object" || details === null) {
    return undefined;
  }

  const code = (details as { code?: string }).code;
  return typeof code === "string" && code.startsWith("ERR_J")
    ? code
    : undefined;
}

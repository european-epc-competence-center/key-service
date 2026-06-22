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
  const conciseDetail =
    structuredDetails !== undefined
      ? formatConciseDetails(structuredDetails)
      : undefined;

  if (!summaryMessage) {
    return conciseDetail
      ? `Failed to sign: ${conciseDetail}`
      : "Failed to sign: Unknown error";
  }

  if (!conciseDetail || isDetailRedundant(summaryMessage, conciseDetail)) {
    return `Failed to sign: ${summaryMessage}`;
  }

  return `Failed to sign: ${joinSigningMessageParts(summaryMessage, conciseDetail)}`;
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

type JsonLdEventShape = {
  message?: string;
  details?: { property?: string; expandedProperty?: string };
};

function formatConciseDetails(details: unknown): string | undefined {
  if (typeof details === "string") {
    return details;
  }

  if (typeof details !== "object" || details === null) {
    return undefined;
  }

  const record = details as Record<string, unknown>;

  const jsonLdEvent = formatJsonLdEventConcise(
    record.event as JsonLdEventShape | undefined,
  );
  if (jsonLdEvent) {
    return jsonLdEvent;
  }

  const joseDetail = formatJoseConcise(record);
  if (joseDetail) {
    return joseDetail;
  }

  return formatLoadingDocumentConcise(record);
}

function formatJsonLdEventConcise(
  event: JsonLdEventShape | undefined,
): string | undefined {
  const message = event?.message?.trim();
  if (!message) {
    return undefined;
  }

  const property = event?.details?.property ?? event?.details?.expandedProperty;
  if (
    property &&
    message ===
      "Dropping property that did not expand into an absolute IRI or keyword."
  ) {
    return `Dropping property '${property}' that did not expand into an absolute IRI or keyword.`;
  }

  return message;
}

function formatJoseConcise(
  details: Record<string, unknown>,
): string | undefined {
  const code = details.code;
  if (typeof code !== "string" || !code.startsWith("ERR_J")) {
    return undefined;
  }

  const parts = [code];
  if (typeof details.claim === "string") {
    parts.push(`claim: ${details.claim}`);
  }
  if (typeof details.reason === "string") {
    parts.push(`reason: ${details.reason}`);
  }
  if (typeof details.cause === "string") {
    parts.push(details.cause);
  }

  return parts.join(", ");
}

function formatLoadingDocumentConcise(
  details: Record<string, unknown>,
): string | undefined {
  if (details.code !== "loading document failed") {
    return undefined;
  }

  const url = typeof details.url === "string" ? details.url : undefined;
  const status = details.httpStatusCode;

  if (url && status !== undefined) {
    return `loading document failed for ${url} (${status})`;
  }
  if (url) {
    return `loading document failed for ${url}`;
  }

  return "loading document failed";
}

function joinSigningMessageParts(
  summaryMessage: string,
  conciseDetail: string,
): string {
  const summary = summaryMessage.trim();
  const detail = conciseDetail.trim();

  if (summary.endsWith(".")) {
    return `${summary} ${detail}`;
  }

  return `${summary}. ${detail}`;
}

function isDetailRedundant(
  summaryMessage: string,
  conciseDetail: string,
): boolean {
  const summary = summaryMessage.toLowerCase();
  const detail = conciseDetail.toLowerCase();

  if (summary.includes(detail)) {
    return true;
  }

  const urlMatch = detail.match(/for (https?:\/\/\S+)/);
  if (urlMatch && summary.includes(urlMatch[1].toLowerCase())) {
    return true;
  }

  return false;
}

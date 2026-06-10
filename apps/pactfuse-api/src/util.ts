import { createHash, randomUUID } from "node:crypto";
import { ZodError, type ZodType } from "zod";
import { canonicalizeJson, type ApiError } from "@pactfuse/evidence-schema";

export const ZERO_HASH = `0x${"0".repeat(64)}` as const;

export function sha256Hex(input: string | Buffer): `0x${string}` {
  return `0x${createHash("sha256").update(input).digest("hex")}`;
}

export function hashJson(value: unknown): `0x${string}` {
  return sha256Hex(canonicalizeJson(value));
}

export function newRequestId(prefix = "req"): string {
  return `${prefix}_${randomUUID()}`;
}

export function nowIso(): string {
  return new Date().toISOString();
}

export function parseStrict<T>(schema: ZodType<T>, value: unknown): T {
  return schema.parse(value);
}

export function toApiError(error: unknown, requestId: string): ApiError {
  if (
    error &&
    typeof error === "object" &&
    "apiError" in error &&
    typeof (error as { apiError?: unknown }).apiError === "object"
  ) {
    return (error as { apiError: ApiError }).apiError;
  }
  if (error instanceof ZodError) {
    return {
      code: "bad_request",
      message: "request failed strict schema validation",
      requestId,
      retryable: false,
      downgrade: "failed",
      details: {
        issues: error.issues.map((issue) => ({
          path: issue.path.join("."),
          message: issue.message,
        })),
      },
    };
  }
  if (error instanceof Error) {
    return {
      code: "internal_error",
      message: error.message,
      requestId,
      retryable: false,
      downgrade: "blocked",
    };
  }
  return {
    code: "internal_error",
    message: "unknown error",
    requestId,
    retryable: false,
    downgrade: "blocked",
  };
}

export function conflictError(requestId: string): ApiError {
  return {
    code: "idempotency_conflict",
    message: "same action scope and idempotency key were used with a different request hash",
    requestId,
    retryable: false,
    downgrade: "failed",
  };
}

export function badRequestError(requestId: string, message: string, details?: Record<string, unknown>): ApiError {
  return {
    code: "bad_request",
    message,
    requestId,
    retryable: false,
    downgrade: "failed",
    details: details as never,
  };
}

export function forbiddenError(requestId: string, message: string): ApiError {
  return {
    code: "forbidden",
    message,
    requestId,
    retryable: false,
    downgrade: "blocked",
  };
}

export function notFoundError(requestId: string, subject: string): ApiError {
  return {
    code: "not_found",
    message: `${subject} not found`,
    requestId,
    retryable: false,
    downgrade: "blocked",
  };
}

export function proofPendingError(requestId: string, message: string): ApiError {
  return {
    code: "proof_pending",
    message,
    requestId,
    retryable: true,
    downgrade: "pending",
  };
}

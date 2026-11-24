export type ErrorCode =
  | "BAD_USER_INPUT"
  | "UNAUTHENTICATED"
  | "FORBIDDEN"
  | "NOT_FOUND"
  | "USERNAME_TAKEN"
  | "RATE_LIMITED"
  | "INTERNAL";

const STATUS: Record<ErrorCode, number> = {
  BAD_USER_INPUT: 400,
  UNAUTHENTICATED: 401,
  FORBIDDEN: 403,
  NOT_FOUND: 404,
  USERNAME_TAKEN: 409,
  RATE_LIMITED: 429,
  INTERNAL: 500,
};

export class AppError extends Error {
  code: ErrorCode;
  status: number;
  retryAfterSec: number | undefined;
  constructor(code: ErrorCode, message: string, retryAfterSec?: number) {
    super(message);
    this.code = code;
    this.status = STATUS[code];
    this.retryAfterSec = retryAfterSec;
  }
}

import { randomUUID } from "node:crypto";
import type { NextFunction, Request, Response } from "express";

declare global {
  namespace Express {
    interface Request {
      requestId?: string;
    }
  }
}

export function attachRequestContext(request: Request, response: Response, next: NextFunction): void {
  request.requestId = randomUUID();
  response.setHeader("x-request-id", request.requestId);
  next();
}

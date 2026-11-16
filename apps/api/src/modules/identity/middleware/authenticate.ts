import type { NextFunction, Request, Response } from "express";

import { verifyAccessToken } from "../token.js";

export async function authenticate(
  request: Request,
  response: Response,
  next: NextFunction,
): Promise<void> {
  const authorization = request.header("authorization");
  const [scheme, token] = authorization?.split(" ") ?? [];

  if (scheme !== "Bearer" || !token) {
    response.status(401).json({
      error: { code: "UNAUTHENTICATED", message: "A valid access token is required." },
    });
    return;
  }

  try {
    request.principal = await verifyAccessToken(token);
    next();
  } catch {
    response.status(401).json({
      error: { code: "INVALID_TOKEN", message: "The access token is invalid or expired." },
    });
  }
}

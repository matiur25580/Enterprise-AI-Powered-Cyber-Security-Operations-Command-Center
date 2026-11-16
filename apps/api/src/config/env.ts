import "dotenv/config";

import { z } from "zod";

const developmentFallbackSecret = "development-only-secret-key-32-plus-chars";

const environmentSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  API_PORT: z.coerce.number().int().min(1).max(65_535).default(4000),
  API_HOST: z.string().min(1).default("0.0.0.0"),
  WEB_ORIGIN: z.string().url().default("http://localhost:5173"),
  MONGODB_URI: z.string().min(1).default("mongodb://localhost:27017/soc_command_center"),
  MONGODB_DB_NAME: z.string().min(1).default("soc_command_center"),
  JWT_ACCESS_SECRET: z.string(),
  JWT_REFRESH_SECRET: z.string(),
});

const isProduction = process.env.NODE_ENV === "production";
const secretNames = ["JWT_ACCESS_SECRET", "JWT_REFRESH_SECRET"] as const;

for (const name of secretNames) {
  const secret = process.env[name];

  if (isProduction && !secret) {
    throw new Error(`${name} is required in production.`);
  }
  if (isProduction && secret !== undefined && secret.length < 32) {
    throw new Error(`${name} must be at least 32 characters in production.`);
  }
  if (secret !== undefined && secret.length < 32) {
    throw new Error(`${name} must be at least 32 characters.`);
  }
}

export const env = environmentSchema.parse({
  ...process.env,
  JWT_ACCESS_SECRET: process.env.JWT_ACCESS_SECRET ?? (!isProduction ? developmentFallbackSecret : undefined),
  JWT_REFRESH_SECRET: process.env.JWT_REFRESH_SECRET ?? (!isProduction ? `${developmentFallbackSecret}-refresh` : undefined),
});

if (env.JWT_ACCESS_SECRET === env.JWT_REFRESH_SECRET) {
  throw new Error("Access and refresh token secrets must be different.");
}

import "dotenv/config";

import { z } from "zod";

const environmentSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  API_PORT: z.coerce.number().int().min(1).max(65_535).default(4000),
  API_HOST: z.string().min(1).default("0.0.0.0"),
  WEB_ORIGIN: z.string().url().default("http://localhost:5173"),
  MONGODB_URI: z.string().min(1).default("mongodb://localhost:27017/soc_command_center"),
  MONGODB_DB_NAME: z.string().min(1).default("soc_command_center"),
  JWT_ACCESS_SECRET: z.string().min(32).optional(),
  JWT_REFRESH_SECRET: z.string().min(32).optional(),
});

export const env = environmentSchema.parse(process.env);

if (env.NODE_ENV === "production" && (!env.JWT_ACCESS_SECRET || !env.JWT_REFRESH_SECRET)) {
  throw new Error("JWT_ACCESS_SECRET and JWT_REFRESH_SECRET are required in production.");
}

if (env.JWT_ACCESS_SECRET && env.JWT_REFRESH_SECRET && env.JWT_ACCESS_SECRET === env.JWT_REFRESH_SECRET) {
  throw new Error("Access and refresh token secrets must be different.");
}

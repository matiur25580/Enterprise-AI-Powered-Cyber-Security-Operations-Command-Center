import "dotenv/config";

import argon2 from "argon2";
import mongoose from "mongoose";
import { z } from "zod";

import { env } from "../config/env.js";
import { connectDatabase, disconnectDatabase } from "../config/database.js";
import { Membership } from "../modules/identity/models/Membership.js";
import { Organization } from "../modules/identity/models/Organization.js";
import { User } from "../modules/identity/models/User.js";

const bootstrapSchema = z.object({
  BOOTSTRAP_TENANT_NAME: z.string().trim().min(2).max(160),
  BOOTSTRAP_TENANT_SLUG: z.string().trim().toLowerCase().min(2).max(80).regex(/^[a-z0-9-]+$/),
  BOOTSTRAP_ADMIN_EMAIL: z.string().email().max(254),
  BOOTSTRAP_ADMIN_NAME: z.string().trim().min(2).max(120),
  BOOTSTRAP_ADMIN_PASSWORD: z.string().min(14).max(256),
});

async function main(): Promise<void> {
  const config = bootstrapSchema.parse(process.env);
  await connectDatabase();

  const emailNormalized = config.BOOTSTRAP_ADMIN_EMAIL.toLowerCase();
  const existingUser = await User.findOne({ emailNormalized }).lean();
  if (existingUser) {
    throw new Error("A user with this email already exists. Bootstrap will not reset or overwrite accounts.");
  }

  let organization = await Organization.findOne({ slug: config.BOOTSTRAP_TENANT_SLUG });
  if (!organization) {
    organization = await Organization.create({
      name: config.BOOTSTRAP_TENANT_NAME,
      slug: config.BOOTSTRAP_TENANT_SLUG,
      status: "active",
    });
  }

  const passwordHash = await argon2.hash(config.BOOTSTRAP_ADMIN_PASSWORD, {
    type: argon2.argon2id,
    memoryCost: 19_456,
    timeCost: 2,
    parallelism: 1,
  });

  const user = await User.create({
    emailNormalized,
    displayName: config.BOOTSTRAP_ADMIN_NAME,
    passwordHash,
    status: "active",
  });

  await Membership.create({
    tenantId: organization._id,
    userId: user._id,
    roles: ["super_admin"],
    status: "active",
  });

  console.info(`Created initial administrator for organization "${organization.slug}".`);
  console.info("Remove bootstrap environment variables after this command completes.");
}

main()
  .catch((error: unknown) => {
    console.error("Administrator bootstrap failed:", error instanceof Error ? error.message : "Unknown error");
    process.exitCode = 1;
  })
  .finally(async () => {
    await disconnectDatabase();
    await mongoose.disconnect();
  });

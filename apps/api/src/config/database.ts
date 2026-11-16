import mongoose from "mongoose";

import { env } from "./env.js";

let connected = false;

export async function connectDatabase(): Promise<void> {
  if (connected || mongoose.connection.readyState === 1) {
    connected = true;
    return;
  }

  mongoose.set("strictQuery", true);
  await mongoose.connect(env.MONGODB_URI, {
    dbName: env.MONGODB_DB_NAME,
    serverSelectionTimeoutMS: 5_000,
    autoIndex: env.NODE_ENV !== "production",
  });

  connected = true;
  mongoose.connection.on("disconnected", () => {
    connected = false;
    console.error("MongoDB connection lost.");
  });
  mongoose.connection.on("error", (error) => {
    connected = false;
    console.error("MongoDB connection error:", error.name);
  });
}

export function isDatabaseReady(): boolean {
  return connected && mongoose.connection.readyState === 1;
}

export async function disconnectDatabase(): Promise<void> {
  connected = false;
  await mongoose.disconnect();
}

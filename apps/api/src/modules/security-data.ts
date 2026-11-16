const sensitiveKeyPattern = /password|passwd|passphrase|token|jwt|secret|authorization|cookie|credential|api.?key|private.?key|refresh.?token|access.?token|session.?key|session.?id|auth.?token|auth.?secret|auth.?key|auth.?header|signature|csrf|xsrf|mfa.?code|one.?time.?password|\botp\b/i;
const embeddedCredentialPattern = /\b(password|passwd|passphrase|access[_ -]?token|refresh[_ -]?token|session[_ -]?id|auth[_ -]?(?:token|secret|key|header)|csrf|xsrf|mfa[_ -]?code|one[_ -]?time[_ -]?password|otp|token|secret|api[_ -]?key|private[_ -]?key|authorization|cookie|credential)\b(["']?\s*[:=]\s*["']?)([^\s,;&"']+)/gi;
const bearerPattern = /\bBearer\s+[A-Za-z0-9._~+/-]+=*/gi;
const authHeaderPattern = /\b(authorization|cookie)\b(["']?\s*[:=]\s*["]?)[^\r\n,;]+/gi;

function redactEmbeddedSecrets(value: string): string {
  return value
    .replace(bearerPattern, "Bearer [REDACTED]")
    .replace(authHeaderPattern, "$1$2[REDACTED]")
    .replace(embeddedCredentialPattern, "$1$2[REDACTED]");
}

export function sanitizeSensitiveData(value: unknown, depth = 0): unknown {
  if (depth > 12) {
    throw new Error("Structured data exceeds the maximum nesting depth.");
  }

  if (typeof value === "string") return redactEmbeddedSecrets(value);
  if (value === null || typeof value === "boolean" || typeof value === "number") {
    return value;
  }

  if (Array.isArray(value)) {
    if (value.length > 1_000) {
      throw new Error("Structured data contains too many array items.");
    }
    return value.map((item) => sanitizeSensitiveData(item, depth + 1));
  }

  if (typeof value !== "object") {
    throw new Error("Structured data must contain only JSON-compatible values.");
  }

  const entries = Object.entries(value);
  if (entries.length > 500) {
    throw new Error("Structured data contains too many fields.");
  }

  const result: Record<string, unknown> = {};
  for (const [key, nestedValue] of entries) {
    if (key === "__proto__" || key === "prototype" || key === "constructor") {
      throw new Error("Structured data contains a prohibited field name.");
    }
    result[key] = sensitiveKeyPattern.test(key)
      ? "[REDACTED]"
      : sanitizeSensitiveData(nestedValue, depth + 1);
  }
  return result;
}

export function assertJsonSize(value: unknown, maximumBytes: number): void {
  const serialized = JSON.stringify(value);
  if (Buffer.byteLength(serialized, "utf8") > maximumBytes) {
    throw new Error("Structured data exceeds the maximum allowed size.");
  }
}

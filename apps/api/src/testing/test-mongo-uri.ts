const testDatabasePrefix = "soc_api_test";
const loopbackHosts = new Set(["localhost", "127.0.0.1", "::1"]);

export function validateLocalTestMongoUri(uri: string | undefined): string | undefined {
  if (!uri) return undefined;

  let parsed: URL;
  try {
    parsed = new URL(uri);
  } catch {
    throw new Error("API_TEST_MONGODB_URI must be a valid local MongoDB test URI.");
  }

  const hostname = parsed.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  const databaseName = decodeURIComponent(parsed.pathname.replace(/^\/+/, "").split("/")[0] ?? "");
  if (
    parsed.protocol !== "mongodb:"
    || !loopbackHosts.has(hostname)
    || !new RegExp(`^${testDatabasePrefix}(?:_|$)`).test(databaseName)
  ) {
    throw new Error("Integration tests require a loopback MongoDB URI with a soc_api_test database name.");
  }

  return uri;
}

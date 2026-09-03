// Claude Code OAuth access-token import helpers. Kept free of Next/db imports
// so validation and the persistence contract can be unit tested directly.

export const CLAUDE_OAUTH_TOKEN_PREFIX = "sk-ant-oat";
export const CLAUDE_API_KEY_PREFIXES = ["sk-ant-api", "sk-ant-admin"];
export const CLAUDE_REFRESH_TOKEN_PREFIX = "sk-ant-ort";
export const CLAUDE_TOKEN_MIN_LENGTH = 20;
export const CLAUDE_TOKEN_MAX_LENGTH = 4096;
export const CLAUDE_TOKEN_AUTH_METHOD = "access_token";

const BEARER_PREFIX = /^Bearer(?:[ \t]+|$)/i;
const CONTAINS_WHITESPACE = /\s/;

function reject(reason, error) {
  return { ok: false, reason, error };
}

/** Normalize and validate a pasted Claude Code OAuth access token. */
export function normalizeClaudeOAuthToken(raw) {
  if (typeof raw !== "string") {
    return reject("missing", "Access token is required");
  }

  const token = raw.trim().replace(BEARER_PREFIX, "").trim();

  if (!token) {
    return reject("missing", "Access token is required");
  }
  if (CONTAINS_WHITESPACE.test(token)) {
    return reject("whitespace", "Access token must not contain spaces or line breaks");
  }
  if (token.length > CLAUDE_TOKEN_MAX_LENGTH) {
    return reject("too_long", `Access token is too long (max ${CLAUDE_TOKEN_MAX_LENGTH} characters)`);
  }
  if (CLAUDE_API_KEY_PREFIXES.some((prefix) => token.startsWith(prefix))) {
    return reject(
      "api_key",
      "This is an Anthropic API key, not a Claude OAuth token. Add it under the Anthropic provider instead."
    );
  }
  if (token.startsWith(CLAUDE_REFRESH_TOKEN_PREFIX)) {
    return reject(
      "refresh_token",
      "This is a Claude OAuth refresh token. Paste the access token (sk-ant-oat...) or sign in with the browser."
    );
  }
  if (!token.startsWith(CLAUDE_OAUTH_TOKEN_PREFIX) || token.length < CLAUDE_TOKEN_MIN_LENGTH) {
    return reject(
      "malformed",
      `Invalid Claude OAuth token — expected a value starting with ${CLAUDE_OAUTH_TOKEN_PREFIX}`
    );
  }

  return { ok: true, token };
}

/** Build the payload persisted for a token-only Claude connection. */
export function buildClaudeTokenConnectionInput(token, options = {}) {
  const name = typeof options.name === "string" ? options.name.trim() : "";
  return {
    provider: "claude",
    authType: "oauth",
    accessToken: token,
    ...(name ? { name } : {}),
    providerSpecificData: { authMethod: CLAUDE_TOKEN_AUTH_METHOD },
    testStatus: "active",
  };
}

/** Remove every occurrence of the token from an error before surfacing it. */
export function scrubToken(message, token) {
  if (typeof message !== "string") return "";
  if (!token) return message;
  return message.split(token).join("[redacted]");
}

/** Project a saved connection down to safe client metadata. */
export function toSafeClaudeConnection(connection) {
  return {
    id: connection?.id ?? null,
    provider: connection?.provider ?? "claude",
    authType: connection?.authType ?? "oauth",
    name: connection?.name ?? null,
    email: connection?.email ?? null,
    authMethod: CLAUDE_TOKEN_AUTH_METHOD,
  };
}

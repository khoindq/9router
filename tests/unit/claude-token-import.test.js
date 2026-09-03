import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  normalizeClaudeOAuthToken,
  buildClaudeTokenConnectionInput,
  toSafeClaudeConnection,
  scrubToken,
  CLAUDE_TOKEN_MAX_LENGTH,
} from "@/lib/oauth/utils/claudeToken.js";

const TOKEN = `sk-ant-oat01-${"a".repeat(80)}`;
const API_KEY = `sk-ant-api03-${"b".repeat(80)}`;
const REFRESH_TOKEN = `sk-ant-ort01-${"c".repeat(80)}`;

describe("normalizeClaudeOAuthToken", () => {
  it("accepts a Claude OAuth token and strips one optional Bearer prefix", () => {
    expect(normalizeClaudeOAuthToken(TOKEN)).toEqual({ ok: true, token: TOKEN });
    expect(normalizeClaudeOAuthToken(`  Bearer ${TOKEN}\n`)).toEqual({ ok: true, token: TOKEN });
  });

  it.each([undefined, null, "", "Bearer "])("rejects missing input", (input) => {
    expect(normalizeClaudeOAuthToken(input)).toMatchObject({ ok: false, reason: "missing" });
  });

  it("rejects whitespace and a doubled Bearer prefix", () => {
    expect(normalizeClaudeOAuthToken(`${TOKEN} extra`)).toMatchObject({ ok: false, reason: "whitespace" });
    expect(normalizeClaudeOAuthToken(`Bearer Bearer ${TOKEN}`)).toMatchObject({ ok: false, reason: "whitespace" });
  });

  it("rejects API keys, refresh tokens, malformed and oversized tokens", () => {
    expect(normalizeClaudeOAuthToken(API_KEY)).toMatchObject({ ok: false, reason: "api_key" });
    expect(normalizeClaudeOAuthToken(REFRESH_TOKEN)).toMatchObject({ ok: false, reason: "refresh_token" });
    expect(normalizeClaudeOAuthToken("sk-ant-oat01-abc")).toMatchObject({ ok: false, reason: "malformed" });
    expect(normalizeClaudeOAuthToken(`sk-ant-oat01-${"x".repeat(CLAUDE_TOKEN_MAX_LENGTH)}`))
      .toMatchObject({ ok: false, reason: "too_long" });
  });

  it("never echoes rejected credentials in an error", () => {
    for (const input of [API_KEY, REFRESH_TOKEN, `${TOKEN} extra`, "sk-ant-oat01-abc"]) {
      const result = normalizeClaudeOAuthToken(input);
      expect(result.ok).toBe(false);
      expect(result.error).not.toContain(input);
    }
  });
});

describe("Claude token connection contract", () => {
  it("stores access token only as OAuth with no refresh or expiry", () => {
    const input = buildClaudeTokenConnectionInput(TOKEN);
    expect(input).toEqual({
      provider: "claude",
      authType: "oauth",
      accessToken: TOKEN,
      providerSpecificData: { authMethod: "access_token" },
      testStatus: "active",
    });
    expect(input).not.toHaveProperty("refreshToken");
    expect(input).not.toHaveProperty("expiresAt");
    expect(input).not.toHaveProperty("expiresIn");
  });

  it("returns safe metadata only", () => {
    const safe = toSafeClaudeConnection({
      id: "conn-1",
      provider: "claude",
      authType: "oauth",
      name: "Account 1",
      accessToken: TOKEN,
    });
    expect(JSON.stringify(safe)).not.toContain(TOKEN);
    expect(safe).toMatchObject({
      id: "conn-1",
      provider: "claude",
      authType: "oauth",
      authMethod: "access_token",
    });
  });

  it("scrubs every occurrence of a token from errors", () => {
    expect(scrubToken(`failed: ${TOKEN} (${TOKEN})`, TOKEN))
      .toBe("failed: [redacted] ([redacted])");
  });
});

function jsonResponseMock() {
  return {
    NextResponse: {
      json(body, init = {}) {
        return new Response(JSON.stringify(body), {
          status: init.status || 200,
          headers: { "Content-Type": "application/json" },
        });
      },
    },
  };
}

function makeRequest(body) {
  return new Request("https://9router.local/api/oauth/claude/import-token", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
}

async function loadRoute(createProviderConnection) {
  vi.resetModules();
  vi.doMock("next/server", () => jsonResponseMock());
  vi.doMock("@/models", () => ({ createProviderConnection }));
  const { POST } = await import("@/app/api/oauth/claude/import-token/route.js");
  return POST;
}

describe("POST /api/oauth/claude/import-token", () => {
  let logSpy;

  beforeEach(() => {
    vi.clearAllMocks();
    logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
  });

  afterEach(() => {
    logSpy.mockRestore();
    vi.doUnmock("next/server");
    vi.doUnmock("@/models");
    vi.resetModules();
  });

  it("persists the normalized token but returns metadata only", async () => {
    const createProviderConnection = vi.fn(async (data) => ({ id: "conn-1", name: "Account 1", ...data }));
    const POST = await loadRoute(createProviderConnection);
    const response = await POST(makeRequest({ accessToken: `Bearer ${TOKEN}` }));
    const raw = await response.text();

    expect(response.status).toBe(200);
    expect(createProviderConnection).toHaveBeenCalledWith(expect.objectContaining({
      provider: "claude",
      authType: "oauth",
      accessToken: TOKEN,
    }));
    expect(raw).not.toContain(TOKEN);
  });

  it.each([API_KEY, REFRESH_TOKEN, "", `${TOKEN} extra`])("rejects invalid credentials", async (accessToken) => {
    const createProviderConnection = vi.fn();
    const POST = await loadRoute(createProviderConnection);
    const response = await POST(makeRequest({ accessToken }));

    expect(response.status).toBe(400);
    expect(createProviderConnection).not.toHaveBeenCalled();
  });

  it("scrubs the token from storage errors and logs", async () => {
    const createProviderConnection = vi.fn(async () => {
      throw new Error(`insert failed for ${TOKEN}`);
    });
    const POST = await loadRoute(createProviderConnection);
    const response = await POST(makeRequest({ accessToken: TOKEN }));
    const raw = await response.text();

    expect(response.status).toBe(500);
    expect(raw).not.toContain(TOKEN);
    expect(logSpy.mock.calls.flat().join(" ")).not.toContain(TOKEN);
  });
});

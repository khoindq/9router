import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  createProviderConnection: vi.fn(),
}));

vi.mock("next/server", () => ({
  NextResponse: {
    json(body, init = {}) {
      return new Response(JSON.stringify(body), {
        status: init.status || 200,
        headers: { "Content-Type": "application/json" },
      });
    },
  },
}));

vi.mock("@/models", () => ({
  createProviderConnection: mocks.createProviderConnection,
}));

const { GET, POST } = await import("../../src/app/api/oauth/claude/import-token/route.js");
const { DefaultExecutor } = await import("../../open-sse/executors/default.js");

function jsonRequest(body) {
  return new Request("http://localhost/api/oauth/claude/import-token", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

describe("/api/oauth/claude/import-token", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.createProviderConnection.mockImplementation(async (data) => ({ id: "conn-1", ...data }));
  });

  it("documents the JSON-only setup-token contract", async () => {
    const response = await GET();
    const body = await response.json();

    expect(response.status).toBe(200);
    expect(body).toMatchObject({
      provider: "claude",
      method: "setup_token",
      generateWith: "claude setup-token",
      refreshable: false,
    });
    expect(JSON.stringify(body)).not.toContain("sk-ant-oat01-");
  });

  it.each([
    [{}, "Access token is required"],
    [{ accessToken: "" }, "Access token is required"],
    [{ accessToken: "not-a-setup-token" }, "Expected a Claude setup token"],
    [{ accessToken: "sk-ant-oat01-has whitespace" }, "Access token format is invalid"],
    [{ accessToken: "sk-ant-oat01-test", name: 42 }, "Name must be a string"],
  ])("rejects invalid input %#", async (payload, expectedError) => {
    const response = await POST(jsonRequest(payload));
    const body = await response.json();

    expect(response.status).toBe(400);
    expect(body.error).toContain(expectedError);
    expect(mocks.createProviderConnection).not.toHaveBeenCalled();
  });

  it("rejects malformed JSON", async () => {
    const response = await POST(new Request("http://localhost/api/oauth/claude/import-token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{",
    }));

    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "Request body must be valid JSON" });
  });

  it("stores the token as a non-refreshable access-token connection", async () => {
    const token = "sk-ant-oat01-test_token-123";
    const response = await POST(jsonRequest({ accessToken: `  ${token}  `, name: "  CI token  " }));
    const body = await response.json();

    expect(response.status).toBe(200);
    expect(mocks.createProviderConnection).toHaveBeenCalledWith({
      provider: "claude",
      authType: "access_token",
      accessToken: token,
      name: "CI token",
      providerSpecificData: {
        authMethod: "setup_token",
        nonRefreshable: true,
      },
      testStatus: "active",
    });
    expect(body).toEqual({
      success: true,
      connection: {
        id: "conn-1",
        provider: "claude",
        authType: "access_token",
        name: "CI token",
        refreshable: false,
      },
    });
    expect(JSON.stringify(body)).not.toContain(token);
  });

  it("does not leak the token when persistence fails", async () => {
    const token = "sk-ant-oat01-secret-test-token";
    mocks.createProviderConnection.mockRejectedValue(new Error(`database rejected ${token}`));
    const consoleSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    const response = await POST(jsonRequest({ accessToken: token }));
    const body = await response.json();

    expect(response.status).toBe(500);
    expect(body).toEqual({ error: "Failed to import Claude setup token" });
    expect(JSON.stringify(body)).not.toContain(token);
    expect(JSON.stringify(consoleSpy.mock.calls)).not.toContain(token);
    consoleSpy.mockRestore();
  });
});

describe("Claude setup-token runtime compatibility", () => {
  it("keeps the existing 9Router OAuth bearer and Claude CLI headers", () => {
    const executor = new DefaultExecutor("claude");
    const headers = executor.buildHeaders(
      { accessToken: "sentinel-setup-token" },
      true,
      executor.buildUrl("claude-sonnet-5", true),
      "claude-sonnet-5",
    );

    expect(headers.Authorization).toBe("Bearer sentinel-setup-token");
    expect(headers["x-api-key"]).toBeUndefined();
    expect(headers.Accept).toBe("text/event-stream");
    expect(headers["Anthropic-Version"]).toBe("2023-06-01");
    expect(headers["Anthropic-Beta"]).toContain("claude-code-20250219");
    expect(headers["Anthropic-Beta"]).toContain("oauth-2025-04-20");
    expect(headers["Anthropic-Dangerous-Direct-Browser-Access"]).toBe("true");
    expect(headers["X-App"]).toBe("cli");
  });

  it("does not attempt OAuth refresh without a refresh token", async () => {
    const executor = new DefaultExecutor("claude");

    await expect(executor.refreshCredentials({ accessToken: "sentinel-setup-token" })).resolves.toBeNull();
  });
});

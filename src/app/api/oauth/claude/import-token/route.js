import { NextResponse } from "next/server";
import { createProviderConnection } from "@/models";

const TOKEN_PREFIX = "sk-ant-oat";
const MAX_TOKEN_LENGTH = 4096;
const MAX_NAME_LENGTH = 120;

function badRequest(error) {
  return NextResponse.json({ error }, { status: 400 });
}

/**
 * POST /api/oauth/claude/import-token
 * Import a long-lived token created by `claude setup-token`.
 *
 * Body: { accessToken: string, name?: string }
 */
export async function POST(request) {
  let payload;
  try {
    payload = await request.json();
  } catch {
    return badRequest("Request body must be valid JSON");
  }

  const { accessToken, name } = payload || {};
  if (typeof accessToken !== "string" || !accessToken.trim()) {
    return badRequest("Access token is required");
  }
  if (name !== undefined && typeof name !== "string") {
    return badRequest("Name must be a string");
  }

  const token = accessToken.trim();
  const connectionName = name?.trim() || "Claude Setup Token";

  if (!token.startsWith(TOKEN_PREFIX)) {
    return badRequest("Expected a Claude setup token starting with sk-ant-oat");
  }
  if (token.length > MAX_TOKEN_LENGTH || /\s/.test(token)) {
    return badRequest("Access token format is invalid");
  }
  if (connectionName.length > MAX_NAME_LENGTH) {
    return badRequest(`Name must be ${MAX_NAME_LENGTH} characters or fewer`);
  }

  try {
    const connection = await createProviderConnection({
      provider: "claude",
      authType: "access_token",
      accessToken: token,
      name: connectionName,
      providerSpecificData: {
        authMethod: "setup_token",
        nonRefreshable: true,
      },
      // setup-token is already issued by Claude Code and can be used immediately.
      // Runtime failures still update the connection status through the normal path.
      testStatus: "active",
    });

    return NextResponse.json({
      success: true,
      connection: {
        id: connection.id,
        provider: connection.provider,
        authType: connection.authType,
        name: connection.name,
        refreshable: false,
      },
    });
  } catch {
    // Keep persistence errors secret-safe: adapter errors can include bound values.
    console.error("Claude setup token import failed");
    return NextResponse.json({ error: "Failed to import Claude setup token" }, { status: 500 });
  }
}

/**
 * GET /api/oauth/claude/import-token
 * Return the JSON contract without exposing or reading stored credentials.
 */
export async function GET() {
  return NextResponse.json({
    provider: "claude",
    method: "setup_token",
    generateWith: "claude setup-token",
    endpoint: "/api/oauth/claude/import-token",
    requestBody: {
      accessToken: "required string (sk-ant-oat...)",
      name: "optional string",
    },
    refreshable: false,
  });
}

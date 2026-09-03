import { NextResponse } from "next/server";
import { createProviderConnection } from "@/models";
import {
  normalizeClaudeOAuthToken,
  buildClaudeTokenConnectionInput,
  toSafeClaudeConnection,
  scrubToken,
} from "@/lib/oauth/utils/claudeToken";

/**
 * POST /api/oauth/claude/import-token
 * Body: { accessToken: string, name?: string }
 */
export async function POST(request) {
  let token = null;
  try {
    let body;
    try {
      body = await request.json();
    } catch {
      return NextResponse.json({ error: "Invalid or empty request body" }, { status: 400 });
    }

    const normalized = normalizeClaudeOAuthToken(body?.accessToken);
    if (!normalized.ok) {
      return NextResponse.json({ error: normalized.error }, { status: 400 });
    }
    token = normalized.token;

    const connection = await createProviderConnection(
      buildClaudeTokenConnectionInput(token, { name: body?.name })
    );

    return NextResponse.json({ success: true, connection: toSafeClaudeConnection(connection) });
  } catch (error) {
    const message = scrubToken(error?.message, token) || "Failed to save Claude connection";
    console.log("Claude access token import error:", message);
    return NextResponse.json({ error: message }, { status: 500 });
  }
}

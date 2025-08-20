import { DurableObject } from "cloudflare:workers";

export interface Env {
  GITHUB_CLIENT_ID: string;
  GITHUB_CLIENT_SECRET: string;
  UserDO: DurableObjectNamespace<UserDO>;
  CodeDO: DurableObjectNamespace<CodeDO>;
}

interface OAuthState {
  redirectTo?: string;
  codeVerifier: string;
  resource?: string;
  clientId?: string;
  originalState?: string;
  redirectUri?: string;
  message?: string;
}

export interface GitHubUser {
  id: number;
  login: string;
  name: string;
  email: string;
  avatar_url: string;
  [key: string]: any;
}

export interface CloudflareAPIKey {
  id: string;
  name: string;
  accountId: string;
  apiKey: string;
  createdAt: string;
  lastUsed?: string;
}

export class UserDO extends DurableObject {
  private storage: DurableObjectStorage;

  constructor(state: DurableObjectState, env: Env) {
    super(state, env);
    this.storage = state.storage;
  }

  async setUser(user: GitHubUser, githubAccessToken: string) {
    await this.storage.put("user", user);
    await this.storage.put("github_access_token", githubAccessToken);
    await this.storage.put("last_login", new Date().toISOString());
  }

  async getUser(): Promise<{
    user: GitHubUser;
    githubAccessToken: string;
    lastLogin: string;
  } | null> {
    const user = await this.storage.get<GitHubUser>("user");
    const githubAccessToken = await this.storage.get<string>(
      "github_access_token"
    );
    const lastLogin = await this.storage.get<string>("last_login");

    if (!user || !githubAccessToken) {
      return null;
    }

    return {
      user,
      githubAccessToken,
      lastLogin: lastLogin || new Date().toISOString(),
    };
  }

  async addCloudflareKey(key: CloudflareAPIKey) {
    const keys =
      (await this.storage.get<CloudflareAPIKey[]>("cloudflare_keys")) || [];
    keys.push(key);
    await this.storage.put("cloudflare_keys", keys);
  }

  async getCloudflareKeys(): Promise<CloudflareAPIKey[]> {
    return (
      (await this.storage.get<CloudflareAPIKey[]>("cloudflare_keys")) || []
    );
  }

  async updateKeyLastUsed(keyId: string) {
    const keys =
      (await this.storage.get<CloudflareAPIKey[]>("cloudflare_keys")) || [];
    const keyIndex = keys.findIndex((k) => k.id === keyId);
    if (keyIndex !== -1) {
      keys[keyIndex].lastUsed = new Date().toISOString();
      await this.storage.put("cloudflare_keys", keys);
    }
  }

  async removeCloudflareKey(keyId: string) {
    const keys =
      (await this.storage.get<CloudflareAPIKey[]>("cloudflare_keys")) || [];
    const filteredKeys = keys.filter((k) => k.id !== keyId);
    await this.storage.put("cloudflare_keys", filteredKeys);
  }

  async updateGitHubToken(githubAccessToken: string) {
    await this.storage.put("github_access_token", githubAccessToken);
    await this.storage.put("last_login", new Date().toISOString());
  }
}

export class CodeDO extends DurableObject {
  private storage: DurableObjectStorage;

  constructor(state: DurableObjectState, env: Env) {
    super(state, env);
    this.storage = state.storage;
    // Set alarm for 10 minutes from now for auth codes
    this.storage.setAlarm(Date.now() + 10 * 60 * 1000);
  }

  async alarm() {
    await this.storage.deleteAll();
  }

  async setAuthData(
    username: string,
    githubAccessToken: string,
    clientId: string,
    redirectUri: string,
    selectedKeyId?: string,
    resource?: string,
    message?: string
  ) {
    await this.storage.put("data", {
      username,
      github_access_token: githubAccessToken,
      clientId,
      redirectUri,
      selectedKeyId,
      resource,
      message,
    });
  }

  async getAuthData() {
    return this.storage.get<{
      username: string;
      github_access_token: string;
      clientId: string;
      redirectUri: string;
      selectedKeyId?: string;
      resource?: string;
      message?: string;
    }>("data");
  }
}

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
};

export async function handleOAuth(
  request: Request,
  env: Env,
  scope = "user:email",
  sameSite: "Strict" | "Lax" = "Lax"
): Promise<Response | null> {
  const url = new URL(request.url);
  const path = url.pathname;

  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: corsHeaders,
    });
  }

  if (
    !env.GITHUB_CLIENT_ID ||
    !env.GITHUB_CLIENT_SECRET ||
    !env.UserDO ||
    !env.CodeDO
  ) {
    return new Response(
      `Environment misconfigured. Ensure to have GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET secrets set, as well as the USERS and CODES DO bindings.`,
      { status: 500 }
    );
  }

  // OAuth metadata endpoints
  if (path === "/.well-known/oauth-authorization-server") {
    return handleAuthorizationServerMetadata(request, env);
  }

  if (path === "/.well-known/oauth-protected-resource") {
    return handleProtectedResourceMetadata(request, env);
  }

  if (path === "/token") {
    return handleToken(request, env, scope);
  }

  if (path === "/authorize") {
    return handleAuthorize(request, env, scope, sameSite);
  }

  if (path === "/callback") {
    return handleCallback(request, env, sameSite);
  }

  if (path === "/logout") {
    const url = new URL(request.url);
    const redirectTo = url.searchParams.get("redirect_to") || "/";
    return new Response(null, {
      status: 302,
      headers: {
        Location: redirectTo,
        "Set-Cookie": `github_login=; HttpOnly; Secure; SameSite=${sameSite}; Max-Age=0; Path=/`,
      },
    });
  }

  if (path === "/register") {
    if (request.method !== "POST") {
      return new Response("Method not allowed", { status: 405 });
    }

    try {
      const body = await request.json<{ redirect_uris: string[] }>();

      // Validate redirect_uris is present and is an array
      if (
        !body.redirect_uris ||
        !Array.isArray(body.redirect_uris) ||
        body.redirect_uris.length === 0
      ) {
        return new Response(
          JSON.stringify({
            error: "invalid_client_metadata",
            error_description: "redirect_uris must be a non-empty array",
          }),
          {
            status: 400,
            headers: {
              "Content-Type": "application/json",
              ...corsHeaders,
            },
          }
        );
      }

      // Extract hosts from all redirect URIs
      const hosts = new Set();
      for (const uri of body.redirect_uris) {
        try {
          const url = new URL(uri);
          hosts.add(url.host);
        } catch (e) {
          return new Response(
            JSON.stringify({
              error: "invalid_redirect_uri",
              error_description: `Invalid redirect URI: ${uri}`,
            }),
            {
              status: 400,
              headers: {
                "Content-Type": "application/json",
                ...corsHeaders,
              },
            }
          );
        }
      }

      // Ensure all redirect URIs have the same host
      if (hosts.size !== 1) {
        return new Response(
          JSON.stringify({
            error: "invalid_client_metadata",
            error_description: "All redirect URIs must have the same host",
          }),
          {
            status: 400,
            headers: { "Content-Type": "application/json", ...corsHeaders },
          }
        );
      }

      const clientHost = Array.from(hosts)[0];

      // Response with client_id as the host
      const response = {
        client_id: clientHost,
        redirect_uris: body.redirect_uris,
        token_endpoint_auth_method: "none", // Public client, no secret needed
        grant_types: ["authorization_code"],
        response_types: ["code"],
      };

      return new Response(JSON.stringify(response, null, 2), {
        status: 201,
        headers: {
          "Content-Type": "application/json",
          "Cache-Control": "no-store",
          Pragma: "no-cache",
          ...corsHeaders,
        },
      });
    } catch (error) {
      return new Response(
        JSON.stringify({
          error: "invalid_client_metadata",
          error_description: "Invalid JSON in request body",
        }),
        {
          status: 400,
          headers: { "Content-Type": "application/json", ...corsHeaders },
        }
      );
    }
  }

  return null;
}

function handleAuthorizationServerMetadata(
  request: Request,
  env: Env
): Response {
  const url = new URL(request.url);
  const baseUrl = `${url.protocol}//${url.host}`;

  const metadata = {
    issuer: baseUrl,
    authorization_endpoint: `${baseUrl}/authorize`,
    token_endpoint: `${baseUrl}/token`,
    registration_endpoint: `${url.origin}/register`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code"],
    code_challenge_methods_supported: ["S256"],
    scopes_supported: ["user:email"],
    token_endpoint_auth_methods_supported: ["none"],
  };

  return new Response(JSON.stringify(metadata), {
    headers: {
      "Content-Type": "application/json",
      ...corsHeaders,
    },
  });
}

function handleProtectedResourceMetadata(request: Request, env: Env): Response {
  const url = new URL(request.url);
  const baseUrl = `${url.protocol}//${url.host}`;

  const metadata = {
    resource: baseUrl,
    authorization_servers: [baseUrl],
    bearer_methods_supported: ["header"],
    resource_documentation: `${baseUrl}`,
  };

  return new Response(JSON.stringify(metadata), {
    headers: {
      "Content-Type": "application/json",
      ...corsHeaders,
    },
  });
}

async function handleAuthorize(
  request: Request,
  env: Env,
  scope: string,
  sameSite: string
): Promise<Response> {
  const url = new URL(request.url);
  const clientId = url.searchParams.get("client_id");
  let redirectUri = url.searchParams.get("redirect_uri");
  const responseType = url.searchParams.get("response_type") || "code";
  const state = url.searchParams.get("state");
  const resource = url.searchParams.get("resource");
  let message = url.searchParams.get("message"); // New parameter

  if (message) {
    message = sanitizeMessage(message);
  }

  // If no client_id, this is a direct login request
  if (!clientId) {
    const url = new URL(request.url);
    const redirectTo = url.searchParams.get("redirect_to") || "/";
    const resource = url.searchParams.get("resource");
    const message = url.searchParams.get("message");

    // Check if user is already logged in
    const username = getGitHubUsername(request);
    if (username) {
      // User is already logged in, redirect to destination
      return new Response(null, {
        status: 302,
        headers: { Location: redirectTo },
      });
    }

    // Generate PKCE code verifier and challenge
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = await generateCodeChallenge(codeVerifier);

    const state: OAuthState = { redirectTo, codeVerifier, resource, message };
    const stateString = btoa(JSON.stringify(state));

    // Build GitHub OAuth URL
    const githubUrl = new URL("https://github.com/login/oauth/authorize");
    githubUrl.searchParams.set("client_id", env.GITHUB_CLIENT_ID);
    githubUrl.searchParams.set("redirect_uri", `${url.origin}/callback`);
    githubUrl.searchParams.set("scope", scope);
    githubUrl.searchParams.set("state", stateString);
    githubUrl.searchParams.set("code_challenge", codeChallenge);
    githubUrl.searchParams.set("code_challenge_method", "S256");

    return new Response(null, {
      status: 302,
      headers: {
        Location: githubUrl.toString(),
        "Set-Cookie": `oauth_state=${encodeURIComponent(
          stateString
        )}; HttpOnly; Secure; SameSite=${sameSite}; Max-Age=600; Path=/`,
      },
    });
  }

  // Validate client_id
  if (!isValidDomain(clientId) && clientId !== "localhost") {
    return new Response("Invalid client_id: must be a valid domain", {
      status: 400,
    });
  }

  // Validate message parameter (optional security measure)
  if (message && !isValidMessage(message)) {
    return new Response("Invalid message: contains unsafe content", {
      status: 400,
    });
  }

  // If no redirect_uri provided, use default pattern
  if (!redirectUri) {
    redirectUri = `https://${clientId}/callback`;
  }

  // Validate redirect_uri
  try {
    const redirectUrl = new URL(redirectUri);
    if (redirectUrl.protocol !== "https:" && clientId !== "localhost") {
      return new Response("Invalid redirect_uri: must use HTTPS", {
        status: 400,
      });
    }
    if (redirectUrl.hostname !== clientId) {
      return new Response(
        "Invalid redirect_uri: must be on same origin as client_id",
        {
          status: 400,
        }
      );
    }
  } catch {
    return new Response("Invalid redirect_uri format", { status: 400 });
  }

  // Only support authorization code flow
  if (responseType !== "code") {
    return new Response("Unsupported response_type", { status: 400 });
  }

  // Check if user is already authenticated
  const username = getGitHubUsername(request);
  if (username) {
    // User is authenticated, show key selection/management page
    return await showKeyManagementPage(
      request,
      env,
      clientId,
      redirectUri,
      state,
      username,
      resource,
      message
    );
  }

  // User not authenticated, redirect to GitHub OAuth
  const providerState = {
    clientId,
    redirectUri,
    originalState: state,
    resource,
    message,
  };

  const providerStateString = btoa(JSON.stringify(providerState));

  // Generate PKCE for GitHub OAuth
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = await generateCodeChallenge(codeVerifier);

  const githubState: OAuthState = {
    redirectTo: url.pathname + url.search,
    codeVerifier,
    resource,
    clientId,
    originalState: state,
    redirectUri,
    message,
  };

  const githubStateString = btoa(JSON.stringify(githubState));

  const githubUrl = new URL("https://github.com/login/oauth/authorize");
  githubUrl.searchParams.set("client_id", env.GITHUB_CLIENT_ID);
  githubUrl.searchParams.set("redirect_uri", `${url.origin}/callback`);
  githubUrl.searchParams.set("scope", scope);
  githubUrl.searchParams.set("state", githubStateString);
  githubUrl.searchParams.set("code_challenge", codeChallenge);
  githubUrl.searchParams.set("code_challenge_method", "S256");

  const headers = new Headers({ Location: githubUrl.toString() });
  headers.append(
    "Set-Cookie",
    `oauth_state=${encodeURIComponent(
      githubStateString
    )}; HttpOnly; Secure; SameSite=${sameSite}; Max-Age=600; Path=/`
  );

  return new Response(null, { status: 302, headers });
}

async function showKeyManagementPage(
  request: Request,
  env: Env,
  clientId: string,
  redirectUri: string,
  state: string | null,
  username: string,
  resource?: string,
  message?: string
): Promise<Response> {
  // Get user's data
  const userDOId = env.UserDO.idFromName(`user:${username}`);
  const userDO = env.UserDO.get(userDOId);
  const userData = await userDO.getUser();
  const keys = await userDO.getCloudflareKeys();

  if (!userData) {
    return new Response("User not found", { status: 404 });
  }

  const { user } = userData;

  // Handle form submission
  if (request.method === "POST") {
    const formData = await request.formData();
    const action = formData.get("action");

    if (action === "select") {
      const selectedKeyId = formData.get("keyId");
      if (selectedKeyId) {
        return await createAuthCodeAndRedirect(
          env,
          clientId,
          redirectUri,
          state,
          username,
          userData.githubAccessToken,
          selectedKeyId.toString(),
          resource,
          message
        );
      }
    }

    if (action === "add") {
      const name = formData.get("name")?.toString();
      const accountId = formData.get("accountId")?.toString();
      const apiKey = formData.get("apiKey")?.toString();

      if (!name || !accountId || !apiKey) {
        //@ts-ignore
        return showKeyManagementPageHTML(
          user,
          keys,
          clientId,
          "Missing required fields",
          true,
          message
        );
      }

      // Validate the API key by making a test request
      const testResponse = await fetch(
        `https://api.cloudflare.com/client/v4/accounts/${accountId}`,
        {
          headers: {
            Authorization: `Bearer ${apiKey}`,
            "Content-Type": "application/json",
          },
        }
      );

      if (!testResponse.ok) {
        return showKeyManagementPageHTML(
          user,
          keys,
          clientId,
          "Invalid API key or Account ID",
          true,
          message
        );
      }

      const newKey: CloudflareAPIKey = {
        id: crypto.randomUUID(),
        name,
        accountId,
        apiKey,
        createdAt: new Date().toISOString(),
      };

      await userDO.addCloudflareKey(newKey);

      // Redirect to same page to show updated keys
      return new Response(null, {
        status: 302,
        headers: { Location: request.url },
      });
    }

    if (action === "delete") {
      const keyId = formData.get("keyId")?.toString();
      if (keyId) {
        await userDO.removeCloudflareKey(keyId);
        return new Response(null, {
          status: 302,
          headers: { Location: request.url },
        });
      }
    }
  }

  return showKeyManagementPageHTML(
    user,
    keys,
    clientId,
    undefined,
    true,
    message
  );
}

function showKeyManagementPageHTML(
  user: GitHubUser,
  keys: CloudflareAPIKey[],
  clientId: string,
  error?: string,
  isOAuthFlow = false,
  message?: string
): Response {
  const keyOptions = keys
    .map(
      (key) => `
    <div class="key-item">
      <div class="key-info">
        <div class="key-name">${escapeHtml(key.name)}</div>
        <div class="key-details">
          <span class="key-date">Added ${new Date(
            key.createdAt
          ).toLocaleDateString()}</span>
        </div>
      </div>
      <div class="key-actions">
        ${
          isOAuthFlow
            ? `<button type="submit" name="keyId" value="${key.id}" class="btn btn-primary">Select</button>`
            : ""
        }
        <form method="POST" style="display: inline;">
          <input type="hidden" name="action" value="delete">
          <input type="hidden" name="keyId" value="${key.id}">
          <button type="submit" class="btn btn-text" title="Remove key" onclick="return confirm('Remove this API key?')">Remove</button>
        </form>
      </div>
    </div>
  `
    )
    .join("");

  // Format the authorization message
  const defaultMessage = `Access Requested to your Cloudflare account. Select an API key to grant access with the required permissions.`;
  const authMessage = message ? sanitizeMessage(message) : defaultMessage;

  return new Response(
    `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <title>${
        isOAuthFlow ? "Authorize Access" : "Manage API Keys"
      } - Simpler Auth</title>
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <meta charset="utf-8">
      <style>
        * { box-sizing: border-box; }
        
        body { 
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
          margin: 0;
          padding: 20px;
          background: #fafafa;
          color: #333;
          line-height: 1.5;
        }
        
        .container {
          max-width: 480px;
          margin: 0 auto;
          background: white;
          border-radius: 8px;
          box-shadow: 0 2px 12px rgba(0,0,0,0.08);
          border: 1px solid #e1e5e9;
        }
        
        .header {
          padding: 32px 32px 24px;
          text-align: center;
          border-bottom: 1px solid #e1e5e9;
        }
        
        .logo {
          font-size: 20px;
          font-weight: 600;
          color: #2563eb;
          margin-bottom: 8px;
        }
        
        .subtitle {
          font-size: 15px;
          color: #6b7280;
          margin: 0;
        }
        
        .content {
          padding: 32px;
        }
        
        .user-info {
          display: flex;
          align-items: center;
          padding: 16px;
          background: #f8fafc;
          border: 1px solid #e1e5e9;
          border-radius: 6px;
          margin-bottom: 24px;
        }
        
        .user-info img {
          width: 32px;
          height: 32px;
          border-radius: 50%;
          margin-right: 12px;
        }
        
        .user-name {
          font-weight: 500;
          color: #111827;
        }
        
        .oauth-notice {
          background: #fef3c7;
          border: 1px solid #f59e0b;
          border-radius: 6px;
          padding: 16px;
          margin-bottom: 24px;
          font-size: 12px;
          line-height: 1.6;
        }
        
        .oauth-notice strong {
          color: #92400e;
        }
        
        .oauth-notice .client-id {
          font-family: monospace;
          background: rgba(0,0,0,0.1);
          padding: 2px 4px;
          border-radius: 3px;
          font-weight: 600;
        }
        
        .oauth-message {
          margin-top: 8px;
          color: #374151;
        }
        
        .error {
          background: #fef2f2;
          border: 1px solid #fecaca;
          color: #b91c1c;
          padding: 12px 16px;
          border-radius: 6px;
          margin-bottom: 24px;
          font-size: 14px;
        }
        
        .section-title {
          font-size: 16px;
          font-weight: 600;
          margin: 0 0 16px 0;
          color: #111827;
        }
        
        .key-item {
          display: flex;
          align-items: center;
          justify-content: space-between;
          padding: 16px;
          border: 1px solid #e1e5e9;
          border-radius: 6px;
          margin-bottom: 12px;
          background: #fafafa;
        }
        
        .key-info {
          flex: 1;
          min-width: 0;
        }
        
        .key-name {
          font-weight: 500;
          color: #111827;
          margin-bottom: 4px;
        }
        
        .key-details {
          display: flex;
          flex-direction: column;
          gap: 2px;
        }
        
        .account-id {
          font-family: monospace;
          font-size: 12px;
          color: #6b7280;
        }
        
        .key-date {
          font-size: 12px;
          color: #9ca3af;
        }
        
        .key-actions {
          display: flex;
          gap: 8px;
          align-items: center;
          margin-left: 16px;
        }
        
        .btn {
          padding: 8px 16px;
          border: 1px solid transparent;
          border-radius: 6px;
          font-size: 14px;
          font-weight: 500;
          cursor: pointer;
          text-decoration: none;
          display: inline-flex;
          align-items: center;
          justify-content: center;
          transition: all 0.2s;
        }
        
        .btn-primary {
          background: #2563eb;
          color: white;
          border-color: #2563eb;
        }
        
        .btn-primary:hover {
          background: #1d4ed8;
          border-color: #1d4ed8;
        }
        
        .btn-text {
          background: transparent;
          color: #6b7280;
          border: none;
          padding: 4px 8px;
          font-size: 13px;
        }
        
        .btn-text:hover {
          color: #dc2626;
        }
        
        .form-section {
          margin-top: 32px;
          padding-top: 24px;
          border-top: 1px solid #e1e5e9;
        }
        
        .form-group {
          margin-bottom: 16px;
        }
        
        .form-label {
          display: block;
          font-size: 14px;
          font-weight: 500;
          color: #374151;
          margin-bottom: 6px;
        }
        
        .form-input {
          width: 100%;
          padding: 10px 12px;
          border: 1px solid #d1d5db;
          border-radius: 6px;
          font-size: 14px;
          background: white;
          transition: border-color 0.2s;
        }
        
        .form-input:focus {
          outline: none;
          border-color: #2563eb;
          box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.1);
        }
        
        .form-help {
          font-size: 12px;
          color: #6b7280;
          margin-top: 4px;
        }
        
        .help-box {
          background: #f0f9ff;
          border: 1px solid #bae6fd;
          border-radius: 6px;
          padding: 16px;
          margin-bottom: 20px;
          font-size: 13px;
          line-height: 1.6;
        }
        
        .help-box a {
          color: #2563eb;
          text-decoration: none;
        }
        
        .help-box a:hover {
          text-decoration: underline;
        }
        
        .empty-state {
          text-align: center;
          padding: 32px 16px;
          color: #6b7280;
          font-size: 14px;
        }
        
        .footer {
          padding: 24px 32px;
          text-align: center;
          border-top: 1px solid #e1e5e9;
          background: #f8fafc;
        }
        
        .footer-text {
          font-size: 12px;
          color: #9ca3af;
        }
        
        .nav-link {
          color: #6b7280;
          text-decoration: none;
          font-size: 14px;
          margin-right: 16px;
        }
        
        .nav-link:hover {
          color: #2563eb;
        }
        
        @media (max-width: 640px) {
          body { padding: 12px; }
          .container { margin: 0; }
          .header { padding: 24px 24px 20px; }
          .content { padding: 24px; }
          .key-item { flex-direction: column; align-items: flex-start; gap: 12px; }
          .key-actions { margin-left: 0; }
        }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <div class="logo">Simpler Auth</div>
          <div class="subtitle">
            ${isOAuthFlow ? "Authorize API Access" : "Manage Cloudflare Keys"}
          </div>
        </div>
        
        <div class="content">
          ${
            !isOAuthFlow
              ? `
            <div style="margin-bottom: 24px;">
              <a href="/" class="nav-link">← Back to Home</a>
              <a href="/logout" class="nav-link">Sign Out</a>
            </div>
          `
              : ""
          }
          
          <div class="user-info">
            <img src="${user.avatar_url}" alt="${escapeHtml(
      user.name || user.login
    )}">
            <div class="user-name">${escapeHtml(user.name || user.login)}</div>
          </div>
          
          ${
            isOAuthFlow
              ? `
            <div class="oauth-notice">
              <strong>⚠️ Authorization Request by <span class="client-id">${escapeHtml(
                clientId
              )}</span></strong>
              <div class="oauth-message">${authMessage}</div>
            </div>
          `
              : ""
          }
          
          ${error ? `<div class="error">${escapeHtml(error)}</div>` : ""}
          
          ${
            keys.length > 0
              ? `
            <div class="section-title">Your API Keys</div>
            <form method="POST">
              <input type="hidden" name="action" value="select">
              ${keyOptions}
            </form>
          `
              : isOAuthFlow
              ? `
            <div class="empty-state">
              <div style="font-size: 48px; margin-bottom: 16px;">🔐</div>
              <div>No API keys found</div>
              <div>Add your first Cloudflare API key below to continue</div>
            </div>
          `
              : ""
          }
          
          <div class="form-section">
            <div class="section-title">Add New API Key</div>
            
            <div class="help-box">
              <strong>How to create a Cloudflare API token:</strong><br>
              1. Visit <a href="https://dash.cloudflare.com/?to=/:account/api-tokens" target="_blank">Cloudflare Dashboard → Manage Account → Account API Tokens</a><br>
              2. Click "Create Token" and select a template or custom token with the scopes you need<br>
              3. The account-id is in the URL
            </div>
            
            <form method="POST">
              <input type="hidden" name="action" value="add">
              
              <div class="form-group">
                <label class="form-label" for="name">Key Name</label>
                <input type="text" id="name" name="name" class="form-input" required 
                       placeholder="e.g., My Website API Key">
                <div class="form-help">A name to help you identify this key</div>
              </div>
              
              <div class="form-group">
                <label class="form-label" for="accountId">Account ID</label>
                <input type="text" id="accountId" name="accountId" class="form-input" required 
                       placeholder="1234567890abcdef1234567890abcdef">
                <div class="form-help">Found in the right sidebar of your Cloudflare dashboard</div>
              </div>
              
              <div class="form-group">
                <label class="form-label" for="apiKey">API Token</label>
                <input type="password" id="apiKey" name="apiKey" class="form-input" required 
                       placeholder="Your API token">
                <div class="form-help">The token you created in the Cloudflare dashboard</div>
              </div>
              
              <button type="submit" class="btn btn-primary" style="width: 100%;">
                Add API Key
              </button>
            </form>
          </div>
        </div>
        
        <div class="footer">
          <div class="footer-text">Powered by Simpler Auth</div>
        </div>
      </div>
    </body>
    </html>
  `,
    { headers: { "Content-Type": "text/html;charset=utf8" } }
  );
}

async function createAuthCodeAndRedirect(
  env: Env,
  clientId: string,
  redirectUri: string,
  state: string | null,
  username: string,
  githubAccessToken: string,
  selectedKeyId: string,
  resource?: string,
  message?: string
): Promise<Response> {
  // Generate auth code
  const authCode = generateCodeVerifier();

  // Create Durable Object for this auth code
  const id = env.CodeDO.idFromName(`code:${authCode}`);
  const authCodeDO = env.CodeDO.get(id);

  await authCodeDO.setAuthData(
    username,
    githubAccessToken,
    clientId,
    redirectUri,
    selectedKeyId,
    resource,
    message
  );

  // Redirect back to client with auth code
  const redirectUrl = new URL(redirectUri);
  redirectUrl.searchParams.set("code", authCode);
  if (state) {
    redirectUrl.searchParams.set("state", state);
  }

  return new Response(null, {
    status: 302,
    headers: { Location: redirectUrl.toString() },
  });
}

async function handleToken(
  request: Request,
  env: Env,
  scope: string
): Promise<Response> {
  if (request.method !== "POST") {
    return new Response("Method not allowed", {
      status: 405,
      headers: { "Access-Control-Allow-Origin": "*" },
    });
  }

  const headers = {
    "Content-Type": "application/json",
    ...corsHeaders,
  };

  const formData = await request.formData();
  const grantType = formData.get("grant_type");
  const code = formData.get("code");
  const clientId = formData.get("client_id");
  const redirectUri = formData.get("redirect_uri");
  const resource = formData.get("resource");

  if (grantType !== "authorization_code") {
    return new Response(JSON.stringify({ error: "unsupported_grant_type" }), {
      status: 400,
      headers,
    });
  }

  if (!code || !clientId) {
    return new Response(JSON.stringify({ error: "invalid_request" }), {
      status: 400,
      headers,
    });
  }

  // Validate client_id
  if (
    !isValidDomain(clientId.toString()) &&
    clientId.toString() !== "localhost"
  ) {
    return new Response(JSON.stringify({ error: "invalid_client" }), {
      status: 400,
      headers,
    });
  }

  // Get auth code data
  const id = env.CodeDO.idFromName(`code:${code.toString()}`);
  const authCodeDO = env.CodeDO.get(id);
  const authData = await authCodeDO.getAuthData();

  if (!authData) {
    return new Response(JSON.stringify({ error: "invalid_grant" }), {
      status: 400,
      headers,
    });
  }

  // Validate client_id and redirect_uri match
  if (
    authData.clientId !== clientId ||
    (redirectUri && authData.redirectUri !== redirectUri)
  ) {
    return new Response(JSON.stringify({ error: "invalid_grant" }), {
      status: 400,
      headers,
    });
  }

  // Validate resource parameter
  if (resource && authData.resource !== resource) {
    return new Response(JSON.stringify({ error: "invalid_grant" }), {
      status: 400,
      headers,
    });
  }

  // Get the selected Cloudflare API key
  const userDOId = env.UserDO.idFromName(`user:${authData.username}`);
  const userDO = env.UserDO.get(userDOId);
  const keys = await userDO.getCloudflareKeys();
  const selectedKey = keys.find((k) => k.id === authData.selectedKeyId);

  if (!selectedKey) {
    return new Response(JSON.stringify({ error: "invalid_grant" }), {
      status: 400,
      headers,
    });
  }

  // Update last used timestamp
  await userDO.updateKeyLastUsed(selectedKey.id);

  // Generate a bearer token that represents this access
  const bearerToken = await generateBearerToken(
    authData.username,
    selectedKey.id,
    env.GITHUB_CLIENT_SECRET
  );

  // Return the Cloudflare API key details
  return new Response(
    JSON.stringify({
      access_token: bearerToken,
      token_type: "bearer",
      scope,
      cloudflare_account_id: selectedKey.accountId,
      cloudflare_api_key: selectedKey.apiKey,
      cloudflare_key_name: selectedKey.name,
      ...(authData.message && { message: authData.message }),
    }),
    { headers }
  );
}

async function handleCallback(
  request: Request,
  env: Env,
  sameSite: string
): Promise<Response> {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const stateParam = url.searchParams.get("state");

  if (!code || !stateParam) {
    return new Response("Missing code or state parameter", { status: 400 });
  }

  // Get state from cookie
  const cookies = parseCookies(request.headers.get("Cookie") || "");
  const stateCookie = cookies.oauth_state;

  if (!stateCookie || stateCookie !== stateParam) {
    return new Response("Invalid state parameter", { status: 400 });
  }

  // Parse state
  let state: OAuthState;
  try {
    state = JSON.parse(atob(stateParam));
  } catch {
    return new Response("Invalid state format", { status: 400 });
  }

  // Exchange code for token with GitHub
  const tokenResponse = await fetch(
    "https://github.com/login/oauth/access_token",
    {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        client_id: env.GITHUB_CLIENT_ID,
        client_secret: env.GITHUB_CLIENT_SECRET,
        code,
        redirect_uri: `${url.origin}/callback`,
        code_verifier: state.codeVerifier,
      }),
    }
  );

  const tokenData = (await tokenResponse.json()) as any;

  if (!tokenData.access_token) {
    return new Response("Failed to get access token", { status: 400 });
  }

  // Get user info from GitHub
  const userResponse = await fetch("https://api.github.com/user", {
    headers: {
      Authorization: `Bearer ${tokenData.access_token}`,
      "User-Agent": "CloudflareOAuthProvider",
    },
  });

  if (!userResponse.ok) {
    return new Response("Failed to get user info", { status: 400 });
  }

  const user = (await userResponse.json()) as GitHubUser;

  // Store user data by GitHub username
  const userDOId = env.UserDO.idFromName(`user:${user.login}`);
  const userDO = env.UserDO.get(userDOId);

  // Check if user exists, if so just update token, otherwise create new
  const existingUser = await userDO.getUser();
  if (existingUser) {
    await userDO.updateGitHubToken(tokenData.access_token);
  } else {
    await userDO.setUser(user, tokenData.access_token);
  }

  // Set login cookie with 90-day expiration
  const maxAge = 90 * 24 * 60 * 60; // 90 days in seconds
  const cookieValue = `${user.login}:${await generateLoginToken(
    user.login,
    env.GITHUB_CLIENT_SECRET
  )}`;

  // Check if this was part of an OAuth provider flow
  if (state.clientId) {
    // Redirect back to the authorize endpoint to show key selection
    const redirectUrl = new URL(`${url.origin}/authorize`);
    redirectUrl.searchParams.set("client_id", state.clientId);
    redirectUrl.searchParams.set("redirect_uri", state.redirectUri || "");
    redirectUrl.searchParams.set("response_type", "code");
    if (state.originalState) {
      redirectUrl.searchParams.set("state", state.originalState);
    }
    if (state.resource) {
      redirectUrl.searchParams.set("resource", state.resource);
    }
    if (state.message) {
      redirectUrl.searchParams.set("message", state.message);
    }

    const headers = new Headers({ Location: redirectUrl.toString() });
    headers.append(
      "Set-Cookie",
      `oauth_state=; HttpOnly; Secure; SameSite=${sameSite}; Max-Age=0; Path=/`
    );
    headers.append(
      "Set-Cookie",
      `github_login=${cookieValue}; HttpOnly; Secure; SameSite=${sameSite}; Max-Age=${maxAge}; Path=/`
    );

    return new Response(null, { status: 302, headers });
  }

  // Normal redirect (direct login)
  const headers = new Headers({ Location: state.redirectTo || "/" });
  headers.append(
    "Set-Cookie",
    `oauth_state=; HttpOnly; Secure; SameSite=${sameSite}; Max-Age=0; Path=/`
  );
  headers.append(
    "Set-Cookie",
    `github_login=${cookieValue}; HttpOnly; Secure; SameSite=${sameSite}; Max-Age=${maxAge}; Path=/`
  );

  return new Response(null, { status: 302, headers });
}

export function getGitHubUsername(request: Request): string | null {
  const cookies = parseCookies(request.headers.get("Cookie") || "");
  const githubLogin = cookies.github_login;

  if (!githubLogin) return null;

  const [username] = githubLogin.split(":");
  return username;
}

// Management routes
export async function handleManagement(
  request: Request,
  env: Env
): Promise<Response | null> {
  const url = new URL(request.url);
  const path = url.pathname;

  if (path === "/manage") {
    const username = getGitHubUsername(request);
    if (!username) {
      return new Response(null, {
        status: 302,
        headers: { Location: "/authorize?redirect_to=/manage" },
      });
    }

    const userDOId = env.UserDO.idFromName(`user:${username}`);
    const userDO = env.UserDO.get(userDOId);
    const userData = await userDO.getUser();
    const keys = await userDO.getCloudflareKeys();

    if (!userData) {
      return new Response("User not found", { status: 404 });
    }

    if (request.method === "POST") {
      const formData = await request.formData();
      const action = formData.get("action");

      if (action === "add") {
        const name = formData.get("name")?.toString();
        const accountId = formData.get("accountId")?.toString();
        const apiKey = formData.get("apiKey")?.toString();

        if (!name || !accountId || !apiKey) {
          return showKeyManagementPageHTML(
            userData.user,
            keys,
            "",
            "Missing required fields"
          );
        }

        // Validate the API key by making a test request
        const testResponse = await fetch(
          `https://api.cloudflare.com/client/v4/accounts/${accountId}`,
          {
            headers: {
              Authorization: `Bearer ${apiKey}`,
              "Content-Type": "application/json",
            },
          }
        );

        if (!testResponse.ok) {
          return showKeyManagementPageHTML(
            userData.user,
            keys,
            "",
            "Invalid API key or Account ID"
          );
        }

        const newKey: CloudflareAPIKey = {
          id: crypto.randomUUID(),
          name,
          accountId,
          apiKey,
          createdAt: new Date().toISOString(),
        };

        await userDO.addCloudflareKey(newKey);
        return new Response(null, {
          status: 302,
          headers: { Location: "/manage" },
        });
      }

      if (action === "delete") {
        const keyId = formData.get("keyId")?.toString();
        if (keyId) {
          await userDO.removeCloudflareKey(keyId);
        }
        return new Response(null, {
          status: 302,
          headers: { Location: "/manage" },
        });
      }
    }

    return showKeyManagementPageHTML(userData.user, keys, "", undefined, false);
  }

  return null;
}

// Utility functions
function parseCookies(cookieHeader: string): Record<string, string> {
  const cookies: Record<string, string> = {};
  cookieHeader.split(";").forEach((cookie) => {
    const [name, value] = cookie.trim().split("=");
    if (name && value) {
      cookies[name] = decodeURIComponent(value);
    }
  });
  return cookies;
}

function isValidDomain(domain: string): boolean {
  const domainRegex =
    /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
  return (
    domainRegex.test(domain) && domain.includes(".") && domain.length <= 253
  );
}

function isValidMessage(message: string): boolean {
  // Basic validation for the message parameter
  // - Max length of 500 characters
  // - No HTML tags or script content
  // - No URLs to prevent phishing

  if (!message || message.length > 500) {
    return false;
  }

  // Check for HTML tags
  if (/<[^>]*>/.test(message)) {
    return false;
  }

  // Check for URLs (basic detection)
  if (/https?:\/\/|www\.|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/i.test(message)) {
    return false;
  }

  return true;
}

export function sanitizeMessage(message: string): string {
  return message
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function generateCodeVerifier(): string {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return btoa(String.fromCharCode.apply(null, Array.from(array)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

async function generateCodeChallenge(verifier: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return btoa(
    String.fromCharCode.apply(null, Array.from(new Uint8Array(digest)))
  )
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

async function generateLoginToken(
  username: string,
  secret: string
): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(`${username}:${Date.now()}`);
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", keyMaterial, data);
  return btoa(
    String.fromCharCode.apply(null, Array.from(new Uint8Array(signature)))
  )
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

async function generateBearerToken(
  username: string,
  keyId: string,
  secret: string
): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(`${username}:${keyId}:${Date.now()}`);
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", keyMaterial, data);
  return btoa(
    String.fromCharCode.apply(null, Array.from(new Uint8Array(signature)))
  )
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

// Simple HTML escaping for server-side
function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    // Handle OAuth routes
    const oauthResponse = await handleOAuth(request, env);
    if (oauthResponse) return oauthResponse;

    // Handle management routes
    const managementResponse = await handleManagement(request, env);
    if (managementResponse) return managementResponse;

    const url = new URL(request.url);
    const path = url.pathname;

    if (path === "/" || path === "/README.md") {
      return handleHome(request, env);
    }

    if (path === "/demo") {
      return handleDemo(request, env);
    }

    return new Response("Not found", { status: 404 });
  },
} satisfies ExportedHandler<Env>;

async function handleHome(request: Request, env: Env): Promise<Response> {
  const username = getGitHubUsername(request);
  const url = new URL(request.url);
  const baseUrl = `${url.protocol}//${url.host}`;

  const readme = `# Login with Cloudflare

Securely provide your Cloudflare API keys to trusted applications through OAuth 2.0.

## For Users

${
  username
    ? `**Welcome back, ${username}!**

- [Manage your API keys](/manage)
- [Try OAuth demo](/demo)
- [Logout](/logout)

`
    : `**Get Started:**

1. [Login with GitHub](/authorize) to get started
2. Add your Cloudflare API keys
3. Grant access to trusted applications

`
}## For Developers

Integrate "Login with Cloudflare" into your application using standard OAuth 2.0 flow:

### Step 1: Authorization Request

Redirect users to the authorization endpoint:

\`\`\`
${baseUrl}/authorize?client_id=yourdomain.com&redirect_uri=https://yourdomain.com/callback&response_type=code&state=random-state-string&message=We need access to deploy your site to Cloudflare
\`\`\`

**Parameters:**
- \`client_id\`: Your domain (e.g., \`yourdomain.com\`)
- \`redirect_uri\`: Where to redirect after authorization (must be HTTPS and on same domain)
- \`response_type\`: Must be \`code\`
- \`state\`: Random string to prevent CSRF attacks
- \`message\`: (Optional) Custom message to show users explaining why you need access

### Step 2: Handle Authorization Code

After user grants access, they'll be redirected to your \`redirect_uri\` with:
- \`code\`: Authorization code to exchange for access token
- \`state\`: The same state parameter you sent

### Step 3: Exchange Code for Token

Make a POST request to exchange the authorization code:

\`\`\`bash
curl -X POST ${baseUrl}/token \\
  -H "Content-Type: application/x-www-form-urlencoded" \\
  -d "grant_type=authorization_code&code=AUTH_CODE&client_id=yourdomain.com&redirect_uri=https://yourdomain.com/callback"
\`\`\`

**Response:**
\`\`\`json
{
  "access_token": "bearer-token-here",
  "token_type": "bearer",
  "scope": "user:email",
  "cloudflare_account_id": "account123",
  "cloudflare_api_key": "token456",
  "cloudflare_key_name": "My API Key",
  "message": "We need access to deploy your site to Cloudflare"
}
\`\`\`

### Step 4: Use Cloudflare API

Use the provided credentials to access Cloudflare APIs:

\`\`\`bash
curl -X GET https://api.cloudflare.com/client/v4/zones \\
  -H "Authorization: Bearer token456" \\
  -H "Content-Type: application/json"
\`\`\`

## Implementation Examples

### JavaScript/Node.js

\`\`\`javascript
// Redirect to authorization with custom message
const authUrl = new URL('${baseUrl}/authorize');
authUrl.searchParams.set('client_id', 'yourdomain.com');
authUrl.searchParams.set('redirect_uri', 'https://yourdomain.com/callback');
authUrl.searchParams.set('response_type', 'code');
authUrl.searchParams.set('state', generateRandomState());
authUrl.searchParams.set('message', 'We need access to deploy your site to Cloudflare');
window.location.href = authUrl.toString();

// Handle callback
app.get('/callback', async (req, res) => {
  const { code, state } = req.query;
  
  const response = await fetch('${baseUrl}/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      client_id: 'yourdomain.com',
      redirect_uri: 'https://yourdomain.com/callback'
    })
  });
  
  const data = await response.json();
  // Use data.cloudflare_api_key and data.cloudflare_account_id
  // The original message is available in data.message
});
\`\`\`

### Python

\`\`\`python
import requests
import urllib.parse

# Redirect to authorization with custom message
auth_url = '${baseUrl}/authorize'
params = {
    'client_id': 'yourdomain.com',
    'redirect_uri': 'https://yourdomain.com/callback',
    'response_type': 'code',
    'state': generate_random_state(),
    'message': 'We need access to deploy your site to Cloudflare'
}
redirect_url = f"{auth_url}?{urllib.parse.urlencode(params)}"

# Exchange code for token
response = requests.post('${baseUrl}/token', data={
    'grant_type': 'authorization_code',
    'code': auth_code,
    'client_id': 'yourdomain.com',
    'redirect_uri': 'https://yourdomain.com/callback'
})

token_data = response.json()
api_key = token_data['cloudflare_api_key']
account_id = token_data['cloudflare_account_id']
original_message = token_data.get('message')  # Optional field

# Use Cloudflare API
cf_response = requests.get(
    'https://api.cloudflare.com/client/v4/zones',
    headers={
        'Authorization': f'Bearer {api_key}',
        'Content-Type': 'application/json'
    }
)
\`\`\`

## Custom Messages

The \`message\` parameter allows you to provide context to users about why your application needs access to their Cloudflare account. This improves user trust and understanding.

**Guidelines for messages:**
- Keep it concise (max 500 characters)
- Explain the specific use case
- No HTML, URLs, or script content allowed
- Be honest and transparent

**Good examples:**
- "We need access to deploy your site to Cloudflare"
- "Required to manage DNS records for your domain"
- "Needed to configure SSL certificates for your website"

**Bad examples:**
- "Give us access" (too vague)
- "Visit https://example.com for more info" (contains URL)
- Messages with HTML or script content

## Security Considerations

⚠️ **Important**: This service provides users' actual Cloudflare API keys to your application. Only use this for applications you completely trust.

**Best practices:**
- Create dedicated API tokens with minimal required permissions
- Use separate keys for different applications
- Regularly rotate API keys
- Monitor key usage through the management interface
- Use meaningful messages to build user trust

## OAuth 2.0 Discovery

This service supports OAuth 2.0 discovery endpoints:

- Authorization Server Metadata: \`${baseUrl}/.well-known/oauth-authorization-server\`
- Protected Resource Metadata: \`${baseUrl}/.well-known/oauth-protected-resource\`

## Support

- GitHub: [Report issues](https://github.com/your-repo/issues)
- Documentation: [Full API reference](https://your-docs.com)

---

*Powered by Cloudflare Workers and Durable Objects*`;

  return new Response(readme, {
    headers: { "Content-Type": "text/markdown; charset=utf-8" },
  });
}

async function handleDemo(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const baseUrl = `${url.protocol}//${url.host}`;

  return new Response(
    `
    <!DOCTYPE html>
    <html>
    <head>
      <title>OAuth Demo - Login with Cloudflare</title>
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <style>
        body { font-family: system-ui, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
        .code { background: #f8f9fa; padding: 15px; border-radius: 8px; font-family: monospace; margin: 10px 0; white-space: pre-wrap; }
        .nav { margin-bottom: 20px; }
        .nav a { color: #007bff; text-decoration: none; margin-right: 20px; }
        .nav a:hover { text-decoration: underline; }
        button { background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; margin: 5px; }
        button:hover { background: #0056b3; }
        #result { margin-top: 20px; padding: 15px; border-radius: 8px; }
        .success { background: #d4edda; border: 1px solid #c3e6cb; color: #155724; }
        .error { background: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; }
        .form-group { margin: 10px 0; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input[type="text"], textarea { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }
        textarea { height: 80px; resize: vertical; }
        .char-count { font-size: 12px; color: #666; text-align: right; margin-top: 2px; }
      </style>
    </head>
    <body>
      <div class="nav">
        <a href="/">Home</a>
        <a href="/manage">Manage Keys</a>
        <a href="/logout">Logout</a>
      </div>

      <h1>OAuth Demo</h1>
      <p>This demo shows how other applications can integrate with Login with Cloudflare, including custom messages.</p>

      <h2>Step 1: Authorization with Custom Message</h2>
      <p>Customize the message shown to users during authorization:</p>
      
      <div class="form-group">
        <label for="customMessage">Authorization Message:</label>
        <textarea id="customMessage" placeholder="We need access to deploy your site to Cloudflare">We need access to deploy your site to Cloudflare</textarea>
        <div class="char-count">
          <span id="charCount">52</span>/500 characters
        </div>
      </div>
      
      <button onclick="startOAuth()">Start OAuth Flow</button>
      <button onclick="startOAuth('')">Start OAuth Flow (No Message)</button>

      <h2>Step 2: Token Exchange</h2>
      <p>After authorization, the code will be exchanged for an access token automatically.</p>

      <h2>Step 3: Result</h2>
      <div id="result"></div>

      <h2>Implementation Example</h2>
      <div class="code">// 1. Redirect user to authorize endpoint with custom message
const authUrl = new URL('${baseUrl}/authorize');
authUrl.searchParams.set('client_id', 'yourdomain.com');
authUrl.searchParams.set('redirect_uri', 'https://yourdomain.com/callback');
authUrl.searchParams.set('response_type', 'code');
authUrl.searchParams.set('state', 'random-state-string');
authUrl.searchParams.set('message', 'We need access to deploy your site to Cloudflare');
window.location.href = authUrl.toString();

// 2. Handle callback and exchange code for token
const response = await fetch('${baseUrl}/token', {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({
    grant_type: 'authorization_code',
    code: 'AUTH_CODE_FROM_CALLBACK',
    client_id: 'yourdomain.com',
    redirect_uri: 'https://yourdomain.com/callback'
  })
});

const data = await response.json();
// data.cloudflare_api_key contains the user's API key
// data.cloudflare_account_id contains the account ID
// data.message contains the original authorization message</div>

      <script>
        const CLIENT_ID = window.location.hostname;
        const REDIRECT_URI = window.location.origin + '/demo';
        
        // Character counter
        const messageInput = document.getElementById('customMessage');
        const charCountSpan = document.getElementById('charCount');
        
        messageInput.addEventListener('input', function() {
          const count = this.value.length;
          charCountSpan.textContent = count;
          charCountSpan.style.color = count > 500 ? '#dc3545' : '#666';
        });

        function startOAuth(customMessage = null) {
          const message = customMessage !== null ? customMessage : document.getElementById('customMessage').value;
          
          const authUrl = new URL('${baseUrl}/authorize');
          authUrl.searchParams.set('client_id', CLIENT_ID);
          authUrl.searchParams.set('redirect_uri', REDIRECT_URI);
          authUrl.searchParams.set('response_type', 'code');
          authUrl.searchParams.set('state', Math.random().toString(36));
          
          if (message && message.trim()) {
            authUrl.searchParams.set('message', message.trim());
          }
          
          window.location.href = authUrl.toString();
        }

        // Handle OAuth callback
        async function handleCallback() {
          const urlParams = new URLSearchParams(window.location.search);
          const code = urlParams.get('code');
          const state = urlParams.get('state');

          if (code) {
            try {
              const response = await fetch('${baseUrl}/token', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: new URLSearchParams({
                  grant_type: 'authorization_code',
                  code: code,
                  client_id: CLIENT_ID,
                  redirect_uri: REDIRECT_URI
                })
              });

              const data = await response.json();
              
              if (data.cloudflare_api_key) {
                document.getElementById('result').innerHTML = \`
                  <div class="success">
                    <h3>✅ Success!</h3>
                    <p><strong>Key Name:</strong> \${data.cloudflare_key_name}</p>
                    <p><strong>Account ID:</strong> \${data.cloudflare_account_id}</p>
                    <p><strong>API Key:</strong> \${data.cloudflare_api_key.substring(0, 20)}...</p>
                    \${data.message ? \`<p><strong>Original Message:</strong> \${data.message}</p>\` : ''}
                    <p><em>In a real application, you would now use these credentials to access the Cloudflare API.</em></p>
                  </div>
                \`;
              } else {
                document.getElementById('result').innerHTML = \`
                  <div class="error">
                    <h3>❌ Error</h3>
                    <p>Token exchange failed: \${JSON.stringify(data)}</p>
                  </div>
                \`;
              }
            } catch (error) {
              document.getElementById('result').innerHTML = \`
                <div class="error">
                  <h3>❌ Error</h3>
                  <p>Token exchange failed: \${error.message}</p>
                </div>
              \`;
            }

            // Clean up URL
            window.history.replaceState({}, document.title, window.location.pathname);
          }
        }

        // Check for OAuth callback on page load
        handleCallback();
      </script>
    </body>
    </html>
  `,
    { headers: { "Content-Type": "text/html;charset=utf8" } }
  );
}

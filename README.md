# X OAuth Provider

[![janwilmake/x-oauth-client-provider context](https://badge.forgithub.com/janwilmake/x-oauth-client-provider/tree/main/README.md)](https://uithub.com/janwilmake/x-oauth-client-provider/tree/main/README.md) [![](https://b.lmpify.com)](https://letmeprompt.com?q=https://uithub.com/janwilmake/x-oauth-client-provider/tree/main/README.md)

This X OAuth client-provider uses the client's domain name as the client_id and automatically derives the `redirect_uri` from it (e.g., `https://example.com/callback`), eliminating the need for client registration while maintaining security through domain validation.

**Key Features:**

- 🚀 No client registration required - use any domain as client_id
- 🔒 Secure domain validation and HTTPS enforcement
- 🎯 MCP (Model Context Protocol) compliant OAuth 2.0 implementation, including dynamic client registration
- ⚡ Built for Cloudflare Workers with Durable Objects
- 🌐 Standard OAuth 2.0 flow compatible with existing libraries

## Setup

1. Installation:

```bash
npm i x-oauth-client-provider
```

2. Set environment variables:

   - `X_CLIENT_ID`: Your X OAuth app client ID
   - `X_CLIENT_SECRET`: Your X OAuth app client secret

3. Add Durable Object binding to your `wrangler.toml`:

```toml
[[durable_objects.bindings]]
name = "UserDO"
class_name = "UserDO"

[[migrations]]
new_sqlite_classes = ["UserDO"]
tag = "v1"
```

## Usage Examples

### Simple Enforced Authentication

```typescript path="src/index.ts"
import { UserDO, withSimplerAuth } from "x-oauth-client-provider";
export { UserDO };

export default {
  fetch: withSimplerAuth(
    async (request, env, ctx) => {
      return new Response(
        `<html><body>
        <h1>X OAuth Demo</h1>
        <p>Welcome, ${ctx.user.name || ctx.user.username}!</p>
        <img src="${
          ctx.user.profile_image_url || "/default-avatar.png"
        }" alt="Avatar" width="400" height="400" style="border-radius:200px;">
        <p>Username: @${ctx.user.username}</p>
        <p>Verified: ${ctx.user.verified ? "✓" : "✗"}</p>
        <a href="/logout">Logout</a>
      </body></html>`,
        { headers: { "Content-Type": "text/html;charset=utf8" } }
      );
    },
    { isLoginRequired: true }
  ),
};
```

### Manual Authentication Flow

```typescript path="src/manual.ts"
import { UserDO, handleOAuth, getAccessToken } from "x-oauth-client-provider";
export { UserDO };

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    // Handle OAuth routes
    const oauthResponse = await handleOAuth(request, env);
    if (oauthResponse) return oauthResponse;

    // Check if user is authenticated
    const accessToken = getAccessToken(request);
    if (!accessToken) {
      // Redirect to login
      return Response.redirect(
        "/authorize?redirect_to=" + encodeURIComponent(request.url)
      );
    }

    // Your app logic here
    return new Response("Hello authenticated user!");
  },
};
```

## OAuth Provider Flow

Your worker acts as an OAuth 2.0 provider that other applications can use for X authentication. Here's how any client application can integrate:

### Client Integration Guide

Any application at any domain can use your OAuth provider without registration. Here's a complete implementation:

```typescript path="client-worker.ts"
// Example client implementation for Cloudflare Workers
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/") {
      return handleHome(request);
    }

    if (url.pathname === "/login") {
      return handleLogin(request, env);
    }

    if (url.pathname === "/callback") {
      return handleCallback(request, env);
    }

    if (url.pathname === "/profile") {
      return handleProfile(request, env);
    }

    return new Response("Not found", { status: 404 });
  },
};

async function handleHome(request: Request): Promise<Response> {
  // Check if user has access token
  const cookies = parseCookies(request.headers.get("Cookie") || "");
  const accessToken = cookies.access_token;

  if (accessToken) {
    return new Response(
      `
      <html><body>
        <h1>Welcome back!</h1>
        <a href="/profile">View Profile</a> | 
        <a href="/logout">Logout</a>
      </body></html>
    `,
      { headers: { "Content-Type": "text/html" } }
    );
  }

  return new Response(
    `
    <html><body>
      <h1>My App</h1>
      <p>Please login with X to continue.</p>
      <a href="/login">Login with X</a>
    </body></html>
  `,
    { headers: { "Content-Type": "text/html" } }
  );
}

async function handleLogin(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);

  // Your OAuth provider URL
  const PROVIDER_URL = "https://your-oauth-provider.com";

  // Generate CSRF state
  const state = generateRandomString(32);

  // Build authorization URL
  const authUrl = new URL(`${PROVIDER_URL}/authorize`);
  authUrl.searchParams.set("client_id", url.hostname); // Use domain as client_id
  authUrl.searchParams.set("redirect_uri", `${url.origin}/callback`);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("state", state);
  authUrl.searchParams.set("scope", "users.read tweet.read");

  // Store state in cookie for validation
  return new Response(null, {
    status: 302,
    headers: {
      Location: authUrl.toString(),
      "Set-Cookie": `oauth_state=${state}; HttpOnly; Secure; SameSite=Lax; Max-Age=600; Path=/`,
    },
  });
}

async function handleCallback(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");

  if (!code || !state) {
    return new Response("Missing code or state parameter", { status: 400 });
  }

  // Validate state
  const cookies = parseCookies(request.headers.get("Cookie") || "");
  if (cookies.oauth_state !== state) {
    return new Response("Invalid state parameter", { status: 400 });
  }

  // Exchange code for access token
  const PROVIDER_URL = "https://your-oauth-provider.com";

  const tokenResponse = await fetch(`${PROVIDER_URL}/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code: code,
      client_id: url.hostname,
      redirect_uri: `${url.origin}/callback`,
    }),
  });

  if (!tokenResponse.ok) {
    return new Response(`Token exchange failed: ${tokenResponse.status}`, {
      status: 400,
    });
  }

  const tokenData = (await tokenResponse.json()) as {
    access_token: string;
    token_type: string;
    scope: string;
  };

  // Store access token and redirect to home
  return new Response(null, {
    status: 302,
    headers: {
      Location: "/",
      "Set-Cookie": [
        `access_token=${tokenData.access_token}; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000; Path=/`,
        `oauth_state=; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Path=/`, // Clear state
      ].join(", "),
    },
  });
}

async function handleProfile(request: Request, env: Env): Promise<Response> {
  const cookies = parseCookies(request.headers.get("Cookie") || "");
  const accessToken = cookies.access_token;

  if (!accessToken) {
    return new Response(null, {
      status: 302,
      headers: { Location: "/login" },
    });
  }

  // Get user info from the OAuth provider's /me endpoint
  const PROVIDER_URL = "https://your-oauth-provider.com";

  try {
    const userResponse = await fetch(`${PROVIDER_URL}/me`, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });

    if (!userResponse.ok) {
      // Token might be expired, redirect to login
      return new Response(null, {
        status: 302,
        headers: {
          Location: "/login",
          "Set-Cookie": `access_token=; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Path=/`,
        },
      });
    }

    const userData = (await userResponse.json()) as {
      data: {
        id: string;
        name: string;
        username: string;
        profile_image_url?: string;
        verified?: boolean;
      };
    };

    const user = userData.data;

    return new Response(
      `
      <html><body>
        <h1>Your X Profile</h1>
        <div style="display: flex; align-items: center; gap: 20px;">
          ${
            user.profile_image_url
              ? `<img src="${user.profile_image_url}" alt="Avatar" width="100" height="100" style="border-radius: 50px;">`
              : ""
          }
          <div>
            <h2>${user.name || user.username}</h2>
            <p>@${user.username}</p>
            <p>Verified: ${user.verified ? "✓" : "✗"}</p>
            <p>ID: ${user.id}</p>
          </div>
        </div>
        <p><a href="/">← Back to Home</a></p>
      </body></html>
    `,
      {
        headers: { "Content-Type": "text/html" },
      }
    );
  } catch (error) {
    return new Response(`Error fetching user data: ${error}`, { status: 500 });
  }
}

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

function generateRandomString(length: number): string {
  const chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let result = "";
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}
```

### Step-by-Step Integration

1. **Authorization Request**: Redirect users to your provider's authorize endpoint:

```
https://your-provider.com/authorize?client_id=CLIENT_DOMAIN&redirect_uri=REDIRECT_URI&response_type=code&state=RANDOM_STATE
```

Parameters:

- `client_id`: Your client's domain (e.g., `example.com`)
- `redirect_uri`: Where to redirect after auth (must be HTTPS and on same domain as client_id)
- `response_type`: Must be `code`
- `state`: Random string for CSRF protection

2. **Handle Authorization Callback**: After user authorizes, they'll be redirected to your `redirect_uri` with:

```
https://your-app.com/callback?code=AUTH_CODE&state=YOUR_STATE
```

3. **Exchange Code for Token**: Make a POST request to exchange the authorization code:

```javascript path="token-exchange.js"
const response = await fetch("https://your-provider.com/token", {
  method: "POST",
  headers: { "Content-Type": "application/x-www-form-urlencoded" },
  body: new URLSearchParams({
    grant_type: "authorization_code",
    code: "AUTH_CODE_FROM_CALLBACK",
    client_id: "your-domain.com",
    redirect_uri: "https://your-domain.com/callback",
  }),
});

const { access_token } = await response.json();
```

4. **Get User Information**: Use the `/me` endpoint to get X user data:

```javascript path="get-user.js"
const userResponse = await fetch("https://your-provider.com/me", {
  headers: { Authorization: `Bearer ${access_token}` },
});

const userData = await userResponse.json();
console.log(userData.data); // X user object with id, name, username, etc.
```

### Available User Data

The `/me` endpoint returns X user information in this format:

```json path="user-response.json"
{
  "data": {
    "id": "123456789",
    "name": "John Doe",
    "username": "johndoe",
    "profile_image_url": "https://pbs.twimg.com/profile_images/.../photo.jpg",
    "verified": false
  }
}
```

## API Routes

Your OAuth provider exposes these endpoints:

- `GET /authorize` - OAuth authorization endpoint
- `POST /token` - OAuth token endpoint
- `GET /callback` - X OAuth callback handler
- `GET /me` - Get authenticated user information
- `GET /logout` - Logout and clear session
- `GET /.well-known/oauth-authorization-server` - OAuth server metadata (MCP required)
- `GET /.well-known/oauth-protected-resource` - Protected resource metadata (MCP required)

## Security Features

- **Domain Validation**: Client domains are validated - `client_id` must be a valid domain
- **HTTPS Enforcement**: Redirect URIs must be HTTPS and on the same domain as `client_id`
- **CSRF Protection**: State parameter validation prevents cross-site request forgery
- **Token Expiration**: Authorization codes expire after 10 minutes
- **Secure Storage**: User data encrypted in Durable Objects
- **PKCE Support**: Proof Key for Code Exchange for enhanced security

## Configuration Options

### `withSimplerAuth` Options

```typescript
withSimplerAuth(handler, {
  isLoginRequired: true, // Force authentication
  scope: "users.read tweet.read offline.access", // X API scopes
  sameSite: "Lax", // Cookie SameSite policy
});
```

### `handleOAuth` Options

```typescript
handleOAuth(request, env, scope, sameSite);
```

## MCP Compliance

This implementation is fully compliant with the Model Context Protocol (MCP) OAuth 2.0 requirements, including:

- RFC 8414 OAuth 2.0 Authorization Server Metadata
- RFC 9728 OAuth 2.0 Protected Resource Metadata
- Proper WWW-Authenticate headers with login URLs
- Bearer token support in Authorization headers
- Resource parameter support for audience validation

## Notes

This provider is designed to be agent-friendly while maintaining security. When authentication is required, it provides multiple indicators for where to login:

```typescript
{
  status: isBrowser ? 302 : 401,
  headers: {
    Location: loginUrl,
    "X-Login-URL": loginUrl,
    "WWW-Authenticate": `Bearer realm="main", login_url="${loginUrl}", resource_metadata="${resourceMetadataUrl}"`,
  },
}
```

Agents can either attempt automated login or direct users to the login URL for credential retrieval.

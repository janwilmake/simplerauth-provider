/// <reference types="@cloudflare/workers-types" />

export interface UserContext extends ExecutionContext {
  /** Authenticated user from the OAuth provider */
  user: User | undefined;
  /** Access token for API calls */
  accessToken: string | undefined;
  /** Whether user is authenticated */
  authenticated: boolean;
}

type User = {
  id: string;
  name: string;
  username: string;
  profile_image_url?: string | undefined;
  verified?: boolean | undefined;
};

interface UserFetchHandler<TEnv = {}> {
  (request: Request, env: TEnv, ctx: UserContext): Response | Promise<Response>;
}

interface SimplerAuthConfig {
  /** If true, login will be forced and user will always be present */
  isLoginRequired?: boolean;
  /** OAuth scopes to request */
  scope?: string;
  /** Cookie SameSite setting */
  sameSite?: "Strict" | "Lax";
  /** The OAuth provider hostname (defaults to login.wilmake.com) */
  providerHostname?: string;
}

/**
 * Middleware that adds OAuth authentication using a centralized provider
 */
export function withSimplerAuth<TEnv = {}>(
  handler: UserFetchHandler<TEnv>,
  config: SimplerAuthConfig = {}
): ExportedHandlerFetchHandler<TEnv> {
  const {
    isLoginRequired = false,
    scope = "profile",
    sameSite = "Lax",
    providerHostname = "login.wilmake.com",
  } = config;

  return async (
    request: Request,
    env: TEnv,
    ctx: ExecutionContext
  ): Promise<Response> => {
    const url = new URL(request.url);
    const path = url.pathname;

    // Handle OAuth endpoints
    if (path === "/.well-known/oauth-authorization-server") {
      return handleAuthorizationServerMetadata(url, providerHostname);
    }

    if (path === "/.well-known/oauth-protected-resource") {
      return handleProtectedResourceMetadata(url, providerHostname);
    }

    if (path === "/authorize") {
      return handleAuthorize(request, env, providerHostname, scope, sameSite);
    }

    if (path === "/callback") {
      return handleCallback(request, providerHostname, sameSite);
    }

    if (path === "/token") {
      return handleToken(request, providerHostname);
    }

    if (path === "/me") {
      return handleMe(request, providerHostname);
    }

    if (path === "/logout") {
      return handleLogout(request, sameSite);
    }

    // Get user from access token
    let user: User | undefined = undefined;
    let authenticated = false;
    const accessToken = getAccessToken(request);

    if (accessToken) {
      try {
        // Verify token with provider and get user info
        const userResponse = await fetch(`https://${providerHostname}/me`, {
          headers: { Authorization: `Bearer ${accessToken}` },
        });

        if (userResponse.ok) {
          user = await userResponse.json();
          authenticated = true;
        }
      } catch (error) {
        console.error("Error verifying token:", error);
      }
    }

    // Check if authentication is required
    if (isLoginRequired && !authenticated) {
      const isBrowser = request.headers.get("accept")?.includes("text/html");
      const loginUrl = `/authorize?redirect_to=${encodeURIComponent(
        url.pathname + url.search
      )}`;
      const resourceMetadataUrl = `${url.origin}/.well-known/oauth-protected-resource`;

      return new Response(
        isBrowser
          ? `Redirecting to login...`
          : `Authentication required. Login at ${loginUrl}`,
        {
          status: isBrowser ? 302 : 401,
          headers: {
            ...(isBrowser && { Location: loginUrl }),
            "X-Login-URL": loginUrl,
            "WWW-Authenticate": `Bearer realm="main", login_url="${loginUrl}", resource_metadata="${resourceMetadataUrl}"`,
          },
        }
      );
    }

    // Create enhanced context
    const enhancedCtx: UserContext = {
      props: ctx.props,
      passThroughOnException: () => ctx.passThroughOnException(),
      waitUntil: (promise: Promise<any>) => ctx.waitUntil(promise),
      user,
      accessToken,
      authenticated,
    };

    // Call the user's handler
    return handler(request, env, enhancedCtx);
  };
}

function handleAuthorizationServerMetadata(
  url: URL,
  providerHostname: string
): Response {
  const metadata = {
    issuer: `https://${providerHostname}`,
    authorization_endpoint: `https://${providerHostname}/authorize`,
    token_endpoint: `https://${providerHostname}/token`,
    token_endpoint_auth_methods_supported: ["none"],
    registration_endpoint: `https://${providerHostname}/register`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code"],
    code_challenge_methods_supported: ["S256"],
    scopes_supported: ["profile"],
  };

  return new Response(JSON.stringify(metadata, null, 2), {
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "public, max-age=3600",
    },
  });
}

function handleProtectedResourceMetadata(
  url: URL,
  providerHostname: string
): Response {
  const metadata = {
    resource: url.origin,
    authorization_servers: [`https://${providerHostname}`],
    scopes_supported: ["profile"],
    bearer_methods_supported: ["header", "body"],
    resource_documentation: url.origin,
  };

  return new Response(JSON.stringify(metadata, null, 2), {
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "public, max-age=3600",
    },
  });
}

function isLocalhost(request: Request) {
  const url = new URL(request.url);
  return (
    url.hostname === "localhost" ||
    url.hostname === "127.0.0.1" ||
    // only at localhost!
    request.headers.get("cf-connecting-ip") === "::1" ||
    request.headers.get("cf-connecting-ip") === "127.0.0.1"
  );
}

function handleAuthorize(
  request: Request,
  env: any,
  providerHostname: string,
  scope: string,
  sameSite: string
): Response {
  const url = new URL(request.url);

  const clientId =
    url.searchParams.get("client_id") || isLocalhost(request)
      ? "localhost"
      : url.hostname;

  // 8787 is wrangler default
  const port = env.PORT || 8787;

  // force https
  const redirectUri = url.searchParams.get("redirect_uri")
    ? url.searchParams.get("redirect_uri")
    : isLocalhost(request)
    ? `http://localhost:${port}/callback`
    : `https://${url.host}/callback`;

  const state = url.searchParams.get("state");
  const redirectTo = url.searchParams.get("redirect_to") || "/";

  // Build provider authorization URL
  const providerUrl = new URL(`https://${providerHostname}/authorize`);
  providerUrl.searchParams.set("client_id", clientId);
  providerUrl.searchParams.set("redirect_uri", redirectUri);
  providerUrl.searchParams.set("response_type", "code");
  providerUrl.searchParams.set("scope", scope);
  if (state) {
    providerUrl.searchParams.set("state", state);
  }
  // Store original redirect destination
  providerUrl.searchParams.set("resource", url.origin);

  const providerUrlString = providerUrl.toString();
  console.log({ providerUrlString });

  // Set cookies for redirect_uri and redirect_to
  const securePart = isLocalhost(request) ? "" : "Secure; ";
  const headers = new Headers();
  headers.set("Location", providerUrlString);
  headers.append(
    "Set-Cookie",
    `redirect_uri=${encodeURIComponent(
      redirectUri
    )}; HttpOnly; ${securePart}Max-Age=600; SameSite=${sameSite}; Path=/`
  );
  headers.append(
    "Set-Cookie",
    `redirect_to=${encodeURIComponent(
      redirectTo
    )}; HttpOnly; ${securePart}Max-Age=600; SameSite=${sameSite}; Path=/`
  );

  return new Response(null, {
    status: 302,
    headers,
  });
}

async function handleCallback(
  request: Request,
  providerHostname: string,
  sameSite: string
): Promise<Response> {
  const url = new URL(request.url);
  const cookies = parseCookies(request.headers.get("Cookie") || "");

  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");

  if (!code) {
    return new Response("Missing authorization code", { status: 400 });
  }

  // Get redirect_uri and redirect_to from cookies
  const redirectUri = cookies.redirect_uri || `${url.origin}/callback`;
  const redirectTo = cookies.redirect_to || state || "/";

  try {
    const params = {
      grant_type: "authorization_code",
      code: code,
      client_id: isLocalhost(request) ? "localhost" : url.hostname,
      redirect_uri: redirectUri,
      ...(state && { state }),
    };
    console.log({ params });
    // Exchange code for token with the provider
    const tokenResponse = await fetch(`https://${providerHostname}/token`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams(params),
    });

    if (!tokenResponse.ok) {
      const errorText = await tokenResponse.text();
      console.error("Token exchange failed:", errorText);
      return new Response(`Token exchange failed: ${errorText}`, {
        status: 400,
      });
    }

    const tokenData: { access_token: string } = await tokenResponse.json();

    if (!tokenData.access_token) {
      return new Response("No access token received", { status: 400 });
    }

    const securePart = isLocalhost(request) ? "" : "Secure; ";
    // Set access token cookie and clear temporary cookies, then redirect
    const headers = new Headers();
    headers.set("Location", redirectTo);
    headers.append(
      "Set-Cookie",
      `access_token=${tokenData.access_token}; HttpOnly; ${securePart}Max-Age=34560000; SameSite=${sameSite}; Path=/`
    );
    headers.append(
      "Set-Cookie",
      `redirect_uri=; HttpOnly; ${securePart}Max-Age=0; SameSite=${sameSite}; Path=/`
    );
    headers.append(
      "Set-Cookie",
      `redirect_to=; HttpOnly; ${securePart}Max-Age=0; SameSite=${sameSite}; Path=/`
    );

    return new Response(null, {
      status: 302,
      headers,
    });
  } catch (error) {
    console.error("Callback error:", error);
    return new Response("Authentication failed", { status: 500 });
  }
}

async function handleToken(
  request: Request,
  providerHostname: string
): Promise<Response> {
  // Handle preflight OPTIONS request
  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
      },
    });
  }

  // Proxy token requests to the provider
  const url = new URL(request.url);
  const providerUrl = `https://${providerHostname}/token`;

  const response = await fetch(providerUrl, {
    method: request.method,
    headers: request.headers,
    body: request.body,
  });

  // Return the provider's response with CORS headers
  const newResponse = new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: {
      ...Object.fromEntries(response.headers),
      "Access-Control-Allow-Origin": "*",
    },
  });

  return newResponse;
}

async function handleMe(
  request: Request,
  providerHostname: string
): Promise<Response> {
  // Handle preflight OPTIONS request
  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
      },
    });
  }

  // Proxy /me requests to the provider
  const providerUrl = `https://${providerHostname}/me`;

  const response = await fetch(providerUrl, {
    method: request.method,
    headers: request.headers,
  });

  // Return the provider's response with CORS headers

  type UserResult = {
    data: {
      id: string;
      name: string;
      username: string;
      profile_image_url?: string | undefined;
      verified?: boolean | undefined;
    };
  };
  const newResponse = new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: {
      ...Object.fromEntries(response.headers),
      "Access-Control-Allow-Origin": "*",
    },
  });

  return newResponse;
}

function handleLogout(request: Request, sameSite: string): Response {
  const url = new URL(request.url);
  const redirectTo = url.searchParams.get("redirect_to") || "/";
  const securePart = isLocalhost(request) ? "" : "Secure; ";

  return new Response(null, {
    status: 302,
    headers: {
      Location: redirectTo,
      "Set-Cookie": `access_token=; HttpOnly; ${securePart}SameSite=${sameSite}; Max-Age=0; Path=/`,
    },
  });
}

/**
 * Extract access token from request cookies or Authorization header
 */
function getAccessToken(request: Request): string | null {
  // Check Authorization header first (for API clients)
  const authHeader = request.headers.get("Authorization");
  if (authHeader?.startsWith("Bearer ")) {
    return authHeader.substring(7);
  }

  // Check cookie (for browser clients)
  const cookies = parseCookies(request.headers.get("Cookie") || "");
  return cookies.access_token || null;
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

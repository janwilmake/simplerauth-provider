import { AuthProvider, oauthEndpoints } from "login-with-cloudflare";

export interface Env {
  AuthProvider: DurableObjectNamespace;
  // Add other environment variables if needed
}

export default {
  async fetch(
    request: Request,
    env: Env,
    ctx: ExecutionContext
  ): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    // Handle OAuth endpoints
    if (oauthEndpoints.includes(path)) {
      const id = env.AuthProvider.idFromName("auth-provider");
      const authProvider = env.AuthProvider.get(id);
      return authProvider.fetch(request);
    }

    // Handle your application routes
    if (path === "/") {
      return handleHome(request, env);
    }

    if (path === "/protected") {
      return handleProtected(request, env);
    }

    if (path === "/logout") {
      return handleLogout(request, env);
    }

    return new Response("Not Found", { status: 404 });
  },
};

async function handleHome(request: Request, env: Env): Promise<Response> {
  const html = `
    <!DOCTYPE html>
    <html>
      <head>
        <title>Cloudflare Login Demo</title>
        <style>
          body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
          .button { display: inline-block; padding: 10px 20px; background: #0066cc; color: white; text-decoration: none; border-radius: 4px; }
          .user-info { background: #f0f0f0; padding: 10px; margin: 10px 0; border-radius: 4px; }
        </style>
      </head>
      <body>
        <h1>Login with Cloudflare Demo</h1>
        <p>This demo shows how to use Cloudflare authentication in a Worker.</p>
        <a href="/protected" class="button">Access Protected Area</a>
        <p><small>You'll be redirected to Cloudflare login if not authenticated.</small></p>
      </body>
    </html>
  `;

  return new Response(html, {
    headers: { "Content-Type": "text/html" },
  });
}

async function handleProtected(request: Request, env: Env): Promise<Response> {
  const user = await getCurrentUser(request, env);

  if (!user) {
    // User not authenticated, redirect to login
    const loginUrl = await getLoginUrl(request, env);
    return Response.redirect(loginUrl, 302);
  }

  const html = `
    <!DOCTYPE html>
    <html>
      <head>
        <title>Protected Area</title>
        <style>
          body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
          .user-info { background: #f0f0f0; padding: 15px; margin: 15px 0; border-radius: 4px; }
          .button { display: inline-block; padding: 10px 20px; background: #0066cc; color: white; text-decoration: none; border-radius: 4px; margin: 5px; }
          .logout { background: #cc0000; }
          pre { background: #f8f8f8; padding: 10px; border-radius: 4px; overflow-x: auto; }
        </style>
      </head>
      <body>
        <h1>Protected Area</h1>
        <p>Welcome! You are successfully authenticated.</p>
        
        <div class="user-info">
          <h3>User Information:</h3>
          <p><strong>Name:</strong> ${user.name}</p>
          <p><strong>Username:</strong> ${user.username}</p>
          <p><strong>Verified:</strong> ${user.verified ? "Yes" : "No"}</p>
          <p><strong>Cloudflare Account ID:</strong> ${
            user.cloudflare_account_id
          }</p>
          <p><strong>API Key Name:</strong> ${user.cloudflare_key_name}</p>
        </div>

        <div>
          <h3>Full User Data:</h3>
          <pre>${JSON.stringify(user, null, 2)}</pre>
        </div>

        <div>
          <a href="/" class="button">Home</a>
          <a href="/logout" class="button logout">Logout</a>
        </div>
      </body>
    </html>
  `;

  return new Response(html, {
    headers: { "Content-Type": "text/html" },
  });
}

async function handleLogout(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const clientId = url.hostname;

  // Clear session cookie
  const sessionCookieName = `session_${clientId.replace(/[^a-zA-Z0-9]/g, "_")}`;

  return new Response(null, {
    status: 302,
    headers: {
      Location: "/",
      "Set-Cookie": `${sessionCookieName}=; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Path=/; Domain=${url.hostname}`,
    },
  });
}

async function getCurrentUser(request: Request, env: Env): Promise<any | null> {
  const url = new URL(request.url);
  const clientId = url.hostname;

  // Check for session cookie
  const cookies = request.headers.get("Cookie");
  const sessionCookieName = `session_${clientId.replace(/[^a-zA-Z0-9]/g, "_")}`;

  if (!cookies) return null;

  const cookieMatch = cookies.match(new RegExp(`${sessionCookieName}=([^;]+)`));
  if (!cookieMatch) return null;

  const accessToken = cookieMatch[1];

  // Get user info from auth provider
  const userRequest = new Request(`${url.origin}/user`, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
    },
  });

  const id = env.AuthProvider.idFromName("auth-provider");
  const authProvider = env.AuthProvider.get(id);
  const userResponse = await authProvider.fetch(userRequest);

  if (!userResponse.ok) return null;

  return await userResponse.json();
}

async function getLoginUrl(request: Request, env: Env): Promise<string> {
  const url = new URL(request.url);
  const clientId = url.hostname;

  // Generate OAuth authorization URL
  const authUrl = new URL(`${url.origin}/authorize`);
  authUrl.searchParams.set("client_id", clientId);
  authUrl.searchParams.set("redirect_uri", `${url.origin}/protected`);
  authUrl.searchParams.set("state", "protected");
  authUrl.searchParams.set("message", "Login to access protected content");

  return authUrl.toString();
}

// Export the AuthProvider Durable Object
export { AuthProvider };

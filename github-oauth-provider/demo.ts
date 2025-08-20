import {
  handleOAuth,
  Env,
  CodeDO,
  GitHubUser,
} from "./github-oauth-client-provider";

export { CodeDO };

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    // Handle OAuth routes first
    const oauthResponse = await handleOAuth(request, env);
    if (oauthResponse) {
      return oauthResponse;
    }

    const url = new URL(request.url);

    if (url.pathname === "/") {
      return handleHome(request, env);
    }

    return new Response("Not found", { status: 404 });
  },
} satisfies ExportedHandler<Env>;

async function handleHome(request: Request, env: Env): Promise<Response> {
  const accessToken =
    decodeURIComponent(
      request.headers
        .get("Cookie")
        ?.split(";")
        .find((c) => c.trim().startsWith("access_token="))
        ?.split("=")[1] || "",
    ) || null;

  if (!accessToken) {
    return new Response(
      `
      <html>
        <body>
          <h1>OAuth Demo</h1>
          <p>You are not logged in.</p>
          <a href="/authorize">Login with GitHub (direct flow)</a><br>
          <a href="/provider">Try provider flow example</a>
        </body>
      </html>
    `,
      { headers: { "Content-Type": "text/html" } },
    );
  }

  const userDOId = env.CODES.idFromName(`user:${accessToken}`);
  const userDO = env.CODES.get(userDOId);
  const userData = await userDO.getUser();
  if (!userData) {
    return new Response(
      `
            <html>
            <body>
            <h1>OAuth Demo</h1>
            <p>Error fetching user info</p>
            <a href="/logout">Logout</a>
            </body>
            </html>
            `,
      {
        headers: { "Content-Type": "text/html" },
      },
    );
  }
  const { user } = userData as unknown as { user: GitHubUser };

  return new Response(
    `
    <html>
      <body>
        <h1>OAuth Demo</h1>
        <p>Welcome, ${user.name || user.login}!</p>
        <img src="${user.avatar_url}" alt="Avatar" width="50" height="50">
        <p>Username: ${user.login}</p>
        <p>Email: ${user.email || "Private"}</p>
        <a href="/logout">Logout</a><br>
        <a href="/provider">Try provider flow example</a>
      </body>
    </html>
  `,
    {
      headers: { "Content-Type": "text/html" },
    },
  );
}

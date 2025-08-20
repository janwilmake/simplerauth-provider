# GitHub OAuth Provider

[![janwilmake/github-oauth-client-provider context](https://badge.forgithub.com/janwilmake/github-oauth-client-provider/tree/main/README.md)](https://uithub.com/janwilmake/github-oauth-client-provider/tree/main/README.md) [![](https://b.lmpify.com)](https://letmeprompt.com?q=https://uithub.com/janwilmake/github-oauth-client-provider/tree/main/README.md) [![](https://badge.xymake.com/janwilmake/status/1935257829767524501)](https://x.com/janwilmake/status/1935257829767524501)

This github oauth client-provider uses the client's domain name as the client_id and automatically derives the `redirect_uri` from it (e.g., `https://example.com/callback`), eliminating the need for client registration while maintaining security through domain validation.

## Setup

1. Installation:

```
npm i simplerauth-github-provider
```

2. Set environment variables:

   - `GITHUB_CLIENT_ID`: Your GitHub OAuth app client ID
   - `GITHUB_CLIENT_SECRET`: Your GitHub OAuth app client secret

3. Add to your worker:

### Direct flow

```typescript
import {
  handleOAuth,
  getAccessToken,
  CodeDO,
} from "simplerauth-github-provider";
export { CodeDO };
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    // Handle OAuth routes
    const oauthResponse = await handleOAuth(request, env);
    if (oauthResponse) return oauthResponse;

    // Check if user is authenticated
    const accessToken = getAccessToken(request);
    if (!accessToken) {
      // Redirect users to `/authorize?redirect_to=/dashboard` for simple login.
      return Response.redirect(
        "/authorize?redirect_to=" + encodeURIComponent(request.url),
      );
    }

    // Your app logic here
    return new Response("Hello authenticated user!");
  },
};
```

### Enforced Authentication Flow:

```typescript
import { CodeDO, withSimplerAuth } from "simplerauth-github-provider";
export { CodeDO };
export default {
  fetch: withSimplerAuth(async (request, env, ctx) => {
    return new Response(
      `<html><body>
        <h1>OAuth Demo</h1>
        <p>Welcome, ${ctx.user.name || ctx.user.login}!</p>
        <img src="${ctx.user.avatar_url}" alt="Avatar" width="50" height="50">
        <p>Username: ${ctx.user.login}</p>
        <a href="/logout">Logout</a><br>
        <a href="/provider">Try provider flow example</a>
      </body></html>`,
      { headers: { "Content-Type": "text/html" } },
    );
  }),
};
```

### OAuth Provider Flow

Other apps can use standard OAuth 2.0 flow with your worker as the provider. See [public/provider.html](public/provider.html) for a client example.

### Client Integration Steps

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

```javascript
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

4. **Use Access Token**: Use the token to make GitHub API requests:

```javascript
const userResponse = await fetch("https://api.github.com/user", {
  headers: { Authorization: `Bearer ${access_token}` },
});
```

### Security Notes

- Client domains are validated - `client_id` must be a valid domain
- Redirect URIs must be HTTPS and on the same domain as `client_id`
- Authorization codes expire after 10 minutes
- No client registration required - the domain serves as the client identifier

## Routes

- `/authorize` - OAuth authorization endpoint
- `/token` - OAuth token endpoint
- `/callback` - GitHub OAuth callback
- `/logout` - Logout and clear session

## Notes

As an attempt at making this more agent-friendly, this uses standard OAuth 2.0. However, I also used the following logic in `withSimplerAuth` to tell agents where to login if they're not familiar with OAuth 2.0:

```ts
{
  status: isBrowser ? 302 : 401,
  headers: {
    Location,
    "X-Login-URL": Location,
    // see https://datatracker.ietf.org/doc/html/rfc9110#name-www-authenticate
    "WWW-Authenticate": `Bearer realm="main", login_url="${Location}"`,
  },
}
```

An agent not using a browser could either try and login themselves at `Location`, or they could pass that to a User-controlled browser to retrieve the required credentials.

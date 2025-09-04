# SimplerAuth Client

Context: https://unpkg.com/simplerauth-client/README.md

OAuth middleware for Cloudflare Workers.

## Usage

```ts
import { withSimplerAuth } from "simplerauth-client";

export default {
  fetch: withSimplerAuth(
    async (request, env, ctx) => {
      if (ctx.authenticated) {
        return new Response(`Hello ${ctx.user.name}!`);
      }
      return new Response("Hello, anonymous!");
    },
    { isLoginRequired: true }
  ),
};
```

## API

```ts
/**
 * OAuth middleware that adds authentication to your handler
 */
function withSimplerAuth<TEnv = {}>(
  handler: UserFetchHandler<TEnv>,
  config?: SimplerAuthConfig
): ExportedHandlerFetchHandler<TEnv>;

interface SimplerAuthConfig {
  /** Force login for all requests */
  isLoginRequired?: boolean;
  /** OAuth scopes (default: "profile") */
  scope?: string;
  /** Cookie SameSite setting (default: "Lax") */
  sameSite?: "Strict" | "Lax";
  /** OAuth provider hostname (default: "login.wilmake.com") */
  providerHostname?: string;
}

interface UserContext extends ExecutionContext {
  /** Authenticated user info */
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
  profile_image_url?: string;
  verified?: boolean;
};
```

Provides OAuth endpoints: `/authorize`, `/callback`, `/token`, `/me`, `/logout`

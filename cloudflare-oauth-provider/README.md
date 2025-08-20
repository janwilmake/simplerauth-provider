# Login with Cloudflare

See https://cloudflare.simplerauth.com for how to use it fully raw (any programming language)

Also good to use in combination with https://uithub.com/janwilmake/simplerauth-provider. See [mod.ts](mod.ts) on how this can be used while also exposing an MCP-compatible oauth provider. Can be installed using `npm i login-with-cloudflare` and add to your wrangler.json:

```json
{
  "durable_objects": {
    "bindings": [{ "name": "AuthProvider", "class_name": "AuthProvider" }]
  },
  "migrations": [{ "tag": "v1", "new_sqlite_classes": ["AuthProvider"] }]
}
```

And then use it like this:

```ts
import { oauthEndpoints, AuthProvider } from "login-with-cloudflare";
export { AuthProvider };
type Env = {
  AuthProvider: DurableObjectNamespace;
};
export default {
  fetch: (request: Request, env: Env, ctx: ExecutionContext) => {
    const url = new URL(request.url);
    if (oauthEndpoints.includes(url.pathname)) {
      return env.AuthProvider.get(
        env.AuthProvider.idFromName("oauth-central")
      ).fetch(request);
    }
    return new Response("Not found", { status: 404 });
  },
};
```

See [demo](demo) for a more complete example

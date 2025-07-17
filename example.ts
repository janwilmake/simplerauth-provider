import { oauthEndpoints } from "./provider";

type Env = {
  AuthProvider: DurableObjectNamespace;
  CLIENT_ID: string;
  CLIENT_SECRET: string;
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

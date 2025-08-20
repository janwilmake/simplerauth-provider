import { CodeDO, withSimplerAuth } from "./github-oauth-client-provider";
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

import { CodeDO, withSimplerAuth } from "./x-oauth-client-provider";
export { CodeDO };
export default {
  fetch: withSimplerAuth(async (request, env, ctx) => {
    return new Response(
      `<html><body>
        <h1>X OAuth Demo</h1>
        <p>Welcome, ${ctx.user.name || ctx.user.username}!</p>
        <img src="${
          ctx.user.profile_image_url || "/default-avatar.png"
        }" alt="Avatar" width="400" height="400" style="border-radius:200px;">
        <p>Username: @${ctx.user.username}</p>
        <p>Verified: ${ctx.user.verified ? "✓" : "✗"}</p>
        <a href="/logout">Logout</a><br>
        <a href="/provider">Try provider flow example</a>
      </body></html>`,
      { headers: { "Content-Type": "text/html;charset=utf8" } },
    );
  }),
};

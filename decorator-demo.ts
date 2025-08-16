import { UserDO, withSimplerAuth } from "./x-oauth-client-provider";
export { UserDO };
export default {
  fetch: withSimplerAuth(async (request, env, ctx) => {
    if (!ctx.user) {
      return new Response(null, {
        status: 302,
        headers: { Location: "/authorize?redirect_to=/" },
      });
    }
    return new Response(
      `<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>X OAuth Demo</title><style>*{margin:0;padding:0;box-sizing:border-box}body{font:16px/1.5 -apple-system,sans-serif;background:linear-gradient(135deg,#667eea,#764ba2);min-height:100vh;display:flex;align-items:center;justify-content:center;color:#fff}main{background:rgba(255,255,255,.1);backdrop-filter:blur(10px);border-radius:20px;padding:40px;text-align:center;box-shadow:0 8px 32px rgba(0,0,0,.3);max-width:400px;width:90%}h1{font-size:28px;margin-bottom:20px;text-shadow:0 2px 4px rgba(0,0,0,.3)}img{border-radius:50%;border:4px solid rgba(255,255,255,.3);margin:20px 0;transition:transform .3s ease}img:hover{transform:scale(1.1)}p{margin:10px 0;font-size:18px}.verified{color:#1da1f2}.username{font-weight:bold;font-size:20px}a{display:inline-block;margin:10px 8px;padding:12px 24px;background:rgba(255,255,255,.2);color:#fff;text-decoration:none;border-radius:25px;transition:all .3s ease;border:1px solid rgba(255,255,255,.3)}a:hover{background:rgba(255,255,255,.3);transform:translateY(-2px);box-shadow:0 4px 12px rgba(0,0,0,.2)}</style></head><body><main>
        <h1>✨ X OAuth Demo</h1>
        <p class="username">Welcome, ${ctx.user.name || ctx.user.username}!</p>
        <img src="${
          ctx.user.profile_image_url || "/default-avatar.png"
        }" alt="Avatar" width="120" height="120">
        <p>@${ctx.user.username}</p>
        <p class="verified">${
          ctx.user.verified ? "✓ Verified" : "Not verified"
        }</p>
        <div><a href="/logout">Logout</a><a href="/provider">Try Provider Flow</a></div>
      </main></body></html>`,
      { headers: { "Content-Type": "text/html;charset=utf-8" } }
    );
  }, {}),
};

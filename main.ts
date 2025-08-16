import { UserDO, withSimplerAuth } from "./x-oauth-client-provider";
export { UserDO };
const allowedClients = undefined;
export default {
  fetch: withSimplerAuth(
    async (request, env, ctx) => {
      return new Response(
        `<html><head><meta charset="utf8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SimplerAuth X Provider</title><style>*{margin:0;padding:0;box-sizing:border-box}body{font:14px system-ui;background:#fcfcfa;color:#1d1b16;min-height:100vh;display:flex;align-items:center;justify-content:center}@media(prefers-color-scheme:dark){body{background:#1d1b16;color:#fcfcfa}}.card{background:#fcfcfa;border:1px solid #d8d0bf;border-radius:12px;padding:24px;text-align:center;box-shadow:0 2px 8px rgba(29,27,22,.1);max-width:320px}@media(prefers-color-scheme:dark){.card{background:#1d1b16;border-color:#d8d0bf33}}.avatar{width:80px;height:80px;border-radius:50%;margin:0 auto 16px;display:block;border:2px solid #d8d0bf}h1{font-size:20px;margin-bottom:16px}p{margin-bottom:8px;color:#d8d0bf}.name{color:#1d1b16;font-weight:600;font-size:16px}@media(prefers-color-scheme:dark){.name{color:#fcfcfa}}a{color:#fb631b;text-decoration:none;margin:8px 12px 0;display:inline-block}a:hover{text-decoration:underline}</style></head><body><div class="card"><img src="${
          ctx.user.profile_image_url || "/default-avatar.png"
        }" alt="Avatar" class="avatar"><h1>SimplerAuth X Provider</h1><p>Any client will be able to retrieve your profile without further consent.</p><p class="name">${
          ctx.user.name || ctx.user.username
        }</p><p>@${ctx.user.username}</p><p>${
          ctx.user.verified ? "✓ Verified" : "Unverified"
        }</p><p><a href="/logout">Logout</a></p>${
          env.ADMIN_X_USERNAME === ctx.user.username
            ? '<p><a target="_blank" href="/admin">Admin</a>'
            : ""
        }</div></body></html>`,
        { headers: { "Content-Type": "text/html;charset=utf8" } }
      );
    },
    { isLoginRequired: true, allowedClients }
  ),
};

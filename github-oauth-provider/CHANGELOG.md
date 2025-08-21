# 2025-06-18

Initial prompt: https://letmeprompt.com/httpsuithubcomj-uiq7t40

- ✅ Add `withSimplerAuth(handler,config?:{scope?:string})` fetch wrapper to have a one-liner that logs in if unauthenticated and passes user simple user-do access to ctx.
- ✅ Create minimal demo `withSimplerAuth`
- ✅ Create `withPathKv(handler,config:{binding:string})` that can wrap this to add the path-kv pattern allowing public exceptions

# 2025-08-20

- ✅ Moved to https://github.com/janwilmake/simplerauth-provider
- ✅ Refactored to align with pattern of `x-oauth-provider`: now supports multi-client state, dynamic client registration, and more.
- ✅ Deploy and test, confirm it works.
- ✅ Remove emails from user if present, document what fields user has
- ✅ Work on explaining, focus on a blog about building 'login with Parallel' and the thought process. Focus on the why
- ❗️❗️❗️❗️❗️ Ensure `github-oauth-provider` works with `simplerauth-client` in the same way as `x-oauth-provider`. The spec must be exactly the same. Extrahere `simplerauth-provider-specification.md` document that summarizes it in RFC-style, and also turn that into an `simplerauth-provider.openapi.json`.

# Next time

- Create new version of `cloudflare-oauth-provider`; Try using `github-oauth-provider` as package and add just the dialog and storage, proxy the rest. If this is more practical, consider using as binding or remote, or don't wrap it at all. What's important: composability and MCP features.
- If that works, do the same for `parallel-oauth-provider`. Here, maybe, we want to host the `github-oauth-provider` ourselves too (custom client), at `gh.p0web.com`. Then, 'login with Parallel' is fully Parallel branded. To make it fully trustworthy, `parallel-web` needs to be the one creating the OAuth Client.

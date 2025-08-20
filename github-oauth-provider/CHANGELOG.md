# 2025-06-18

Initial prompt: https://letmeprompt.com/httpsuithubcomj-uiq7t40

- ✅ Add `withSimplerAuth(handler,config?:{scope?:string})` fetch wrapper to have a one-liner that logs in if unauthenticated and passes user simple user-do access to ctx.
- ✅ Create minimal demo `withSimplerAuth`
- ✅ Create `withPathKv(handler,config:{binding:string})` that can wrap this to add the path-kv pattern allowing public exceptions

# 2025-08-20

- ✅ Moved to https://github.com/janwilmake/simplerauth-provider
- ✅ Refactored to align with pattern of `x-oauth-provider`: now supports multi-client state, dynamic client registration, and more.
- Deploy and test, confirm it works.
- Remove emails from user if present, document what fields user has
- Ensure `github-oauth-provider` works with `simplerauth-client`.
- Improve `cloudflare-oauth-provider`; Try using `github-oauth-provider` as package and add just the dialog and storage, proxy the rest. If more practical, consider using as binding or remote, or don't wrap it at all....
- Make `parallel-oauth-provider` that adds a dialog for API key selection, and proxies to `gh.wilmake.com`.
- Work on explaining, focus on a blog about building 'login with Parallel'.

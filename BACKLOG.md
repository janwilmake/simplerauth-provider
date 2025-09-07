# Work towards parallel oauth provider

- Ensure `github-oauth-provider` works with `simplerauth-client` in the same way as `x-oauth-provider`. The spec must be exactly the same. Extrahere `simplerauth-provider-specification.md` document that summarizes it in RFC-style, and also turn that into an `simplerauth-provider.openapi.json`.
- If that works, do the same for `parallel-oauth-provider`. Here, maybe, we want to host the `github-oauth-provider` ourselves too (custom client), at `gh.p0web.com`. Then, 'login with Parallel' is fully Parallel branded. To make it fully trustworthy, `parallel-web` needs to be the one creating the OAuth Client.
- Optional: Create new version of `cloudflare-oauth-provider`; Try using `github-oauth-provider` as package and add just the dialog and storage, proxy the rest. If this is more practical, consider using as binding or remote, or don't wrap it at all. What's important: composability and MCP features.

# Scalability

- Figure out how I can reduce load on aggregate.
  - Cache `/me` from `simplerauth-client`?
  - Only connect to aggregate once per 15 minutes (from user DO, not exported handler?)
- Add per-apex (or per-user) ratelimit (1200 requests per minute should do) to prevent capacity constraints and DDOS problems

# Work on potenital MCP protocol change proposoal (SEP)

Look at https://github.com/modelcontextprotocol/modelcontextprotocol/discussions/1405 again and see what I can change to the SPEC without breaking anything and without adding complexity. The main thing this solves is spoofing attacks when allowing for DCR (although spoofing can still be done if people confuse hostnames with similar ones)

# Goal This Weekend: Successfully go through Entire OAuth flow with SimplerAuth Client, be able to have Anthropic log into it.

- Fix login problem when doing oauth. Test flow with `npx @modelcontextprotocol/inspector`.
- Confirm `x-oauth-provider` is complete and functional now
- Write more about DCR security
- Ensure `github-oauth-provider` works with `simplerauth-client` in the same way as `x-oauth-provider`. The spec must be exactly the same. Extrahere `simplerauth-provider-specification.md` document that summarizes it in RFC-style, and also turn that into an `simplerauth-provider.openapi.json`.
- Create new version of `cloudflare-oauth-provider`; Try using `github-oauth-provider` as package and add just the dialog and storage, proxy the rest. If this is more practical, consider using as binding or remote, or don't wrap it at all. What's important: composability and MCP features.
- If that works, do the same for `parallel-oauth-provider`. Here, maybe, we want to host the `github-oauth-provider` ourselves too (custom client), at `gh.p0web.com`. Then, 'login with Parallel' is fully Parallel branded. To make it fully trustworthy, `parallel-web` needs to be the one creating the OAuth Client.

# DRC Security

https://tailscale.com/blog/dynamic-client-registration-dcr-for-mcp-ai

Proposal to have separate domain-hosted document with client information - https://github.com/modelcontextprotocol/modelcontextprotocol/issues/991

My proposal:
https://github.com/modelcontextprotocol/modelcontextprotocol/discussions/1405

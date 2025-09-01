# Goal This Weekend

Successfully go through Entire OAuth flow with SimplerAuth Client, be able to have Anthropic log into Markdownfeed MCP, Curl MCP, OpenAPI MCP Server

# Hostname-as-Client-ID Principle Discussion

✅ Write more about DCR security: https://github.com/modelcontextprotocol/modelcontextprotocol/discussions/1405

# Create MCP-compatible OAuth Flow Test

✅ It'd be great to have a UI myself too for this as part of `universal-mcp-oauth`. Similarly, can be all purely front-end. Let's host it at https://mcp.agent-friendly.com.

Use latest X OAuth provider at markdownfeed. Confirm `x-oauth-provider` is complete and functional now.

Test it with `npx @modelcontextprotocol/inspector` and https://mcp.agent-friendly.com

# Other providers

- Ensure `github-oauth-provider` works with `simplerauth-client` in the same way as `x-oauth-provider`. The spec must be exactly the same. Extrahere `simplerauth-provider-specification.md` document that summarizes it in RFC-style, and also turn that into an `simplerauth-provider.openapi.json`.
- Create new version of `cloudflare-oauth-provider`; Try using `github-oauth-provider` as package and add just the dialog and storage, proxy the rest. If this is more practical, consider using as binding or remote, or don't wrap it at all. What's important: composability and MCP features.
- If that works, do the same for `parallel-oauth-provider`. Here, maybe, we want to host the `github-oauth-provider` ourselves too (custom client), at `gh.p0web.com`. Then, 'login with Parallel' is fully Parallel branded. To make it fully trustworthy, `parallel-web` needs to be the one creating the OAuth Client.

# Improve MCP

Look at https://github.com/modelcontextprotocol/modelcontextprotocol/discussions/1405 again and see what I can change to the SPEC without breaking anything and without adding complexity. The main thing this solves is spoofing attacks when allowing for DCR (although spoofing can still be done if people confuse hostnames with similar ones)

# DCR Security

https://tailscale.com/blog/dynamic-client-registration-dcr-for-mcp-ai

Proposal to have separate domain-hosted document with client information - https://github.com/modelcontextprotocol/modelcontextprotocol/issues/991

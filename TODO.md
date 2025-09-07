# Goal This Weekend - Fix MCP login

Successfully go through Entire OAuth flow with SimplerAuth Client, be able to have the Claude.ai client log into Markdownfeed MCP, Curl MCP, OpenAPI MCP Server. Host these all!

❗️ Now, I'm getting: `{"error":"invalid_token","error_description":"Token not found or expired"}` for `/authorize` if done from https://mcp.p0web.com. Am I calling the endpoint correctly? Go over the code here.

Let's look in the database if things are done correctly and if every error is logged.

Use latest X OAuth provider at `markdownfeed`. Confirm `x-oauth-provider` is complete and functional now. Test it with `npx @modelcontextprotocol/inspector` and https://mcp.agent-friendly.com

🔥🔥🔥🔥 After I have this.... I can finally ship MCPs with login. Add `withMcp` to `flaredream-user-worker` and start shipping `agent-friendly` workers. 🔥🔥🔥🔥

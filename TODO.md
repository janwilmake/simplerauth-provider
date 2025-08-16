# This weekend (or monday)

- ✅ Need `withSimplerAuth` implementation that uses arbitrary address for token exchange, not X.
- ❗️ Ensure the access-token encodes the `user_id` as well as the `client_id` (needs new table `logins`): now, each client has a different access token for each user.
- Change registered scopes in `simplerauth-client` to just `profile` (standard)
- Keep track of created at, updated at, and request_count in logins!!! Super valueable stats
- use user_id for DO name
- don't use aggregate for read-only queries
- Make admin truly read only
- Confirm it's secure and complies with https://modelcontextprotocol.io/specification/draft/basic/authorization and security best practices. Put a LMPIFY prompt in readme that shows this!

- Lay out the concept of `domain-as-client-id` and explain MCP-recommended programmatic oauth flow. This is also great to share on X and with the team.
- Change to use this provider in `markdownfeed`, `universal-oauth-provider`, and `basedpeople` (and from now on, everywhere)
- Test markdownfeed MCP with https://universal.simplerauth.com
- Figure out if we should require a unique access_token per client-id (since we may wanna reuse it directly for api calls, it makes sense)
- Make it a `flaredream build` module that removes it from worker-custom code while still allowing for `wrangler dev`.
- Add it to `system[-ts].md`

AMBITION - SOLVE OAUTH ONCE AND FOR ALL! Use this by default unless specificaly disabled.

Bonus:

- Having a way to track which users are logged in with which client_id's and when/where/how often they're active
- When logged in, connect durable-worker with user-DO
- Stripeflare must take user-ID and must be able to have metadata for payment callback with custom logic per metadata. May need different boundary.

Meeting Mv:

- Make standalone POC OAuth with all MCP stuff?

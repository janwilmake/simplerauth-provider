# This weekend (or monday)

- Need `withSimplerAuth` implementation that uses arbitrary address for token exchange, not X.
- Change to use this provider in `markdownfeed`, `universal-oauth-provider`, and `basedpeople` (and from now on, everywhere)
- Confirm it's secure and complies with https://modelcontextprotocol.io/specification/draft/basic/authorization and security best practices. Put a LMPIFY prompt in readme that shows this!
- Think about the permissiveness of giving user to every client after one approval - be super clear on this!
- Lay out the concept of `domain-as-client-id` and explain MCP-recommended programmatic oauth flow. This is also great to share on X and with the team.
- Test markdownfeed MCP with https://universal.simplerauth.com
- Make it a `flaredream build` module that removes it from worker-custom code while still allowing for `wrangler dev`.
- Add it to `system[-ts].md`

AMBITION - SOLVE OAUTH ONCE AND FOR ALL! Use this by default unless specificaly disabled.

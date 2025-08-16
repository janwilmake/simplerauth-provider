# Changelog

## 2025-06-27

Initial implementation based on GitHub OAuth client-provider pattern.

- ✅ Add `withSimplerAuth(handler,config?:{scope?:string})` fetch wrapper to have a one-liner that logs in if unauthenticated and passes user simple user-do access to ctx.
- ✅ Create minimal demo `withSimplerAuth`
- ✅ X OAuth 2.0 PKCE flow implementation
- ✅ Domain-based client identification (no registration required)
- ✅ MCP-compliant OAuth 2.0 server metadata endpoints
- ✅ Encrypted access token storage using Durable Objects
- ✅ Support for both direct login and OAuth provider flows

## 2025-08-15

- ✅ Turn users into a table
- ✅ Add multistub and queryable-object and enable admin login

AMBITION - SOLVE OAUTH ONCE AND FOR ALL! Use this by default unless specificaly disabled.

# TODO

## provider

- ✅ Need `withSimplerAuth` implementation that uses arbitrary address for token exchange, not X.
- 🤔 Figure out if we should require a unique access_token per client-id (since we may wanna reuse it directly for api calls, it makes sense)
- ❗️ Ensure the access-token encodes the `user_id` as well as the `client_id` (needs new table `logins`): now, each client has a different access tokens for each user, and there can be as many as required.
- use user_id for DO name
- don't use `aggregate` for read-only queries
- Every new login would create a new unique login! To not overwrite other devices.
- Keep track of created at, updated at, and request_count in logins!!! Super valueable stats
- 🟠 Add configuration `allowedClients` to restrict which clients can authorize.
- Make admin truly read-only
- Expose `/query` and MCP for that

## Client

- Change registered scopes in `simplerauth-client` to just `profile` (standard)
- Confirm it's secure and complies with https://modelcontextprotocol.io/specification/draft/basic/authorization and security best practices. Put a LMPIFY prompt in readme that shows this!
- Make it a `flaredream build` module that removes it from worker-custom code while still allowing for `wrangler dev`.
- Add it to `system[-ts].md`

## Content

- Lay out the concept of `domain-as-client-id` and explain MCP-recommended programmatic oauth flow. This is also great to share on X and with the team.

## Apply it

- Change to use this provider in `markdownfeed`, `universal-oauth-provider`, and `basedpeople` (and from now on, everywhere)
- Test markdownfeed MCP with https://universal.simplerauth.com

## Bonus

- Flaredream: When logged in, connect durable-worker with user-DO.
- Stripeflare must take user-ID and must be able to have metadata for payment callback with custom logic per metadata. May need different boundary.

## Meeting Mv:

- Make standalone POC OAuth with all MCP stuff?

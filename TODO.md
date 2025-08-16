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

# TODO

AMBITION - SOLVE OAUTH ONCE AND FOR ALL! Use this by default unless specificaly disabled (flaredream).

## Provider

- 🤔 Figure out if we should require a unique access_token per client-id (since we may wanna reuse it directly for api calls, it makes sense) **yes we do**
- ✅ Improved structure and README of this repo. A lot.
- ✅ Make admin truly read-only
- ✅ Create a new table `logins` that holds the access_token. Store x_access_token on the users, but access_token on the logins.
- ✅ Update datastructure
  - Create a new table `logins` that holds the access_token. Store x_access_token on the users, but access_token on the logins.
  - Ensure the access-token encodes and encrypts `user_id` as well as the `client_id` plus the x access token.
  - access*token format is of format simple*{encrypted_data} where the decrypted is in format `user_id:client_id:token` to keep it short. encrypted with env.X_CLIENT_SECRET. Now, each client has a different access tokens for each user, and there can be as many as required.
  - For all DO functions that affect either the logins or users table, use `user:${user_id}` for DO name. we can decrypt the access token to know the user_id
  - no backwards compatibility required
- Don't hit `aggregate` for read-only queries
- Every new login would create a new unique login! To not overwrite other devices.
- Keep track of created at, updated at, and request_count in logins!!! Super valueable stats
- 🟠 Add configuration `allowedClients` to restrict which clients can authorize.
- For admin, also expose `/query` and MCP for that
- Also expose `llms.txt` and `openapi.json` for the provider.

## Client

- ✅ Need `withSimplerAuth` implementation that uses arbitrary address for token exchange, not X.
- Change registered scopes in `simplerauth-client` to just `profile` (standard)
- Confirm it's secure and complies with https://modelcontextprotocol.io/specification/draft/basic/authorization and security best practices. Put a LMPIFY prompt in readme that shows this!

## Content

- Lay out the concept of `domain-as-client-id` and explain MCP-recommended programmatic oauth flow.
- This is also great to share on X and with the team.

## Apply it

- Change to use this provider in `markdownfeed`, `universal-oauth-provider`, and `basedpeople` (and from now on, everywhere)
- Test markdownfeed MCP with https://universal.simplerauth.com

## Bonus

- Make it a `flaredream build` module that removes it from worker-custom code while still allowing for `wrangler dev`.
- Add it to `system[-ts].md`
- Flaredream: When logged in, connect durable-worker with user-DO.
- Stripeflare must take user-ID and must be able to have metadata for payment callback with custom logic per metadata. May need different boundary.
- Create @wilmakesystems account with more subtle profile picture, and align the logo with that, so login comes over more trustworthy.

## Meeting Mv:

- Make standalone POC OAuth with all MCP stuff?

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

## 2025-08-16

- 🤔 Figure out if we should require a unique access_token per client-id (since we may wanna reuse it directly for api calls, it makes sense) **yes we do**
- ✅ Improved structure and README of this repo. A lot.
- ✅ Make admin truly read-only
- ✅ Create a new table `logins` that holds the access_token. Store x_access_token on the users, but access_token on the logins.
- ✅ Update datastructure
  - Create a new table `logins` that holds the access_token. Store x_access_token on the users, but access_token on the logins.
  - Ensure the access-token encodes and encrypts `user_id` as well as the `client_id` plus the x access token.
  - access*token format is of format `simple*{encrypted_data}` where the decrypted is in format`user_id:client_id:token`to keep it short. encrypted with `env.X_CLIENT_SECRET`. Now, each client has a different access tokens for each user, and there can be as many as required.
  - For all DO functions that affect either the logins or users table, use `user:${user_id}` for DO name. we can decrypt the access token to know the user_id
  - no backwards compatibility required
- ✅ Every new login would create a new unique login! To not overwrite other devices.
- ✅ Keep track of created at, updated at, and request_count in logins!!! Super valueable stats. The logic should be as follows:
  - upon /callback, set last_active_at.
  - when calling /me, if last_active_at is more than an hour old but less than 4 hours old, only update last_active_at. if last_active_at is more than 4 hours old, increment session_count (there was inactivity for >3 hours)
- ✅ Client needs `withSimplerAuth` implementation that uses arbitrary address for token exchange, not X.
- ✅ Change registered scopes in `simplerauth-client` to just `profile` (standard)

# 2025-08-18

- ✅ Change to use `simplerauth-client` in `universal-oauth-provider`
- ✅ Improve `simplerauth-client` so localhost development 'just works' (But is this secure to open up?) `Invalid client_id: must be a valid domain`. For localhost, getting invalid grant. Test `basedpeople` locally.
  - ✅ Added check to `env.PORT` and header check to see if ip is localhost loopback ip
  - ✅ Fixed client to set temporary cookies for redirect_uri and redirect_to to ensure we can send them to the token endpoint
- 🤔 Specifically for basedpeople, doing a request to `ctx.user` every time makes this worker twice as expensive. Kinda wasteful, but is that important? Maybe, a cache to `/me` can be made configurable? Seems exessive to fetch it every time **Skip for now since this also tracks the user, which is something we want**
- ✅ Create `@wilmakesystems` account with more subtle profile picture, and align the logo with that, so login comes over more trustworthy. **Actually it wasn't needed since it doesn't change anything, but it's good to have a separate account for login so it won't get banned easily. I can now get 'basic' on janwilmake and experiment on that account while keeping this stable**

# TODO

AMBITION - SOLVE OAUTH ONCE AND FOR ALL! Use this by default unless specificaly disabled (flaredream).

- ✅ If it's easy enough, change to use this login in `markdownfeed`
- ✅ Add configuration `allowedClients` to restrict which clients can authorize.
- ✅ Test markdownfeed MCP with https://mcp.p0web.com. The problem now is that I don't hit 401 because the initialize endpoint is public. How do I tell `withMcp` that authorization is required? Is there a way in MCP authorization to make it optional? How should clients implement optional oauth? **Not possible** there seems no way currently to have an optional oauth requirement. You either make the server public or authenticated!
  - ✅ Make `withMcp` config to respond with 401 with `www-authorize` by proxying the response to a provided endpoint, e.g. `/me`. This one should be compliant, moving the auth compliance one level down.
  - ✅ Confirm new `withMcp` works in markdownfeed
- 🟠 Confirm it's secure and complies with https://modelcontextprotocol.io/specification/draft/basic/authorization.
  - ✅ Added PCKE check and resource check to client, making it work with localhost too
  - ✅ Fix resource audience validation in provider: https://letmeprompt.com/rules-httpsuithu-nwbujx0
  - Also hold my implementation against https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices
  - Put a LMPIFY prompt in readme that shows it's all good.

## Scalability

- Figure out how I can reduce load on aggregate.
  - Cache `/me` from `simplerauth-client`?
  - Only connect to aggregate once per 15 minutes (from user DO, not exported handler?)
- Add per-apex ratelimit (1200 requests per minute should do) to prevent capacity constraints and DDOS problems

## Blogpost

It'd be great to put all of this into a nice blogpost going into the why as well...

- Write a section in readme about scalability and performance, and how this may improve in the future (moving DOs around)
- Lay out the concept of `domain-as-client-id` and explain MCP-recommended programmatic oauth flow.
- When all is well, do an announcement for the `simplerauth-client`, it being the easiest way to add X login to your app (no secrets).
- Think about critics and put this into the blog with counterarguments.

## Meeting Mv

First probe enthousiasm to create 'login with parallel' functionality

Find approval for one of these:

- Option 1: Demonstrate standalone POC OAuth with all MCP stuff
- Option 2: Make parallel oauth provider that binds parallel API key to your X account, after which it's super easy to login into different recipes or tiny apps.

## Parallel OAuth provider

Just proxy through to login.wilmake.com to be logged in and let /token endpoint respond with the parallel API key instead

Context - https://github.com/janwilmake/simplerauth-provider

Makes no sense to wait for parallel oauth since it may take months; instead, use this first, and use it. Replace with their own oauth later.

Discuss: require Github login or X login? their choice.

## Bonus

- Make it a `flaredream build` module that removes it from worker-custom code while still allowing for `wrangler dev`. More work required to allow for packages (can hardcode speicific single-file ones maybe, at first, to skip bundling still)
- Add it to `system[-ts].md`. Can even be without being a module for now, just package and proper buildscript and main entry should be configured.
- Flaredream: When logged in, connect durable-worker with user-DO.
- Stripeflare must take user-ID and must be able to have metadata for payment callback with custom logic per metadata. May need different boundary.
- For admin, also expose `/query` and MCP for that
- Also expose `llms.txt` and `openapi.json` for the provider.
- Other modules (flaredream)
  - Stripeflare module
  - Toolflare module

All in all this will allow super easy paid app creation, perfect to promote parallel

https://github.com/janwilmake/openapi-to-mcp

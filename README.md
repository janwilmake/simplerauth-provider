[![](https://badge.forgithub.com/janwilmake/simplerauth-provider?lines=false)](https://uithub.com/janwilmake/simplerauth-provider?lines=false) [![](https://b.lmpify.com)](https://letmeprompt.com?q=https://uithub.com/janwilmake/simplerauth-provider)

Very readable, minimal, MCP compatible oauth-provider

- implements 'domain-as-client-id'
- dynamic client registration
- prevents re-login if already authenticated

The same patterns can be used for any downstream oauth provider, but in this case it uses X.

**Installation** - Just copy the file [provider.ts](provider.ts) and add an AuthProvider SQLite Durable Object to your [wrangler.json](wrangler.json).

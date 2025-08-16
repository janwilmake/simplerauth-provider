POC of a client that uses the `x-oauth-provider`, then also, in turn, makes itself a provider. Go to https://client.simplerauth.com to see this in practice.

- **Simpler** - literally wrap your fetch handler with `withSimplerAuth(handler,config)` and you'll have access to `ctx.user`.
- **Secretless** - no secrets needed due to the 'hostname as client-id' principle.
- **Stateless** - no state needed since every user gets their own tiny DB in the provider, yielding super high performance
- **Self-hostable** - Works with login.wilmake.com by default, but you can also host your own X OAuth Provider and configure that.

Usage

```
npm i simplerauth-client
```

```ts
import { withSimplerAuth } from "simplerauth-config";
export default {
  fetch: withSimplerAuth(handler, config),
};
```

Done!

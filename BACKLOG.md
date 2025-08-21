## Scalability

- Figure out how I can reduce load on aggregate.
  - Cache `/me` from `simplerauth-client`?
  - Only connect to aggregate once per 15 minutes (from user DO, not exported handler?)
- Add per-apex (or per-user) ratelimit (1200 requests per minute should do) to prevent capacity constraints and DDOS problems

# Fix security encryption

https://x.com/wgw_eth/status/1957840161263268344

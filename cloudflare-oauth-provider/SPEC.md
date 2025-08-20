https://uithub.com/janwilmake/gists/tree/main/named-codeblocks.md
OAuth provider for Cloudflare

- First, login with github
- Tied to GitHub, provide Account ID and Account-owned api key and give it a name.
- Every next login you can choose one of your previously provided keys to be passed back from `/token`. Allows any client to get access to this key DIRECTLY (be clear)

https://uithub.com/janwilmake/github-oauth-client-provider?lines=false

please implement this and add a very good README.md that explains exactly how to use it. will be hosted at cloudflare.simplerauth.com

NB:

- use `charset=utf8` in content-type responses
- logo is available at /logo.png
- expose README.md at `/README.md` by using `assets.directory = './'` and an appropriate `.assetsignore`

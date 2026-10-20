# Auth

Google sign-in's single redirect URI, `https://auth.app.haddow.me/callback`, shared by every app on `*.app.haddow.me`. New apps need no Google Cloud Console change.

An app starts sign-in with that `redirect_uri` and a state of `<subdomain>.<random>`. Google sends the reply here, and this Worker redirects it, query untouched, to `https://<subdomain>.app.haddow.me/auth/callback`. The app checks the state against its own cookie and exchanges the code itself (client secret and PKCE verifier), passing the same `redirect_uri`. This Worker keeps nothing and has no secrets. A code sent somewhere else is useless without that app's verifier, and it can only go to an `app.haddow.me` subdomain anyway.

`src/index.js` is the whole thing. `npm test`. Pushing to `main` deploys through Workers Builds (`npm test`, then `npx wrangler deploy`).

Google setup, done once: the OAuth client (the one budget uses) lists `https://auth.app.haddow.me/callback` under Authorised redirect URIs.

# Auth

Google sign-in's single redirect URI, `https://auth.app.haddow.me/callback`, shared by every app on `*.app.haddow.me`. New apps need no Google Cloud Console change.

An app starts sign-in with that `redirect_uri` and a state of `<subdomain>.<random>`. Google sends the reply here, and this Worker redirects it, query untouched, to `https://<subdomain>.app.haddow.me/auth/callback`. The app checks the state against its own cookie and exchanges the code itself (client secret and PKCE verifier), passing the same `redirect_uri`. This Worker keeps nothing and has no secrets. A code sent somewhere else is useless without that app's verifier, and it can only go to an `app.haddow.me` subdomain anyway.

`src/index.js` is the whole Worker.

`src/google.js` is the sign-in code the apps share (no dependencies): `startSignIn` builds Google's sign-in URL with PKCE, and `finishSignIn` swaps the code for an ID token, checks it and returns the verified email. Apps install it from GitHub (`"auth": "github:jonhaddow/auth"`) and import `auth/google`; their lockfile pins the commit, so run `npm update auth` in an app to pick up a change. It's not part of the deployed Worker.

 `npm test`. Pushing to `main` deploys through Workers Builds (`npm test`, then `npx wrangler deploy`).

Google setup, done once: the OAuth client (the one budget uses) lists `https://auth.app.haddow.me/callback` under Authorised redirect URIs.

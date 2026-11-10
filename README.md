# Auth

Google sign-in's single redirect URI, `https://auth.app.haddow.me/callback`, shared by every app on `*.app.haddow.me`. New apps need no Google Cloud Console change.

An app starts sign-in with that `redirect_uri` and a state of `<subdomain>.<random>`. Google sends the reply here, and this Worker redirects it, query untouched, to `https://<subdomain>.app.haddow.me/auth/callback`. The app checks the state against its own cookie and exchanges the code itself (client secret and PKCE verifier), passing the same `redirect_uri`. This Worker keeps nothing and has no secrets. A code sent somewhere else is useless without that app's verifier, and it can only go to an `app.haddow.me` subdomain anyway.

`src/index.js` is the whole Worker. `npm test`. Pushing to `main` deploys through Workers Builds (`npm test`, then `npx wrangler deploy`).

`src/google.js` is the sign-in code the apps share (no dependencies), imported as `auth/google`. It's not part of the deployed Worker. In an app (with `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` in its env):

- `npm install github:jonhaddow/auth`. The lockfile pins the commit, so run `npm update auth` to pick up a change.
- `/auth/google`: `redirect(302, await startSignIn(cookies, env.GOOGLE_CLIENT_ID, url.hostname), { external: ['https://accounts.google.com'] })`. It sets the `oauth_state` and `oauth_verifier` cookies.
- `/auth/callback`: `const result = await finishSignIn(cookies, url, env.GOOGLE_CLIENT_ID, env.GOOGLE_CLIENT_SECRET)`. It clears those cookies, checks the state, swaps the code for an ID token and checks it, then returns `{ email }` (verified) or `{ error: 'expired' | 'google' }`, already logged. The app then checks its allowlist and starts a session.

Google setup, done once: the OAuth client (the one budget uses) lists `https://auth.app.haddow.me/callback` under Authorised redirect URIs.

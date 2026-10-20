// Google sign-in's one redirect URI for every *.app.haddow.me app.
// Each app starts sign-in with redirect_uri https://auth.app.haddow.me/callback
// and a state of "<subdomain>.<random>". This sends Google's reply (code or
// error, plus state) on to that app's /auth/callback, which checks the state
// against its own cookie and does the token exchange with its PKCE verifier.
// Nothing is stored here and there are no secrets.

const APP = /^[a-z0-9-]+$/;

export function target(url) {
	const state = url.searchParams.get('state') ?? '';
	const dot = state.indexOf('.');
	const app = state.slice(0, dot);
	if (url.pathname !== '/callback' || dot < 0 || !APP.test(app) || app === 'auth') return null;
	return `https://${app}.app.haddow.me/auth/callback${url.search}`;
}

export default {
	fetch(request) {
		const to = target(new URL(request.url));
		if (!to) return new Response('Not found', { status: 404 });
		return new Response(null, {
			status: 302,
			headers: { location: to, 'referrer-policy': 'no-referrer', 'cache-control': 'no-store' }
		});
	}
};

// Google sign-in (OAuth 2 with PKCE) for the *.app.haddow.me apps, with no
// dependencies. The state and PKCE verifier live in short-lived cookies; each
// app keeps its own allowlist and sessions. `cookies` is SvelteKit's.
//
//   GET /auth/google:   redirect(302, await startSignIn(cookies, clientId, url.hostname))
//   GET /auth/callback: const result = await finishSignIn(cookies, url, clientId, clientSecret)
//                       result.email, or result.error ('expired' or 'google', already logged)

export const REDIRECT_URI = 'https://auth.app.haddow.me/callback';
const AUTHORIZE = 'https://accounts.google.com/o/oauth2/v2/auth';
const TOKEN = 'https://oauth2.googleapis.com/token';
const ISSUERS = ['https://accounts.google.com', 'accounts.google.com'];
const STATE = 'oauth_state';
const VERIFIER = 'oauth_verifier';
const COOKIE = { path: '/', httpOnly: true, sameSite: 'lax', maxAge: 600 };

const base64url = (bytes) =>
	btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const random = () => base64url(crypto.getRandomValues(new Uint8Array(32)));

// Sets the state and verifier cookies and returns Google's sign-in URL.
export async function startSignIn(cookies, clientId, hostname) {
	// The subdomain first, so the shared redirect knows where to send Google's reply.
	const state = `${hostname.split('.')[0]}.${random()}`;
	const verifier = random();
	const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
	cookies.set(STATE, state, COOKIE);
	cookies.set(VERIFIER, verifier, COOKIE);
	const query = new URLSearchParams({
		response_type: 'code',
		client_id: clientId,
		redirect_uri: REDIRECT_URI,
		scope: 'openid email profile',
		state,
		code_challenge: base64url(new Uint8Array(digest)),
		code_challenge_method: 'S256',
		prompt: 'select_account'
	});
	return `${AUTHORIZE}?${query}`;
}

// Handles Google's reply on /auth/callback: clears the cookies, checks the
// state, swaps the code for an ID token and checks it. Returns { email } (a
// verified address) or { error }, logged here without the code or tokens:
// 'expired' (no or mismatched state, also how a cancelled sign-in arrives) or
// 'google' (the exchange or the token's checks failed).
export async function finishSignIn(cookies, url, clientId, clientSecret) {
	const state = cookies.get(STATE);
	const verifier = cookies.get(VERIFIER);
	cookies.delete(STATE, { path: '/' });
	cookies.delete(VERIFIER, { path: '/' });

	const code = url.searchParams.get('code');
	if (!code || !state || !verifier || url.searchParams.get('state') !== state) {
		console.warn('Sign-in failed: missing or mismatched state', {
			hasCode: !!code,
			hasStateCookie: !!state,
			googleError: url.searchParams.get('error')
		});
		return { error: 'expired' };
	}
	try {
		return { email: await exchange(clientId, clientSecret, code, verifier) };
	} catch (e) {
		console.error('Sign-in failed:', e.message, e.details);
		return { error: 'google' };
	}
}

class SignInError extends Error {
	constructor(message, details) {
		super(message);
		this.name = 'SignInError';
		this.details = details;
	}
}

async function exchange(clientId, clientSecret, code, verifier) {
	const res = await fetch(TOKEN, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
		body: new URLSearchParams({
			grant_type: 'authorization_code',
			code,
			code_verifier: verifier,
			redirect_uri: REDIRECT_URI,
			client_id: clientId,
			client_secret: clientSecret
		})
	});
	const body = await res.json().catch(() => ({}));
	if (!res.ok || typeof body.id_token !== 'string')
		throw new SignInError('Google token exchange failed', {
			status: res.status,
			error: body.error,
			description: body.error_description
		});

	// The ID token came straight from Google's token endpoint over TLS, so its
	// signature doesn't need re-checking; the claims still do.
	const claims = decodeClaims(body.id_token);
	const checks = {
		issuerOk: ISSUERS.includes(claims.iss),
		audienceOk: claims.aud === clientId,
		notExpired: claims.exp * 1000 > Date.now(),
		emailVerified: claims.email_verified === true && typeof claims.email === 'string'
	};
	if (!Object.values(checks).every(Boolean))
		throw new SignInError('ID token checks failed', { ...checks, email: claims.email });
	return claims.email;
}

function decodeClaims(idToken) {
	try {
		const payload = idToken.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
		const bytes = Uint8Array.from(atob(payload), (c) => c.charCodeAt(0));
		return JSON.parse(new TextDecoder().decode(bytes));
	} catch {
		throw new SignInError('ID token unreadable');
	}
}

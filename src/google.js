// Google sign-in (OAuth 2 with PKCE) for the *.app.haddow.me apps, with no
// dependencies. Each app keeps its own cookies, allowlist and sessions:
//
//   GET /auth/google:   const { url, state, verifier } = await startSignIn(clientId, url.hostname)
//                       store state and verifier in short-lived cookies, redirect to url
//   GET /auth/callback: check ?state= against the cookie, then
//                       const email = await finishSignIn(clientId, clientSecret, code, verifier)

export const REDIRECT_URI = 'https://auth.app.haddow.me/callback';
const AUTHORIZE = 'https://accounts.google.com/o/oauth2/v2/auth';
const TOKEN = 'https://oauth2.googleapis.com/token';
const ISSUERS = ['https://accounts.google.com', 'accounts.google.com'];

const base64url = (bytes) =>
	btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const random = () => base64url(crypto.getRandomValues(new Uint8Array(32)));

export async function startSignIn(clientId, hostname) {
	// The subdomain first, so the shared redirect knows where to send Google's reply.
	const state = `${hostname.split('.')[0]}.${random()}`;
	const verifier = random();
	const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
	const url = new URL(AUTHORIZE);
	for (const [k, v] of Object.entries({
		response_type: 'code',
		client_id: clientId,
		redirect_uri: REDIRECT_URI,
		scope: 'openid email profile',
		state,
		code_challenge: base64url(new Uint8Array(digest)),
		code_challenge_method: 'S256',
		prompt: 'select_account'
	}))
		url.searchParams.set(k, v);
	return { url: url.toString(), state, verifier };
}

export class SignInError extends Error {
	constructor(message, details) {
		super(message);
		this.name = 'SignInError';
		this.details = details;
	}
}

// Swaps the code for an ID token and returns its verified email address.
// Throws SignInError (never including the code or tokens) if anything's off.
export async function finishSignIn(clientId, clientSecret, code, verifier) {
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

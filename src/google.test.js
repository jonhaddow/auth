import assert from 'node:assert/strict';
import { afterEach, beforeEach, test } from 'node:test';
import { REDIRECT_URI, finishSignIn, startSignIn } from './google.js';

const realFetch = globalThis.fetch;
const realLog = { warn: console.warn, error: console.error };
beforeEach(() => (console.warn = console.error = () => {}));
afterEach(() => {
	globalThis.fetch = realFetch;
	Object.assign(console, realLog);
});

const jar = (init = {}) => {
	const m = new Map(Object.entries(init));
	return { get: (k) => m.get(k), set: (k, v) => m.set(k, v), delete: (k) => m.delete(k), m };
};
const b64url = (s) => Buffer.from(s).toString('base64url');
const idToken = (claims) => `${b64url('{}')}.${b64url(JSON.stringify(claims))}.sig`;
const good = {
	iss: 'https://accounts.google.com',
	aud: 'client',
	exp: Date.now() / 1000 + 60,
	email: 'you@example.com',
	email_verified: true
};
const google = (status, body) => {
	const calls = [];
	globalThis.fetch = async (url, init) => {
		calls.push({ url, body: Object.fromEntries(init.body) });
		return new Response(JSON.stringify(body), { status });
	};
	return calls;
};
const signedIn = () => jar({ oauth_state: 'plants.s', oauth_verifier: 'ver' });
const reply = (q = 'code=abc&state=plants.s') =>
	new URL(`https://plants.app.haddow.me/auth/callback?${q}`);

test('startSignIn sets the cookies and builds a PKCE URL with the app in the state', async () => {
	const cookies = jar();
	const u = new URL(await startSignIn(cookies, 'client', 'plants.app.haddow.me'));
	const state = cookies.get('oauth_state');
	const verifier = cookies.get('oauth_verifier');
	assert.match(state, /^plants\.[\w-]{43}$/);
	assert.match(verifier, /^[\w-]{43}$/);
	assert.equal(u.origin + u.pathname, 'https://accounts.google.com/o/oauth2/v2/auth');
	assert.equal(u.searchParams.get('state'), state);
	assert.equal(u.searchParams.get('client_id'), 'client');
	assert.equal(u.searchParams.get('redirect_uri'), REDIRECT_URI);
	assert.equal(u.searchParams.get('code_challenge_method'), 'S256');
	const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
	assert.equal(u.searchParams.get('code_challenge'), Buffer.from(digest).toString('base64url'));
});

test('finishSignIn exchanges the code, clears the cookies and returns the email', async () => {
	const calls = google(200, { id_token: idToken(good) });
	const cookies = signedIn();
	assert.deepEqual(await finishSignIn(cookies, reply(), 'client', 'secret'), {
		email: 'you@example.com'
	});
	assert.equal(cookies.m.size, 0);
	assert.equal(calls[0].url, 'https://oauth2.googleapis.com/token');
	assert.deepEqual(calls[0].body, {
		grant_type: 'authorization_code',
		code: 'abc',
		code_verifier: 'ver',
		redirect_uri: REDIRECT_URI,
		client_id: 'client',
		client_secret: 'secret'
	});
});

test('finishSignIn says expired for a missing or mismatched state', async () => {
	const calls = google(200, { id_token: idToken(good) });
	for (const [cookies, url] of [
		[jar(), reply()],
		[signedIn(), reply('code=abc&state=plants.other')],
		[signedIn(), reply('error=access_denied&state=plants.s')]
	])
		assert.deepEqual(await finishSignIn(cookies, url, 'client', 's'), { error: 'expired' });
	assert.equal(calls.length, 0);
});

test('finishSignIn refuses a failed exchange or bad claims', async () => {
	const refused = async () =>
		assert.deepEqual(await finishSignIn(signedIn(), reply(), 'client', 's'), { error: 'google' });
	google(400, { error: 'invalid_grant' });
	await refused();
	for (const bad of [
		{ iss: 'evil' },
		{ aud: 'other' },
		{ exp: Date.now() / 1000 - 1 },
		{ email_verified: false },
		{ email: undefined }
	]) {
		google(200, { id_token: idToken({ ...good, ...bad }) });
		await refused();
	}
	google(200, { id_token: 'junk' });
	await refused();
});

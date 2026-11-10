import assert from 'node:assert/strict';
import { afterEach, test } from 'node:test';
import { REDIRECT_URI, SignInError, finishSignIn, startSignIn } from './google.js';

const realFetch = globalThis.fetch;
afterEach(() => (globalThis.fetch = realFetch));

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

test('startSignIn builds a PKCE URL with the app in the state', async () => {
	const { url, state, verifier } = await startSignIn('client', 'plants.app.haddow.me');
	const u = new URL(url);
	assert.match(state, /^plants\.[\w-]{43}$/);
	assert.match(verifier, /^[\w-]{43}$/);
	assert.equal(u.searchParams.get('state'), state);
	assert.equal(u.searchParams.get('client_id'), 'client');
	assert.equal(u.searchParams.get('redirect_uri'), REDIRECT_URI);
	assert.equal(u.searchParams.get('code_challenge_method'), 'S256');
	const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
	assert.equal(u.searchParams.get('code_challenge'), Buffer.from(digest).toString('base64url'));
});

test('finishSignIn exchanges the code and returns the email', async () => {
	const calls = google(200, { id_token: idToken(good) });
	assert.equal(await finishSignIn('client', 'secret', 'abc', 'ver'), 'you@example.com');
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

test('finishSignIn refuses a failed exchange or bad claims', async () => {
	google(400, { error: 'invalid_grant' });
	await assert.rejects(finishSignIn('client', 's', 'c', 'v'), (e) => {
		assert.ok(e instanceof SignInError);
		assert.equal(e.details.error, 'invalid_grant');
		return true;
	});
	for (const bad of [
		{ iss: 'evil' },
		{ aud: 'other' },
		{ exp: Date.now() / 1000 - 1 },
		{ email_verified: false },
		{ email: undefined }
	]) {
		google(200, { id_token: idToken({ ...good, ...bad }) });
		await assert.rejects(finishSignIn('client', 's', 'c', 'v'), SignInError);
	}
	google(200, { id_token: 'junk' });
	await assert.rejects(finishSignIn('client', 's', 'c', 'v'), SignInError);
});

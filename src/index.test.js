import assert from 'node:assert/strict';
import { test } from 'node:test';
import { target } from './index.js';

const t = (path) => target(new URL(`https://auth.app.haddow.me${path}`));

test('forwards the whole query to the app named in state', () => {
	assert.equal(
		t('/callback?code=abc&state=plants.xyz'),
		'https://plants.app.haddow.me/auth/callback?code=abc&state=plants.xyz'
	);
	assert.equal(
		t('/callback?error=access_denied&state=budget.xyz'),
		'https://budget.app.haddow.me/auth/callback?error=access_denied&state=budget.xyz'
	);
});

test('refuses anything that is not a plain subdomain', () => {
	for (const state of ['', 'xyz', '.xyz', 'evil/x.y', 'x:1.y', 'Plants.x', 'auth.x', 'a@b.x'])
		assert.equal(t(`/callback?state=${encodeURIComponent(state)}`), null, state);
	assert.equal(t('/other?state=plants.x'), null);
});

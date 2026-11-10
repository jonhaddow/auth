export const REDIRECT_URI: string;

/** The parts of SvelteKit's `Cookies` this uses. */
type Cookies = {
	get(name: string): string | undefined;
	set(name: string, value: string, opts: { path: string } & Record<string, unknown>): void;
	delete(name: string, opts: { path: string }): void;
};

export function startSignIn(cookies: Cookies, clientId: string, hostname: string): Promise<string>;

export function finishSignIn(
	cookies: Cookies,
	url: URL,
	clientId: string,
	clientSecret: string
): Promise<{ email: string; error?: never } | { email?: never; error: 'expired' | 'google' }>;

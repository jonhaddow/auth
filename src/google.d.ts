export const REDIRECT_URI: string;

export function startSignIn(
	clientId: string,
	hostname: string
): Promise<{ url: string; state: string; verifier: string }>;

export class SignInError extends Error {
	details?: Record<string, unknown>;
}

export function finishSignIn(
	clientId: string,
	clientSecret: string,
	code: string,
	verifier: string
): Promise<string>;

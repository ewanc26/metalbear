/*
 * Browser-native WebAuthn glue: converts between this app's base64url JSON
 * wire format (what the server sends/expects, see src/oauth/webauthn.c) and
 * the ArrayBuffer-based shapes navigator.credentials.create()/get() use.
 * No client library -- the browser's own WebAuthn API is all this needs.
 */

function base64urlToBytes(value: string): Uint8Array<ArrayBuffer> {
	const padded = value.replace(/-/g, '+').replace(/_/g, '/');
	const padding = padded.length % 4 === 0 ? '' : '='.repeat(4 - (padded.length % 4));
	const binary = atob(padded + padding);
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
	return bytes;
}

function bytesToBase64url(bytes: ArrayBuffer): string {
	let binary = '';
	for (const byte of new Uint8Array(bytes)) binary += String.fromCharCode(byte);
	return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function isWebAuthnSupported(): boolean {
	return (
		typeof window !== 'undefined' &&
		typeof window.PublicKeyCredential !== 'undefined' &&
		typeof navigator.credentials?.create === 'function'
	);
}

export interface RegistrationOptions {
	challenge: string;
	rp: { id: string; name: string };
	user: { id: string; name: string; displayName: string };
	pubKeyCredParams: Array<{ type: 'public-key'; alg: number }>;
	attestation: AttestationConveyancePreference;
	authenticatorSelection: AuthenticatorSelectionCriteria;
	excludeCredentials: Array<{ type: 'public-key'; id: string }>;
}

export interface RegistrationResult {
	id: string;
	response: { clientDataJSON: string; attestationObject: string };
}

export async function createPasskey(options: RegistrationOptions): Promise<RegistrationResult> {
	const credential = (await navigator.credentials.create({
		publicKey: {
			challenge: base64urlToBytes(options.challenge),
			rp: options.rp,
			user: {
				id: base64urlToBytes(options.user.id),
				name: options.user.name,
				displayName: options.user.displayName
			},
			pubKeyCredParams: options.pubKeyCredParams,
			attestation: options.attestation,
			authenticatorSelection: options.authenticatorSelection,
			excludeCredentials: options.excludeCredentials.map((c) => ({
				type: c.type,
				id: base64urlToBytes(c.id)
			}))
		}
	})) as PublicKeyCredential | null;
	if (!credential) throw new Error('Passkey registration was cancelled');
	const response = credential.response as AuthenticatorAttestationResponse;
	return {
		id: bytesToBase64url(credential.rawId),
		response: {
			clientDataJSON: bytesToBase64url(response.clientDataJSON),
			attestationObject: bytesToBase64url(response.attestationObject)
		}
	};
}

export interface AuthenticationOptions {
	challenge: string;
	rpId: string;
	userVerification: UserVerificationRequirement;
	allowCredentials: Array<{ type: 'public-key'; id: string }>;
}

export interface AuthenticationResult {
	id: string;
	response: { clientDataJSON: string; authenticatorData: string; signature: string };
}

export async function authenticateWithPasskey(
	options: AuthenticationOptions
): Promise<AuthenticationResult> {
	const credential = (await navigator.credentials.get({
		publicKey: {
			challenge: base64urlToBytes(options.challenge),
			rpId: options.rpId,
			userVerification: options.userVerification,
			allowCredentials: options.allowCredentials.map((c) => ({
				type: c.type,
				id: base64urlToBytes(c.id)
			}))
		}
	})) as PublicKeyCredential | null;
	if (!credential) throw new Error('Passkey sign-in was cancelled');
	const response = credential.response as AuthenticatorAssertionResponse;
	return {
		id: bytesToBase64url(credential.rawId),
		response: {
			clientDataJSON: bytesToBase64url(response.clientDataJSON),
			authenticatorData: bytesToBase64url(response.authenticatorData),
			signature: bytesToBase64url(response.signature)
		}
	};
}

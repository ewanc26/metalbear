/*
 * com.atproto.admin.* is gated by HTTP Basic auth against a fixed "admin"
 * username and the server's configured METALBEAR_ADMIN_PASSWORD -- there is
 * no bearer session, so every call here carries the service URL and password
 * explicitly rather than relying on same-origin/cookie state (there is no
 * "origin" on mobile the way there is for the web frontend this mirrors).
 */

export interface AdminSession {
	serviceUrl: string; // e.g. https://bear1.croft.click
	password: string;
}

function xrpcUrl(session: AdminSession, path: string, params?: Record<string, string>): string {
	const url = new URL(`/xrpc/${path}`, session.serviceUrl);
	for (const [k, v] of Object.entries(params ?? {})) url.searchParams.set(k, v);
	return url.toString();
}

function authHeader(password: string): string {
	// btoa is not available in the RN/Hermes runtime; base64-encode manually.
	return `Basic ${base64Encode(`admin:${password}`)}`;
}

function base64Encode(input: string): string {
	const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
	let output = '';
	let i = 0;
	const bytes = Array.from(input, (c) => c.charCodeAt(0));
	while (i < bytes.length) {
		const b1 = bytes[i++];
		const b2 = i < bytes.length ? bytes[i++] : NaN;
		const b3 = i < bytes.length ? bytes[i++] : NaN;
		output += chars[b1 >> 2];
		output += chars[((b1 & 3) << 4) | (isNaN(b2) ? 0 : b2 >> 4)];
		output += isNaN(b2) ? '=' : chars[((b2 & 15) << 2) | (isNaN(b3) ? 0 : b3 >> 6)];
		output += isNaN(b3) ? '=' : chars[b3 & 63];
	}
	return output;
}

async function xrpcAdminQuery<T>(
	session: AdminSession,
	path: string,
	params?: Record<string, string>
): Promise<T> {
	const res = await fetch(xrpcUrl(session, path, params), {
		headers: { accept: 'application/json', authorization: authHeader(session.password) }
	});
	if (!res.ok) throw new Error(`${path}: ${res.status}`);
	return res.json() as Promise<T>;
}

async function xrpcAdminProcedure<T>(session: AdminSession, path: string, body: unknown): Promise<T> {
	const res = await fetch(xrpcUrl(session, path), {
		method: 'POST',
		headers: {
			'content-type': 'application/json',
			accept: 'application/json',
			authorization: authHeader(session.password)
		},
		body: JSON.stringify(body)
	});
	if (!res.ok) throw new Error(`${path}: ${res.status}`);
	return res.json() as Promise<T>;
}

/* Verifies the given credentials against the server rather than just storing
 * them -- getInviteCodes is a harmless, side-effect-free admin query well
 * suited as an auth check. */
export async function adminLogin(serviceUrl: string, password: string): Promise<void> {
	const session: AdminSession = { serviceUrl, password };
	const res = await fetch(xrpcUrl(session, 'com.atproto.admin.getInviteCodes', { limit: '1' }), {
		headers: { accept: 'application/json', authorization: authHeader(password) }
	});
	if (!res.ok) {
		if (res.status === 401) throw new Error('Incorrect admin password');
		throw new Error(`Could not reach ${serviceUrl} (${res.status})`);
	}
}

export interface AdminAccountView {
	did: string;
	handle: string;
	email?: string;
	indexedAt: string;
	invitesDisabled?: boolean;
	emailConfirmedAt?: string;
	deactivatedAt?: string;
}

export function adminGetAccountInfo(session: AdminSession, did: string): Promise<AdminAccountView> {
	return xrpcAdminQuery<AdminAccountView>(session, 'com.atproto.admin.getAccountInfo', { did });
}

export interface StatusAttr {
	applied: boolean;
	ref?: string;
}

export interface SubjectStatus {
	subject: { $type: string; did: string };
	takedown?: StatusAttr;
	deactivated?: StatusAttr;
}

export function adminGetSubjectStatus(session: AdminSession, did: string): Promise<SubjectStatus> {
	return xrpcAdminQuery<SubjectStatus>(session, 'com.atproto.admin.getSubjectStatus', { did });
}

export async function adminSetTakedown(
	session: AdminSession,
	did: string,
	applied: boolean,
	ref?: string
): Promise<void> {
	await xrpcAdminProcedure(session, 'com.atproto.admin.updateSubjectStatus', {
		subject: { $type: 'com.atproto.admin.defs#repoRef', did },
		takedown: { applied, ...(ref ? { ref } : {}) }
	});
}

export async function adminSetDeactivated(
	session: AdminSession,
	did: string,
	applied: boolean
): Promise<void> {
	await xrpcAdminProcedure(session, 'com.atproto.admin.updateSubjectStatus', {
		subject: { $type: 'com.atproto.admin.defs#repoRef', did },
		deactivated: { applied }
	});
}

export interface AdminInviteCode {
	code: string;
	available: number;
	disabled: boolean;
	forAccount: string;
	createdBy: string;
	createdAt: string;
	uses: unknown[];
}

export function adminGetInviteCodes(
	session: AdminSession,
	cursor?: string,
	limit = 100
): Promise<{ codes: AdminInviteCode[]; cursor?: string }> {
	return xrpcAdminQuery(session, 'com.atproto.admin.getInviteCodes', {
		limit: String(limit),
		...(cursor ? { cursor } : {})
	});
}

export async function adminDisableInviteCodes(session: AdminSession, codes: string[]): Promise<void> {
	await xrpcAdminProcedure(session, 'com.atproto.admin.disableInviteCodes', { codes });
}

export async function adminSetAccountInvitesEnabled(
	session: AdminSession,
	did: string,
	enabled: boolean
): Promise<void> {
	await xrpcAdminProcedure(
		session,
		enabled ? 'com.atproto.admin.enableAccountInvites' : 'com.atproto.admin.disableAccountInvites',
		{ account: did }
	);
}

/* Public, unauthenticated -- lets the lookup form accept a handle in
 * addition to a raw DID. */
export async function resolveHandle(session: AdminSession, handle: string): Promise<string> {
	const url = new URL('/xrpc/com.atproto.identity.resolveHandle', session.serviceUrl);
	url.searchParams.set('handle', handle);
	const res = await fetch(url.toString(), { headers: { accept: 'application/json' } });
	if (!res.ok) throw new Error(`resolveHandle: ${res.status}`);
	const { did } = (await res.json()) as { did: string };
	return did;
}

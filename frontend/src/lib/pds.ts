/*
 * Client for the PDS this page is served from.
 *
 * The page is prerendered to static files, so everything here runs in the
 * browser against the same origin. That keeps the landing page honest: it
 * reports what the server actually answers right now rather than what was
 * true when the site was built.
 */

import { auth } from './stores/auth';
import type { Session } from './stores/auth';
import { adminAuth } from './stores/adminAuth';
import type { RegistrationOptions } from './webauthn';

export interface ServerInfo {
	did: string;
	availableUserDomains: string[];
	inviteCodeRequired?: boolean;
	contact?: { email?: string };
	links?: { privacyPolicy?: string; termsOfService?: string };
}

export interface AuthorizeInfo {
	client_id: string;
	scope: string;
	/** Present only when the client's metadata document offers them. */
	client_name?: string;
	client_uri?: string;
	logo_uri?: string;
}

export interface RepoInfo {
	did: string;
	head: string;
	rev: string;
	active: boolean;
	status?: string;
}

export interface OperatorInfo {
	operator?: { name?: string; email?: string; url?: string; supportUrl?: string };
	software?: {
		name?: string;
		version?: string;
		/** The SDK version this build is linked against. */
		wolframVersion?: string;
		/** Short git commit this build was compiled from. */
		commit?: string;
		/** UTC build timestamp, ISO 8601. */
		builtAt?: string;
		/**
		 * Where this build sits on the software release life cycle
		 * (https://en.wikipedia.org/wiki/Software_release_life_cycle):
		 * "pre-alpha" | "alpha" | "beta" | "rc" | "stable" by convention, set
		 * at build time via -DMETALBEAR_RELEASE_STAGE. Not validated against
		 * that list here — display whatever the server reports.
		 */
		releaseStage?: string;
		repository?: string;
		license?: string;
	};
	description?: string;
	development?: boolean;
}

export interface RelayStatus {
	/** Relay hostname, for display. */
	name: string;
	/** null while loading, false when the relay does not know this host. */
	known: boolean | null;
	seq: number | null;
	status: string | null;
}

export interface SessionResponse {
	accessJwt: string;
	refreshJwt: string;
	handle: string;
	did: string;
	didDoc?: Record<string, unknown>;
	email?: string;
	emailConfirmed?: boolean;
	emailAuthFactor?: boolean;
	active: boolean;
	status?: string;
}

export interface AppPassword {
	name: string;
	createdAt: string;
	privileged: boolean;
}

export interface CreateAppPasswordResponse {
	name: string;
	password: string;
	createdAt: string;
	privileged: boolean;
}

export interface ListAppPasswordsResponse {
	passwords: AppPassword[];
}

/** Relays worth asking about a host's federation state. */
export const RELAYS = [
	{ label: 'Bluesky', host: 'bsky.network' },
	{ label: 'Bluesky West', host: 'relay1.us-west.bsky.network' },
	{ label: 'Bluesky East', host: 'relay1.us-east.bsky.network' },
	{ label: 'Microcosm Montreal', host: 'relay.fire.hose.cam' },
	{ label: 'Microcosm France', host: 'relay3.fr.hose.cam' },
	{ label: 'Upcloud', host: 'relay.upcloud.world' }
] as const;

function currentSession(): Session | null {
	let val: Session | null = null;
	const unsub = auth.subscribe((s) => (val = s));
	unsub();
	return val;
}

async function xrpc<T>(path: string, params?: Record<string, string>): Promise<T> {
	const url = new URL(`/xrpc/${path}`, window.location.origin);
	for (const [k, v] of Object.entries(params ?? {})) url.searchParams.set(k, v);
	const res = await fetch(url, { headers: { accept: 'application/json' } });
	if (!res.ok) throw new Error(`${path}: ${res.status}`);
	return res.json() as Promise<T>;
}

/* A GET query, but with the session's Bearer token attached -- for the
 * (growing) set of XRPC queries that require auth, where xrpc() (no
 * Authorization header at all) would just get a 401. */
async function xrpcAuthed<T>(path: string, params?: Record<string, string>): Promise<T> {
	const session = currentSession();
	if (!session) throw new Error('Not authenticated');
	const url = new URL(`/xrpc/${path}`, window.location.origin);
	for (const [k, v] of Object.entries(params ?? {})) url.searchParams.set(k, v);
	const res = await fetch(url, {
		headers: {
			accept: 'application/json',
			authorization: `Bearer ${session.accessJwt}`
		}
	});
	if (!res.ok) throw new Error(`${path}: ${res.status}`);
	return res.json() as Promise<T>;
}

async function xrpcPost<T>(path: string, body: unknown): Promise<T> {
	const session = currentSession();
	const url = new URL(`/xrpc/${path}`, window.location.origin);
	const headers: Record<string, string> = {
		'content-type': 'application/json',
		accept: 'application/json'
	};
	if (session) headers['authorization'] = `Bearer ${session.accessJwt}`;
	const res = await fetch(url, {
		method: 'POST',
		headers,
		body: JSON.stringify(body)
	});
	if (!res.ok) throw new Error(`${path}: ${res.status}`);
	return res.json() as Promise<T>;
}

async function xrpcPostPlain<T>(path: string, body: unknown): Promise<T> {
	const url = new URL(`/xrpc/${path}`, window.location.origin);
	const res = await fetch(url, {
		method: 'POST',
		headers: {
			'content-type': 'application/json',
			accept: 'application/json'
		},
		body: JSON.stringify(body)
	});
	if (!res.ok) throw new Error(`${path}: ${res.status}`);
	return res.json() as Promise<T>;
}

/*
 * /operator.json is MetalBear's own, not a protocol route: who runs the
 * instance and whether it is a testing one have no lexicon field. Reading it
 * here keeps the server config the single source of truth, rather than
 * duplicating operator details into this page where they would go stale.
 */
export async function operatorInfo(): Promise<OperatorInfo | null> {
	try {
		const res = await fetch(new URL('/operator.json', window.location.origin), {
			headers: { accept: 'application/json' }
		});
		if (!res.ok) return null;
		return (await res.json()) as OperatorInfo;
	} catch {
		return null;
	}
}

export function describeServer(): Promise<ServerInfo> {
	return xrpc<ServerInfo>('com.atproto.server.describeServer');
}

/*
 * The named failure reasons GET /oauth/authorize/info distinguishes (see
 * oauth_authorize_info's doc comment in oauth_routes.c): 'expired' (the
 * request_uri is unknown or its 5-minute PAR lifetime passed -- the only
 * one actually fixable by going back to the application and starting
 * over), 'client_mismatch' (a real, live request_uri, but for a different
 * client_id than the one asking -- not something retrying fixes),
 * 'invalid_request' (client_id/request_uri missing from the query
 * entirely), and 'server_error' (an internal failure building the
 * response, or this client couldn't reach/parse the server's response at
 * all -- worth a literal retry).
 */
export type AuthorizeInfoError = 'invalid_request' | 'expired' | 'client_mismatch' | 'server_error';

const AUTHORIZE_INFO_ERRORS: readonly AuthorizeInfoError[] = [
	'invalid_request',
	'expired',
	'client_mismatch',
	'server_error'
];

/*
 * What a pending OAuth authorization request is actually asking for --
 * requested scope, and the requesting client's display name/logo when its
 * metadata document offers them. Read-only: unlike approving the request,
 * this does not consume it, so the consent page can safely reload or retry.
 */
export async function authorizeInfo(
	clientId: string,
	requestUri: string
): Promise<{ ok: true; info: AuthorizeInfo } | { ok: false; error: AuthorizeInfoError }> {
	try {
		const url = new URL('/oauth/authorize/info', window.location.origin);
		url.searchParams.set('client_id', clientId);
		url.searchParams.set('request_uri', requestUri);
		const res = await fetch(url, { headers: { accept: 'application/json' } });
		if (!res.ok) {
			const body = (await res.json().catch(() => null)) as { error?: string } | null;
			const error =
				body?.error && AUTHORIZE_INFO_ERRORS.includes(body.error as AuthorizeInfoError)
					? (body.error as AuthorizeInfoError)
					: 'server_error';
			return { ok: false, error };
		}
		return { ok: true, info: (await res.json()) as AuthorizeInfo };
	} catch {
		return { ok: false, error: 'server_error' };
	}
}

export async function listRepos(): Promise<RepoInfo[]> {
	const { repos } = await xrpc<{ repos: RepoInfo[] }>('com.atproto.sync.listRepos', {
		limit: '100'
	});
	return repos ?? [];
}

export async function health(): Promise<string | null> {
	try {
		const { version } = await xrpc<{ version: string }>('_health');
		return version ?? null;
	} catch {
		return null;
	}
}

/*
 * Ask each relay whether it is consuming this host.
 *
 * `seq` is the useful number: -1 means the relay knows the host but has never
 * ingested an event from it, which is what a host that is registered but not
 * actually federating looks like. A missing host answers HostNotFound.
 */
export async function relayStatus(hostname: string): Promise<RelayStatus[]> {
	return Promise.all(
		RELAYS.map(async ({ label, host }): Promise<RelayStatus> => {
			try {
				const res = await fetch(
					`https://${host}/xrpc/com.atproto.sync.getHostStatus?hostname=${encodeURIComponent(hostname)}`,
					{ headers: { accept: 'application/json' } }
				);
				if (!res.ok) return { name: label, known: false, seq: null, status: null };
				const body = (await res.json()) as { seq?: number; status?: string; error?: string };
				if (body.error) return { name: label, known: false, seq: null, status: null };
				return {
					name: label,
					known: true,
					seq: body.seq ?? null,
					status: body.status ?? null
				};
			} catch {
				/* A relay we cannot reach is unknown, not unhealthy: say so rather
				 * than implying anything about this server. */
				return { name: label, known: false, seq: null, status: null };
			}
		})
	);
}

/* ---- Auth / Session ---- */

export async function createSession(
	identifier: string,
	password: string
): Promise<SessionResponse> {
	return xrpcPostPlain<SessionResponse>('com.atproto.server.createSession', {
		identifier,
		password
	});
}

/*
 * Establish an OAuth device session: a browser-held cookie proving this
 * browser has presented this account's password, separate from (and not a
 * side effect of) the regular createSession JWT above. `GET /oauth/authorize`
 * checks this cookie, not the JWT, before it will mint an authorization code
 * -- a plain top-level page navigation with no Authorization header to carry
 * a bearer token, which is exactly what a bearer token is everywhere else.
 * Any page that signs a user in as part of approving an OAuth request must
 * call this too, or the "Approve" step has nothing to check and the flow
 * cannot complete.
 */
export async function signInDevice(identifier: string, password: string): Promise<{ did: string }> {
	const res = await fetch(new URL('/oauth/signin', window.location.origin), {
		method: 'POST',
		headers: { 'content-type': 'application/json', accept: 'application/json' },
		body: JSON.stringify({ identifier, password })
	});
	if (!res.ok) {
		const body = (await res.json().catch(() => null)) as { message?: string } | null;
		throw new Error(body?.message ?? `oauth/signin: ${res.status}`);
	}
	return res.json() as Promise<{ did: string }>;
}

export interface DeviceSessionInfo {
	/** Every account currently signed in on this browser (a multi-account
	 *  host can have more than one device session at once). Empty when none. */
	subjects: string[];
	/** The most recently signed-in subject, or null if none. */
	did: string | null;
	/** Set only when a `loginHint` was passed to deviceSessions(): whether
	 *  THAT specific account (resolved server-side, so a handle and a DID
	 *  naming the same account agree) is among `subjects`. Null otherwise. */
	matchesHint: boolean | null;
}

/*
 * What OAuth device sessions this browser currently holds (see
 * signInDevice) -- read-only, no side effects. The consent page uses this to
 * send a user to sign in *before* rendering a consent screen it cannot
 * actually finish, rather than after: a regular JWT session (the `auth`
 * store) is not proof of a device session on its own.
 *
 * Passing `loginHint` also asks the server whether THAT specific account is
 * among the signed-in ones (`matchesHint`) -- checking that, not just
 * whether ANY session exists, is what actually closes the loop where an
 * authorize request for account A redirects back to this same consent page
 * having done nothing because a session for a DIFFERENT account B looked
 * like "signed in" to a caller that only checked for "any session at all".
 */
export async function deviceSessions(loginHint?: string): Promise<DeviceSessionInfo> {
	const empty = (matchesHint: boolean | null): DeviceSessionInfo => ({
		subjects: [],
		did: null,
		matchesHint
	});
	try {
		const url = new URL('/oauth/session', window.location.origin);
		if (loginHint) url.searchParams.set('login_hint', loginHint);
		const res = await fetch(url, { headers: { accept: 'application/json' } });
		if (!res.ok) return empty(loginHint ? false : null);
		const body = (await res.json()) as {
			subjects?: string[];
			did?: string;
			matches_hint?: boolean;
		};
		return {
			subjects: body.subjects ?? [],
			did: body.did ?? null,
			matchesHint: typeof body.matches_hint === 'boolean' ? body.matches_hint : null
		};
	} catch {
		return empty(loginHint ? false : null);
	}
}

/*
 * Sign out of one account's device session (`did` given) or every one of
 * them (omitted) -- see oauth_signout's doc comment in oauth_routes.c. Used
 * by the account picker's "not you?" affordance and by a full sign-out.
 */
export async function signOutDevice(did?: string): Promise<void> {
	await fetch(new URL('/oauth/signout', window.location.origin), {
		method: 'POST',
		headers: { 'content-type': 'application/json', accept: 'application/json' },
		body: JSON.stringify(did ? { did } : {})
	});
}

/* ---- Passkeys (WebAuthn) ----
 * Registration/listing/removal require a device session for `did` (see
 * oauth_routes.c's passkey_register_options and friends) -- the same
 * "already proved a password once" cookie signInDevice sets, checked here
 * implicitly since these are same-origin fetches and the cookie rides
 * along automatically. */

async function passkeyFetch<T>(path: string, body: unknown): Promise<T> {
	const res = await fetch(new URL(path, window.location.origin), {
		method: 'POST',
		headers: { 'content-type': 'application/json', accept: 'application/json' },
		body: JSON.stringify(body)
	});
	if (!res.ok) {
		const parsed = (await res.json().catch(() => null)) as { message?: string } | null;
		throw new Error(parsed?.message ?? `${path}: ${res.status}`);
	}
	return res.json() as Promise<T>;
}

export type PasskeyRegistrationOptions = RegistrationOptions;

export function passkeyRegisterOptions(did: string): Promise<PasskeyRegistrationOptions> {
	return passkeyFetch('/oauth/passkey/register/options', { did });
}

export function passkeyRegisterVerify(
	did: string,
	name: string | undefined,
	response: { id: string; response: { clientDataJSON: string; attestationObject: string } }
): Promise<{ ok: true }> {
	return passkeyFetch('/oauth/passkey/register/verify', {
		did,
		name,
		response: response.response
	});
}

export interface PasskeyAuthenticateOptions {
	available: boolean;
	challenge?: string;
	rpId?: string;
	userVerification?: string;
	allowCredentials?: Array<{ type: 'public-key'; id: string }>;
}

export function passkeyAuthenticateOptions(identifier: string): Promise<PasskeyAuthenticateOptions> {
	return passkeyFetch('/oauth/passkey/authenticate/options', { identifier });
}

export function passkeyAuthenticateVerify(response: {
	id: string;
	response: { clientDataJSON: string; authenticatorData: string; signature: string };
}): Promise<{ did: string }> {
	return passkeyFetch('/oauth/passkey/authenticate/verify', response);
}

export interface PasskeyInfo {
	id: string;
	name?: string;
	createdAt: number;
	lastUsedAt?: number;
}

export async function passkeyList(did: string): Promise<PasskeyInfo[]> {
	const url = new URL('/oauth/passkey/list', window.location.origin);
	url.searchParams.set('did', did);
	const res = await fetch(url, { headers: { accept: 'application/json' } });
	if (!res.ok) throw new Error(`passkey/list: ${res.status}`);
	const body = (await res.json()) as { passkeys: PasskeyInfo[] };
	return body.passkeys;
}

export function passkeyRemove(did: string, id: string): Promise<void> {
	return passkeyFetch('/oauth/passkey/remove', { did, id });
}

export async function getSession(): Promise<SessionResponse> {
	const session = currentSession();
	if (!session) throw new Error('Not authenticated');
	const url = new URL('/xrpc/com.atproto.server.getSession', window.location.origin);
	const res = await fetch(url, {
		headers: {
			accept: 'application/json',
			authorization: `Bearer ${session.accessJwt}`
		}
	});
	if (!res.ok) throw new Error(`getSession: ${res.status}`);
	return res.json() as Promise<SessionResponse>;
}

export async function refreshSession(): Promise<SessionResponse> {
	const session = currentSession();
	if (!session) throw new Error('Not authenticated');
	const url = new URL('/xrpc/com.atproto.server.refreshSession', window.location.origin);
	const res = await fetch(url, {
		method: 'POST',
		headers: {
			accept: 'application/json',
			authorization: `Bearer ${session.refreshJwt}`
		}
	});
	if (!res.ok) throw new Error(`refreshSession: ${res.status}`);
	return res.json() as Promise<SessionResponse>;
}

export async function deleteSession(): Promise<void> {
	const session = currentSession();
	if (!session) throw new Error('Not authenticated');
	const url = new URL('/xrpc/com.atproto.server.deleteSession', window.location.origin);
	await fetch(url, {
		method: 'POST',
		headers: {
			accept: 'application/json',
			authorization: `Bearer ${session.refreshJwt}`
		}
	});
}

/* ---- App Passwords ---- */

export async function createAppPassword(
	name: string,
	privileged?: boolean
): Promise<CreateAppPasswordResponse> {
	return xrpcPost<CreateAppPasswordResponse>('com.atproto.server.createAppPassword', {
		name,
		privileged: privileged ?? false
	});
}

export async function listAppPasswords(): Promise<AppPassword[]> {
	/* listAppPasswords is registered as a query (GET-only) -- xrpcPost (which
	 * this used to call) gets refused with "Incorrect HTTP method for this
	 * endpoint", so this was silently broken until this fix. */
	const { passwords } = await xrpcAuthed<ListAppPasswordsResponse>(
		'com.atproto.server.listAppPasswords'
	);
	return passwords;
}

export async function revokeAppPassword(name: string): Promise<void> {
	await xrpcPost<Record<string, never>>('com.atproto.server.revokeAppPassword', { name });
}

/* ---- OAuth account management: connected apps, active devices ---- */

export interface DeviceInfo {
	sessionId: string;
	expiresAt: number;
}

export async function listDevices(): Promise<DeviceInfo[]> {
	const { devices } = await xrpcAuthed<{ devices: DeviceInfo[] }>(
		'com.metalbear.oauth.listDevices'
	);
	return devices;
}

export async function revokeDevice(sessionId: string): Promise<void> {
	await xrpcPost<Record<string, never>>('com.metalbear.oauth.revokeDevice', { sessionId });
}

export interface GrantInfo {
	clientId: string;
	scope: string;
	expiresAt: number;
}

export async function listGrants(): Promise<GrantInfo[]> {
	const { grants } = await xrpcAuthed<{ grants: GrantInfo[] }>('com.metalbear.oauth.listGrants');
	return grants;
}

export async function revokeGrant(clientId: string): Promise<void> {
	await xrpcPost<Record<string, never>>('com.metalbear.oauth.revokeGrant', { clientId });
}

/* ---- Password reset / change ----
 * requestPasswordReset and resetPassword are both unauthenticated per the
 * lexicon (the emailed token is the credential, not a session) -- used both
 * for a signed-out "forgot password" flow and, from the account page, as a
 * signed-in "change password" flow that just emails a code to the account's
 * own known address. xrpcPostPlain deliberately never attaches a session
 * token here. */

export async function requestPasswordReset(email: string): Promise<void> {
	await xrpcPostPlain<Record<string, never>>('com.atproto.server.requestPasswordReset', {
		email
	});
}

export async function resetPassword(token: string, password: string): Promise<void> {
	await xrpcPostPlain<Record<string, never>>('com.atproto.server.resetPassword', {
		token,
		password
	});
}

/* ---- Email update / verification ---- */

export async function requestEmailUpdate(): Promise<{ tokenRequired: boolean }> {
	return xrpcPost<{ tokenRequired: boolean }>('com.atproto.server.requestEmailUpdate', {});
}

/* `token` is required only when the current email is already confirmed --
 * see update_email in account_routes.c. Omit it for an unconfirmed email. */
export async function updateEmail(email: string, token?: string): Promise<void> {
	await xrpcPost<Record<string, never>>(
		'com.atproto.server.updateEmail',
		token ? { email, token } : { email }
	);
}

export async function requestEmailConfirmation(): Promise<void> {
	await xrpcPost<Record<string, never>>('com.atproto.server.requestEmailConfirmation', {});
}

export async function confirmEmail(email: string, token: string): Promise<void> {
	await xrpcPost<Record<string, never>>('com.atproto.server.confirmEmail', { email, token });
}

/* ---- Handle change ---- */

export async function updateHandle(handle: string): Promise<void> {
	await xrpcPost<Record<string, never>>('com.atproto.identity.updateHandle', { handle });
}

/* ---- Account deactivation / reactivation / deletion ---- */

export async function deactivateAccount(): Promise<void> {
	await xrpcPost<Record<string, never>>('com.atproto.server.deactivateAccount', {});
}

export async function activateAccount(): Promise<void> {
	await xrpcPost<Record<string, never>>('com.atproto.server.activateAccount', {});
}

export async function requestAccountDelete(): Promise<void> {
	await xrpcPost<Record<string, never>>('com.atproto.server.requestAccountDelete', {});
}

/* Unauthenticated per the lexicon: the token+password together are the
 * credential, matching how deleteAccount is implemented server-side (it
 * looks the account up by `did`, not by session). */
export async function deleteAccount(did: string, password: string, token: string): Promise<void> {
	await xrpcPostPlain<Record<string, never>>('com.atproto.server.deleteAccount', {
		did,
		password,
		token
	});
}

/* ---- Admin ----
 * com.atproto.admin.* is gated by HTTP Basic auth against a fixed "admin"
 * username and the server's configured METALBEAR_ADMIN_PASSWORD -- there is
 * no bearer session, so every call here carries the password directly
 * rather than going through xrpc()/xrpcPost()'s session-based auth. */

function currentAdminPassword(): string | null {
	let val: string | null = null;
	const unsub = adminAuth.subscribe((p) => (val = p));
	unsub();
	return val;
}

function adminAuthHeader(): string {
	const password = currentAdminPassword();
	if (!password) throw new Error('Not authenticated');
	return `Basic ${btoa(`admin:${password}`)}`;
}

async function xrpcAdminQuery<T>(path: string, params?: Record<string, string>): Promise<T> {
	const url = new URL(`/xrpc/${path}`, window.location.origin);
	for (const [k, v] of Object.entries(params ?? {})) url.searchParams.set(k, v);
	const res = await fetch(url, {
		headers: { accept: 'application/json', authorization: adminAuthHeader() }
	});
	if (!res.ok) throw new Error(`${path}: ${res.status}`);
	return res.json() as Promise<T>;
}

async function xrpcAdminProcedure<T>(path: string, body: unknown): Promise<T> {
	const url = new URL(`/xrpc/${path}`, window.location.origin);
	const res = await fetch(url, {
		method: 'POST',
		headers: {
			'content-type': 'application/json',
			accept: 'application/json',
			authorization: adminAuthHeader()
		},
		body: JSON.stringify(body)
	});
	if (!res.ok) throw new Error(`${path}: ${res.status}`);
	return res.json() as Promise<T>;
}

/* Verifies the given password against the server rather than just storing
 * it -- getInviteCodes is a harmless, side-effect-free admin query well
 * suited as an auth check. */
export async function adminLogin(password: string): Promise<void> {
	const url = new URL('/xrpc/com.atproto.admin.getInviteCodes', window.location.origin);
	url.searchParams.set('limit', '1');
	const res = await fetch(url, {
		headers: { accept: 'application/json', authorization: `Basic ${btoa(`admin:${password}`)}` }
	});
	if (!res.ok) throw new Error(res.status === 401 ? 'Incorrect admin password' : `${res.status}`);
	adminAuth.login(password);
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

export async function adminGetAccountInfo(did: string): Promise<AdminAccountView> {
	return xrpcAdminQuery<AdminAccountView>('com.atproto.admin.getAccountInfo', { did });
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

export async function adminGetSubjectStatus(did: string): Promise<SubjectStatus> {
	return xrpcAdminQuery<SubjectStatus>('com.atproto.admin.getSubjectStatus', { did });
}

export async function adminSetTakedown(did: string, applied: boolean, ref?: string): Promise<void> {
	await xrpcAdminProcedure('com.atproto.admin.updateSubjectStatus', {
		subject: { $type: 'com.atproto.admin.defs#repoRef', did },
		takedown: { applied, ...(ref ? { ref } : {}) }
	});
}

export async function adminSetDeactivated(did: string, applied: boolean): Promise<void> {
	await xrpcAdminProcedure('com.atproto.admin.updateSubjectStatus', {
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

export async function adminGetInviteCodes(
	cursor?: string,
	limit = 100
): Promise<{ codes: AdminInviteCode[]; cursor?: string }> {
	return xrpcAdminQuery('com.atproto.admin.getInviteCodes', {
		limit: String(limit),
		...(cursor ? { cursor } : {})
	});
}

export async function adminDisableInviteCodes(codes: string[]): Promise<void> {
	await xrpcAdminProcedure('com.atproto.admin.disableInviteCodes', { codes });
}

export async function adminSetAccountInvitesEnabled(did: string, enabled: boolean): Promise<void> {
	await xrpcAdminProcedure(
		enabled ? 'com.atproto.admin.enableAccountInvites' : 'com.atproto.admin.disableAccountInvites',
		{ account: did }
	);
}

/* Public, unauthenticated -- lets the admin lookup form accept a handle in
 * addition to a raw DID. */
export async function resolveHandle(handle: string): Promise<string> {
	const { did } = await xrpc<{ did: string }>('com.atproto.identity.resolveHandle', { handle });
	return did;
}

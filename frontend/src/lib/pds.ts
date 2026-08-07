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
 * What a pending OAuth authorization request is actually asking for --
 * requested scope, and the requesting client's display name/logo when its
 * metadata document offers them. Read-only: unlike approving the request,
 * this does not consume it, so the consent page can safely reload or retry.
 * Returns null on any failure (network error, or the server rejecting an
 * unknown/expired/mismatched request) -- the caller distinguishes "still
 * loading" from "failed" with its own state, same as the rest of this file.
 */
export async function authorizeInfo(
	clientId: string,
	requestUri: string
): Promise<AuthorizeInfo | null> {
	try {
		const url = new URL('/oauth/authorize/info', window.location.origin);
		url.searchParams.set('client_id', clientId);
		url.searchParams.set('request_uri', requestUri);
		const res = await fetch(url, { headers: { accept: 'application/json' } });
		if (!res.ok) return null;
		return (await res.json()) as AuthorizeInfo;
	} catch {
		return null;
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

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

export async function createSession(identifier: string, password: string): Promise<SessionResponse> {
	return xrpcPostPlain<SessionResponse>('com.atproto.server.createSession', {
		identifier,
		password
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

export async function createAppPassword(name: string, privileged?: boolean): Promise<CreateAppPasswordResponse> {
	return xrpcPost<CreateAppPasswordResponse>('com.atproto.server.createAppPassword', {
		name,
		privileged: privileged ?? false
	});
}

export async function listAppPasswords(): Promise<AppPassword[]> {
	const { passwords } = await xrpcPost<ListAppPasswordsResponse>('com.atproto.server.listAppPasswords', {});
	return passwords;
}

export async function revokeAppPassword(name: string): Promise<void> {
	await xrpcPost<Record<string, never>>('com.atproto.server.revokeAppPassword', { name });
}

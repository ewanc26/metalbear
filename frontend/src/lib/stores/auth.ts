import { writable } from 'svelte/store';

export interface Session {
	accessJwt: string;
	refreshJwt: string;
	handle: string;
	did: string;
	email?: string;
	emailConfirmed?: boolean;
	emailAuthFactor?: boolean;
	active: boolean;
	status?: string;
	didDoc?: Record<string, unknown>;
}

const STORAGE_KEY = 'metalbear_session';

function isBrowser(): boolean {
	return typeof window !== 'undefined' && typeof localStorage !== 'undefined';
}

function createAuthStore() {
	function load(): Session | null {
		if (!isBrowser()) return null;
		try {
			const raw = localStorage.getItem(STORAGE_KEY);
			if (!raw) return null;
			return JSON.parse(raw) as Session;
		} catch {
			if (isBrowser()) localStorage.removeItem(STORAGE_KEY);
			return null;
		}
	}

	const { subscribe, set } = writable<Session | null>(load());

	return {
		subscribe,
		login(session: Session) {
			if (isBrowser()) localStorage.setItem(STORAGE_KEY, JSON.stringify(session));
			set(session);
		},
		logout() {
			if (isBrowser()) localStorage.removeItem(STORAGE_KEY);
			set(null);
		},
		refresh(session: Session) {
			if (isBrowser()) localStorage.setItem(STORAGE_KEY, JSON.stringify(session));
			set(session);
		}
	};
}

export const auth = createAuthStore();

import { writable } from 'svelte/store';

/*
 * Admin auth is HTTP Basic against a fixed "admin" username and the
 * server's configured METALBEAR_ADMIN_PASSWORD (see server.c's admin
 * routes) -- there is no session/token issued, so this store just holds
 * the password for the lifetime of the tab. sessionStorage rather than
 * localStorage: an admin password shouldn't outlive the browser tab it
 * was typed into.
 */

const STORAGE_KEY = 'metalbear_admin_password';

function isBrowser(): boolean {
	return typeof window !== 'undefined' && typeof sessionStorage !== 'undefined';
}

function createAdminAuthStore() {
	function load(): string | null {
		if (!isBrowser()) return null;
		return sessionStorage.getItem(STORAGE_KEY);
	}

	const { subscribe, set } = writable<string | null>(load());

	return {
		subscribe,
		login(password: string) {
			if (isBrowser()) sessionStorage.setItem(STORAGE_KEY, password);
			set(password);
		},
		logout() {
			if (isBrowser()) sessionStorage.removeItem(STORAGE_KEY);
			set(null);
		}
	};
}

export const adminAuth = createAdminAuthStore();

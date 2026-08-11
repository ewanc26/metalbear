import React, { createContext, useContext, useMemo, useState } from 'react';
import type { AdminSession } from '../api/pds';
import { adminLogin } from '../api/pds';

/*
 * Held in memory only, like the web admin page's sessionStorage-backed store
 * -- an admin password shouldn't outlive the moment it's needed. On mobile
 * that means it's cleared when the app is killed, so logging back in after a
 * cold start is expected, not a bug.
 */

interface AdminSessionContextValue {
	session: AdminSession | null;
	login: (serviceUrl: string, password: string) => Promise<void>;
	logout: () => void;
}

const AdminSessionContext = createContext<AdminSessionContextValue | null>(null);

export function AdminSessionProvider({ children }: { children: React.ReactNode }) {
	const [session, setSession] = useState<AdminSession | null>(null);

	const value = useMemo<AdminSessionContextValue>(
		() => ({
			session,
			async login(serviceUrl: string, password: string) {
				const normalized = serviceUrl.replace(/\/+$/, '');
				await adminLogin(normalized, password);
				setSession({ serviceUrl: normalized, password });
			},
			logout() {
				setSession(null);
			}
		}),
		[session]
	);

	return <AdminSessionContext.Provider value={value}>{children}</AdminSessionContext.Provider>;
}

export function useAdminSession(): AdminSessionContextValue {
	const ctx = useContext(AdminSessionContext);
	if (!ctx) throw new Error('useAdminSession must be used within AdminSessionProvider');
	return ctx;
}

/*
 * Operator branding (issue #260).
 *
 * /operator.json is the single source of truth: the frontend is prerendered,
 * so it reads the operator's name, logo, colours and links at runtime rather
 * than baking them into the build. Defaults below are the built-in MetalBear
 * palette, so a server with no [branding] config looks exactly as before.
 */

import { writable } from 'svelte/store';
import { operatorInfo, type Branding } from '#lib/pds.ts';

export const DEFAULT_BRANDING: Branding = {
	serviceName: 'MetalBear',
	logoUrl: '',
	colors: {
		primary: '#059669',
		primaryHover: '#10b981',
		onPrimary: '#ffffff',
		error: '#ef4444',
		warning: '#f59e0b',
		info: '#3b82f6',
		success: '#10b981'
	},
	background: { lightUrl: '', darkUrl: '' },
	links: { homeUrl: '/' }
};

export const branding = writable<Branding>(DEFAULT_BRANDING);

/* The server restricts URLs to safe path/http(s) values; escaping the quotes
 * here as well means a CSS url() can never be broken out of. */
function cssUrl(value: string): string {
	return value ? `url("${value.replaceAll('"', '%22')}")` : 'none';
}

function setVar(name: string, value: string): void {
	document.documentElement.style.setProperty(name, value);
}

/** Publish the resolved branding as CSS custom properties for every page. */
export function applyBranding(value: Branding): void {
	const css = value.colors;
	setVar('--mb-primary', css.primary);
	setVar('--mb-primary-hover', css.primaryHover);
	setVar('--mb-on-primary', css.onPrimary);
	setVar('--mb-error', css.error);
	setVar('--mb-warning', css.warning);
	setVar('--mb-info', css.info);
	setVar('--mb-success', css.success);
	/* emerald-400 is the built-in hover shade; keep it exactly when the operator
	 * has not chosen a palette, and use the configured hover otherwise. */
	setVar(
		'--mb-primary-soft',
		css.primaryHover === DEFAULT_BRANDING.colors.primaryHover ? '#34d399' : css.primaryHover
	);
	setVar('--mb-bg-light', cssUrl(value.background.lightUrl));
	setVar('--mb-bg-dark', cssUrl(value.background.darkUrl));
	branding.set(value);
}

/** Fetch once at layout mount. Failure leaves the built-in palette in place. */
export async function loadBranding(): Promise<void> {
	try {
		const info = await operatorInfo();
		if (info?.branding) applyBranding(info.branding);
	} catch {
		/* The page still works with the defaults. */
	}
}

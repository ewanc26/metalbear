/*
 * Human-readable descriptions for AT Protocol OAuth scope grants, for the
 * consent screen. Display only -- the server (src/oauth/oauth_scope.c) is
 * the actual authority on what each scope allows; this only has to be
 * honest about what it shows, not exhaustive about every edge case the
 * grammar supports.
 */

const REPO_ACTION_LABELS: Record<string, string> = {
	create: 'create',
	update: 'edit',
	delete: 'delete'
};

const ACCOUNT_ATTR_LABELS: Record<string, string> = {
	email: 'your email address',
	repo: 'your full repository (export/import)',
	status: 'your account status (activation, takedown)'
};

function queryParams(query: string | undefined): URLSearchParams {
	return new URLSearchParams(query ?? '');
}

/* Splits "type:positional?query" into its three parts. `positional` is ''
 * when the scope carries no positional segment (e.g. "atproto"). */
function splitScope(token: string): { type: string; positional: string; query: string } {
	const qIdx = token.indexOf('?');
	const head = qIdx === -1 ? token : token.slice(0, qIdx);
	const query = qIdx === -1 ? '' : token.slice(qIdx + 1);
	const cIdx = head.indexOf(':');
	if (cIdx === -1) return { type: head, positional: '', query };
	return { type: head.slice(0, cIdx), positional: head.slice(cIdx + 1), query };
}

function humanizeOne(token: string): string {
	if (token === 'atproto') return 'Full read and write access to your account';
	if (token === 'transition:generic') return 'General API access';
	if (token === 'transition:email') return 'Read your email address';
	if (token === 'transition:chat.bsky') return 'Access your direct messages';

	const { type, positional, query } = splitScope(token);

	if (type === 'repo') {
		const params = queryParams(query);
		const actions = params.getAll('action');
		const actionLabel =
			actions.length === 0
				? 'create, edit, and delete'
				: actions.map((a) => REPO_ACTION_LABELS[a] ?? a).join(', ');
		const collection = positional === '*' ? 'any collection' : positional || 'a collection';
		return `Permission to ${actionLabel} records in ${collection}`;
	}

	if (type === 'blob') {
		const mime = positional || 'any type';
		return `Upload files (${mime})`;
	}

	if (type === 'identity') {
		if (positional === 'handle') return 'Change your handle';
		if (positional === '*') return 'Manage your identity (handle, rotation keys)';
		return `Manage your identity (${positional})`;
	}

	if (type === 'account') {
		const params = queryParams(query);
		const manage = params.getAll('action').includes('manage');
		const attr = ACCOUNT_ATTR_LABELS[positional] ?? positional;
		return `${manage ? 'Manage' : 'View'} ${attr}`;
	}

	if (type === 'rpc') {
		const params = queryParams(query);
		const aud = params.get('aud');
		const lxm = positional || params.getAll('lxm').join(', ') || 'a method';
		return aud && aud !== '*'
			? `Call ${lxm} on behalf of your account (via ${aud})`
			: `Call ${lxm} on behalf of your account`;
	}

	/* Unrecognized scope (a newer grammar this build predates, or an
	 * `include:` reference): show it verbatim rather than guessing. */
	return token;
}

/* The individual whitespace-separated tokens of a scope string. Kept as raw
 * strings because the server validates the approved scope token-by-token --
 * the consent UI must select and send back those exact tokens, not a
 * re-serialized description of them. */
export function scopeTokens(scope: string): string[] {
	return scope
		.split(/\s+/)
		.map((t) => t.trim())
		.filter(Boolean);
}

/* Scopes the user is not allowed to uncheck. Mirrors mb_scope_is_required in
 * src/oauth/oauth_scope.c: `atproto` (needed by every issued token), plus
 * transition/identity grants and their include: references. The server
 * enforces this too, so a crafted request cannot drop one. */
export function isRequiredScope(token: string): boolean {
	const value = token.startsWith('include:') ? token.slice('include:'.length) : token;
	if (value === 'atproto') return true;
	return value.startsWith('transition:') || value.startsWith('identity:');
}

/* Whether `token` is newly requested compared with a previous grant. A
 * token absent from the previous scope is new; with no previous grant every
 * token is new. */
export function isNewScope(token: string, previousScope: string | undefined): boolean {
	if (!previousScope) return true;
	return !scopeTokens(previousScope).includes(token);
}

/* Human-readable description of a single raw scope token. */
export function describeScope(token: string): string {
	return humanizeOne(token);
}

/* Human-readable descriptions for every recognized token in a
 * space-separated scope string. "atproto" is filtered out of the list when
 * present alongside other scopes, since it already implies everything else
 * an app could ask for -- listing both is redundant, not more informative. */
export function humanizeScopes(scope: string): string[] {
	const tokens = scopeTokens(scope);
	if (tokens.length === 0) return [];
	if (tokens.includes('atproto')) {
		return ['Full read and write access to your account'];
	}
	return tokens.map(humanizeOne);
}

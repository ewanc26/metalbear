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

/* Human-readable descriptions for every recognized token in a
 * space-separated scope string. "atproto" is filtered out of the list when
 * present alongside other scopes, since it already implies everything else
 * an app could ask for -- listing both is redundant, not more informative. */
export function humanizeScopes(scope: string): string[] {
	const tokens = scope
		.split(/\s+/)
		.map((t) => t.trim())
		.filter(Boolean);
	if (tokens.length === 0) return [];
	if (tokens.includes('atproto')) {
		return ['Full read and write access to your account'];
	}
	return tokens.map(humanizeOne);
}

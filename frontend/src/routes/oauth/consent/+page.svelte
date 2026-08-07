<script lang="ts">
	import { authorizeInfo, deviceSessions } from '$lib/pds';
	import type { AuthorizeInfo, AuthorizeInfoError } from '$lib/pds';
	import { humanizeScopes } from '$lib/oauthScopes';
	import { goto } from '$app/navigation';
	import { page } from '$app/stores';
	import { onMount } from 'svelte';

	let clientId: string = $state('');
	let requestUri: string = $state('');
	let loginHint: string = $state('');
	let loading: boolean = $state(true);
	let confirming: boolean = $state(false);
	let info: AuthorizeInfo | null = $state(null);
	/*
	 * Which of authorizeInfo's named failure reasons happened, if any --
	 * distinguishing 'expired' (retrying won't help; go back to the app),
	 * 'client_mismatch' (also won't self-resolve), and 'server_error'
	 * (worth a literal retry) is the whole point of #26 item 3: one
	 * generic "unknown, expired, or no longer valid" message covered all
	 * three before, even though only one of them actually meant that.
	 */
	let infoError: AuthorizeInfoError | null = $state(null);

	const INFO_ERROR_TEXT: Record<AuthorizeInfoError, { heading: string; message: string }> = {
		expired: {
			heading: 'This request has expired',
			message:
				'Authorization requests are only valid for a few minutes. Go back to the application and try connecting again.'
		},
		client_mismatch: {
			heading: "This link isn't valid",
			message:
				"This authorization link doesn't match the application that started it. Go back to the application and try connecting again."
		},
		invalid_request: {
			heading: 'Missing information',
			message:
				'This link is missing information needed to continue. Go back to the application and try again.'
		},
		server_error: {
			heading: 'Something went wrong',
			message: 'The server had a problem loading this request. Try again in a moment.'
		}
	};
	/* True for the brief window between deciding a sign-in is needed and the
	 * goto() to /login actually navigating away. */
	let redirecting: boolean = $state(false);
	/*
	 * Some OAuth clients omit login_hint entirely, expecting the provider
	 * itself to ask "who are you?" -- oauth_authorize redirects here without
	 * one rather than erroring in that case (see redirect_to_consent in
	 * oauth_routes.c). identifierInput collects it directly instead of
	 * requiring the client to have resolved a handle up front.
	 */
	let needsIdentifier: boolean = $state(false);
	let identifierInput: string = $state('');
	/*
	 * MetalBear is a multi-account host, and a browser can hold more than one
	 * signed-in account's device session at once. When the client omitted
	 * login_hint and this browser already has one or more, offer them as a
	 * picker instead of falling straight to the identifier-entry form --
	 * that form is for adding an account this browser hasn't signed into
	 * yet, not for re-typing one that's already signed in.
	 */
	let pickerSubjects: string[] = $state([]);
	let picking: boolean = $state(false);

	async function proceedWithLoginHint() {
		/*
		 * Checking THIS specific account's device session, not just whether
		 * any session exists, is what actually matters here: a browser
		 * signed into a DIFFERENT account still has "a" session, but
		 * /oauth/authorize will refuse it for this login_hint just the
		 * same, and a check that only asked "any session?" would show
		 * "Approve" anyway -- the click would redirect to /oauth/authorize,
		 * get bounced right back here with nothing changed, and loop
		 * forever. Send the browser to sign in as THIS account instead,
		 * without disturbing whatever other account's session already
		 * exists (see /oauth/signin's doc comment).
		 */
		const redirectTarget = `/oauth/consent?${new URLSearchParams({
			client_id: clientId,
			request_uri: requestUri,
			...(loginHint ? { login_hint: loginHint } : {})
		}).toString()}`;
		const sessions = await deviceSessions(loginHint);
		if (!sessions.matchesHint) {
			loading = false;
			redirecting = true;
			goto(`/login?redirect=${encodeURIComponent(redirectTarget)}`);
			return;
		}

		const result = await authorizeInfo(clientId, requestUri);
		if (result.ok) {
			info = result.info;
			infoError = null;
		} else {
			info = null;
			infoError = result.error;
		}
		loading = false;
	}

	async function handleRetryInfo() {
		loading = true;
		await proceedWithLoginHint();
	}

	onMount(async () => {
		clientId = $page.url.searchParams.get('client_id') ?? '';
		requestUri = $page.url.searchParams.get('request_uri') ?? '';
		loginHint = $page.url.searchParams.get('login_hint') ?? '';

		if (!clientId || !requestUri) {
			loading = false;
			return;
		}

		if (!loginHint) {
			const sessions = await deviceSessions();
			if (sessions.subjects.length > 0) {
				pickerSubjects = sessions.subjects;
				picking = true;
				loading = false;
				return;
			}
			needsIdentifier = true;
			loading = false;
			return;
		}

		await proceedWithLoginHint();
	});

	async function handleIdentifierSubmit(e: Event) {
		e.preventDefault();
		if (!identifierInput.trim()) return;
		loginHint = identifierInput.trim();
		needsIdentifier = false;
		loading = true;
		await proceedWithLoginHint();
	}

	async function handlePickAccount(subject: string) {
		loginHint = subject;
		picking = false;
		loading = true;
		await proceedWithLoginHint();
	}

	function handleUseDifferentAccount() {
		picking = false;
		needsIdentifier = true;
	}

	async function handleApprove() {
		confirming = true;
		const url = new URL('/oauth/authorize', window.location.origin);
		url.searchParams.set('client_id', clientId);
		url.searchParams.set('request_uri', requestUri);
		if (loginHint) url.searchParams.set('login_hint', loginHint);
		window.location.href = url.toString();
	}

	function handleDeny() {
		const fallback = $page.url.searchParams.get('redirect_uri') ?? '/';
		window.location.href = fallback;
	}
</script>

<svelte:head>
	<title>Authorize application — MetalBear</title>
</svelte:head>

<main class="mx-auto flex min-h-screen max-w-lg flex-col justify-center px-6">
	{#if loading}
		<p class="text-sm text-slate-400">Loading…</p>
	{:else if !clientId || !requestUri}
		<div class="rounded-lg border border-red-900/60 bg-red-950/40 px-4 py-3 text-sm text-red-300">
			Missing required OAuth parameters (<code>client_id</code> and <code>request_uri</code>).
		</div>
		<p class="mt-4 text-center text-sm text-slate-500">
			<a href="/" class="text-emerald-500 hover:text-emerald-400">← Back to status</a>
		</p>
	{:else if picking}
		<div class="rounded-lg border border-slate-800 bg-slate-900/30 p-8">
			<h1 class="mb-2 text-xl font-semibold text-white">Choose an account</h1>
			<p class="mb-6 text-sm text-slate-400">
				An application is requesting access to an account on this server. This browser is signed
				into more than one — pick which one to continue with.
			</p>
			<div class="flex flex-col gap-2">
				{#each pickerSubjects as subject (subject)}
					<button
						onclick={() => handlePickAccount(subject)}
						class="rounded-lg border border-slate-700 px-4 py-2.5 text-left font-mono text-sm text-slate-200 transition hover:border-emerald-500 hover:text-white"
					>
						Continue as <span class="text-emerald-400">{subject}</span>
					</button>
				{/each}
			</div>
			<button
				onclick={handleUseDifferentAccount}
				class="mt-4 text-sm text-slate-500 hover:text-slate-400"
			>
				Use a different account
			</button>
		</div>
	{:else if needsIdentifier}
		<div class="rounded-lg border border-slate-800 bg-slate-900/30 p-8">
			<h1 class="mb-2 text-xl font-semibold text-white">Sign in to authorize</h1>
			<p class="mb-6 text-sm text-slate-400">
				An application is requesting access to an account on this server. Enter your handle or DID
				to continue.
			</p>
			<form onsubmit={handleIdentifierSubmit} class="flex flex-col gap-4">
				<div>
					<label for="identifier" class="mb-1.5 block text-sm font-medium text-slate-300"
						>Handle or DID</label
					>
					<input
						id="identifier"
						type="text"
						bind:value={identifierInput}
						placeholder="alice.bsky.social"
						required
						autocomplete="username"
						class="w-full rounded-lg border border-slate-700 bg-slate-900 px-4 py-2.5 text-sm text-white placeholder-slate-500 outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
					/>
				</div>
				<button
					type="submit"
					disabled={!identifierInput.trim()}
					class="rounded-lg bg-emerald-600 px-4 py-2.5 text-sm font-medium text-white transition hover:bg-emerald-500 disabled:cursor-not-allowed disabled:opacity-50"
				>
					Continue
				</button>
			</form>
		</div>
	{:else if redirecting}
		<p class="text-sm text-slate-400">Redirecting to sign in…</p>
	{:else if infoError}
		<div class="rounded-lg border border-red-900/60 bg-red-950/40 px-4 py-3 text-sm text-red-300">
			<p class="font-medium">{INFO_ERROR_TEXT[infoError].heading}</p>
			<p class="mt-1 text-red-300/90">{INFO_ERROR_TEXT[infoError].message}</p>
		</div>
		<div class="mt-4 flex justify-center gap-4 text-sm">
			{#if infoError === 'server_error'}
				<button onclick={handleRetryInfo} class="text-emerald-500 hover:text-emerald-400">
					Try again
				</button>
			{/if}
			<a href="/" class="text-emerald-500 hover:text-emerald-400">← Back to status</a>
		</div>
	{:else}
		<div class="rounded-lg border border-slate-800 bg-slate-900/30 p-8">
			<div class="mb-6 flex items-center gap-3">
				{#if info?.logo_uri}
					<img
						src={info.logo_uri}
						alt=""
						referrerpolicy="no-referrer"
						class="h-10 w-10 rounded-lg border border-slate-700 object-contain"
					/>
				{/if}
				<div>
					<h1 class="text-xl font-semibold text-white">
						{info?.client_name ?? 'An application'} wants to access your account
					</h1>
					{#if info?.client_uri}
						<a
							href={info.client_uri}
							target="_blank"
							rel="noreferrer"
							class="text-xs text-slate-500 hover:text-slate-400"
						>
							{info.client_uri}
						</a>
					{/if}
				</div>
			</div>

			<dl class="mb-8 space-y-4">
				<div>
					<dt class="text-xs font-semibold tracking-widest text-slate-500 uppercase">Client ID</dt>
					<dd class="mt-1 font-mono text-sm break-all text-slate-200">{clientId}</dd>
				</div>
				<div>
					<dt class="text-xs font-semibold tracking-widest text-slate-500 uppercase">
						Signed in as
					</dt>
					<dd class="mt-1 font-mono text-sm text-emerald-400">{loginHint}</dd>
				</div>
			</dl>

			<div class="mb-8">
				<p class="mb-2 text-xs font-semibold tracking-widest text-slate-500 uppercase">
					This app will be able to
				</p>
				<ul
					class="space-y-2 rounded-lg border border-slate-700 bg-slate-950/50 px-4 py-3 text-sm text-slate-300"
				>
					{#each humanizeScopes(info?.scope ?? 'atproto') as permission (permission)}
						<li class="flex gap-2">
							<span class="text-emerald-500">•</span>
							<span>{permission}</span>
						</li>
					{/each}
				</ul>
			</div>

			<div class="flex gap-3">
				<button
					onclick={handleApprove}
					disabled={confirming}
					class="flex-1 rounded-lg bg-emerald-600 px-4 py-2.5 text-sm font-medium text-white transition hover:bg-emerald-500 disabled:opacity-50"
				>
					{confirming ? 'Authorizing…' : 'Approve'}
				</button>
				<button
					onclick={handleDeny}
					class="flex-1 rounded-lg border border-slate-700 px-4 py-2.5 text-sm font-medium text-slate-300 transition hover:border-slate-600 hover:text-white"
				>
					Deny
				</button>
			</div>
		</div>
	{/if}
</main>

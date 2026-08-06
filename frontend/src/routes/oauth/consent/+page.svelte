<script lang="ts">
	import { auth } from '$lib/stores/auth';
	import type { Session } from '$lib/stores/auth';
	import { authorizeInfo, hasDeviceSession } from '$lib/pds';
	import type { AuthorizeInfo } from '$lib/pds';
	import { humanizeScopes } from '$lib/oauthScopes';
	import { goto } from '$app/navigation';
	import { page } from '$app/stores';
	import { onMount } from 'svelte';

	let session: Session | null = $state(null);
	let clientId: string = $state('');
	let requestUri: string = $state('');
	let loginHint: string = $state('');
	let loading: boolean = $state(true);
	let confirming: boolean = $state(false);
	let info: AuthorizeInfo | null = $state(null);
	let infoFailed: boolean = $state(false);
	/*
	 * Some OAuth clients omit login_hint entirely, expecting the provider
	 * itself to ask "who are you?" -- oauth_authorize redirects here without
	 * one rather than erroring in that case (see redirect_to_consent in
	 * oauth_routes.c). identifierInput collects it directly instead of
	 * requiring the client to have resolved a handle up front.
	 */
	let needsIdentifier: boolean = $state(false);
	let identifierInput: string = $state('');

	auth.subscribe((s) => (session = s));

	async function proceedWithLoginHint() {
		/*
		 * A regular JWT session (the `auth` store) proves nothing about the
		 * OAuth device session "Approve" actually needs -- nothing else
		 * establishes one but /oauth/signin, which /login only calls when it
		 * knows it's on an OAuth path. A returning user who already has a
		 * JWT session from an earlier, unrelated visit must still be sent
		 * through /login here, or "Approve" would have nothing to check and
		 * loop back to this same page having done nothing.
		 */
		const redirectTarget = `/oauth/consent?${new URLSearchParams({
			client_id: clientId,
			request_uri: requestUri,
			...(loginHint ? { login_hint: loginHint } : {})
		}).toString()}`;
		if (!session || !(await hasDeviceSession())) {
			loading = false;
			goto(`/login?redirect=${encodeURIComponent(redirectTarget)}`);
			return;
		}

		info = await authorizeInfo(clientId, requestUri);
		infoFailed = info === null;
		loading = false;
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
	{:else if !session}
		<p class="text-sm text-slate-400">Redirecting to sign in…</p>
	{:else if infoFailed}
		<div class="rounded-lg border border-red-900/60 bg-red-950/40 px-4 py-3 text-sm text-red-300">
			This authorization request is unknown, expired, or no longer valid. Go back to the application
			and try signing in again.
		</div>
		<p class="mt-4 text-center text-sm text-slate-500">
			<a href="/" class="text-emerald-500 hover:text-emerald-400">← Back to status</a>
		</p>
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
				{#if loginHint}
					<div>
						<dt class="text-xs font-semibold tracking-widest text-slate-500 uppercase">
							Requested account
						</dt>
						<dd class="mt-1 font-mono text-sm text-slate-200">{loginHint}</dd>
					</div>
				{/if}
				<div>
					<dt class="text-xs font-semibold tracking-widest text-slate-500 uppercase">
						Signed in as
					</dt>
					<dd class="mt-1 font-mono text-sm text-emerald-400">{session.handle}</dd>
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

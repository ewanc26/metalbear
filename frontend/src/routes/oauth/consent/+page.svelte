<script lang="ts">
	import { auth } from '$lib/stores/auth';
	import type { Session } from '$lib/stores/auth';
	import { authorizeInfo } from '$lib/pds';
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

	auth.subscribe((s) => (session = s));

	onMount(async () => {
		clientId = $page.url.searchParams.get('client_id') ?? '';
		requestUri = $page.url.searchParams.get('request_uri') ?? '';
		loginHint = $page.url.searchParams.get('login_hint') ?? '';

		if (!clientId || !requestUri) {
			loading = false;
			return;
		}

		if (!session) {
			loading = false;
			goto(`/login?redirect=${encodeURIComponent($page.url.pathname + $page.url.search)}`);
			return;
		}

		info = await authorizeInfo(clientId, requestUri);
		infoFailed = info === null;
		loading = false;
	});

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

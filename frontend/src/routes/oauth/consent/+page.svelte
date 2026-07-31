<script lang="ts">
	import { auth } from '$lib/stores/auth';
	import type { Session } from '$lib/stores/auth';
	import { goto } from '$app/navigation';
	import { page } from '$app/stores';
	import { onMount } from 'svelte';

	let session: Session | null = $state(null);
	let clientId: string = $state('');
	let requestUri: string = $state('');
	let loginHint: string = $state('');
	let loading: boolean = $state(true);
	let confirming: boolean = $state(false);

	let show = $state(false);

	auth.subscribe((s) => (session = s));

	onMount(() => {
		clientId = $page.url.searchParams.get('client_id') ?? '';
		requestUri = $page.url.searchParams.get('request_uri') ?? '';
		loginHint = $page.url.searchParams.get('login_hint') ?? '';

		if (!clientId || !requestUri) {
			loading = false;
			return;
		}

		loading = false;

		if (!session) {
			goto(`/login?redirect=${encodeURIComponent($page.url.pathname + $page.url.search)}`);
		}
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
	{:else}
		<div class="rounded-lg border border-slate-800 bg-slate-900/30 p-8">
			<h1 class="mb-2 text-xl font-semibold text-white">Authorize application</h1>
			<p class="mb-6 text-sm text-slate-400">
				An application is requesting access to your account.
			</p>

			<dl class="mb-8 space-y-4">
				<div>
					<dt class="text-xs font-semibold tracking-widest text-slate-500 uppercase">Client ID</dt>
					<dd class="mt-1 break-all font-mono text-sm text-slate-200">{clientId}</dd>
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

			<div
				class="mb-8 rounded-lg border border-slate-700 bg-slate-950/50 px-4 py-3 text-sm text-slate-300"
			>
				This will grant the application access to read and write your data via the AT Protocol.
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

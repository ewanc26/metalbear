<script lang="ts">
	import { auth } from '$lib/stores/auth';
	import { getSession, refreshSession } from '$lib/pds';
	import { goto } from '$app/navigation';
	import { onMount } from 'svelte';

	let session = $state<import('$lib/stores/auth').Session | null>(null);
	let current = $state<import('$lib/pds').SessionResponse | null>(null);
	let error = $state('');
	let loading = $state(true);

	auth.subscribe((s) => (session = s));

	onMount(async () => {
		if (!session) {
			goto('/login');
			return;
		}
		try {
			current = await getSession();
		} catch (err) {
			error = err instanceof Error ? err.message : 'Failed to load session';
		} finally {
			loading = false;
		}
	});

	async function handleRefresh() {
		try {
			const updated = await refreshSession();
			auth.refresh({
				accessJwt: updated.accessJwt,
				refreshJwt: updated.refreshJwt,
				handle: updated.handle,
				did: updated.did,
				email: updated.email,
				emailConfirmed: updated.emailConfirmed,
				emailAuthFactor: updated.emailAuthFactor,
				active: updated.active,
				status: updated.status,
				didDoc: updated.didDoc
			});
			current = updated;
		} catch (err) {
			error = err instanceof Error ? err.message : 'Failed to refresh session';
		}
	}
</script>

<svelte:head>
	<title>Account — MetalBear</title>
</svelte:head>

<main class="mx-auto max-w-2xl px-6 py-12">
	<h1 class="mb-8 text-2xl font-semibold text-white">Account</h1>

	{#if loading}
		<p class="text-sm text-slate-400">Loading…</p>
	{:else if error}
		<p class="rounded-lg border border-red-900/60 bg-red-950/40 px-4 py-3 text-sm text-red-300">
			{error}
		</p>
		<a href="/login" class="mt-4 inline-block text-sm text-emerald-500 hover:text-emerald-400">
			Sign in again →
		</a>
	{:else if current}
		<section class="mb-8 rounded-lg border border-slate-800 bg-slate-900/30 p-6">
			<h2 class="mb-4 text-sm font-semibold tracking-widest text-slate-500 uppercase">
				Session
			</h2>
			<dl class="grid gap-x-8 gap-y-4 sm:grid-cols-2">
				<div>
					<dt class="text-sm text-slate-500">Handle</dt>
					<dd class="font-mono text-sm text-slate-200">{current.handle}</dd>
				</div>
				<div>
					<dt class="text-sm text-slate-500">DID</dt>
					<dd class="font-mono text-sm break-all text-slate-200">{current.did}</dd>
				</div>
				{#if current.email}
					<div>
						<dt class="text-sm text-slate-500">Email</dt>
						<dd class="text-sm text-slate-200">
							{current.email}
							{#if current.emailConfirmed}
								<span class="ml-2 text-xs text-emerald-400">confirmed</span>
							{:else}
								<span class="ml-2 text-xs text-amber-400">unconfirmed</span>
							{/if}
						</dd>
					</div>
				{/if}
				<div>
					<dt class="text-sm text-slate-500">Status</dt>
					<dd class="text-sm">
						{#if current.active}
							<span class="text-emerald-400">Active</span>
						{:else}
							<span class="text-amber-400">{current.status ?? 'Deactivated'}</span>
						{/if}
					</dd>
				</div>
			</dl>
		</section>

		<button
			onclick={handleRefresh}
			class="rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-300 transition hover:border-slate-600 hover:text-white"
		>
			Refresh tokens
		</button>
	{/if}
</main>

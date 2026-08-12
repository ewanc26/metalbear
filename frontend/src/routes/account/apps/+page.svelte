<script lang="ts">
	import { auth } from '$lib/stores/auth';
	import { listGrants, revokeGrant } from '$lib/pds';
	import type { GrantInfo } from '$lib/pds';
	import { humanizeScopes } from '$lib/oauthScopes';
	import { formatDate } from '$lib/format';
	import { goto } from '$app/navigation';
	import { onMount } from 'svelte';

	let session = $state<import('$lib/stores/auth').Session | null>(null);
	let grants = $state<GrantInfo[]>([]);
	let error = $state('');
	let loading = $state(true);
	let revokingId = $state<string | null>(null);

	auth.subscribe((s) => (session = s));

	onMount(async () => {
		if (!session) {
			goto('/login');
			return;
		}
		await loadGrants();
	});

	async function loadGrants() {
		loading = true;
		error = '';
		try {
			grants = await listGrants();
		} catch (err) {
			error = err instanceof Error ? err.message : 'Failed to load connected apps';
		} finally {
			loading = false;
		}
	}

	async function handleRevoke(clientId: string) {
		revokingId = clientId;
		try {
			await revokeGrant(clientId);
			grants = await listGrants();
		} catch (err) {
			error = err instanceof Error ? err.message : 'Failed to disconnect app';
		} finally {
			revokingId = null;
		}
	}

	function formatExpiry(expiresAt: number): string {
		return formatDate(expiresAt);
	}
</script>

<svelte:head>
	<title>Connected apps — MetalBear</title>
</svelte:head>

<main class="mx-auto max-w-2xl px-6 py-12">
	<h1 class="mb-2 text-2xl font-semibold text-white">Connected apps</h1>
	<p class="mb-8 text-sm text-slate-400">
		Applications you've authorized via OAuth to access your account. Disconnecting an app ends its
		access immediately, rather than waiting for its current token to expire.
	</p>

	<section class="rounded-lg border border-slate-800 bg-slate-900/30 p-6">
		{#if loading}
			<p class="text-sm text-slate-400">Loading…</p>
		{:else if error}
			<p class="rounded-lg border border-red-900/60 bg-red-950/40 px-4 py-2.5 text-sm text-red-300">
				{error}
			</p>
		{:else if grants.length === 0}
			<p class="text-sm text-slate-500">No connected apps.</p>
		{:else}
			<ul class="divide-y divide-slate-800">
				{#each grants as grant (grant.clientId)}
					<li class="flex items-center justify-between gap-4 py-3">
						<div>
							<span class="text-sm break-all text-slate-200">{grant.clientId}</span>
							<div class="mt-1 flex flex-wrap gap-1.5">
								{#each humanizeScopes(grant.scope) as permission (permission)}
									<span
										class="rounded-full border border-slate-700 bg-slate-950/50 px-2 py-0.5 text-xs text-slate-400"
									>
										{permission}
									</span>
								{/each}
							</div>
							<div class="mt-1.5 text-xs text-slate-500">
								Expires {formatExpiry(grant.expiresAt)}
							</div>
						</div>
						<button
							onclick={() => handleRevoke(grant.clientId)}
							disabled={revokingId === grant.clientId}
							class="shrink-0 text-sm text-red-400 hover:text-red-300 disabled:opacity-50"
						>
							{revokingId === grant.clientId ? 'Disconnecting…' : 'Disconnect'}
						</button>
					</li>
				{/each}
			</ul>
		{/if}
	</section>

	<p class="mt-8 text-center text-sm text-slate-500">
		<a href="/account" class="text-emerald-500 hover:text-emerald-400">← Account settings</a>
	</p>
</main>

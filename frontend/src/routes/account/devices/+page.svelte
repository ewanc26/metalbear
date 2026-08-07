<script lang="ts">
	import { auth } from '$lib/stores/auth';
	import { listDevices, revokeDevice } from '$lib/pds';
	import type { DeviceInfo } from '$lib/pds';
	import { goto } from '$app/navigation';
	import { onMount } from 'svelte';

	let session = $state<import('$lib/stores/auth').Session | null>(null);
	let devices = $state<DeviceInfo[]>([]);
	let error = $state('');
	let loading = $state(true);
	let revokingId = $state<string | null>(null);

	auth.subscribe((s) => (session = s));

	onMount(async () => {
		if (!session) {
			goto('/login');
			return;
		}
		await loadDevices();
	});

	async function loadDevices() {
		loading = true;
		error = '';
		try {
			devices = await listDevices();
		} catch (err) {
			error = err instanceof Error ? err.message : 'Failed to load devices';
		} finally {
			loading = false;
		}
	}

	async function handleRevoke(sessionId: string) {
		revokingId = sessionId;
		try {
			await revokeDevice(sessionId);
			devices = await listDevices();
		} catch (err) {
			error = err instanceof Error ? err.message : 'Failed to sign out device';
		} finally {
			revokingId = null;
		}
	}

	function formatExpiry(expiresAt: number): string {
		return new Date(expiresAt * 1000).toLocaleDateString(undefined, {
			year: 'numeric',
			month: 'short',
			day: 'numeric'
		});
	}
</script>

<svelte:head>
	<title>Active devices — MetalBear</title>
</svelte:head>

<main class="mx-auto max-w-2xl px-6 py-12">
	<h1 class="mb-2 text-2xl font-semibold text-white">Active devices</h1>
	<p class="mb-8 text-sm text-slate-400">
		Browsers currently signed in to your account for authorizing OAuth apps. Signing a device out
		here does not affect your regular login sessions on this site.
	</p>

	<section class="rounded-lg border border-slate-800 bg-slate-900/30 p-6">
		{#if loading}
			<p class="text-sm text-slate-400">Loading…</p>
		{:else if error}
			<p class="rounded-lg border border-red-900/60 bg-red-950/40 px-4 py-2.5 text-sm text-red-300">
				{error}
			</p>
		{:else if devices.length === 0}
			<p class="text-sm text-slate-500">No active devices.</p>
		{:else}
			<ul class="divide-y divide-slate-800">
				{#each devices as device (device.sessionId)}
					<li class="flex items-center justify-between gap-4 py-3">
						<div>
							<span class="font-mono text-xs break-all text-slate-400">{device.sessionId}</span>
							<div class="mt-0.5 text-xs text-slate-500">
								Expires {formatExpiry(device.expiresAt)}
							</div>
						</div>
						<button
							onclick={() => handleRevoke(device.sessionId)}
							disabled={revokingId === device.sessionId}
							class="shrink-0 text-sm text-red-400 hover:text-red-300 disabled:opacity-50"
						>
							{revokingId === device.sessionId ? 'Signing out…' : 'Sign out'}
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

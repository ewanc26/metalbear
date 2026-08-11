<script lang="ts">
	import { auth } from '$lib/stores/auth';
	import {
		getSession,
		deactivateAccount,
		activateAccount,
		requestAccountDelete,
		deleteAccount
	} from '$lib/pds';
	import type { SessionResponse } from '$lib/pds';
	import { goto } from '$app/navigation';
	import { onMount } from 'svelte';

	let session = $state<import('$lib/stores/auth').Session | null>(null);
	let current = $state<SessionResponse | null>(null);
	let loading = $state(true);
	let loadError = $state('');

	auth.subscribe((s) => (session = s));

	onMount(async () => {
		if (!session) {
			goto('/login');
			return;
		}
		try {
			current = await getSession();
		} catch (err) {
			loadError = err instanceof Error ? err.message : 'Failed to load session';
		} finally {
			loading = false;
		}
	});

	/* ---- Deactivate / reactivate ---- */
	let togglePending = $state(false);
	let toggleError = $state('');

	async function handleDeactivate() {
		if (!confirm('Deactivate your account? Your repo stays intact and you can reactivate later.'))
			return;
		toggleError = '';
		togglePending = true;
		try {
			await deactivateAccount();
			current = await getSession();
		} catch (err) {
			toggleError = err instanceof Error ? err.message : 'Failed to deactivate account';
		} finally {
			togglePending = false;
		}
	}

	async function handleReactivate() {
		toggleError = '';
		togglePending = true;
		try {
			await activateAccount();
			current = await getSession();
		} catch (err) {
			toggleError = err instanceof Error ? err.message : 'Failed to reactivate account';
		} finally {
			togglePending = false;
		}
	}

	/* ---- Delete ---- */
	let deleteStep = $state<'idle' | 'sent'>('idle');
	let deleteToken = $state('');
	let deletePassword = $state('');
	let deletePending = $state(false);
	let deleteError = $state('');

	async function requestDelete() {
		deleteError = '';
		deletePending = true;
		try {
			await requestAccountDelete();
			deleteStep = 'sent';
		} catch (err) {
			deleteError = err instanceof Error ? err.message : 'Failed to send deletion code';
		} finally {
			deletePending = false;
		}
	}

	async function confirmDelete(e: Event) {
		e.preventDefault();
		if (!current) return;
		if (
			!confirm(
				'This permanently deletes your account, repo, and all data. This cannot be undone. Continue?'
			)
		)
			return;
		deleteError = '';
		deletePending = true;
		try {
			await deleteAccount(current.did, deletePassword, deleteToken);
			auth.logout();
			goto('/');
		} catch (err) {
			deleteError = err instanceof Error ? err.message : 'Failed to delete account';
			deletePending = false;
		}
	}
</script>

<svelte:head>
	<title>Danger zone — MetalBear</title>
</svelte:head>

<main class="mx-auto max-w-2xl px-6 py-12">
	<h1 class="mb-8 text-2xl font-semibold text-white">Danger zone</h1>

	{#if loading}
		<p class="text-sm text-slate-400">Loading…</p>
	{:else if loadError}
		<p class="rounded-lg border border-red-900/60 bg-red-950/40 px-4 py-3 text-sm text-red-300">
			{loadError}
		</p>
	{:else if current}
		<!-- Deactivate -->
		<section class="mb-8 rounded-lg border border-amber-900/50 bg-amber-950/10 p-6">
			<h2 class="mb-1 text-sm font-semibold tracking-widest text-amber-500 uppercase">
				{current.active ? 'Deactivate account' : 'Account deactivated'}
			</h2>
			<p class="mb-4 text-sm text-slate-400">
				{#if current.active}
					Hides your account from the network without deleting anything. Sign back in to reactivate.
				{:else}
					Your account is currently deactivated ({current.status ?? 'deactivated'}). Reactivate to
					make it visible again.
				{/if}
			</p>
			<button
				onclick={current.active ? handleDeactivate : handleReactivate}
				disabled={togglePending}
				class="rounded-lg border border-amber-700/60 px-4 py-2 text-sm text-amber-300 transition hover:border-amber-600 hover:text-amber-200 disabled:cursor-not-allowed disabled:opacity-50"
			>
				{togglePending ? 'Working…' : current.active ? 'Deactivate account' : 'Reactivate account'}
			</button>
			{#if toggleError}
				<p
					class="mt-4 rounded-lg border border-red-900/60 bg-red-950/40 px-4 py-2.5 text-sm text-red-300"
				>
					{toggleError}
				</p>
			{/if}
		</section>

		<!-- Delete -->
		<section class="rounded-lg border border-red-900/50 bg-red-950/10 p-6">
			<h2 class="mb-1 text-sm font-semibold tracking-widest text-red-500 uppercase">
				Delete account
			</h2>
			<p class="mb-4 text-sm text-slate-400">
				Permanently deletes your account, repo, and every record and blob you've published. This
				cannot be undone.
				{#if current.email}
					We'll email a confirmation code to <span class="text-slate-300">{current.email}</span> first.
				{/if}
			</p>

			{#if deleteStep === 'idle'}
				<button
					onclick={requestDelete}
					disabled={deletePending || !current.email}
					class="rounded-lg border border-red-700/60 px-4 py-2 text-sm text-red-300 transition hover:border-red-600 hover:text-red-200 disabled:cursor-not-allowed disabled:opacity-50"
				>
					{deletePending ? 'Sending…' : 'Request account deletion'}
				</button>
				{#if !current.email}
					<p class="mt-3 text-xs text-slate-500">
						An email address on file is required to confirm deletion.
					</p>
				{/if}
			{:else}
				<form onsubmit={confirmDelete} class="flex flex-col gap-4">
					<div class="flex flex-col gap-4 sm:flex-row">
						<input
							type="text"
							bind:value={deleteToken}
							placeholder="Confirmation code"
							required
							autocomplete="one-time-code"
							class="flex-1 rounded-lg border border-slate-700 bg-slate-900 px-4 py-2 text-sm text-white placeholder-slate-500 outline-none focus:border-red-500 focus:ring-1 focus:ring-red-500"
						/>
						<input
							type="password"
							bind:value={deletePassword}
							placeholder="Password"
							required
							autocomplete="current-password"
							class="flex-1 rounded-lg border border-slate-700 bg-slate-900 px-4 py-2 text-sm text-white placeholder-slate-500 outline-none focus:border-red-500 focus:ring-1 focus:ring-red-500"
						/>
					</div>
					<div class="flex items-center gap-3">
						<button
							type="submit"
							disabled={deletePending || !deleteToken || !deletePassword}
							class="rounded-lg bg-red-700 px-4 py-2 text-sm font-medium text-white transition hover:bg-red-600 disabled:cursor-not-allowed disabled:opacity-50"
						>
							{deletePending ? 'Deleting…' : 'Permanently delete account'}
						</button>
						<button
							type="button"
							onclick={() => (deleteStep = 'idle')}
							class="text-sm text-slate-500 hover:text-slate-300"
						>
							Cancel
						</button>
					</div>
				</form>
			{/if}

			{#if deleteError}
				<p
					class="mt-4 rounded-lg border border-red-900/60 bg-red-950/40 px-4 py-2.5 text-sm text-red-300"
				>
					{deleteError}
				</p>
			{/if}
		</section>
	{/if}

	<p class="mt-8 text-center text-sm text-slate-500">
		<a href="/account" class="text-emerald-500 hover:text-emerald-400">← Account settings</a>
	</p>
</main>

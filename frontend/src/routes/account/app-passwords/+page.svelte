<script lang="ts">
	import { auth } from '$lib/stores/auth';
	import { createAppPassword, listAppPasswords, revokeAppPassword } from '$lib/pds';
	import type { AppPassword } from '$lib/pds';
	import { goto } from '$app/navigation';
	import { onMount } from 'svelte';

	let session = $state<import('$lib/stores/auth').Session | null>(null);
	let passwords = $state<AppPassword[]>([]);
	let error = $state('');
	let loading = $state(true);

	let newName = $state('');
	let newPrivileged = $state(false);
	let createdPassword = $state('');
	let creating = $state(false);
	let createError = $state('');
	let revokingName = $state<string | null>(null);

	auth.subscribe((s) => (session = s));

	onMount(async () => {
		if (!session) {
			goto('/login');
			return;
		}
		await loadPasswords();
	});

	async function loadPasswords() {
		loading = true;
		error = '';
		try {
			passwords = await listAppPasswords();
		} catch (err) {
			error = err instanceof Error ? err.message : 'Failed to load app passwords';
		} finally {
			loading = false;
		}
	}

	async function handleCreate(e: Event) {
		e.preventDefault();
		createError = '';
		createdPassword = '';
		creating = true;
		try {
			const result = await createAppPassword(newName, newPrivileged);
			createdPassword = result.password;
			passwords = await listAppPasswords();
			newName = '';
			newPrivileged = false;
		} catch (err) {
			createError = err instanceof Error ? err.message : 'Failed to create app password';
		} finally {
			creating = false;
		}
	}

	async function handleRevoke(name: string) {
		revokingName = name;
		try {
			await revokeAppPassword(name);
			passwords = await listAppPasswords();
		} catch (err) {
			error = err instanceof Error ? err.message : 'Failed to revoke app password';
		} finally {
			revokingName = null;
		}
	}

	function copyPassword() {
		navigator.clipboard.writeText(createdPassword);
	}
</script>

<svelte:head>
	<title>App passwords — MetalBear</title>
</svelte:head>

<main class="mx-auto max-w-2xl px-6 py-12">
	<h1 class="mb-2 text-2xl font-semibold text-white">App passwords</h1>
	<p class="mb-8 text-sm text-slate-400">
		App passwords let third-party clients access your account without sharing your main password.
	</p>

	<!-- Create form -->
	<section class="mb-10 rounded-lg border border-slate-800 bg-slate-900/30 p-6">
		<h2 class="mb-4 text-sm font-semibold tracking-widest text-slate-500 uppercase">
			Create app password
		</h2>
		<form onsubmit={handleCreate} class="flex flex-col gap-4">
			<div class="flex flex-col gap-4 sm:flex-row sm:items-end">
				<div class="flex-1">
					<label for="name" class="mb-1.5 block text-sm font-medium text-slate-300">Name</label>
					<input
						id="name"
						type="text"
						bind:value={newName}
						placeholder="My client"
						required
						class="w-full rounded-lg border border-slate-700 bg-slate-900 px-4 py-2 text-sm text-white placeholder-slate-500 outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
					/>
				</div>
				<label class="flex items-center gap-2 pb-2 text-sm text-slate-300">
					<input type="checkbox" bind:checked={newPrivileged} class="rounded border-slate-600 bg-slate-800" />
					Privileged
				</label>
				<button
					type="submit"
					disabled={creating || !newName}
					class="rounded-lg bg-emerald-600 px-4 py-2 text-sm font-medium text-white transition hover:bg-emerald-500 disabled:cursor-not-allowed disabled:opacity-50"
				>
					{creating ? 'Creating…' : 'Create'}
				</button>
			</div>
		</form>

		{#if createError}
			<p class="mt-4 rounded-lg border border-red-900/60 bg-red-950/40 px-4 py-2.5 text-sm text-red-300">
				{createError}
			</p>
		{/if}

		{#if createdPassword}
			<div
				class="mt-4 rounded-lg border border-emerald-900/60 bg-emerald-950/40 px-4 py-3 text-sm text-emerald-300"
			>
				<p class="mb-2 font-medium">App password created — copy it now, you won't see it again.</p>
				<div class="flex items-center gap-2">
					<code class="flex-1 break-all rounded bg-slate-800 px-3 py-1.5 font-mono text-sm text-white">
						{createdPassword}
					</code>
					<button
						onclick={copyPassword}
						class="shrink-0 rounded border border-slate-700 px-3 py-1.5 text-xs text-slate-300 hover:border-slate-600"
					>
						Copy
					</button>
				</div>
			</div>
		{/if}
	</section>

	<!-- Existing passwords -->
	<section class="rounded-lg border border-slate-800 bg-slate-900/30 p-6">
		<h2 class="mb-4 text-sm font-semibold tracking-widest text-slate-500 uppercase">
			Existing app passwords
		</h2>

		{#if loading}
			<p class="text-sm text-slate-400">Loading…</p>
		{:else if error}
			<p class="rounded-lg border border-red-900/60 bg-red-950/40 px-4 py-2.5 text-sm text-red-300">
				{error}
			</p>
		{:else if passwords.length === 0}
			<p class="text-sm text-slate-500">No app passwords yet.</p>
		{:else}
			<ul class="divide-y divide-slate-800">
				{#each passwords as pw (pw.name)}
					<li class="flex items-center justify-between gap-4 py-3">
						<div>
							<span class="text-sm text-slate-200">{pw.name}</span>
							<div class="mt-0.5 flex items-center gap-2">
								<span class="text-xs text-slate-500">Created {pw.createdAt}</span>
								{#if pw.privileged}
									<span
										class="rounded-full border border-amber-600/50 bg-amber-950/40 px-2 py-0.5 text-xs text-amber-400"
									>
										Privileged
									</span>
								{/if}
							</div>
						</div>
						<button
							onclick={() => handleRevoke(pw.name)}
							disabled={revokingName === pw.name}
							class="shrink-0 text-sm text-red-400 hover:text-red-300 disabled:opacity-50"
						>
							{revokingName === pw.name ? 'Revoking…' : 'Revoke'}
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

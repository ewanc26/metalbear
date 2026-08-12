<script lang="ts">
	import { auth } from '$lib/stores/auth';
	import { getSession, refreshSession, downloadRepo } from '$lib/pds';
	import { goto } from '$app/navigation';
	import { onMount } from 'svelte';

	let session = $state<import('$lib/stores/auth').Session | null>(null);
	let current = $state<import('$lib/pds').SessionResponse | null>(null);
	let error = $state('');
	let loading = $state(true);
	let downloadPending = $state(false);
	let downloadError = $state('');

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

	async function handleDownload() {
		if (!current) return;
		downloadError = '';
		downloadPending = true;
		try {
			const blob = await downloadRepo(current.did);
			const url = URL.createObjectURL(blob);
			const link = document.createElement('a');
			link.href = url;
			link.download = `${current.handle}-${new Date().toISOString().slice(0, 10)}.car`;
			document.body.appendChild(link);
			link.click();
			link.remove();
			URL.revokeObjectURL(url);
		} catch (err) {
			downloadError = err instanceof Error ? err.message : 'Failed to download your data';
		} finally {
			downloadPending = false;
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
			<h2 class="mb-4 text-sm font-semibold tracking-widest text-slate-500 uppercase">Session</h2>
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

		<section class="mt-8 rounded-lg border border-slate-800 bg-slate-900/30 p-6">
			<h2 class="mb-1 text-sm font-semibold tracking-widest text-slate-500 uppercase">
				Your data
			</h2>
			<p class="mb-4 text-sm text-slate-400">
				Download a full export of your repository as a CAR file — your posts, profile, and every
				other record you own, signed and portable to any other AT Protocol server.
			</p>
			<button
				onclick={handleDownload}
				disabled={downloadPending}
				class="rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-300 transition hover:border-slate-600 hover:text-white disabled:cursor-not-allowed disabled:opacity-50"
			>
				{downloadPending ? 'Preparing download…' : 'Download your data'}
			</button>
			{#if downloadError}
				<p
					class="mt-4 rounded-lg border border-red-900/60 bg-red-950/40 px-4 py-2.5 text-sm text-red-300"
				>
					{downloadError}
				</p>
			{/if}
		</section>

		<section class="mt-8 rounded-lg border border-slate-800 bg-slate-900/30 p-6">
			<h2 class="mb-4 text-sm font-semibold tracking-widest text-slate-500 uppercase">Manage</h2>
			<ul class="space-y-2 text-sm">
				<li>
					<a href="/account/app-passwords" class="text-emerald-500 hover:text-emerald-400"
						>App passwords →</a
					>
				</li>
				<li>
					<a href="/account/apps" class="text-emerald-500 hover:text-emerald-400"
						>Connected apps →</a
					>
				</li>
				<li>
					<a href="/account/devices" class="text-emerald-500 hover:text-emerald-400"
						>Active devices →</a
					>
				</li>
				<li>
					<a href="/account/security" class="text-emerald-500 hover:text-emerald-400"
						>Security (password, email, handle) →</a
					>
				</li>
				<li>
					<a href="/account/recovery-key" class="text-emerald-500 hover:text-emerald-400"
						>Personal recovery key →</a
					>
				</li>
				<li>
					<a href="/account/migrate" class="text-emerald-500 hover:text-emerald-400"
						>Migrate to another server →</a
					>
				</li>
				<li>
					<a href="/account/danger-zone" class="text-red-400 hover:text-red-300">Danger zone →</a>
				</li>
			</ul>
		</section>
	{/if}
</main>

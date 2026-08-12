<script lang="ts">
	import { auth } from '$lib/stores/auth';
	import { getSession, requestPlcOperationSignature } from '$lib/pds';
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

	let tokenPending = $state(false);
	let tokenSent = $state(false);
	let tokenError = $state('');

	async function handleRequestToken() {
		tokenError = '';
		tokenPending = true;
		try {
			await requestPlcOperationSignature();
			tokenSent = true;
		} catch (err) {
			tokenError = err instanceof Error ? err.message : 'Failed to send the signing token';
		} finally {
			tokenPending = false;
		}
	}
</script>

<svelte:head>
	<title>Migrate to another server — MetalBear</title>
</svelte:head>

<main class="mx-auto max-w-2xl px-6 py-12">
	<h1 class="mb-2 text-2xl font-semibold text-white">Migrate to another server</h1>
	<p class="mb-8 text-sm text-slate-400">
		Your account's identity (DID and handle) isn't tied to this server — you can move it to any
		other AT Protocol PDS, including the reference Bluesky-hosted service, without losing your
		handle, followers, or post history. This is an identity-critical, multi-step process; take it
		slowly and keep a backup.
	</p>

	{#if loading}
		<p class="text-sm text-slate-400">Loading…</p>
	{:else if loadError}
		<p class="rounded-lg border border-red-900/60 bg-red-950/40 px-4 py-3 text-sm text-red-300">
			{loadError}
		</p>
	{:else if current}
		<section class="mb-8 rounded-lg border border-slate-800 bg-slate-900/30 p-6">
			<h2 class="mb-4 text-sm font-semibold tracking-widest text-slate-500 uppercase">
				Your identity
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
			</dl>
			<p class="mt-4 text-xs text-slate-500">
				You'll need your DID (above) on the destination server — it's how it knows this is an
				existing account moving in, not a new one.
			</p>
		</section>

		<section class="mb-8 rounded-lg border border-slate-800 bg-slate-900/30 p-6">
			<h2 class="mb-4 text-sm font-semibold tracking-widest text-slate-500 uppercase">
				1. Create the account on your new server
			</h2>
			<p class="text-sm text-slate-400">
				On the destination PDS, create an account using your existing DID above (not a fresh
				one). It starts out deactivated there until identity is fully moved over in step 3.
			</p>
		</section>

		<section class="mb-8 rounded-lg border border-slate-800 bg-slate-900/30 p-6">
			<h2 class="mb-4 text-sm font-semibold tracking-widest text-slate-500 uppercase">
				2. Copy your data over
			</h2>
			<p class="mb-4 text-sm text-slate-400">
				Your repo (posts, profile, and every other record), blobs (images/video), and preferences
				all need to move to the new server before you switch identity over to it.
			</p>
			<a
				href="/account"
				class="inline-block rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-300 transition hover:border-slate-600 hover:text-white"
			>
				Download your data →
			</a>
		</section>

		<section class="mb-8 rounded-lg border border-slate-800 bg-slate-900/30 p-6">
			<h2 class="mb-4 text-sm font-semibold tracking-widest text-slate-500 uppercase">
				3. Point your identity at the new server
			</h2>
			<p class="mb-4 text-sm text-slate-400">
				This is the step that actually moves your account: a signed operation updating where your
				DID says you're hosted. This server has to co-sign it, which needs a one-time token sent
				to your email.
			</p>
			{#if tokenSent}
				<p
					class="mb-4 rounded-lg border border-emerald-900/60 bg-emerald-950/40 px-4 py-2.5 text-sm text-emerald-300"
				>
					Check your email for the signing token, then use it on the new server to complete the
					identity update.
				</p>
			{/if}
			<button
				onclick={handleRequestToken}
				disabled={tokenPending}
				class="rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-300 transition hover:border-slate-600 hover:text-white disabled:cursor-not-allowed disabled:opacity-50"
			>
				{tokenPending ? 'Sending…' : 'Email me a signing token'}
			</button>
			{#if tokenError}
				<p
					class="mt-4 rounded-lg border border-red-900/60 bg-red-950/40 px-4 py-2.5 text-sm text-red-300"
				>
					{tokenError}
				</p>
			{/if}
		</section>

		<section class="mb-8 rounded-lg border border-slate-800 bg-slate-900/30 p-6">
			<h2 class="mb-4 text-sm font-semibold tracking-widest text-slate-500 uppercase">
				4. Finish up
			</h2>
			<p class="text-sm text-slate-400">
				Once the new server confirms your identity has moved, activate your account there. Then
				come back here and deactivate this one from the
				<a href="/account/danger-zone" class="text-emerald-500 hover:text-emerald-400"
					>danger zone →</a
				>
				— your repo stays intact in case anything needs to be re-checked, but the network will
				route to your new server.
			</p>
		</section>

		<section class="rounded-lg border border-slate-800 bg-slate-900/30 p-6">
			<h2 class="mb-4 text-sm font-semibold tracking-widest text-slate-500 uppercase">Tooling</h2>
			<p class="text-sm text-slate-400">
				Steps 1–3 involve calls to both servers (creating the account, importing the repo and
				blobs, and exchanging the signed operation) that aren't safe to automate from a page like
				this one, since the exact operation content depends on keys only the destination server
				has. Bluesky's
				<a
					href="https://github.com/bluesky-social/goat"
					target="_blank"
					rel="noopener noreferrer"
					class="text-emerald-500 hover:text-emerald-400">goat</a
				>
				command-line tool has a dedicated <code class="text-slate-300">account migrate</code> command
				that automates this entire sequence end to end and is the recommended way to actually run
				the migration.
			</p>
		</section>
	{/if}

	<p class="mt-8 text-center text-sm text-slate-500">
		<a href="/account" class="text-emerald-500 hover:text-emerald-400">← Account settings</a>
	</p>
</main>

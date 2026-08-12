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
	<title>Personal recovery key — MetalBear</title>
</svelte:head>

<main class="mx-auto max-w-2xl px-6 py-12">
	<h1 class="mb-2 text-2xl font-semibold text-white">Personal recovery key</h1>
	<p class="mb-8 text-sm text-slate-400">
		This server already holds a rotation key that co-signs every change to your identity (DID) —
		that's what makes normal account operations work. But it means recovering your identity if
		this server ever goes offline for good, or an operator acted against your interest, depends on
		this server's cooperation. Adding a rotation key that only <em>you</em> hold removes that dependency:
		with it, you can redirect your own identity to a new server without needing this one at all.
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
				1. Generate a keypair — offline, on your own device
			</h2>
			<p class="mb-3 text-sm text-slate-400">
				This has to happen somewhere this server (or any server) never sees the private half —
				that's the entire point. Bluesky's
				<a
					href="https://github.com/bluesky-social/goat"
					target="_blank"
					rel="noopener noreferrer"
					class="text-emerald-500 hover:text-emerald-400">goat</a
				>
				command-line tool can generate one:
			</p>
			<pre
				class="overflow-x-auto rounded-lg border border-slate-700 bg-slate-950 px-4 py-3 text-xs text-slate-300"><code>goat key generate</code></pre>
			<p class="mt-3 text-sm text-slate-400">
				It prints a <strong>secret key</strong> and a <strong>public key</strong>
				(<code class="text-slate-300">did:key:...</code>). Save the secret key somewhere durable and
				offline — a password manager entry, a printed copy in a safe place. There is no recovery
				for the recovery key: if you lose it, you're back to depending on this server, exactly
				where you started.
			</p>
		</section>

		<section class="mb-8 rounded-lg border border-slate-800 bg-slate-900/30 p-6">
			<h2 class="mb-4 text-sm font-semibold tracking-widest text-slate-500 uppercase">
				2. Get a signing token
			</h2>
			<p class="mb-4 text-sm text-slate-400">
				Adding a rotation key is still an identity change, so this server co-signs it the same way
				it does for a <a href="/account/migrate" class="text-emerald-500 hover:text-emerald-400"
					>migration</a
				> — a one-time token sent to your email.
			</p>
			{#if tokenSent}
				<p
					class="mb-4 rounded-lg border border-emerald-900/60 bg-emerald-950/40 px-4 py-2.5 text-sm text-emerald-300"
				>
					Check your email for the token, then use it in step 3.
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
				3. Register the public key
			</h2>
			<p class="mb-3 text-sm text-slate-400">
				With the token from your email and the <code class="text-slate-300">did:key:...</code> from
				step 1:
			</p>
			<pre
				class="overflow-x-auto rounded-lg border border-slate-700 bg-slate-950 px-4 py-3 text-xs text-slate-300"><code
					>goat account plc add-rotation-key --token &lt;TOKEN&gt; &lt;PUBLIC_KEY&gt;</code
				></pre>
			<p class="mt-3 text-sm text-slate-400">
				This adds your key alongside this server's — it doesn't remove or replace anything. Verify
				it landed with <code class="text-slate-300">goat account plc current</code>.
			</p>
		</section>

		<section class="rounded-lg border border-slate-800 bg-slate-900/30 p-6">
			<h2 class="mb-4 text-sm font-semibold tracking-widest text-slate-500 uppercase">
				Using it in an emergency
			</h2>
			<p class="text-sm text-slate-400">
				A recovery key only matters the day this server can't or won't cooperate — that's what it's
				for. David Buchanan's
				<a
					href="https://www.da.vidbuchanan.co.uk/blog/adversarial-pds-migration.html"
					target="_blank"
					rel="noopener noreferrer"
					class="text-emerald-500 hover:text-emerald-400">Adversarial ATProto PDS Migration</a
				>
				writeup covers exactly that process: moving to a new server and signing the identity change
				yourself, with your own key, when the old server isn't part of the conversation.
			</p>
		</section>
	{/if}

	<p class="mt-8 text-center text-sm text-slate-500">
		<a href="/account" class="text-emerald-500 hover:text-emerald-400">← Account settings</a>
	</p>
</main>

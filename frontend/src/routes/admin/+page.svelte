<script lang="ts">
	import { adminAuth } from '$lib/stores/adminAuth';
	import {
		adminLogin,
		adminGetAccountInfo,
		adminGetSubjectStatus,
		adminSetTakedown,
		adminSetDeactivated,
		adminSetAccountInvitesEnabled,
		adminGetInviteCodes,
		adminDisableInviteCodes,
		resolveHandle,
		listReposPage
	} from '$lib/pds';
	import type { AdminAccountView, SubjectStatus, AdminInviteCode, RepoInfo } from '$lib/pds';
	import { onMount } from 'svelte';

	let password = $state<string | null>(null);
	adminAuth.subscribe((p) => (password = p));

	/* ---- Login ---- */
	let loginPassword = $state('');
	let loginPending = $state(false);
	let loginError = $state('');

	async function handleLogin(e: Event) {
		e.preventDefault();
		loginError = '';
		loginPending = true;
		try {
			await adminLogin(loginPassword);
			loginPassword = '';
			await loadInviteCodes();
		} catch (err) {
			loginError = err instanceof Error ? err.message : 'Login failed';
		} finally {
			loginPending = false;
		}
	}

	function handleLogout() {
		adminAuth.logout();
		account = null;
		status = null;
		codes = [];
	}

	/* ---- Account lookup ---- */
	let lookupInput = $state('');
	let lookupPending = $state(false);
	let lookupError = $state('');
	let account = $state<AdminAccountView | null>(null);
	let status = $state<SubjectStatus | null>(null);
	let actionPending = $state(false);
	let actionError = $state('');

	async function handleLookup(e: Event) {
		e.preventDefault();
		lookupError = '';
		lookupPending = true;
		account = null;
		status = null;
		try {
			const did = lookupInput.startsWith('did:') ? lookupInput : await resolveHandle(lookupInput);
			const [info, subj] = await Promise.all([
				adminGetAccountInfo(did),
				adminGetSubjectStatus(did)
			]);
			account = info;
			status = subj;
		} catch (err) {
			lookupError = err instanceof Error ? err.message : 'Account not found';
		} finally {
			lookupPending = false;
		}
	}

	async function refreshLookup() {
		if (!account) return;
		const [info, subj] = await Promise.all([
			adminGetAccountInfo(account.did),
			adminGetSubjectStatus(account.did)
		]);
		account = info;
		status = subj;
	}

	async function handleTakedownToggle() {
		if (!account) return;
		actionError = '';
		actionPending = true;
		try {
			await adminSetTakedown(account.did, !status?.takedown?.applied);
			await refreshLookup();
		} catch (err) {
			actionError = err instanceof Error ? err.message : 'Action failed';
		} finally {
			actionPending = false;
		}
	}

	async function handleDeactivateToggle() {
		if (!account) return;
		actionError = '';
		actionPending = true;
		try {
			await adminSetDeactivated(account.did, !status?.deactivated?.applied);
			await refreshLookup();
		} catch (err) {
			actionError = err instanceof Error ? err.message : 'Action failed';
		} finally {
			actionPending = false;
		}
	}

	async function handleInvitesToggle() {
		if (!account) return;
		actionError = '';
		actionPending = true;
		try {
			await adminSetAccountInvitesEnabled(account.did, !!account.invitesDisabled);
			await refreshLookup();
		} catch (err) {
			actionError = err instanceof Error ? err.message : 'Action failed';
		} finally {
			actionPending = false;
		}
	}

	/* ---- Invite codes ---- */
	let codes = $state<AdminInviteCode[]>([]);
	let codesCursor = $state<string | undefined>(undefined);
	let codesLoading = $state(false);
	let codesError = $state('');
	let disablingCode = $state<string | null>(null);

	async function loadInviteCodes(cursor?: string) {
		codesLoading = true;
		codesError = '';
		try {
			const result = await adminGetInviteCodes(cursor);
			codes = cursor ? [...codes, ...result.codes] : result.codes;
			codesCursor = result.cursor;
		} catch (err) {
			codesError = err instanceof Error ? err.message : 'Failed to load invite codes';
		} finally {
			codesLoading = false;
		}
	}

	async function handleDisableCode(code: string) {
		disablingCode = code;
		try {
			await adminDisableInviteCodes([code]);
			await loadInviteCodes();
		} catch (err) {
			codesError = err instanceof Error ? err.message : 'Failed to disable code';
		} finally {
			disablingCode = null;
		}
	}

	/* ---- Accounts (browse) ---- */
	let repos = $state<RepoInfo[]>([]);
	let reposCursor = $state<string | undefined>(undefined);
	let reposLoading = $state(false);
	let reposError = $state('');
	let reposLoaded = $state(false);

	async function loadRepos(cursor?: string) {
		reposLoading = true;
		reposError = '';
		try {
			const result = await listReposPage(cursor);
			repos = cursor ? [...repos, ...result.repos] : result.repos;
			reposCursor = result.cursor;
			reposLoaded = true;
		} catch (err) {
			reposError = err instanceof Error ? err.message : 'Failed to load accounts';
		} finally {
			reposLoading = false;
		}
	}

	function handleBrowseLookup(did: string) {
		lookupInput = did;
		handleLookup(new Event('submit'));
		window.scrollTo({ top: 0, behavior: 'smooth' });
	}

	onMount(() => {
		if (password) loadInviteCodes();
	});
</script>

<svelte:head>
	<title>Admin — MetalBear</title>
</svelte:head>

<main class="mx-auto max-w-3xl px-6 py-12">
	<div class="mb-8 flex items-center justify-between">
		<h1 class="text-2xl font-semibold text-white">Admin</h1>
		{#if password}
			<button onclick={handleLogout} class="text-sm text-slate-500 hover:text-slate-300">
				Sign out
			</button>
		{/if}
	</div>

	{#if !password}
		<section class="mx-auto max-w-sm rounded-lg border border-slate-800 bg-slate-900/30 p-6">
			<h2 class="mb-4 text-sm font-semibold tracking-widest text-slate-500 uppercase">
				Admin sign in
			</h2>
			<form onsubmit={handleLogin} class="flex flex-col gap-4">
				<input
					type="password"
					bind:value={loginPassword}
					placeholder="Admin password"
					required
					autocomplete="current-password"
					class="w-full rounded-lg border border-slate-700 bg-slate-900 px-4 py-2.5 text-sm text-white placeholder-slate-500 outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
				/>
				{#if loginError}
					<p
						class="rounded-lg border border-red-900/60 bg-red-950/40 px-4 py-2.5 text-sm text-red-300"
					>
						{loginError}
					</p>
				{/if}
				<button
					type="submit"
					disabled={loginPending || !loginPassword}
					class="rounded-lg bg-emerald-600 px-4 py-2.5 text-sm font-medium text-white transition hover:bg-emerald-500 disabled:cursor-not-allowed disabled:opacity-50"
				>
					{loginPending ? 'Signing in…' : 'Sign in'}
				</button>
			</form>
		</section>
	{:else}
		<!-- Account lookup -->
		<section class="mb-8 rounded-lg border border-slate-800 bg-slate-900/30 p-6">
			<h2 class="mb-4 text-sm font-semibold tracking-widest text-slate-500 uppercase">
				Account lookup
			</h2>
			<form onsubmit={handleLookup} class="flex gap-3">
				<input
					type="text"
					bind:value={lookupInput}
					placeholder="did:plc:… or handle"
					required
					class="flex-1 rounded-lg border border-slate-700 bg-slate-900 px-4 py-2 text-sm text-white placeholder-slate-500 outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
				/>
				<button
					type="submit"
					disabled={lookupPending || !lookupInput}
					class="shrink-0 rounded-lg bg-emerald-600 px-4 py-2 text-sm font-medium text-white transition hover:bg-emerald-500 disabled:cursor-not-allowed disabled:opacity-50"
				>
					{lookupPending ? 'Looking up…' : 'Look up'}
				</button>
			</form>

			{#if lookupError}
				<p
					class="mt-4 rounded-lg border border-red-900/60 bg-red-950/40 px-4 py-2.5 text-sm text-red-300"
				>
					{lookupError}
				</p>
			{/if}

			{#if account}
				<div class="mt-6 border-t border-slate-800 pt-6">
					<dl class="mb-4 grid gap-x-8 gap-y-3 sm:grid-cols-2">
						<div>
							<dt class="text-sm text-slate-500">Handle</dt>
							<dd class="font-mono text-sm text-slate-200">{account.handle}</dd>
						</div>
						<div>
							<dt class="text-sm text-slate-500">DID</dt>
							<dd class="font-mono text-sm break-all text-slate-200">{account.did}</dd>
						</div>
						{#if account.email}
							<div>
								<dt class="text-sm text-slate-500">Email</dt>
								<dd class="text-sm text-slate-200">{account.email}</dd>
							</div>
						{/if}
						<div>
							<dt class="text-sm text-slate-500">Indexed</dt>
							<dd class="text-sm text-slate-200">{account.indexedAt}</dd>
						</div>
					</dl>

					<div class="flex flex-wrap gap-2">
						<button
							onclick={handleTakedownToggle}
							disabled={actionPending}
							class="rounded-lg border px-3 py-1.5 text-sm transition disabled:opacity-50 {status
								?.takedown?.applied
								? 'border-red-700/60 text-red-300 hover:border-red-600'
								: 'border-slate-700 text-slate-300 hover:border-slate-600 hover:text-white'}"
						>
							{status?.takedown?.applied ? 'Remove takedown' : 'Take down'}
						</button>
						<button
							onclick={handleDeactivateToggle}
							disabled={actionPending}
							class="rounded-lg border px-3 py-1.5 text-sm transition disabled:opacity-50 {status
								?.deactivated?.applied
								? 'border-amber-700/60 text-amber-300 hover:border-amber-600'
								: 'border-slate-700 text-slate-300 hover:border-slate-600 hover:text-white'}"
						>
							{status?.deactivated?.applied ? 'Reactivate' : 'Deactivate'}
						</button>
						<button
							onclick={handleInvitesToggle}
							disabled={actionPending}
							class="rounded-lg border border-slate-700 px-3 py-1.5 text-sm text-slate-300 transition hover:border-slate-600 hover:text-white disabled:opacity-50"
						>
							{account.invitesDisabled ? 'Enable invites' : 'Disable invites'}
						</button>
					</div>

					{#if actionError}
						<p
							class="mt-4 rounded-lg border border-red-900/60 bg-red-950/40 px-4 py-2.5 text-sm text-red-300"
						>
							{actionError}
						</p>
					{/if}
				</div>
			{/if}
		</section>

		<!-- Accounts (browse) -->
		<section class="mb-8 rounded-lg border border-slate-800 bg-slate-900/30 p-6">
			<h2 class="mb-4 text-sm font-semibold tracking-widest text-slate-500 uppercase">
				Accounts
			</h2>

			{#if reposError}
				<p
					class="mb-4 rounded-lg border border-red-900/60 bg-red-950/40 px-4 py-2.5 text-sm text-red-300"
				>
					{reposError}
				</p>
			{/if}

			{#if !reposLoaded}
				<button
					onclick={() => loadRepos()}
					disabled={reposLoading}
					class="rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-300 transition hover:border-slate-600 hover:text-white disabled:opacity-50"
				>
					{reposLoading ? 'Loading…' : 'Browse accounts'}
				</button>
			{:else if repos.length === 0}
				<p class="text-sm text-slate-500">No accounts hosted.</p>
			{:else}
				<ul class="divide-y divide-slate-800">
					{#each repos as r (r.did)}
						<li class="flex items-center justify-between gap-4 py-3">
							<div class="min-w-0">
								<code class="text-sm break-all text-slate-200">{r.did}</code>
								<div class="mt-0.5 flex items-center gap-2 text-xs text-slate-500">
									<span>{r.active ? 'active' : (r.status ?? 'inactive')}</span>
								</div>
							</div>
							<button
								onclick={() => handleBrowseLookup(r.did)}
								class="shrink-0 text-sm text-emerald-500 hover:text-emerald-400"
							>
								Look up →
							</button>
						</li>
					{/each}
				</ul>

				{#if reposCursor}
					<button
						onclick={() => loadRepos(reposCursor)}
						disabled={reposLoading}
						class="mt-4 rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-300 transition hover:border-slate-600 hover:text-white disabled:opacity-50"
					>
						{reposLoading ? 'Loading…' : 'Load more'}
					</button>
				{/if}
			{/if}
		</section>

		<!-- Invite codes -->
		<section class="rounded-lg border border-slate-800 bg-slate-900/30 p-6">
			<h2 class="mb-4 text-sm font-semibold tracking-widest text-slate-500 uppercase">
				Invite codes
			</h2>

			{#if codesError}
				<p
					class="mb-4 rounded-lg border border-red-900/60 bg-red-950/40 px-4 py-2.5 text-sm text-red-300"
				>
					{codesError}
				</p>
			{/if}

			{#if codesLoading && codes.length === 0}
				<p class="text-sm text-slate-400">Loading…</p>
			{:else if codes.length === 0}
				<p class="text-sm text-slate-500">No invite codes.</p>
			{:else}
				<ul class="divide-y divide-slate-800">
					{#each codes as c (c.code)}
						<li class="flex items-center justify-between gap-4 py-3">
							<div>
								<code class="text-sm text-slate-200">{c.code}</code>
								<div class="mt-0.5 flex items-center gap-2 text-xs text-slate-500">
									<span>{c.uses.length}/{c.available < 0 ? '∞' : c.available} used</span>
									<span>·</span>
									<span>for {c.forAccount}</span>
									{#if c.disabled}
										<span class="rounded-full border border-slate-700 px-2 py-0.5 text-slate-400"
											>disabled</span
										>
									{/if}
								</div>
							</div>
							{#if !c.disabled}
								<button
									onclick={() => handleDisableCode(c.code)}
									disabled={disablingCode === c.code}
									class="shrink-0 text-sm text-red-400 hover:text-red-300 disabled:opacity-50"
								>
									{disablingCode === c.code ? 'Disabling…' : 'Disable'}
								</button>
							{/if}
						</li>
					{/each}
				</ul>

				{#if codesCursor}
					<button
						onclick={() => loadInviteCodes(codesCursor)}
						disabled={codesLoading}
						class="mt-4 rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-300 transition hover:border-slate-600 hover:text-white disabled:opacity-50"
					>
						{codesLoading ? 'Loading…' : 'Load more'}
					</button>
				{/if}
			{/if}
		</section>
	{/if}
</main>

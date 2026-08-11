<script lang="ts">
	import { auth } from '$lib/stores/auth';
	import {
		getSession,
		requestPasswordReset,
		resetPassword,
		requestEmailUpdate,
		updateEmail,
		requestEmailConfirmation,
		confirmEmail,
		updateHandle
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

	/* ---- Password ---- */
	let pwStep = $state<'idle' | 'sent'>('idle');
	let pwToken = $state('');
	let pwNew = $state('');
	let pwPending = $state(false);
	let pwError = $state('');
	let pwDone = $state(false);

	async function requestPasswordChange() {
		if (!current?.email) return;
		pwError = '';
		pwPending = true;
		try {
			await requestPasswordReset(current.email);
			pwStep = 'sent';
		} catch (err) {
			pwError = err instanceof Error ? err.message : 'Failed to send reset code';
		} finally {
			pwPending = false;
		}
	}

	async function confirmPasswordChange(e: Event) {
		e.preventDefault();
		pwError = '';
		pwPending = true;
		try {
			await resetPassword(pwToken, pwNew);
			pwDone = true;
			pwStep = 'idle';
			pwToken = '';
			pwNew = '';
		} catch (err) {
			pwError = err instanceof Error ? err.message : 'Failed to change password';
		} finally {
			pwPending = false;
		}
	}

	/* ---- Email ---- */
	let emailStep = $state<'idle' | 'sent'>('idle');
	let emailNew = $state('');
	let emailToken = $state('');
	let emailPending = $state(false);
	let emailError = $state('');
	let emailDone = $state(false);

	/* updateEmail only requires a token when the CURRENT address is already
	 * confirmed (see updateEmail's comment in pds.ts) -- an unconfirmed
	 * current address can be replaced directly with no code at all. */
	async function requestEmailChange() {
		if (!current?.emailConfirmed) return;
		emailError = '';
		emailPending = true;
		try {
			await requestEmailUpdate();
			emailStep = 'sent';
		} catch (err) {
			emailError = err instanceof Error ? err.message : 'Failed to send update code';
		} finally {
			emailPending = false;
		}
	}

	async function submitEmailChange(e: Event) {
		e.preventDefault();
		emailError = '';
		emailPending = true;
		try {
			await updateEmail(emailNew, current?.emailConfirmed ? emailToken : undefined);
			current = await getSession();
			emailDone = true;
			emailStep = 'idle';
			emailNew = '';
			emailToken = '';
		} catch (err) {
			emailError = err instanceof Error ? err.message : 'Failed to update email';
		} finally {
			emailPending = false;
		}
	}

	/* ---- Email verification (confirming the CURRENT address) ---- */
	let verifyStep = $state<'idle' | 'sent'>('idle');
	let verifyToken = $state('');
	let verifyPending = $state(false);
	let verifyError = $state('');

	async function requestVerification() {
		verifyError = '';
		verifyPending = true;
		try {
			await requestEmailConfirmation();
			verifyStep = 'sent';
		} catch (err) {
			verifyError = err instanceof Error ? err.message : 'Failed to send verification code';
		} finally {
			verifyPending = false;
		}
	}

	async function submitVerification(e: Event) {
		e.preventDefault();
		if (!current?.email) return;
		verifyError = '';
		verifyPending = true;
		try {
			await confirmEmail(current.email, verifyToken);
			current = await getSession();
			verifyStep = 'idle';
			verifyToken = '';
		} catch (err) {
			verifyError = err instanceof Error ? err.message : 'Failed to verify email';
		} finally {
			verifyPending = false;
		}
	}

	/* ---- Handle ---- */
	let handleNew = $state('');
	let handlePending = $state(false);
	let handleError = $state('');
	let handleDone = $state(false);

	async function submitHandleChange(e: Event) {
		e.preventDefault();
		handleError = '';
		handlePending = true;
		try {
			await updateHandle(handleNew);
			current = await getSession();
			auth.refresh({
				accessJwt: current.accessJwt,
				refreshJwt: current.refreshJwt,
				handle: current.handle,
				did: current.did,
				email: current.email,
				emailConfirmed: current.emailConfirmed,
				emailAuthFactor: current.emailAuthFactor,
				active: current.active,
				status: current.status,
				didDoc: current.didDoc
			});
			handleDone = true;
			handleNew = '';
		} catch (err) {
			handleError = err instanceof Error ? err.message : 'Failed to update handle';
		} finally {
			handlePending = false;
		}
	}
</script>

<svelte:head>
	<title>Security — MetalBear</title>
</svelte:head>

<main class="mx-auto max-w-2xl px-6 py-12">
	<h1 class="mb-8 text-2xl font-semibold text-white">Security</h1>

	{#if loading}
		<p class="text-sm text-slate-400">Loading…</p>
	{:else if loadError}
		<p class="rounded-lg border border-red-900/60 bg-red-950/40 px-4 py-3 text-sm text-red-300">
			{loadError}
		</p>
	{:else if current}
		<!-- Password -->
		<section class="mb-8 rounded-lg border border-slate-800 bg-slate-900/30 p-6">
			<h2 class="mb-1 text-sm font-semibold tracking-widest text-slate-500 uppercase">Password</h2>
			<p class="mb-4 text-sm text-slate-400">
				{#if current.email}
					We'll email a code to <span class="text-slate-300">{current.email}</span> to confirm the change.
				{:else}
					Add an email address before you can change your password from here.
				{/if}
			</p>

			{#if pwDone}
				<p
					class="mb-4 rounded-lg border border-emerald-900/60 bg-emerald-950/40 px-4 py-2.5 text-sm text-emerald-300"
				>
					Password changed.
				</p>
			{/if}

			{#if pwStep === 'idle'}
				<button
					onclick={requestPasswordChange}
					disabled={pwPending || !current.email}
					class="rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-300 transition hover:border-slate-600 hover:text-white disabled:cursor-not-allowed disabled:opacity-50"
				>
					{pwPending ? 'Sending…' : 'Change password'}
				</button>
			{:else}
				<form onsubmit={confirmPasswordChange} class="flex flex-col gap-4">
					<div class="flex flex-col gap-4 sm:flex-row">
						<input
							type="text"
							bind:value={pwToken}
							placeholder="Code"
							required
							autocomplete="one-time-code"
							class="flex-1 rounded-lg border border-slate-700 bg-slate-900 px-4 py-2 text-sm text-white placeholder-slate-500 outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
						/>
						<input
							type="password"
							bind:value={pwNew}
							placeholder="New password"
							required
							autocomplete="new-password"
							class="flex-1 rounded-lg border border-slate-700 bg-slate-900 px-4 py-2 text-sm text-white placeholder-slate-500 outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
						/>
					</div>
					<div class="flex items-center gap-3">
						<button
							type="submit"
							disabled={pwPending || !pwToken || !pwNew}
							class="rounded-lg bg-emerald-600 px-4 py-2 text-sm font-medium text-white transition hover:bg-emerald-500 disabled:cursor-not-allowed disabled:opacity-50"
						>
							{pwPending ? 'Changing…' : 'Confirm'}
						</button>
						<button
							type="button"
							onclick={() => (pwStep = 'idle')}
							class="text-sm text-slate-500 hover:text-slate-300"
						>
							Cancel
						</button>
					</div>
				</form>
			{/if}

			{#if pwError}
				<p
					class="mt-4 rounded-lg border border-red-900/60 bg-red-950/40 px-4 py-2.5 text-sm text-red-300"
				>
					{pwError}
				</p>
			{/if}
		</section>

		<!-- Email -->
		<section class="mb-8 rounded-lg border border-slate-800 bg-slate-900/30 p-6">
			<h2 class="mb-1 text-sm font-semibold tracking-widest text-slate-500 uppercase">Email</h2>
			<p class="mb-4 text-sm text-slate-400">
				Current: <span class="text-slate-300">{current.email ?? 'none on file'}</span>
				{#if current.email}
					{#if current.emailConfirmed}
						<span class="ml-2 text-xs text-emerald-400">confirmed</span>
					{:else}
						<span class="ml-2 text-xs text-amber-400">unconfirmed</span>
					{/if}
				{/if}
			</p>

			{#if current.email && !current.emailConfirmed}
				<div class="mb-6 border-b border-slate-800 pb-6">
					<p class="mb-3 text-sm text-slate-400">Verify your current address.</p>
					{#if verifyStep === 'idle'}
						<button
							onclick={requestVerification}
							disabled={verifyPending}
							class="rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-300 transition hover:border-slate-600 hover:text-white disabled:opacity-50"
						>
							{verifyPending ? 'Sending…' : 'Send verification code'}
						</button>
					{:else}
						<form onsubmit={submitVerification} class="flex gap-3">
							<input
								type="text"
								bind:value={verifyToken}
								placeholder="Code"
								required
								autocomplete="one-time-code"
								class="flex-1 rounded-lg border border-slate-700 bg-slate-900 px-4 py-2 text-sm text-white placeholder-slate-500 outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
							/>
							<button
								type="submit"
								disabled={verifyPending || !verifyToken}
								class="rounded-lg bg-emerald-600 px-4 py-2 text-sm font-medium text-white transition hover:bg-emerald-500 disabled:opacity-50"
							>
								Verify
							</button>
						</form>
					{/if}
					{#if verifyError}
						<p
							class="mt-3 rounded-lg border border-red-900/60 bg-red-950/40 px-4 py-2.5 text-sm text-red-300"
						>
							{verifyError}
						</p>
					{/if}
				</div>
			{/if}

			{#if emailDone}
				<p
					class="mb-4 rounded-lg border border-emerald-900/60 bg-emerald-950/40 px-4 py-2.5 text-sm text-emerald-300"
				>
					Email updated.
				</p>
			{/if}

			<p class="mb-3 text-sm text-slate-400">Change your address.</p>
			{#if current.emailConfirmed && emailStep === 'idle'}
				<button
					onclick={requestEmailChange}
					disabled={emailPending}
					class="rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-300 transition hover:border-slate-600 hover:text-white disabled:opacity-50"
				>
					{emailPending ? 'Sending…' : 'Change email'}
				</button>
			{:else}
				<form onsubmit={submitEmailChange} class="flex flex-col gap-4">
					<div class="flex flex-col gap-4 sm:flex-row">
						<input
							type="email"
							bind:value={emailNew}
							placeholder="new@example.com"
							required
							autocomplete="email"
							class="flex-1 rounded-lg border border-slate-700 bg-slate-900 px-4 py-2 text-sm text-white placeholder-slate-500 outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
						/>
						{#if current.emailConfirmed}
							<input
								type="text"
								bind:value={emailToken}
								placeholder="Code sent to current address"
								required
								autocomplete="one-time-code"
								class="flex-1 rounded-lg border border-slate-700 bg-slate-900 px-4 py-2 text-sm text-white placeholder-slate-500 outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
							/>
						{/if}
					</div>
					<div class="flex items-center gap-3">
						<button
							type="submit"
							disabled={emailPending || !emailNew || (current.emailConfirmed && !emailToken)}
							class="rounded-lg bg-emerald-600 px-4 py-2 text-sm font-medium text-white transition hover:bg-emerald-500 disabled:cursor-not-allowed disabled:opacity-50"
						>
							{emailPending ? 'Updating…' : 'Save email'}
						</button>
						{#if current.emailConfirmed}
							<button
								type="button"
								onclick={() => (emailStep = 'idle')}
								class="text-sm text-slate-500 hover:text-slate-300"
							>
								Cancel
							</button>
						{/if}
					</div>
				</form>
			{/if}

			{#if emailError}
				<p
					class="mt-4 rounded-lg border border-red-900/60 bg-red-950/40 px-4 py-2.5 text-sm text-red-300"
				>
					{emailError}
				</p>
			{/if}
		</section>

		<!-- Handle -->
		<section class="mb-8 rounded-lg border border-slate-800 bg-slate-900/30 p-6">
			<h2 class="mb-1 text-sm font-semibold tracking-widest text-slate-500 uppercase">Handle</h2>
			<p class="mb-4 text-sm text-slate-400">
				Current: <span class="font-mono text-slate-300">{current.handle}</span>
			</p>

			{#if handleDone}
				<p
					class="mb-4 rounded-lg border border-emerald-900/60 bg-emerald-950/40 px-4 py-2.5 text-sm text-emerald-300"
				>
					Handle updated.
				</p>
			{/if}

			<form onsubmit={submitHandleChange} class="flex flex-col gap-4 sm:flex-row sm:items-start">
				<input
					type="text"
					bind:value={handleNew}
					placeholder="newhandle.example.com"
					required
					class="flex-1 rounded-lg border border-slate-700 bg-slate-900 px-4 py-2 text-sm text-white placeholder-slate-500 outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
				/>
				<button
					type="submit"
					disabled={handlePending || !handleNew}
					class="shrink-0 rounded-lg bg-emerald-600 px-4 py-2 text-sm font-medium text-white transition hover:bg-emerald-500 disabled:cursor-not-allowed disabled:opacity-50"
				>
					{handlePending ? 'Updating…' : 'Change handle'}
				</button>
			</form>

			{#if handleError}
				<p
					class="mt-4 rounded-lg border border-red-900/60 bg-red-950/40 px-4 py-2.5 text-sm text-red-300"
				>
					{handleError}
				</p>
			{/if}
		</section>
	{/if}

	<p class="mt-8 text-center text-sm text-slate-500">
		<a href="/account" class="text-emerald-500 hover:text-emerald-400">← Account settings</a>
	</p>
</main>

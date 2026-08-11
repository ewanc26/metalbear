<script lang="ts">
	import { requestPasswordReset, resetPassword } from '$lib/pds';
	import AuthShell from '$lib/components/AuthShell.svelte';

	type Step = 'request' | 'confirm' | 'done';

	let step = $state<Step>('request');
	let email = $state('');
	let token = $state('');
	let password = $state('');
	let showPassword = $state(false);
	let error = $state('');
	let loading = $state(false);

	async function handleRequest(e: Event) {
		e.preventDefault();
		error = '';
		loading = true;
		try {
			await requestPasswordReset(email);
			/* The server always reports success here to avoid leaking which
			 * addresses have accounts -- see request_password_reset's comment
			 * in account_routes.c. There is deliberately no "email not found"
			 * branch to show. */
			step = 'confirm';
		} catch (err) {
			error = err instanceof Error ? err.message : 'Failed to request a reset code';
		} finally {
			loading = false;
		}
	}

	async function handleConfirm(e: Event) {
		e.preventDefault();
		error = '';
		loading = true;
		try {
			await resetPassword(token, password);
			step = 'done';
		} catch (err) {
			error = err instanceof Error ? err.message : 'Failed to reset password';
		} finally {
			loading = false;
		}
	}
</script>

<AuthShell
	title="Reset password"
	subtitle={step === 'request'
		? "Enter your account's email and we'll send a reset code."
		: step === 'confirm'
			? `Enter the code sent to ${email} and choose a new password.`
			: undefined}
>
	{#if step === 'request'}
		<form onsubmit={handleRequest} class="flex flex-col gap-5">
			<div>
				<label for="email" class="mb-1.5 block text-sm font-medium text-slate-300">Email</label>
				<input
					id="email"
					type="email"
					bind:value={email}
					placeholder="you@example.com"
					required
					autocomplete="email"
					class="w-full rounded-lg border border-slate-700 bg-slate-900 px-4 py-2.5 text-sm text-white placeholder-slate-500 outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
				/>
			</div>

			{#if error}
				<p
					class="rounded-lg border border-red-900/60 bg-red-950/40 px-4 py-2.5 text-sm text-red-300"
				>
					{error}
				</p>
			{/if}

			<button
				type="submit"
				disabled={loading || !email}
				class="mt-2 rounded-lg bg-emerald-600 px-4 py-2.5 text-sm font-medium text-white transition hover:bg-emerald-500 disabled:cursor-not-allowed disabled:opacity-50"
			>
				{loading ? 'Sending…' : 'Send reset code'}
			</button>
		</form>
	{:else if step === 'confirm'}
		<form onsubmit={handleConfirm} class="flex flex-col gap-5">
			<div>
				<label for="token" class="mb-1.5 block text-sm font-medium text-slate-300">Reset code</label
				>
				<input
					id="token"
					type="text"
					bind:value={token}
					placeholder="XXXXX-XXXXX"
					required
					autocomplete="one-time-code"
					class="w-full rounded-lg border border-slate-700 bg-slate-900 px-4 py-2.5 text-sm text-white placeholder-slate-500 outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
				/>
			</div>

			<div>
				<label for="password" class="mb-1.5 block text-sm font-medium text-slate-300"
					>New password</label
				>
				<div class="relative">
					<input
						id="password"
						type={showPassword ? 'text' : 'password'}
						bind:value={password}
						required
						autocomplete="new-password"
						class="w-full rounded-lg border border-slate-700 bg-slate-900 px-4 py-2.5 pr-10 text-sm text-white placeholder-slate-500 outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
					/>
					<button
						type="button"
						onclick={() => (showPassword = !showPassword)}
						class="absolute top-1/2 right-3 -translate-y-1/2 text-xs text-slate-500 hover:text-slate-300"
					>
						{showPassword ? 'Hide' : 'Show'}
					</button>
				</div>
			</div>

			{#if error}
				<p
					class="rounded-lg border border-red-900/60 bg-red-950/40 px-4 py-2.5 text-sm text-red-300"
				>
					{error}
				</p>
			{/if}

			<button
				type="submit"
				disabled={loading || !token || !password}
				class="mt-2 rounded-lg bg-emerald-600 px-4 py-2.5 text-sm font-medium text-white transition hover:bg-emerald-500 disabled:cursor-not-allowed disabled:opacity-50"
			>
				{loading ? 'Resetting…' : 'Reset password'}
			</button>

			<button
				type="button"
				onclick={() => (step = 'request')}
				class="text-center text-sm text-slate-500 hover:text-slate-300"
			>
				Didn't get a code? Send again
			</button>
		</form>
	{:else}
		<div class="flex flex-col items-center gap-4 text-center">
			<p class="text-sm text-emerald-300">
				Password reset. You can now sign in with your new password.
			</p>
			<a
				href="/login"
				class="rounded-lg bg-emerald-600 px-4 py-2.5 text-sm font-medium text-white transition hover:bg-emerald-500"
			>
				Sign in
			</a>
		</div>
	{/if}

	<p class="mt-4 text-center text-sm text-slate-500">
		<a href="/login" class="text-emerald-500 hover:text-emerald-400">← Back to sign in</a>
	</p>
</AuthShell>

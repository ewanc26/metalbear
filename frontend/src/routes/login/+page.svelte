<script lang="ts">
	import { auth } from '$lib/stores/auth';
	import { createSession, signInDevice } from '$lib/pds';
	import { goto } from '$app/navigation';
	import { page } from '$app/stores';
	import { onMount } from 'svelte';
	import AuthShell from '$lib/components/AuthShell.svelte';

	let identifier = $state('');
	let password = $state('');
	let error = $state('');
	let loading = $state(false);
	let showPassword = $state(false);

	let redirectTo = $state('');

	onMount(() => {
		redirectTo = $page.url.searchParams.get('redirect') ?? '/';

		const unsub = auth.subscribe((s) => {
			if (s) goto(redirectTo, { replaceState: true });
		});
		return unsub;
	});

	function isOauthRedirect(target: string): boolean {
		return target.startsWith('/oauth/consent');
	}

	async function handleSubmit(e: Event) {
		e.preventDefault();
		error = '';
		loading = true;
		try {
			const [session] = await Promise.all([
				createSession(identifier, password),
				isOauthRedirect(redirectTo) ? signInDevice(identifier, password) : Promise.resolve()
			]);
			auth.login({
				accessJwt: session.accessJwt,
				refreshJwt: session.refreshJwt,
				handle: session.handle,
				did: session.did,
				email: session.email,
				emailConfirmed: session.emailConfirmed,
				emailAuthFactor: session.emailAuthFactor,
				active: session.active,
				status: session.status,
				didDoc: session.didDoc
			});
			goto(redirectTo);
		} catch (err) {
			error = err instanceof Error ? err.message : 'Login failed';
		} finally {
			loading = false;
		}
	}
</script>

<svelte:head>
	<title>Sign in — MetalBear</title>
</svelte:head>

<AuthShell
	title="Sign in"
	subtitle="Use your account handle or email and an app password to sign in."
>
	<form onsubmit={handleSubmit} class="flex flex-col gap-5">
		<div>
			<label for="identifier" class="mb-1.5 block text-sm font-medium text-slate-300"
				>Handle or email</label
			>
			<input
				id="identifier"
				type="text"
				bind:value={identifier}
				placeholder="alice.bsky.social"
				required
				autocomplete="username"
				class="w-full rounded-lg border border-slate-700 bg-slate-900 px-4 py-2.5 text-sm text-white placeholder-slate-500 outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
			/>
		</div>

		<div>
			<label for="password" class="mb-1.5 block text-sm font-medium text-slate-300">Password</label>
			<div class="relative">
				<input
					id="password"
					type={showPassword ? 'text' : 'password'}
					bind:value={password}
					placeholder="App password"
					required
					autocomplete="current-password"
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
			<p class="rounded-lg border border-red-900/60 bg-red-950/40 px-4 py-2.5 text-sm text-red-300">
				{error}
			</p>
		{/if}

		<button
			type="submit"
			disabled={loading || !identifier || !password}
			class="mt-2 rounded-lg bg-emerald-600 px-4 py-2.5 text-sm font-medium text-white transition hover:bg-emerald-500 disabled:cursor-not-allowed disabled:opacity-50"
		>
			{loading ? 'Signing in…' : 'Sign in'}
		</button>
	</form>

	<p class="mt-4 text-center text-sm text-slate-500">
		<a href="/" class="text-emerald-500 hover:text-emerald-400">← Back to status</a>
	</p>
</AuthShell>

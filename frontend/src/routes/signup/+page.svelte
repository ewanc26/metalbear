<script lang="ts">
	import { goto } from '$app/navigation';
	import { resolve } from '$app/paths';
	import { onMount } from 'svelte';
	import AuthShell from '#lib/components/AuthShell.svelte';
	import { auth } from '#lib/stores/auth.ts';
	import {
		XrpcError,
		checkHandleAvailability,
		createAccount,
		describeServer,
		operatorInfo,
		requestEmailConfirmation,
		resolveHandle,
		signInDevice,
		type OperatorInfo,
		type RegistrationMode,
		type ServerInfo
	} from '#lib/pds.ts';

	type HandleState = 'idle' | 'checking' | 'available' | 'taken' | 'unknown';

	let server = $state<ServerInfo | null>(null);
	let info = $state<OperatorInfo | null>(null);
	let loadingInfo = $state(true);
	let infoError = $state('');

	let label = $state('');
	let domain = $state('');
	let email = $state('');
	let password = $state('');
	let inviteCode = $state('');
	let showPassword = $state(false);

	let handleState = $state<HandleState>('idle');
	let handleMessage = $state('');
	let suggestions = $state<string[]>([]);

	let submitting = $state(false);
	let error = $state('');

	let checkTimer: ReturnType<typeof setTimeout> | undefined;
	let checkToken = 0;

	const mode = $derived<RegistrationMode>(
		info?.registration?.mode ?? (server?.inviteCodeRequired ? 'invite' : 'open')
	);
	const inviteRequired = $derived(mode === 'invite' || server?.inviteCodeRequired === true);
	const fullHandle = $derived(`${label}${domain}`);

	onMount(() => {
		Promise.all([describeServer(), operatorInfo()])
			.then(([s, o]) => {
				server = s;
				info = o;
				domain = s.availableUserDomains[0] ?? '';
				if (!domain) infoError = 'This server has no user domain available for signup.';
			})
			.catch((err: unknown) => {
				infoError = err instanceof Error ? err.message : 'Could not load signup settings';
			})
			.finally(() => {
				loadingInfo = false;
			});
		return () => {
			if (checkTimer) clearTimeout(checkTimer);
		};
	});

	function validLabel(value: string): boolean {
		return (
			value.length >= 3 &&
			value.length <= 18 &&
			/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,16}[A-Za-z0-9])?$/.test(value)
		);
	}

	/* Both checks are needed: checkHandleAvailability knows MetalBear's exact
	 * host-label, reservation and local-registry rules and offers suggestions;
	 * resolveHandle catches a handle already claimed elsewhere. A token drops
	 * stale replies as the user keeps typing. */
	async function checkHandle(handle: string, token: number): Promise<void> {
		try {
			const local = await checkHandleAvailability(handle, email || undefined);
			if (token !== checkToken) return;
			if (!local.available) {
				handleState = 'taken';
				handleMessage = 'That handle is not available on this server.';
				suggestions = local.suggestions.slice(0, 3).map((s) => s.handle);
				return;
			}
			try {
				await resolveHandle(handle);
				if (token !== checkToken) return;
				handleState = 'taken';
				handleMessage = 'That handle is already in use.';
				suggestions = [];
			} catch (err) {
				if (token !== checkToken) return;
				if (err instanceof XrpcError && err.code === 'HandleNotFound') {
					handleState = 'available';
					handleMessage = 'Available';
					suggestions = [];
				} else {
					handleState = 'unknown';
					handleMessage = 'Could not check this handle. You can still try signing up.';
					suggestions = [];
				}
			}
		} catch (err) {
			if (token !== checkToken) return;
			handleState = 'unknown';
			handleMessage = err instanceof Error ? err.message : 'Could not check this handle.';
			suggestions = [];
		}
	}

	function scheduleHandleCheck(): void {
		checkToken++;
		if (checkTimer) clearTimeout(checkTimer);
		handleState = 'idle';
		handleMessage = '';
		suggestions = [];
		if (!domain || !validLabel(label)) return;
		handleState = 'checking';
		const token = checkToken;
		const handle = fullHandle;
		checkTimer = setTimeout(() => void checkHandle(handle, token), 300);
	}

	function useSuggestion(handle: string): void {
		if (domain && handle.endsWith(domain)) label = handle.slice(0, -domain.length);
		else label = handle;
		scheduleHandleCheck();
	}

	function signupError(err: unknown): string {
		if (err instanceof XrpcError) {
			switch (err.code) {
				case 'InvalidInviteCode':
					return 'That invite code is invalid or exhausted.';
				case 'HandleNotAvailable':
					return 'That handle was just taken; choose another.';
				case 'InvalidHandle':
					return 'That handle is not valid on this server.';
				case 'UnsupportedDomain':
					return 'Handles on that domain are not accepted here.';
				case 'InvalidEmail':
					return 'That email address is not valid.';
				case 'InternalError':
					return 'The server could not finish creating the account.';
			}
		}
		return err instanceof Error ? err.message : 'Signup failed';
	}

	async function submit(e: Event): Promise<void> {
		e.preventDefault();
		error = '';
		if (!server || !domain) {
			error = 'Signup settings are not ready yet.';
			return;
		}
		if (mode === 'closed') {
			error = 'Registration is closed on this server.';
			return;
		}
		if (!validLabel(label)) {
			error = 'Use 3–18 letters, numbers or hyphens, without a leading or trailing hyphen.';
			return;
		}
		if (handleState !== 'available' && handleState !== 'unknown') {
			error = 'Choose an available handle first.';
			return;
		}
		if (inviteRequired && !inviteCode.trim()) {
			error = 'An invite code is required.';
			return;
		}

		submitting = true;
		try {
			const created = await createAccount({
				handle: fullHandle,
				email,
				password,
				...(inviteRequired ? { inviteCode: inviteCode.trim() } : {})
			});
			auth.login({
				accessJwt: created.accessJwt,
				refreshJwt: created.refreshJwt,
				handle: created.handle,
				did: created.did,
				didDoc: created.didDoc,
				email,
				emailConfirmed: false,
				emailAuthFactor: created.emailAuthFactor,
				active: true
			});
			/* A device session makes OAuth approvals work later; verification
			 * mail is best-effort and only advertised when SMTP is configured. */
			const deviceReady = signInDevice(created.handle, password).catch(() => false);
			const emailSent =
				info?.capabilities?.emailVerificationAvailable === true
					? requestEmailConfirmation().then(
							() => true,
							() => false
						)
					: Promise.resolve(false);
			await deviceReady;
			const destination = (await emailSent)
				? resolve('/account?registered=1&verifyEmail=1')
				: resolve('/account?registered=1');
			await goto(destination);
		} catch (err) {
			error = signupError(err);
		} finally {
			submitting = false;
		}
	}
</script>

<svelte:head>
	<title>Create an account — MetalBear</title>
</svelte:head>

<AuthShell
	title="Create an account"
	subtitle="Join this Personal Data Server with a handle on its user domain."
>
	{#if loadingInfo}
		<p class="text-sm text-slate-400">Loading signup settings…</p>
	{:else if infoError}
		<p class="rounded-lg border border-red-900/60 bg-red-950/40 px-4 py-2.5 text-sm text-red-300">
			{infoError}
		</p>
	{:else if mode === 'closed'}
		<p class="text-sm text-slate-300">Registration is closed on this server.</p>
	{:else}
		<form onsubmit={submit} class="flex flex-col gap-5">
			<div>
				<label for="handle-label" class="mb-1.5 block text-sm font-medium text-slate-300">
					Handle
				</label>
				<div class="flex items-stretch">
					<input
						id="handle-label"
						type="text"
						bind:value={label}
						oninput={scheduleHandleCheck}
						onblur={scheduleHandleCheck}
						placeholder="alice"
						minlength="3"
						maxlength="18"
						required
						autocomplete="username"
						class="min-w-0 flex-1 rounded-l-lg border border-slate-700 bg-slate-900 px-4 py-2.5 text-sm text-white placeholder-slate-500 outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
					/>
					{#if server && server.availableUserDomains.length > 1}
						<select
							bind:value={domain}
							onchange={scheduleHandleCheck}
							aria-label="Handle domain"
							class="rounded-r-lg border border-l-0 border-slate-700 bg-slate-900 px-2 py-2.5 text-sm text-white outline-none focus:border-emerald-500"
						>
							{#each server.availableUserDomains as option (option)}
								<option value={option}>{option}</option>
							{/each}
						</select>
					{:else if domain}
						<span
							class="flex items-center rounded-r-lg border border-l-0 border-slate-700 bg-slate-800 px-3 font-mono text-sm text-slate-300"
						>
							{domain}
						</span>
					{/if}
				</div>
				<p
					class="mt-1.5 text-xs {handleState === 'available'
						? 'text-emerald-400'
						: handleState === 'taken'
							? 'text-amber-400'
							: 'text-slate-500'}"
				>
					{handleMessage || '3–18 letters, numbers or hyphens.'}
				</p>
				{#if suggestions.length}
					<div class="mt-2 flex flex-wrap gap-2 text-xs">
						{#each suggestions as suggestion (suggestion)}
							<button
								type="button"
								onclick={() => useSuggestion(suggestion)}
								class="rounded border border-slate-700 px-2 py-1 font-mono text-emerald-400 hover:border-emerald-500"
							>
								{suggestion}
							</button>
						{/each}
					</div>
				{/if}
			</div>

			<div>
				<label for="email" class="mb-1.5 block text-sm font-medium text-slate-300">Email</label>
				<input
					id="email"
					type="email"
					bind:value={email}
					placeholder="alice@example.com"
					required
					autocomplete="email"
					onblur={scheduleHandleCheck}
					class="w-full rounded-lg border border-slate-700 bg-slate-900 px-4 py-2.5 text-sm text-white placeholder-slate-500 outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
				/>
			</div>

			<div>
				<label for="password" class="mb-1.5 block text-sm font-medium text-slate-300"
					>Password</label
				>
				<div class="relative">
					<input
						id="password"
						type={showPassword ? 'text' : 'password'}
						bind:value={password}
						placeholder="At least 8 characters"
						minlength="8"
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

			{#if inviteRequired}
				<div>
					<label for="invite-code" class="mb-1.5 block text-sm font-medium text-slate-300">
						Invite code
					</label>
					<input
						id="invite-code"
						type="text"
						bind:value={inviteCode}
						placeholder="Invite code"
						required
						class="w-full rounded-lg border border-slate-700 bg-slate-900 px-4 py-2.5 font-mono text-sm text-white placeholder-slate-500 outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
					/>
				</div>
			{/if}

			{#if error}
				<p
					class="rounded-lg border border-red-900/60 bg-red-950/40 px-4 py-2.5 text-sm text-red-300"
				>
					{error}
				</p>
			{/if}

			<button
				type="submit"
				disabled={submitting || handleState === 'checking' || handleState === 'taken'}
				class="rounded-lg bg-emerald-600 px-4 py-2.5 text-sm font-medium text-white transition hover:bg-emerald-500 disabled:cursor-not-allowed disabled:opacity-50"
			>
				{submitting ? 'Creating account…' : 'Create account'}
			</button>
		</form>
	{/if}

	<p class="mt-4 text-center text-sm text-slate-500">
		<a href={resolve('/login')} class="text-emerald-500 hover:text-emerald-400">
			Already have an account? Sign in
		</a>
	</p>
</AuthShell>

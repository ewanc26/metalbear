<script lang="ts">
	import { onMount } from 'svelte';
	import { adminUpdateAccountPassword } from '#lib/pds.ts';

	let { did, handle }: { did: string; handle: string } = $props();

	const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
	let password = $state('');
	let pending = $state(false);
	let error = $state('');
	let notice = $state('');

	function generate() {
		const bytes = crypto.getRandomValues(new Uint8Array(24));
		password = Array.from(bytes, (byte) => ALPHABET[byte & 63]).join('');
	}

	onMount(generate);

	async function handleSubmit(e: Event) {
		e.preventDefault();
		if (!password || password.length > 256) return;
		if (
			!window.confirm(
				`Reset the password for ${handle}? Existing sessions and trusted devices will be signed out.`
			)
		) {
			return;
		}
		const issued = password;
		error = '';
		notice = '';
		pending = true;
		try {
			await adminUpdateAccountPassword(did, issued);
			notice = `Password reset for ${handle}. New password: ${issued}`;
			password = '';
			generate();
		} catch (err) {
			error = err instanceof Error ? err.message : 'Failed to reset password';
		} finally {
			pending = false;
		}
	}
</script>

<div class="mt-6 border-t border-slate-800 pt-6">
	<h3 class="mb-2 text-sm font-medium text-slate-300">Reset password</h3>
	<p class="mb-3 text-xs text-slate-500">
		Generates a new password locally. Resetting signs out every session and trusted device for this
		account.
	</p>
	<form onsubmit={handleSubmit} class="flex flex-wrap items-end gap-3">
		<label class="min-w-64 flex-1 flex-col gap-1 text-xs text-slate-500">
			New password
			<input
				type="text"
				value={password}
				readonly
				class="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 font-mono text-sm text-white outline-none"
			/>
		</label>
		<button
			type="button"
			onclick={generate}
			disabled={pending}
			class="rounded-lg border border-slate-700 px-3 py-2 text-sm text-slate-300 transition hover:border-slate-600 hover:text-white disabled:opacity-50"
		>
			Generate new
		</button>
		<button
			type="submit"
			disabled={pending || !password}
			class="rounded-lg border border-red-800/60 px-3 py-2 text-sm text-red-300 transition hover:border-red-600 hover:text-red-200 disabled:cursor-not-allowed disabled:opacity-50"
		>
			{pending ? 'Resetting…' : 'Reset password'}
		</button>
	</form>

	{#if error}
		<p
			class="mt-3 rounded-lg border border-red-900/60 bg-red-950/40 px-4 py-2.5 text-sm text-red-300"
		>
			{error}
		</p>
	{/if}

	{#if notice}
		<div
			class="mt-3 rounded-lg border border-emerald-900/60 bg-emerald-950/40 px-4 py-3 text-sm text-emerald-300"
		>
			<p>{notice}</p>
			<p class="mt-1 text-xs text-emerald-400/80">Copy it now; it will not be shown again.</p>
		</div>
	{/if}
</div>

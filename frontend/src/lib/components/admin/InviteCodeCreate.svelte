<script lang="ts">
	import { adminCreateInviteCodes } from '#lib/pds.ts';

	let { onCreated }: { onCreated: () => Promise<void> | void } = $props();

	let codeCount = $state(1);
	let useCount = $state(1);
	let forAccount = $state('');
	let pending = $state(false);
	let error = $state('');
	let created = $state<string[]>([]);

	async function handleSubmit(e: Event) {
		e.preventDefault();
		error = '';
		created = [];
		if (!Number.isInteger(codeCount) || codeCount < 1 || codeCount > 100) {
			error = 'Create between 1 and 100 codes at a time.';
			return;
		}
		if (!Number.isInteger(useCount) || useCount < 1) {
			error = 'Each code needs at least one use.';
			return;
		}
		pending = true;
		try {
			const result = await adminCreateInviteCodes(
				codeCount,
				useCount,
				forAccount.trim() ? [forAccount.trim()] : undefined
			);
			created = result.codes.flatMap((group) => group.codes);
			forAccount = '';
			await onCreated();
		} catch (err) {
			error = err instanceof Error ? err.message : 'Failed to create invite codes';
		} finally {
			pending = false;
		}
	}
</script>

<form onsubmit={handleSubmit} class="mb-6 border-b border-slate-800 pb-6">
	<h3 class="mb-3 text-sm font-medium text-slate-300">Create invite codes</h3>
	<div class="flex flex-wrap items-end gap-3">
		<label class="flex flex-col gap-1 text-xs text-slate-500">
			Codes
			<input
				type="number"
				min="1"
				max="100"
				step="1"
				bind:value={codeCount}
				class="w-24 rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-white outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
			/>
		</label>
		<label class="flex flex-col gap-1 text-xs text-slate-500">
			Uses each
			<input
				type="number"
				min="1"
				step="1"
				bind:value={useCount}
				class="w-24 rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-white outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
			/>
		</label>
		<label class="min-w-48 flex-1 flex-col gap-1 text-xs text-slate-500">
			For DID (optional)
			<input
				type="text"
				bind:value={forAccount}
				placeholder="did:plc:…"
				class="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-white placeholder-slate-500 outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
			/>
		</label>
		<button
			type="submit"
			disabled={pending}
			class="rounded-lg bg-emerald-600 px-4 py-2 text-sm font-medium text-white transition hover:bg-emerald-500 disabled:cursor-not-allowed disabled:opacity-50"
		>
			{pending ? 'Creating…' : 'Create codes'}
		</button>
	</div>

	{#if error}
		<p
			class="mt-4 rounded-lg border border-red-900/60 bg-red-950/40 px-4 py-2.5 text-sm text-red-300"
		>
			{error}
		</p>
	{/if}

	{#if created.length > 0}
		<div
			class="mt-4 rounded-lg border border-emerald-900/60 bg-emerald-950/40 px-4 py-3 text-sm text-emerald-300"
		>
			<p>Created {created.length} invite {created.length === 1 ? 'code' : 'codes'}:</p>
			{#each created as code (code)}
				<code class="mt-1 block font-mono break-all text-emerald-200">{code}</code>
			{/each}
			<p class="mt-2 text-xs text-emerald-400/80">Copy these now; they are shown once here.</p>
		</div>
	{/if}
</form>

<script lang="ts">
	import { adminExportAccountBundle } from '#lib/pds.ts';

	let { did, handle }: { did: string; handle: string } = $props();

	let pending = $state(false);
	let error = $state('');

	async function handleExport() {
		error = '';
		pending = true;
		try {
			const blob = await adminExportAccountBundle(did);
			const url = URL.createObjectURL(blob);
			const link = document.createElement('a');
			link.href = url;
			link.download = `${handle.replace(/[^a-zA-Z0-9.-]/g, '_')}-${new Date().toISOString().slice(0, 10)}.tar`;
			document.body.appendChild(link);
			link.click();
			link.remove();
			URL.revokeObjectURL(url);
		} catch (err) {
			error = err instanceof Error ? err.message : 'Failed to export account bundle';
		} finally {
			pending = false;
		}
	}
</script>

<div class="mt-6 border-t border-slate-800 pt-6">
	<h3 class="mb-2 text-sm font-medium text-slate-300">Export account bundle</h3>
	<p class="mb-3 text-xs text-slate-500">
		Downloads the repo, every blob and the account metadata as a migration tar. Keep it somewhere
		safe.
	</p>
	<button
		onclick={handleExport}
		disabled={pending}
		class="rounded-lg border border-slate-700 px-3 py-2 text-sm text-slate-300 transition hover:border-slate-600 hover:text-white disabled:opacity-50"
	>
		{pending ? 'Preparing…' : 'Export account bundle (.tar)'}
	</button>

	{#if error}
		<p
			class="mt-3 rounded-lg border border-red-900/60 bg-red-950/40 px-4 py-2.5 text-sm text-red-300"
		>
			{error}
		</p>
	{/if}
</div>

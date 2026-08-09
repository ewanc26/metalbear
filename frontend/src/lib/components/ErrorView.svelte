<script lang="ts">
	import AuthShell from './AuthShell.svelte';

	let {
		error,
		message,
		title = 'Something went wrong',
		retry
	}: {
		error?: unknown;
		message?: string;
		title?: string;
		retry?: () => void;
	} = $props();

	const displayMessage = $derived(
		message ?? (error instanceof Error ? error.message : 'An unexpected error occurred.')
	);
</script>

<AuthShell {title}>
	<div class="rounded-lg border border-red-900/60 bg-red-950/40 px-4 py-3 text-sm text-red-300">
		<p>{displayMessage}</p>
	</div>
	{#if retry}
		<button
			onclick={retry}
			class="mt-4 w-full rounded-lg bg-emerald-600 px-4 py-2.5 text-sm font-medium text-white transition hover:bg-emerald-500"
		>
			Try again
		</button>
	{/if}
</AuthShell>

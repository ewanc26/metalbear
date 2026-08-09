<script lang="ts">
	import { onMount } from 'svelte';

	let {
		title,
		redirectUrl,
		redirectMode = 'replace'
	}: {
		title: string;
		redirectUrl: string;
		redirectMode?: 'replace' | 'push';
	} = $props();

	let shown = $state(false);

	onMount(() => {
		setTimeout(() => {
			shown = true;
			if (redirectMode === 'replace') {
				window.history.replaceState(null, '', redirectUrl);
			}
			window.location.replace(redirectUrl);
		}, 500);
	});
</script>

<svelte:head>
	<title>{title}</title>
</svelte:head>

<div class="mx-auto flex min-h-screen max-w-md flex-col justify-center px-6">
	<div class="text-center">
		<p class="text-lg font-medium text-white">{title}</p>
		<p class="mt-2 text-sm text-slate-400">
			{#if shown}
				<a href={redirectUrl} class="text-emerald-500 hover:text-emerald-400">
					Click here if you are not redirected automatically.
				</a>
			{:else}
				Redirecting…
			{/if}
		</p>
	</div>
</div>

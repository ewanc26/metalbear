<script lang="ts">
	import type { Snippet } from 'svelte';

	let {
		title = '',
		subtitle = '',
		children,
		class: className = '',
		documentTitle
	}: {
		title?: string;
		subtitle?: string;
		documentTitle?: string;
		children: Snippet;
		class?: string;
	} = $props();

	const titleString = $derived(title);
	const documentTitleString = $derived(documentTitle ?? title);
</script>

<svelte:head>
	{#if documentTitleString}
		<title>{documentTitleString}</title>
	{/if}
</svelte:head>

<div class="flex min-h-svh flex-col items-center justify-center gap-6 p-6">
	<div class={`flex w-full max-w-sm flex-col ${className}`}>
		<div class="rounded-lg border border-slate-800 bg-slate-900/30 shadow-sm">
			{#if title || subtitle}
				<div class="px-6 pt-6 text-center">
					{#if title}
						<h1 class="text-xl font-semibold text-white">{title}</h1>
					{/if}
					{#if subtitle}
						<p class="mt-1.5 text-sm text-slate-400">{subtitle}</p>
					{/if}
				</div>
			{/if}

			<div class="p-6">
				{@render children()}
			</div>
		</div>
	</div>
</div>

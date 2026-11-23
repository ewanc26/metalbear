<script lang="ts">
	import type { Snippet } from 'svelte';
	import BrandingFooter from '#lib/components/BrandingFooter.svelte';
	import { branding, DEFAULT_BRANDING } from '#lib/stores/branding.ts';
	import type { Branding } from '#lib/pds.ts';

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

	let brand = $state<Branding>(DEFAULT_BRANDING);
	branding.subscribe((value) => (brand = value));

	const titleString = $derived(title);
	/* Only change document titles when the operator has chosen a name: the
	 * built-in auth screens keep their current titles byte for byte. */
	const documentTitleString = $derived(
		brand.serviceName === DEFAULT_BRANDING.serviceName
			? (documentTitle ?? title)
			: `${documentTitle ?? title}${title ? ' — ' : ''}${brand.serviceName}`
	);
</script>

<svelte:head>
	{#if documentTitleString}
		<title>{documentTitleString}</title>
	{/if}
</svelte:head>

<div class="flex min-h-svh flex-col items-center justify-center gap-6 p-6">
	<div class={`flex w-full max-w-sm flex-col ${className}`}>
		<div class="rounded-lg border border-slate-800 bg-slate-900/30 shadow-sm">
			{#if brand.logoUrl}
				<div class="pt-6 text-center">
					<img src={brand.logoUrl} alt="" class="mx-auto h-10 w-10 rounded" />
				</div>
			{/if}
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
		<div class="flex justify-center pt-2">
			<BrandingFooter />
		</div>
	</div>
</div>

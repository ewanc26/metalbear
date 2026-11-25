<script lang="ts">
	import { branding, DEFAULT_BRANDING } from '#lib/stores/branding.ts';
	import type { Branding } from '#lib/pds.ts';

	let brand = $state<Branding>(DEFAULT_BRANDING);
	branding.subscribe((value) => (brand = value));

	/* Home is always present; the other links are the same fields advertised by
	 * describeServer for policy/support and configured under [operator]. */
	const links = $derived(
		[
			{ label: 'Home', href: brand.links.homeUrl },
			brand.links.supportUrl ? { label: 'Support', href: brand.links.supportUrl } : null,
			brand.links.privacyPolicy ? { label: 'Privacy', href: brand.links.privacyPolicy } : null,
			brand.links.termsOfService ? { label: 'Terms', href: brand.links.termsOfService } : null
		].filter((link): link is { label: string; href: string } => link !== null)
	);
</script>

<nav class="flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate-500" aria-label="Operator links">
	{#each links as link (link.label)}
		<!-- eslint-disable-next-line svelte/no-navigation-without-resolve -- operator URLs are passed through verbatim -->
		<a class="text-emerald-500 hover:text-emerald-400" href={link.href}>{link.label}</a>
	{/each}
</nav>

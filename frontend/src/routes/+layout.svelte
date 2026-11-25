<script lang="ts">
	import { resolve } from '$app/paths';
	import './layout.css';
	import favicon from '#lib/assets/favicon.svg';
	import { page } from '$app/state';
	import { onMount } from 'svelte';
	import { auth } from '#lib/stores/auth.ts';
	import { branding, DEFAULT_BRANDING, loadBranding } from '#lib/stores/branding.ts';
	import { deleteSession } from '#lib/pds.ts';
	import type { Branding } from '#lib/pds.ts';

	let { children } = $props();

	let session = $state<import('#lib/stores/auth.ts').Session | null>(null);
	auth.subscribe((s) => (session = s));
	let brand = $state<Branding>(DEFAULT_BRANDING);
	branding.subscribe((b) => (brand = b));

	onMount(() => {
		/* Static prerender: learn the operator's palette and name from the
		 * server at runtime, before applying them to the document. */
		void loadBranding();
	});

	const pathname = $derived(page.url.pathname);
	const isOAuthPage = $derived(pathname === '/login' || pathname.startsWith('/oauth/'));
	$effect(() => {
		document.body.dataset.authPage = isOAuthPage ? 'true' : 'false';
	});

	async function handleLogout() {
		try {
			await deleteSession();
		} catch {
			/* Best-effort; clear local state regardless. */
		}
		auth.logout();
	}

	let showMenu = $state(false);
</script>

<svelte:head><link rel="icon" href={favicon} /></svelte:head>

{#if !isOAuthPage}
	<nav class="flex items-center justify-between border-b border-slate-800 px-6 py-3">
		<div class="flex items-center gap-6">
			<!-- eslint-disable svelte/no-navigation-without-resolve -- operator URLs are passed through verbatim -->
			<a
				href={brand.links.homeUrl}
				class="flex items-center gap-2 text-sm font-semibold text-white hover:text-emerald-400"
			>
				{#if brand.logoUrl}
					<img src={brand.logoUrl} alt="" class="h-6 w-6 rounded" />
				{/if}
				{brand.serviceName}
			</a>
			<!-- eslint-enable svelte/no-navigation-without-resolve -->
		</div>

		<div class="flex items-center gap-4">
			{#if session}
				<div class="relative">
					<button
						onclick={() => (showMenu = !showMenu)}
						class="flex items-center gap-2 rounded-lg px-3 py-1.5 text-sm text-slate-300 hover:bg-slate-800"
					>
						<span class="hidden sm:inline">{session.handle}</span>
						<svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
							<path
								stroke-linecap="round"
								stroke-linejoin="round"
								stroke-width="2"
								d="M19 9l-7 7-7-7"
							/>
						</svg>
					</button>
					{#if showMenu}
						<div
							class="absolute right-0 z-10 mt-1 w-48 rounded-lg border border-slate-700 bg-slate-900 py-1 shadow-lg"
							role="menu"
							tabindex="-1"
							onclick={() => (showMenu = false)}
							onkeydown={(event) => {
								if (event.key === 'Escape') showMenu = false;
							}}
						>
							<a
								href={resolve('/account')}
								class="block px-4 py-2 text-sm text-slate-300 hover:bg-slate-800"
								role="menuitem"
							>
								Account
							</a>
							<a
								href={resolve('/account/app-passwords')}
								class="block px-4 py-2 text-sm text-slate-300 hover:bg-slate-800"
								role="menuitem"
							>
								App passwords
							</a>
							<button
								onclick={handleLogout}
								class="block w-full px-4 py-2 text-left text-sm text-red-400 hover:bg-slate-800"
								role="menuitem"
							>
								Sign out
							</button>
						</div>
					{/if}
				</div>
			{:else}
				<a
					href={resolve('/login')}
					class="rounded-lg bg-emerald-600 px-4 py-1.5 text-sm font-medium text-white transition hover:bg-emerald-500"
				>
					Sign in
				</a>
			{/if}
		</div>
	</nav>
{/if}

{@render children()}

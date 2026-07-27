<script lang="ts">
	import { onMount } from 'svelte';
	import BearLogo from '$lib/components/BearLogo.svelte';
	import {
		describeServer,
		listRepos,
		health,
		relayStatus,
		type ServerInfo,
		type RepoInfo,
		type RelayStatus
	} from '$lib/pds';

	let version = $state<string | null>(null);
	let server = $state<ServerInfo | null>(null);
	let repos = $state<RepoInfo[] | null>(null);
	let relays = $state<RelayStatus[] | null>(null);
	let hostname = $state('');
	let failed = $state(false);

	onMount(async () => {
		hostname = window.location.hostname;
		try {
			[version, server, repos] = await Promise.all([health(), describeServer(), listRepos()]);
		} catch {
			failed = true;
		}
		/* Relays are third parties and slower; let the page render without them. */
		relays = await relayStatus(hostname);
	});

	/* A relay counts as consuming us once it has ingested at least one event.
	 * seq -1 means registered but never consumed, which is not the same thing. */
	const federating = $derived(relays?.filter((r) => r.known && (r.seq ?? -1) > 0).length ?? 0);
</script>

<svelte:head>
	<title>MetalBear{hostname ? ` — ${hostname}` : ''}</title>
	<meta
		name="description"
		content="A Personal Data Server for the AT Protocol, written in pure C11."
	/>
</svelte:head>

<main class="mx-auto max-w-4xl px-6 py-12 sm:py-16">
	<BearLogo />

	<header class="mb-10">
		<h1 class="text-3xl font-semibold tracking-tight text-white sm:text-4xl">MetalBear</h1>
		<p class="mt-2 text-lg text-slate-400">
			A Personal Data Server for the AT Protocol, written in pure C11.
		</p>
		{#if hostname}
			<p class="mt-3 font-mono text-sm text-slate-500">{hostname}</p>
		{/if}
	</header>

	{#if failed}
		<p
			class="mb-10 rounded-lg border border-red-900/60 bg-red-950/40 px-4 py-3 text-sm text-red-300"
		>
			Could not reach this server's XRPC endpoints. It may be restarting.
		</p>
	{/if}

	<section class="mb-10">
		<h2 class="mb-3 text-xs font-semibold tracking-widest text-slate-500 uppercase">Server</h2>
		<dl class="grid gap-x-8 gap-y-3 sm:grid-cols-2">
			<div>
				<dt class="text-sm text-slate-500">Version</dt>
				<dd class="font-mono text-sm text-slate-200">{version ?? '—'}</dd>
			</div>
			<div>
				<dt class="text-sm text-slate-500">Service DID</dt>
				<dd class="font-mono text-sm break-all text-slate-200">{server?.did ?? '—'}</dd>
			</div>
			<div>
				<dt class="text-sm text-slate-500">Accounts</dt>
				<dd class="font-mono text-sm text-slate-200">{repos?.length ?? '—'}</dd>
			</div>
			<div>
				<dt class="text-sm text-slate-500">Registration</dt>
				<dd class="font-mono text-sm text-slate-200">
					{#if server}{server.inviteCodeRequired ? 'invite required' : 'open'}{:else}—{/if}
				</dd>
			</div>
		</dl>
	</section>

	<section class="mb-10">
		<h2 class="mb-3 text-xs font-semibold tracking-widest text-slate-500 uppercase">Federation</h2>
		{#if relays === null}
			<p class="text-sm text-slate-500">Asking relays…</p>
		{:else}
			<p class="mb-4 text-sm text-slate-400">
				Consumed by <span class="font-mono text-emerald-400">{federating}</span> of
				{relays.length} relays.
			</p>
			<ul class="divide-y divide-slate-800 rounded-lg border border-slate-800">
				{#each relays as relay (relay.name)}
					<li class="flex items-center justify-between gap-4 px-4 py-2.5">
						<span class="text-sm text-slate-300">{relay.name}</span>
						{#if relay.known && (relay.seq ?? -1) > 0}
							<span class="font-mono text-xs text-emerald-400">seq {relay.seq}</span>
						{:else if relay.known}
							<span class="font-mono text-xs text-amber-500">registered, no events</span>
						{:else}
							<span class="font-mono text-xs text-slate-600">unknown</span>
						{/if}
					</li>
				{/each}
			</ul>
		{/if}
	</section>

	{#if repos && repos.length > 0}
		<section class="mb-10">
			<h2 class="mb-3 text-xs font-semibold tracking-widest text-slate-500 uppercase">
				Hosted repositories
			</h2>
			<ul class="divide-y divide-slate-800 rounded-lg border border-slate-800">
				{#each repos as repo (repo.did)}
					<li class="px-4 py-2.5">
						<div class="flex items-center justify-between gap-4">
							<code class="text-xs break-all text-slate-300">{repo.did}</code>
							<span
								class="shrink-0 font-mono text-xs {repo.active
									? 'text-emerald-400'
									: 'text-amber-500'}"
							>
								{repo.active ? 'active' : (repo.status ?? 'inactive')}
							</span>
						</div>
						<code class="mt-1 block text-xs text-slate-600">rev {repo.rev}</code>
					</li>
				{/each}
			</ul>
		</section>
	{/if}

	<footer class="mt-12 border-t border-slate-800 pt-6">
		<nav class="flex flex-wrap gap-x-6 gap-y-2 text-sm">
			<a class="text-emerald-500 hover:text-emerald-400" href="https://github.com/ewanc26/metalbear"
				>Source</a
			>
			<a class="text-emerald-500 hover:text-emerald-400" href="https://github.com/ewanc26/wolfram"
				>Wolfram SDK</a
			>
			<a class="text-emerald-500 hover:text-emerald-400" href="https://atproto.com">AT Protocol</a>
		</nav>
		<p class="mt-4 text-xs text-slate-600">
			Public endpoints are served under <code class="text-slate-500">/xrpc/</code>.
		</p>
	</footer>
</main>

<script lang="ts">
	import { onMount } from 'svelte';
	import BearLogo from '$lib/components/BearLogo.svelte';
	import {
		describeServer,
		listRepos,
		health,
		relayStatus,
		operatorInfo,
		type ServerInfo,
		type RepoInfo,
		type RelayStatus,
		type OperatorInfo
	} from '$lib/pds';

	let version = $state<string | null>(null);
	let server = $state<ServerInfo | null>(null);
	let repos = $state<RepoInfo[] | null>(null);
	let relays = $state<RelayStatus[] | null>(null);
	let info = $state<OperatorInfo | null>(null);
	let hostname = $state('');
	let failed = $state(false);

	onMount(async () => {
		hostname = window.location.hostname;
		try {
			[version, server, repos, info] = await Promise.all([
				health(),
				describeServer(),
				listRepos(),
				operatorInfo()
			]);
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
		content="A Personal Data Server for the AT Protocol, written in pure C23."
	/>
</svelte:head>

<main class="mx-auto max-w-4xl px-6 py-12 sm:py-16">
	<BearLogo />

	<header class="mb-10">
		<div class="flex flex-wrap items-center gap-3">
			<h1 class="text-3xl font-semibold tracking-tight text-white sm:text-4xl">
				{info?.operator?.name ? `${info.operator.name}'s PDS` : 'Personal Data Server'}
			</h1>
			{#if info?.development}
				<!-- Say it plainly: the accounts here are tests, not people. -->
				<span
					class="rounded-full border border-amber-600/50 bg-amber-950/40 px-3 py-1 text-xs font-semibold tracking-wide text-amber-400 uppercase"
				>
					Development instance
				</span>
			{/if}
		</div>
		<p class="mt-2 text-lg text-slate-400">
			{info?.description ?? 'An AT Protocol Personal Data Server.'}
		</p>
		{#if hostname}
			<p class="mt-3 font-mono text-sm text-slate-500">{hostname}</p>
		{/if}
		{#if info?.development}
			<p
				class="mt-4 rounded-lg border border-amber-900/50 bg-amber-950/20 px-4 py-3 text-sm text-amber-200/80"
			>
				This server is used for testing MetalBear against the live network. Accounts and posts on it
				exist to exercise federation, and may be removed without notice.
			</p>
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

	<!-- Operator -->
	{#if info?.operator?.name || info?.operator?.email || server?.links}
		<section class="mb-10">
			<h2 class="mb-3 text-xs font-semibold tracking-widest text-slate-500 uppercase">
				Administration
			</h2>
			<dl class="grid gap-x-8 gap-y-3 sm:grid-cols-2">
				{#if info?.operator?.name}
					<div>
						<dt class="text-sm text-slate-500">Operated by</dt>
						<dd class="text-sm text-slate-200">
							{#if info.operator.url}
								<a class="text-emerald-500 hover:text-emerald-400" href={info.operator.url}>
									{info.operator.name}
								</a>
							{:else}{info.operator.name}{/if}
						</dd>
					</div>
				{/if}
				{#if info?.operator?.email}
					<div>
						<dt class="text-sm text-slate-500">Contact</dt>
						<dd class="text-sm">
							<a
								class="text-emerald-500 hover:text-emerald-400"
								href="mailto:{info.operator.email}"
							>
								{info.operator.email}
							</a>
						</dd>
					</div>
				{/if}
				{#if server?.links?.privacyPolicy}
					<div>
						<dt class="text-sm text-slate-500">Privacy policy</dt>
						<dd class="text-sm">
							<a class="text-emerald-500 hover:text-emerald-400" href={server.links.privacyPolicy}>
								Read
							</a>
						</dd>
					</div>
				{/if}
				{#if server?.links?.termsOfService}
					<div>
						<dt class="text-sm text-slate-500">Terms of service</dt>
						<dd class="text-sm">
							<a class="text-emerald-500 hover:text-emerald-400" href={server.links.termsOfService}>
								Read
							</a>
						</dd>
					</div>
				{/if}
			</dl>
		</section>
	{/if}

	<!-- What this runs on -->
	<section class="mb-10 rounded-lg border border-slate-800 bg-slate-900/30 p-5">
		<div class="flex items-start gap-4">
			<div class="min-w-0">
				<h2 class="text-sm font-semibold text-slate-200">
					Running <a
						class="text-emerald-500 hover:text-emerald-400"
						href="https://github.com/ewanc26/metalbear">MetalBear</a
					>
					{#if info?.software?.version}
						<span class="font-mono text-xs text-slate-500">{info.software.version}</span>
					{/if}
					{#if info?.software?.wolframVersion}
						<span class="font-mono text-xs text-slate-500"
							>· Wolfram {info.software.wolframVersion}</span
						>
					{/if}
					{#if info?.software?.releaseStage}
						<span
							class="ml-1 rounded border border-slate-700 px-1.5 py-0.5 align-middle text-[0.65rem] font-medium tracking-wide text-slate-400 uppercase"
							title="Where this build sits on the software release life cycle"
						>
							{info.software.releaseStage}
						</span>
					{/if}
				</h2>
				{#if info?.software?.commit || info?.software?.builtAt}
					<p class="mt-1 font-mono text-xs text-slate-600">
						{#if info?.software?.commit}commit {info.software.commit}{/if}
						{#if info?.software?.commit && info?.software?.builtAt}·{/if}
						{#if info?.software?.builtAt}built {info.software.builtAt}{/if}
					</p>
				{/if}
				<p class="mt-1.5 text-sm text-slate-400">
					An AT Protocol Personal Data Server written from scratch in C/C++, on the
					<a
						class="text-emerald-500 hover:text-emerald-400"
						href="https://github.com/ewanc26/wolfram">Wolfram</a
					> SDK. Free software, AGPL-3.0.
				</p>
				{#if info?.operator?.supportUrl}
					<p class="mt-3 text-sm text-slate-400">
						<a class="text-emerald-500 hover:text-emerald-400" href={info.operator.supportUrl}>
							Support this work →
						</a>
					</p>
				{/if}
			</div>
		</div>
	</section>

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
		<div class="mt-6 space-y-1 text-xs text-slate-600">
			<p>
				MetalBear and Wolfram © Ewan Croft, licensed under the
				<a class="hover:text-slate-400" href="https://www.gnu.org/licenses/agpl-3.0.html"
					>GNU AGPL v3.0</a
				>.
			</p>
			<p>AT Protocol is a trademark of Bluesky Social PBC.</p>
		</div>
	</footer>
</main>

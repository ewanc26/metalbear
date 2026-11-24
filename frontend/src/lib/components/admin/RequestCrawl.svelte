<script lang="ts">
	import { onMount } from 'svelte';
	import { requestCrawl, requestCrawlHost } from '#lib/pds.ts';

	let hostname = $state('');
	let relayHosts = $state('');
	let pending = $state(false);
	let error = $state('');
	let notice = $state('');

	onMount(() => {
		hostname = window.location.host;
	});

	async function handleSubmit(e: Event) {
		e.preventDefault();
		error = '';
		notice = '';
		const own = hostname.trim() || window.location.host;
		const hosts = relayHosts
			.split(',')
			.map((host) => host.trim())
			.filter(Boolean);
		pending = true;
		try {
			if (hosts.length === 0) {
				await requestCrawl(own);
				notice = `Asked ${own} to request a crawl from its configured relays.`;
			} else {
				for (const host of hosts) await requestCrawlHost(host, own);
				notice = `Requested a crawl from ${hosts.length} relay${hosts.length === 1 ? '' : 's'} for ${own}.`;
			}
		} catch (err) {
			error = err instanceof Error ? err.message : 'Failed to request a crawl';
		} finally {
			pending = false;
		}
	}
</script>

<form onsubmit={handleSubmit} class="flex flex-col gap-4">
	<p class="text-xs text-slate-500">
		Leave relay hosts blank to use this server's configured crawlers. Naming hosts mirrors the admin
		CLI's direct requests; a relay must allow browser requests from this origin.
	</p>
	<div class="flex flex-wrap items-end gap-3">
		<label class="min-w-56 flex-1 flex-col gap-1 text-xs text-slate-500">
			Hostname to be crawled
			<input
				type="text"
				bind:value={hostname}
				placeholder="your.pds.example"
				required
				class="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-white placeholder-slate-500 outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
			/>
		</label>
		<label class="min-w-64 flex-1 flex-col gap-1 text-xs text-slate-500">
			Relay hosts (optional, comma-separated)
			<input
				type="text"
				bind:value={relayHosts}
				placeholder="bsky.network, relay.example"
				class="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-white placeholder-slate-500 outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
			/>
		</label>
		<button
			type="submit"
			disabled={pending}
			class="rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-300 transition hover:border-slate-600 hover:text-white disabled:cursor-not-allowed disabled:opacity-50"
		>
			{pending ? 'Requesting…' : 'Request crawl'}
		</button>
	</div>

	{#if error}
		<p class="rounded-lg border border-red-900/60 bg-red-950/40 px-4 py-2.5 text-sm text-red-300">
			{error}
		</p>
	{/if}

	{#if notice}
		<p
			class="rounded-lg border border-emerald-900/60 bg-emerald-950/40 px-4 py-2.5 text-sm text-emerald-300"
		>
			{notice}
		</p>
	{/if}
</form>

<script lang="ts">
	import { resolve } from '$app/paths';
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { formatBytes } from '#lib/format.ts';
	import {
		XrpcError,
		blobUrl,
		describeRepo,
		getLatestCommit,
		getRecord,
		listBlobsPage,
		listRecordsPage,
		repoStatus,
		resolveHandle,
		type DescribeRepo,
		type GetRecordResult,
		type LatestCommit,
		type ListBlobsResult,
		type ListRecordsResult,
		type RepoStatus
	} from '#lib/pds.ts';

	const RECORD_LIMIT = 50;
	const BLOB_LIMIT = 100;
	const COLLECTION_SAMPLE = 100;
	const UNAVAILABLE = new Set(['RepoNotFound', 'RepoTakendown', 'RepoDeactivated']);

	/* Everything on this page is a query parameter: the frontend is fully
	 * prerendered, so a dynamic path segment would 404 on a fresh load. */
	let did = $derived(page.url.searchParams.get('did') ?? '');
	let collection = $derived(page.url.searchParams.get('collection') ?? '');
	let view = $derived(page.url.searchParams.get('view') ?? '');
	let rkey = $derived(page.url.searchParams.get('rkey') ?? '');
	let cursor = $derived(page.url.searchParams.get('cursor') ?? '');
	let blobCursor = $derived(page.url.searchParams.get('blobCursor') ?? '');

	let search = $state('');
	let searchPending = $state(false);
	let searchError = $state('');

	let status = $state<RepoStatus | null>(null);
	let description = $state<DescribeRepo | null>(null);
	let commit = $state<LatestCommit | null>(null);
	let records = $state<ListRecordsResult | null>(null);
	let record = $state<GetRecordResult | null>(null);
	let blobs = $state<ListBlobsResult | null>(null);
	let blobMeta = $state<{ cid: string; size: string; type: string }[]>([]);
	let counts = $state<Record<string, string>>({});
	let unavailable = $state<{ title: string; message: string } | null>(null);
	let loadError = $state('');
	let loading = $state(false);

	/* Stale responses from a previous DID or tab must not overwrite this view. */
	let loadToken = 0;

	function href(params: Record<string, string | null | undefined>): '/repo' | `/repo?${string}` {
		const query: string[] = [];
		if (did) query.push(`did=${encodeURIComponent(did)}`);
		for (const [key, value] of Object.entries(params)) {
			if (value) query.push(`${key}=${encodeURIComponent(value)}`);
		}
		return (query.length ? `/repo?${query.join('&')}` : '/repo') as '/repo' | `/repo?${string}`;
	}

	function preview(value: unknown): string {
		const text = JSON.stringify(value) ?? '';
		return text.length > 140 ? `${text.slice(0, 137)}…` : text;
	}

	async function submitSearch(event: Event) {
		event.preventDefault();
		searchError = '';
		const value = search.trim();
		if (!value) return;
		searchPending = true;
		try {
			const target = value.startsWith('did:') ? value : await resolveHandle(value);
			await goto(resolve(href({ did: target })));
			search = '';
		} catch (err) {
			searchError = err instanceof Error ? err.message : 'Could not resolve that handle';
		} finally {
			searchPending = false;
		}
	}

	async function loadBlobMetadata(target: string, cids: string[], token: number) {
		blobMeta = cids.map((cid) => ({ cid, size: '—', type: '—' }));
		let next = 0;
		const worker = async () => {
			for (;;) {
				const index = next++;
				if (index >= cids.length) return;
				const cid = cids[index];
				try {
					/* getBlob forces attachment/CSP, so only the headers are
					 * useful here; never render the bytes in the page. */
					const res = await fetch(blobUrl(target, cid));
					const length = res.headers.get('content-length');
					const type = res.headers.get('content-type');
					await res.body?.cancel();
					if (token !== loadToken) return;
					blobMeta[index] = {
						cid,
						size: length ? formatBytes(Number(length)) : '—',
						type: type ?? '—'
					};
				} catch {
					/* Best effort: the CID and download link still work. */
				}
			}
		};
		await Promise.all(Array.from({ length: Math.min(8, cids.length) }, worker));
	}

	async function loadRepo(
		target: string,
		col: string,
		whichView: string,
		rk: string,
		cur: string,
		bcur: string,
		token: number
	) {
		loading = true;
		loadError = '';
		unavailable = null;
		status = null;
		description = null;
		commit = null;
		records = null;
		record = null;
		blobs = null;
		blobMeta = [];
		counts = {};
		try {
			/* getRepoStatus answers for taken-down and deactivated accounts,
			 * where describeRepo itself refuses. Check it first. */
			const st = await repoStatus(target);
			if (token !== loadToken) return;
			status = st;
			if (!st.active) {
				unavailable = {
					title: st.status === 'takendown' ? 'Repository taken down' : 'Repository inactive',
					message: `This repository is ${st.status ?? 'inactive'}; its records are not publicly available.`
				};
				return;
			}

			const [desc, head] = await Promise.all([
				describeRepo(target),
				getLatestCommit(target).catch(() => null)
			]);
			if (token !== loadToken) return;
			description = desc;
			commit = head;

			if (whichView === 'blobs') {
				const blobsPage = await listBlobsPage(target, BLOB_LIMIT, bcur || undefined);
				if (token !== loadToken) return;
				blobs = blobsPage;
				void loadBlobMetadata(target, blobsPage.cids, token);
			} else if (rk && col) {
				record = await getRecord(target, col, rk);
			} else if (col) {
				records = await listRecordsPage(target, col, RECORD_LIMIT, cur || undefined);
			}
			if (token !== loadToken) return;

			/* describeRepo has no counts, so sample one page per collection.
			 * A '+' means the first page was full: the number is a lower bound. */
			const sampled: Record<string, string> = {};
			await Promise.all(
				desc.collections.map(async (name) => {
					try {
						const first = await listRecordsPage(target, name, COLLECTION_SAMPLE);
						sampled[name] = `${first.records.length}${first.cursor ? '+' : ''}`;
					} catch {
						sampled[name] = '—';
					}
				})
			);
			if (token === loadToken) counts = sampled;
		} catch (err) {
			if (token !== loadToken) return;
			if (err instanceof XrpcError && UNAVAILABLE.has(err.code)) {
				unavailable = {
					title: 'Repository unavailable',
					message: `${err.code}: this repository's records are not publicly available.`
				};
			} else {
				loadError = err instanceof Error ? err.message : 'Could not load repository';
			}
		} finally {
			if (token === loadToken) loading = false;
		}
	}

	$effect(() => {
		const target = did;
		const col = collection;
		const whichView = view;
		const rk = rkey;
		const cur = cursor;
		const bcur = blobCursor;
		if (!target) return;
		void loadRepo(target, col, whichView, rk, cur, bcur, ++loadToken);
	});
</script>

<svelte:head>
	<title>Repo browser — MetalBear</title>
	<meta
		name="description"
		content="Browse public repositories hosted on this Personal Data Server."
	/>
</svelte:head>

<main class="mx-auto max-w-5xl px-6 py-12">
	<header class="mb-8">
		<a class="text-sm text-emerald-500 hover:text-emerald-400" href={resolve('/')}>← Home</a>
		<h1 class="mt-3 text-3xl font-semibold tracking-tight text-white">Repo browser</h1>
		<p class="mt-2 max-w-2xl text-sm text-slate-400">
			Read-only view of public records on this server. Nothing here is authenticated; taken-down and
			deactivated repositories are reported but their records are withheld.
		</p>
	</header>

	<form class="mb-8 flex flex-wrap gap-2" onsubmit={submitSearch}>
		<input
			type="text"
			bind:value={search}
			placeholder="Handle or DID (alice.example or did:plc:…)"
			aria-label="Handle or DID"
			class="min-w-0 flex-1 rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-white placeholder:text-slate-600 focus:border-emerald-600 focus:outline-none"
		/>
		<button
			type="submit"
			disabled={searchPending}
			class="rounded-lg bg-emerald-600 px-4 py-2 text-sm font-medium text-white transition hover:bg-emerald-500 disabled:opacity-50"
		>
			{searchPending ? 'Resolving…' : 'Browse'}
		</button>
	</form>

	{#if searchError}
		<p
			class="mb-6 rounded-lg border border-red-900/60 bg-red-950/40 px-4 py-2.5 text-sm text-red-300"
		>
			{searchError}
		</p>
	{/if}

	{#if !did}
		<section class="rounded-lg border border-slate-800 bg-slate-900/30 p-6">
			<h2 class="text-sm font-semibold tracking-widest text-slate-500 uppercase">
				Find a repository
			</h2>
			<p class="mt-3 text-sm text-slate-400">
				Enter a hosted handle or a DID above, or follow a “Browse repo” link from the admin lookup
				page.
			</p>
		</section>
	{:else if unavailable}
		<section class="rounded-lg border border-amber-800/60 bg-amber-950/30 p-6">
			<h2 class="text-lg font-semibold text-amber-200">{unavailable.title}</h2>
			<p class="mt-2 text-sm text-amber-200/80">{unavailable.message}</p>
			<p class="mt-3 font-mono text-xs break-all text-amber-200/60">{did}</p>
		</section>
	{:else if loadError}
		<section class="rounded-lg border border-red-900/60 bg-red-950/40 p-6">
			<h2 class="text-lg font-semibold text-red-200">Could not load repository</h2>
			<p class="mt-2 text-sm text-red-300">{loadError}</p>
			<button
				onclick={() => void loadRepo(did, collection, view, rkey, cursor, blobCursor, ++loadToken)}
				class="mt-4 rounded-lg border border-red-800 px-3 py-1.5 text-sm text-red-200 hover:border-red-600"
			>
				Retry
			</button>
		</section>
	{:else if status}
		<section class="mb-6 rounded-lg border border-slate-800 bg-slate-900/30 p-6">
			<dl class="grid gap-x-8 gap-y-3 sm:grid-cols-2">
				<div>
					<dt class="text-xs tracking-widest text-slate-500 uppercase">Handle</dt>
					<dd class="mt-1 font-mono text-sm text-slate-200">{description?.handle ?? '—'}</dd>
				</div>
				<div>
					<dt class="text-xs tracking-widest text-slate-500 uppercase">DID</dt>
					<dd class="mt-1 font-mono text-sm break-all text-slate-200">{did}</dd>
				</div>
				<div>
					<dt class="text-xs tracking-widest text-slate-500 uppercase">Repo head</dt>
					<dd class="mt-1 font-mono text-xs break-all text-slate-300">
						{commit ? `${commit.cid} · rev ${commit.rev}` : 'No commits yet'}
					</dd>
				</div>
				<div>
					<dt class="text-xs tracking-widest text-slate-500 uppercase">State</dt>
					<dd class="mt-1 text-sm text-emerald-400">
						{status.active ? 'active' : (status.status ?? 'inactive')}
					</dd>
				</div>
			</dl>
		</section>

		<nav class="mb-6 flex gap-4 text-sm">
			<a
				class={view === 'blobs' ? 'text-slate-400 hover:text-white' : 'text-emerald-400'}
				href={resolve(
					href({ view: null, collection: null, rkey: null, cursor: null, blobCursor: null })
				)}
			>
				Collections
			</a>
			<a
				class={view === 'blobs' ? 'text-emerald-400' : 'text-slate-400 hover:text-white'}
				href={resolve(
					href({ view: 'blobs', collection: null, rkey: null, cursor: null, blobCursor: null })
				)}
			>
				Blobs
			</a>
		</nav>

		{#if rkey && record}
			<section class="rounded-lg border border-slate-800 bg-slate-900/30 p-6">
				<div class="mb-4 flex flex-wrap items-center justify-between gap-3">
					<h2 class="text-lg font-semibold text-white">{rkey}</h2>
					<a
						class="text-sm text-emerald-500 hover:text-emerald-400"
						href={resolve(href({ collection, rkey: null, cursor, blobCursor: null }))}
					>
						← Back to records
					</a>
				</div>
				<dl class="mb-5 grid gap-x-8 gap-y-3 sm:grid-cols-2">
					<div>
						<dt class="text-xs tracking-widest text-slate-500 uppercase">Collection</dt>
						<dd class="mt-1 font-mono text-sm break-all text-slate-200">{collection}</dd>
					</div>
					<div>
						<dt class="text-xs tracking-widest text-slate-500 uppercase">CID</dt>
						<dd class="mt-1 font-mono text-xs break-all text-slate-300">{record.cid}</dd>
					</div>
					<div>
						<dt class="text-xs tracking-widest text-slate-500 uppercase">URI</dt>
						<dd class="mt-1 font-mono text-xs break-all text-slate-300">{record.uri}</dd>
					</div>
					<div>
						<dt class="text-xs tracking-widest text-slate-500 uppercase">Repo head rev</dt>
						<dd class="mt-1 font-mono text-xs break-all text-slate-300">{commit?.rev ?? '—'}</dd>
					</div>
				</dl>
				<pre
					class="overflow-x-auto rounded-lg border border-slate-800 bg-slate-950 p-4 text-xs text-slate-300">{JSON.stringify(
						record.value,
						null,
						2
					)}</pre>
			</section>
		{:else if collection && records}
			<section class="rounded-lg border border-slate-800 bg-slate-900/30 p-6">
				<div class="mb-4 flex flex-wrap items-center justify-between gap-3">
					<h2 class="font-mono text-sm break-all text-white">{collection}</h2>
					{#if commit}
						<span class="font-mono text-xs text-slate-500">rev {commit.rev}</span>
					{/if}
				</div>
				{#if records.records.length === 0}
					<p class="text-sm text-slate-500">No records in this collection.</p>
				{:else}
					<ul class="divide-y divide-slate-800">
						{#each records.records as row (row.cid + row.uri)}
							<li class="py-3">
								<a
									class="font-mono text-sm break-all text-emerald-500 hover:text-emerald-400"
									href={resolve(
										href({
											collection,
											rkey: row.uri.split('/').pop(),
											cursor,
											blobCursor: null
										})
									)}
								>
									{row.uri.split('/').pop()}
								</a>
								<p class="mt-1 font-mono text-xs break-all text-slate-500">{preview(row.value)}</p>
							</li>
						{/each}
					</ul>
					{#if records.cursor}
						<a
							class="mt-4 inline-block rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-300 hover:border-slate-600 hover:text-white"
							href={resolve(
								href({ collection, cursor: records.cursor, rkey: null, blobCursor: null })
							)}
						>
							Load more →
						</a>
					{/if}
				{/if}
			</section>
		{:else if view === 'blobs' && blobs}
			<section class="rounded-lg border border-slate-800 bg-slate-900/30 p-6">
				<h2 class="mb-4 text-sm font-semibold tracking-widest text-slate-500 uppercase">Blobs</h2>
				{#if blobs.cids.length === 0}
					<p class="text-sm text-slate-500">No blobs stored for this repository.</p>
				{:else}
					<table class="w-full text-left text-sm">
						<thead class="text-xs tracking-widest text-slate-500 uppercase">
							<tr>
								<th class="pb-2">CID</th>
								<th class="pb-2">Size</th>
								<th class="pb-2">Type</th>
							</tr>
						</thead>
						<tbody class="divide-y divide-slate-800">
							{#each blobMeta as blob (blob.cid)}
								<tr>
									<td class="py-2 pr-4">
										<!-- eslint-disable svelte/no-navigation-without-resolve -- blob URLs are constructed by the XRPC helper -->
										<a
											class="font-mono text-xs break-all text-emerald-500 hover:text-emerald-400"
											href={blobUrl(did, blob.cid)}
										>
											{blob.cid}
										</a>
										<!-- eslint-enable svelte/no-navigation-without-resolve -->
									</td>
									<td class="py-2 pr-4 font-mono text-xs text-slate-400">{blob.size}</td>
									<td class="py-2 font-mono text-xs text-slate-400">{blob.type}</td>
								</tr>
							{/each}
						</tbody>
					</table>
					{#if blobs.cursor}
						<a
							class="mt-4 inline-block rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-300 hover:border-slate-600 hover:text-white"
							href={resolve(
								href({ blobCursor: blobs.cursor, collection: null, rkey: null, cursor: null })
							)}
						>
							Load more →
						</a>
					{/if}
				{/if}
			</section>
		{:else}
			<section class="rounded-lg border border-slate-800 bg-slate-900/30 p-6">
				<h2 class="mb-4 text-sm font-semibold tracking-widest text-slate-500 uppercase">
					Collections
				</h2>
				{#if !description || description.collections.length === 0}
					<p class="text-sm text-slate-500">This repository has no collections yet.</p>
				{:else}
					<ul class="divide-y divide-slate-800">
						{#each description.collections as name (name)}
							<li class="flex items-center justify-between gap-4 py-3">
								<a
									class="font-mono text-sm break-all text-emerald-500 hover:text-emerald-400"
									href={resolve(
										href({ collection: name, rkey: null, cursor: null, blobCursor: null })
									)}
								>
									{name}
								</a>
								<span
									class="shrink-0 font-mono text-xs text-slate-500"
									title="Lower bound from the first page (up to 100 records)"
								>
									{counts[name] ?? '…'} records
								</span>
							</li>
						{/each}
					</ul>
				{/if}
			</section>
		{/if}

		{#if loading}
			<p class="mt-4 text-xs text-slate-500">Loading…</p>
		{/if}
	{/if}
</main>

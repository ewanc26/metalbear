<script lang="ts">
	import { resolve } from '$app/paths';
	import {
		XrpcError,
		adminGetSubjectStatusFor,
		adminSetBlobTakedown,
		adminSetRecordTakedown,
		getRecord
	} from '#lib/pds.ts';
	import type { AdminSubject, SubjectStatus } from '#lib/pds.ts';

	let { did }: { did: string } = $props();

	type Kind = 'record' | 'blob';

	let kind = $state<Kind>('record');
	let recordUri = $state('');
	let recordCid = $state('');
	let blobCid = $state('');
	let status = $state<SubjectStatus | null>(null);
	let pending = $state(false);
	let error = $state('');
	let notice = $state('');

	function parsedUri() {
		const match = /^at:\/\/([^/]+)\/([^/]+)\/([^/]+)$/.exec(recordUri.trim());
		return match ? { repo: match[1], collection: match[2], rkey: match[3] } : null;
	}

	let repoQuery = $derived.by(() => {
		const parsed = kind === 'record' ? parsedUri() : null;
		return `?did=${encodeURIComponent(did)}${parsed ? `&collection=${encodeURIComponent(parsed.collection)}&rkey=${encodeURIComponent(parsed.rkey)}` : ''}`;
	});

	function chooseKind(next: Kind) {
		kind = next;
		status = null;
		error = '';
		notice = '';
	}

	async function resolveRecordCid() {
		const given = recordCid.trim();
		if (given) return given;
		const uri = recordUri.trim();
		if (
			status?.subject.$type === 'com.atproto.repo.strongRef' &&
			status.subject.uri === uri &&
			status.subject.cid
		) {
			recordCid = status.subject.cid;
			return status.subject.cid;
		}
		const parsed = parsedUri();
		if (!parsed) {
			throw new Error('Enter a full at:// URI, such as at://did:plc:…/app.bsky.feed.post/rkey.');
		}
		const record = await getRecord(parsed.repo, parsed.collection, parsed.rkey);
		recordCid = record.cid;
		return record.cid;
	}

	async function checkStatus(quiet = false) {
		if (!quiet) {
			error = '';
			notice = '';
			status = null;
		}
		pending = true;
		try {
			if (kind === 'record') {
				const uri = recordUri.trim();
				if (!parsedUri()) {
					throw new Error('Enter a full at:// URI before checking a record.');
				}
				try {
					status = await adminGetSubjectStatusFor({ uri });
				} catch (err) {
					if (!(err instanceof XrpcError) || err.code !== 'NotFound') throw err;
					/* The server reports NotFound both for a missing subject
					 * and for one with no recorded takedown. Resolve the
					 * record first so a genuinely absent URI still fails. */
					const cid = await resolveRecordCid();
					const subject: AdminSubject = {
						$type: 'com.atproto.repo.strongRef',
						uri,
						cid
					};
					status = { subject, takedown: { applied: false } };
				}
			} else {
				const cid = blobCid.trim();
				if (!cid) {
					throw new Error('Enter a blob CID; blobs are keyed by both DID and CID.');
				}
				try {
					status = await adminGetSubjectStatusFor({ did, blob: cid });
				} catch (err) {
					/* No takedown row is the normal state for a live blob. */
					if (!(err instanceof XrpcError) || err.code !== 'NotFound') throw err;
					const subject: AdminSubject = {
						$type: 'com.atproto.admin.defs#repoBlobRef',
						did,
						cid
					};
					status = { subject, takedown: { applied: false } };
				}
			}
			return true;
		} catch (err) {
			error = err instanceof Error ? err.message : 'Failed to read subject status';
			return false;
		} finally {
			pending = false;
		}
	}

	async function toggleTakedown() {
		const applied = status?.takedown?.applied ?? false;
		if (!applied && !window.confirm('Take this subject down? It will read as absent to clients.')) {
			return;
		}
		error = '';
		notice = '';
		pending = true;
		try {
			const ref = applied ? undefined : String(Date.now());
			if (kind === 'record') {
				const uri = recordUri.trim();
				if (!parsedUri()) {
					throw new Error('Enter a full at:// URI before taking down a record.');
				}
				await adminSetRecordTakedown(uri, await resolveRecordCid(), !applied, ref);
			} else {
				const cid = blobCid.trim();
				if (!cid) {
					throw new Error('Enter a blob CID; blobs are keyed by both DID and CID.');
				}
				await adminSetBlobTakedown(did, cid, !applied, ref);
			}
			if (await checkStatus(true)) notice = applied ? 'Takedown lifted.' : 'Takedown applied.';
		} catch (err) {
			error = err instanceof Error ? err.message : 'Failed to update subject status';
		} finally {
			pending = false;
		}
	}
</script>

<div class="mt-6 border-t border-slate-800 pt-6">
	<h3 class="mb-2 text-sm font-medium text-slate-300">Record and blob takedowns</h3>
	<p class="mb-3 text-xs text-slate-500">
		A record is named by its <code class="font-mono">at://</code> URI. A blob needs both its CID and the
		DID that holds it, because identical bytes can belong to several accounts.
	</p>

	<div class="mb-4 flex gap-2">
		<button
			type="button"
			onclick={() => chooseKind('record')}
			class="rounded-lg border px-3 py-1.5 text-sm transition {kind === 'record'
				? 'border-emerald-700/60 text-emerald-300'
				: 'border-slate-700 text-slate-400 hover:border-slate-600 hover:text-white'}"
		>
			Record
		</button>
		<button
			type="button"
			onclick={() => chooseKind('blob')}
			class="rounded-lg border px-3 py-1.5 text-sm transition {kind === 'blob'
				? 'border-emerald-700/60 text-emerald-300'
				: 'border-slate-700 text-slate-400 hover:border-slate-600 hover:text-white'}"
		>
			Blob
		</button>
		<a
			href={resolve(`/repo${repoQuery}` as `/repo?${string}`)}
			class="ml-auto rounded-lg px-3 py-1.5 text-sm text-emerald-500 hover:text-emerald-400"
		>
			Open in repo browser →
		</a>
	</div>

	{#if kind === 'record'}
		<div class="flex flex-wrap items-end gap-3">
			<label class="min-w-80 flex-1 flex-col gap-1 text-xs text-slate-500">
				Record URI
				<input
					type="text"
					bind:value={recordUri}
					oninput={() => (recordCid = '')}
					placeholder="at://did:plc:…/app.bsky.feed.post/rkey"
					class="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 font-mono text-sm text-white placeholder-slate-500 outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
				/>
			</label>
			<label class="min-w-56 flex-col gap-1 text-xs text-slate-500">
				CID (filled from the record if blank)
				<input
					type="text"
					bind:value={recordCid}
					placeholder="bafy…"
					class="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 font-mono text-sm text-white placeholder-slate-500 outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
				/>
			</label>
		</div>
	{:else}
		<div class="flex flex-wrap items-end gap-3">
			<label class="min-w-80 flex-1 flex-col gap-1 text-xs text-slate-500">
				Blob CID
				<input
					type="text"
					bind:value={blobCid}
					placeholder="bafy…"
					class="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 font-mono text-sm text-white placeholder-slate-500 outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
				/>
			</label>
			<p class="pb-2 font-mono text-xs break-all text-slate-500">did: {did}</p>
		</div>
	{/if}

	<div class="mt-3 flex flex-wrap gap-2">
		<button
			type="button"
			onclick={() => void checkStatus()}
			disabled={pending}
			class="rounded-lg border border-slate-700 px-3 py-1.5 text-sm text-slate-300 transition hover:border-slate-600 hover:text-white disabled:opacity-50"
		>
			{pending ? 'Working…' : 'Check status'}
		</button>
		<button
			type="button"
			onclick={toggleTakedown}
			disabled={pending}
			class="rounded-lg border px-3 py-1.5 text-sm transition disabled:opacity-50 {status?.takedown
				?.applied
				? 'border-red-700/60 text-red-300 hover:border-red-600'
				: 'border-slate-700 text-slate-300 hover:border-slate-600 hover:text-white'}"
		>
			{status?.takedown?.applied ? 'Lift takedown' : 'Take down'}
		</button>
	</div>

	{#if status}
		<p class="mt-3 text-sm text-slate-300">
			Status: <span class="font-medium">{status.takedown?.applied ? 'taken down' : 'live'}</span>
			{#if status.takedown?.ref}
				<span class="text-slate-500">· ref {status.takedown.ref}</span>
			{/if}
		</p>
	{/if}

	{#if error}
		<p
			class="mt-3 rounded-lg border border-red-900/60 bg-red-950/40 px-4 py-2.5 text-sm text-red-300"
		>
			{error}
		</p>
	{/if}

	{#if notice}
		<p
			class="mt-3 rounded-lg border border-emerald-900/60 bg-emerald-950/40 px-4 py-2.5 text-sm text-emerald-300"
		>
			{notice}
		</p>
	{/if}
</div>

<script lang="ts">
	import { page } from '$app/stores';
	import ErrorView from '$lib/components/ErrorView.svelte';

	const { error, status } = $props();

	const title = $derived(
		status === 404 ? 'Page not found' : status === 500 ? 'Server error' : 'Something went wrong'
	);
</script>

<ErrorView {error} message={error?.message} {title} />

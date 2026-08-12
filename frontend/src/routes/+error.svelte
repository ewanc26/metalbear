<script lang="ts">
	import { page } from '$app/stores';
	import ErrorView from '$lib/components/ErrorView.svelte';

	const title = $derived(
		$page.status === 404
			? 'Page not found'
			: $page.status === 500
				? 'Server error'
				: 'Something went wrong'
	);
</script>

<ErrorView error={$page.error} message={$page.error?.message} {title} />

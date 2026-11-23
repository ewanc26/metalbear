/*
 * Date formatting fixed to ISO 8601 (YYYY-MM-DD) rather than
 * toLocaleDateString(): the latter renders differently per visitor's
 * browser/OS locale (date order, month names, separators), which is
 * confusing to compare across screenshots, support requests, and users.
 */
export function formatDate(unixSeconds: number): string {
	return new Date(unixSeconds * 1000).toISOString().slice(0, 10);
}

/* Blob metadata comes from getBlob's Content-Length header, so it is a byte
 * count with no unit attached. Keep the units stable for screenshots and
 * support conversations, like formatDate does for dates. */
export function formatBytes(bytes: number): string {
	if (!Number.isFinite(bytes) || bytes < 0) return '—';
	if (bytes < 1024) return `${bytes} B`;
	const units = ['KiB', 'MiB', 'GiB', 'TiB'];
	let value = bytes / 1024;
	let unit = 0;
	while (value >= 1024 && unit + 1 < units.length) {
		value /= 1024;
		unit++;
	}
	return `${value < 10 ? value.toFixed(1) : Math.round(value)} ${units[unit]}`;
}

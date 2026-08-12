/*
 * Date formatting fixed to ISO 8601 (YYYY-MM-DD) rather than
 * toLocaleDateString(): the latter renders differently per visitor's
 * browser/OS locale (date order, month names, separators), which is
 * confusing to compare across screenshots, support requests, and users.
 */
export function formatDate(unixSeconds: number): string {
	return new Date(unixSeconds * 1000).toISOString().slice(0, 10);
}

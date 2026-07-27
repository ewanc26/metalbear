/*
 * Fully prerendered: nginx serves the built files straight from disk, so
 * there is no Node process behind this page. Everything dynamic on it is
 * fetched in the browser from the PDS's own XRPC endpoints.
 */
export const prerender = true;
export const ssr = true;

/*
 * The browser owns this page's state: query parameters drive every view and
 * all data comes from public XRPC at runtime. Prerendering a server-rendered
 * shell would try to read url.searchParams, which SvelteKit deliberately does
 * not provide for prerendered pages. A client-only shell is still a static
 * file, so /repo?did=… works with the same frontend deployment as every other
 * route.
 */
export const prerender = true;
export const ssr = false;

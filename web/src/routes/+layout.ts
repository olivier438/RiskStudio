// Every page is prerendered into a static shell; data is fetched in the
// browser from the PHP API. Nothing needs a Node.js server in production.
export const prerender = true;
export const trailingSlash = 'always';

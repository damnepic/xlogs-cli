// HOSTS THAT EXIST ONLY IN DOCUMENTATION (2026-10-06). No imports, shared by the database detector
// (lib/live-supabase.mjs) and the backend-origin inventory (lib/origins.mjs), so a tutorial page is
// never described as an app that talks to a database.
//
// Exact names only, like the vendor sample keys in patterns.mjs: a pattern would hide real projects.
// Hosted Supabase project refs are twenty lowercase letters, so none of these can be a real project.
export const DOC_EXAMPLE_HOSTS = new Set([
  "xyzcompany.supabase.co",        // Supabase's own documentation example
  "your-project.supabase.co",
  "your-project-ref.supabase.co",
  "your-project-id.supabase.co",
  "project-ref.supabase.co",
  "your-ref.supabase.co",
]);

/** Accepts a host or a URL. */
export function isDocExampleHost(hostOrUrl) {
  let host = String(hostOrUrl || "").toLowerCase();
  try { if (/^https?:\/\//.test(host)) host = new URL(host).hostname; } catch { return false; }
  return DOC_EXAMPLE_HOSTS.has(host);
}

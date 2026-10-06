// THE PASTE-READY CATALOGUE AUDIT (XL-189).
//
// The live scan asks your database for rows as a stranger, which is the strongest evidence about
// what is exposed and is also, necessarily, limited to what a stranger can reach. The questions it
// cannot answer are the ones only the database itself knows: which tables exist at all, which have
// row level security switched on, what the policies actually say, and whether your storage buckets
// are public. Answering those needs a credential, and xlogs will not hold one.
//
// So the user runs it. This module produces SQL they paste into their own Supabase editor or hand
// to their own coding agent. xlogs never connects, never sees a connection string, and never stores
// a result. The findings from it are free, like every other finding.
//
// THE PROPERTY THAT MAKES THIS SAFE IS A PROPERTY OF THE SQL, NOT A PROMISE.
// Every statement reads from the PostgreSQL system catalogues (pg_catalog, information_schema) or
// from storage.buckets, which is metadata about buckets and not their contents. There is no
// statement that selects from an application table, so there is nothing to leak by running it:
// the output is names and settings, never rows of anybody's data. `assertReadOnly()` below proves
// that mechanically, and its test runs on every commit, so the property cannot quietly lapse.

export const CATALOGUE_SQL = `-- xlogs catalogue audit. READ-ONLY. Reads PostgreSQL system catalogues only.
-- It selects NOTHING from any application table, so running it cannot expose your data.
-- Paste into the Supabase SQL editor (or your own agent) and send the output back to yourself.

-- 1. Tables without row level security. Anything listed here is readable by whoever holds the
--    anon key, which in a browser app is everybody.
select
  n.nspname  as schema,
  c.relname  as table,
  c.relrowsecurity as rls_enabled,
  c.relforcerowsecurity as rls_forced
from pg_catalog.pg_class c
join pg_catalog.pg_namespace n on n.oid = c.relnamespace
where c.relkind = 'r'
  and n.nspname not in ('pg_catalog','information_schema','auth','storage','extensions','graphql','realtime','vault','supabase_migrations')
order by c.relrowsecurity asc, n.nspname, c.relname;

-- 2. Every policy, with its actual predicate. Look for "true" as a whole predicate, and for
--    predicates that check only that SOMEONE is signed in rather than WHICH someone.
select
  schemaname as schema,
  tablename  as table,
  policyname as policy,
  roles,
  cmd        as command,
  qual       as using_expression,
  with_check as with_check_expression
from pg_catalog.pg_policies
where schemaname not in ('pg_catalog','information_schema','auth','storage','extensions','graphql','realtime','vault','supabase_migrations')
order by schemaname, tablename, policyname;

-- 3. Tables with row level security ON but NO policy. This denies everyone, which is safe but is
--    usually an accident: it is the shape that breaks an app rather than exposes it.
select n.nspname as schema, c.relname as table
from pg_catalog.pg_class c
join pg_catalog.pg_namespace n on n.oid = c.relnamespace
where c.relkind = 'r'
  and c.relrowsecurity
  and n.nspname not in ('pg_catalog','information_schema','auth','storage','extensions','graphql','realtime','vault','supabase_migrations')
  and not exists (select 1 from pg_catalog.pg_policy p where p.polrelid = c.oid)
order by 1, 2;

-- 4. Storage buckets marked public. This is bucket METADATA, not the files in them.
select id, name, public, file_size_limit, allowed_mime_types
from storage.buckets
order by public desc, name;

-- 5. Functions that run as their owner rather than the caller. SECURITY DEFINER is legitimate and
--    common; it is also how a policy gets bypassed, so each one is worth being able to explain.
select
  n.nspname as schema,
  p.proname as function,
  p.prosecdef as security_definer
from pg_catalog.pg_proc p
join pg_catalog.pg_namespace n on n.oid = p.pronamespace
where p.prosecdef
  and n.nspname not in ('pg_catalog','information_schema','extensions','graphql','realtime','vault')
order by 1, 2;

-- 6. What the anon and authenticated roles have been granted directly. Table privileges sit
--    UNDERNEATH row level security: a grant here is what makes a policy the only thing in the way.
select table_schema as schema, table_name as table, grantee, privilege_type
from information_schema.role_table_grants
where grantee in ('anon','authenticated')
  and table_schema not in ('pg_catalog','information_schema','auth','storage','extensions','graphql','realtime','vault','supabase_migrations')
order by grantee, table_schema, table_name, privilege_type;
`;

// The schemas whose contents are Supabase's own machinery rather than the user's data.
const SYSTEM_SOURCES = [
  "pg_catalog.pg_class", "pg_catalog.pg_namespace", "pg_catalog.pg_policies", "pg_catalog.pg_policy",
  "pg_catalog.pg_proc", "information_schema.role_table_grants", "storage.buckets",
];

/**
 * PROVE the read-only property mechanically rather than asserting it in a comment.
 *
 * Two independent conditions, because either alone can be satisfied by accident:
 *   1. No statement writes. No insert, update, delete, drop, alter, create, grant, truncate, copy.
 *   2. Every FROM and JOIN source is a system catalogue on the allowlist above. A source that is
 *      not on the list fails, so adding a query against an application table cannot pass review by
 *      being small.
 *
 * @param {string} sql
 * @returns {{ok: boolean, problems: string[], sources: string[]}}
 */
export function assertReadOnly(sql = CATALOGUE_SQL) {
  const problems = [];
  // Comments carry the explanation, and the explanation legitimately contains words like "expose".
  const code = String(sql).replace(/--[^\n]*/g, " ").replace(/\/\*[\s\S]*?\*\//g, " ");

  const WRITES = /\b(insert\s+into|update\s+\w|delete\s+from|drop\s+\w|alter\s+\w|create\s+\w|grant\s+\w|revoke\s+\w|truncate|copy\s+\w|do\s+\$\$|call\s+\w)\b/gi;
  for (const m of code.matchAll(WRITES)) problems.push(`writes or executes: ${m[0].trim()}`);

  const sources = [];
  for (const m of code.matchAll(/\b(?:from|join)\s+([A-Za-z_][\w$]*(?:\s*\.\s*[A-Za-z_][\w$]*)?)/gi)) {
    const src = m[1].replace(/\s+/g, "").toLowerCase();
    // A correlated subquery alias (from pg_catalog.pg_policy p) resolves to its table, already
    // captured; bare single-word sources are the ones that need checking.
    sources.push(src);
    if (!SYSTEM_SOURCES.includes(src)) problems.push(`reads a source that is not a system catalogue: ${src}`);
  }
  if (!sources.length) problems.push("no source was found, so the audit could not be verified");

  return { ok: problems.length === 0, problems, sources: [...new Set(sources)].sort() };
}

// What each block answers, for the UI. Kept beside the SQL so a block cannot be added without a
// description, or described without existing.
export const CATALOGUE_BLOCKS = [
  { n: 1, title: "Tables without row level security", why: "Anything here is readable by whoever holds the anon key, which in a browser app is everybody." },
  { n: 2, title: "Every policy and its real predicate", why: "Look for a predicate of just \"true\", and for predicates that check only that someone is signed in rather than which someone." },
  { n: 3, title: "Row level security on, but no policy", why: "Denies everyone. Safe, but usually an accident: this shape breaks an app rather than exposing it." },
  { n: 4, title: "Public storage buckets", why: "Bucket metadata, not the files. A public bucket is a deliberate choice worth confirming." },
  { n: 5, title: "SECURITY DEFINER functions", why: "Legitimate and common, and also how a policy gets bypassed. Each one is worth being able to explain." },
  { n: 6, title: "Direct grants to anon and authenticated", why: "Table privileges sit underneath row level security. A grant here is what makes a policy the only thing in the way." },
];

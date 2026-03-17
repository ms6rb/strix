---
name: directory_bruteforce
description: Directory and path brute-forcing to discover hidden endpoints, admin panels, API routes, and debug interfaces
---

# Directory Brute-Force

Hidden paths are one of the richest attack surfaces in web applications. Admin panels, debug endpoints, API routes, and backup files are routinely exposed at predictable paths that never appear in the UI. Brute-force early, before testing anything else.

## Tool Selection

**ffuf** is preferred — fastest, most flexible filtering, native JSON output.
**dirsearch** is a solid fallback with built-in extension cycling.
**gobuster** is useful for DNS mode and when Go is the only runtime available.

## Wordlist Selection

Match the wordlist to the detected stack:

| Stack | Wordlist |
|---|---|
| General | `/usr/share/seclists/Discovery/Web-Content/raft-large-words.txt` |
| API-first | `/usr/share/seclists/Discovery/Web-Content/api/objects.txt` |
| Spring Boot | `/usr/share/seclists/Discovery/Web-Content/spring-boot.txt` |
| PHP/Laravel | `/usr/share/seclists/Discovery/Web-Content/CMS/WordPress.fuzz.txt` |
| Node/Express | `/usr/share/seclists/Discovery/Web-Content/nodejs.txt` |
| IIS/.NET | `/usr/share/seclists/Discovery/Web-Content/IIS.fuzz.txt` |

For unknown stacks, start with `raft-medium-directories.txt` then escalate to `raft-large-words.txt` on interesting paths.

## Command Patterns

**Basic discovery:**
```bash
ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -mc 200,301,302,401,403,500 -t 40 -o ffuf_root.json -of json
```

**With extensions (PHP/ASP targets):**
```bash
ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt \
  -e .php,.bak,.old,.txt,.config,.env -mc 200,301,302,401,403 -t 30
```

**API endpoint discovery:**
```bash
ffuf -u https://api.target.com/v1/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/objects.txt \
  -H "Authorization: Bearer TOKEN" -mc 200,201,400,401,403,405 -t 50
```

**Recursive (use sparingly — can be noisy):**
```bash
ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -recursion -recursion-depth 2 -mc 200,301,302,401,403 -t 20
```

**Rate-limited scan for sensitive targets:**
```bash
ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt \
  -mc 200,301,302,401,403 -rate 50 -t 10
```

**Dirsearch fallback:**
```bash
dirsearch -u https://target.com -e php,asp,aspx,jsp,json,bak,old,txt -t 20 --format json -o dirsearch.json
```

## Filtering Noise

Responses with identical sizes are usually catch-all 404s. Filter them out immediately:

```bash
# First, probe a known-dead path to find the baseline size
curl -s -o /dev/null -w "%{size_download}" https://target.com/definitely-does-not-exist-xyz123

# Then filter by that size
ffuf -u https://target.com/FUZZ -w wordlist.txt -fs 1234 -mc all
```

Additional filters:
- `-fw 10` — filter by word count (useful for dynamic "page not found" messages)
- `-fl 5` — filter by line count
- `-fc 404` — filter specific status codes
- `-fr "Not Found|Page does not exist"` — filter by response body regex

## Interpreting Results

| Status | Meaning | Action |
|---|---|---|
| 200 | Accessible | Investigate content, look for functionality |
| 301/302 | Redirect | Follow redirect, note destination |
| 401 | Auth required | Credential stuffing, default creds, bypass attempts |
| 403 | Access denied | Try path normalization, method override, header bypass |
| 500 | Server error | Note — may reveal stack info or indicate injection point |

**403 bypass attempts:**
```bash
# Path normalization
curl https://target.com/admin/../admin/
curl https://target.com/%61dmin/
curl https://target.com/admin/ -H "X-Original-URL: /admin"
curl https://target.com/admin/ -H "X-Rewrite-URL: /admin"
```

## High-Value Paths

Always check these regardless of wordlist hits:
- `/.env`, `/.env.local`, `/.env.production`
- `/api/`, `/api/v1/`, `/api/v2/`, `/graphql`, `/graphql/playground`
- `/admin/`, `/administrator/`, `/wp-admin/`, `/dashboard/`
- `/actuator/`, `/actuator/env`, `/actuator/beans` (Spring Boot)
- `/debug/`, `/__debug__/`, `/debug_toolbar/`
- `/.git/`, `/.git/config`, `/.svn/entries`
- `/backup/`, `/backup.zip`, `/db.sql`, `/dump.sql`
- `/swagger/`, `/swagger-ui.html`, `/api-docs`, `/openapi.json`

## Output

After completing the scan, use `create_note` to record structured findings:

```
Title: Directory Brute-Force — target.com

## Summary
- Tool: ffuf with raft-large-words.txt
- Paths tested: 50,000 | Interesting hits: 23

## API Endpoints
- /api/v1/ → 200 (authenticated)
- /api/v2/ → 200 (authenticated)
- /graphql → 200 (playground enabled — no auth)

## Admin / Management
- /admin/ → 302 → /admin/login
- /actuator/env → 403

## Docs / Specs
- /swagger-ui.html → 200 (public)
- /api-docs → 200 (full OpenAPI spec)

## Debug / Backup
- /.env → 403 (exists — attempt bypass)
- /backup.zip → 404

## Static / Other
- /assets/ → 200
- /uploads/ → 403

## Next Steps
- Test /graphql playground for introspection (unauthenticated)
- Pull OpenAPI spec from /api-docs for endpoint mapping
- Attempt 403 bypass on /actuator/env and /.env
```

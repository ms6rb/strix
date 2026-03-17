---
name: subdomain_enumeration
description: Subdomain enumeration via passive sources, certificate transparency, DNS brute-force, and live host validation
---

# Subdomain Enumeration

Subdomains expose separate attack surfaces: staging environments, internal tools, forgotten legacy apps, and misconfigured cloud storage. Enumerate broadly before focusing on any single target.

## Passive Enumeration

Passive sources don't touch the target. Run these first.

**subfinder (aggregates many passive sources):**
```bash
subfinder -d target.com -all -recursive -o subfinder_out.txt
subfinder -d target.com -all -o subfinder_out.txt -json | tee subfinder.json
```

**Certificate Transparency via crt.sh:**
```bash
# Query crt.sh directly
curl -s "https://crt.sh/?q=%25.target.com&output=json" | \
  jq -r '.[].name_value' | sort -u | grep -v '*' > crtsh_out.txt

# Combine with subfinder
cat subfinder_out.txt crtsh_out.txt | sort -u > passive_subs.txt
```

**DNS brute-force (active — generates DNS traffic):**
```bash
# Use puredns with a quality resolver list
puredns bruteforce /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt target.com \
  -r /opt/resolvers.txt -o dns_brute.txt

# Alternatively with shuffledns
shuffledns -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
  -r /opt/resolvers.txt -o shuffledns_out.txt
```

**Amass (comprehensive but slow):**
```bash
amass enum -passive -d target.com -o amass_passive.txt
amass enum -active -d target.com -o amass_active.txt
```

## Active Validation

Resolve and probe each candidate with httpx to confirm live hosts:

```bash
# Merge all passive results
cat passive_subs.txt dns_brute.txt amass_passive.txt 2>/dev/null | sort -u > all_subs.txt

# Probe for live HTTP/HTTPS services
httpx -l all_subs.txt -ports 80,443,8080,8443,8888,3000,4443 \
  -title -tech-detect -status-code -ip -cdn -o httpx_live.json

# Extract just the live URLs
httpx -l all_subs.txt -silent -o live_hosts.txt
```

## Scope Filtering

Cross-reference discovered subdomains with `scope_rules` before testing:

```bash
# Get in-scope patterns from the MCP tool, then filter
grep -iE "(app|api|staging|dev|admin|portal|internal)\.target\.com" all_subs.txt
```

Out-of-scope subdomains are still valuable for:
- Identifying technology stacks used company-wide
- Finding internal naming patterns (used for further brute-force)
- Subdomain takeover checks even when OOS for direct testing

## Cloud Asset Patterns

Cloud services follow predictable naming. Check these manually:

**AWS S3:**
```bash
# Common bucket naming patterns
for pattern in target target-prod target-staging target-assets target-backups target-uploads; do
  curl -s -I "https://${pattern}.s3.amazonaws.com" | head -2
done
```

**Azure Blob / Static Sites:**
- `target.blob.core.windows.net`
- `target.azurewebsites.net`
- `target.azurestaticapps.net`

**GCP:**
- `target.storage.googleapis.com`
- `target.appspot.com`

**Other:**
- `target.netlify.app`, `target.vercel.app`, `target.pages.dev`
- `target.github.io`, `target.gitlab.io`

## Subdomain Takeover Detection

A dangling CNAME points to a service where the underlying resource no longer exists.

```bash
# subjack scans for known takeover-vulnerable services
subjack -w all_subs.txt -t 100 -timeout 30 -o subjack_results.txt -ssl -v

# nuclei has takeover templates
nuclei -l live_hosts.txt -t /opt/nuclei-templates/takeovers/ -o takeover_findings.json
```

**Manual check for common services:**
```bash
# Check CNAME record
dig CNAME staging.target.com

# If CNAME points to e.g. target.ghost.io and returns NXDOMAIN → takeover candidate
nslookup target.ghost.io
```

Signs of a takeover-vulnerable subdomain:
- CNAME resolves to `*.github.io`, `*.ghost.io`, `*.s3.amazonaws.com`, `*.azurewebsites.net`, etc.
- The destination returns a 404 or "no such repository" / "bucket does not exist" page

## Interesting Subdomain Patterns

Prioritize subdomains matching these patterns for testing:
- `admin.`, `internal.`, `corp.`, `intranet.`, `portal.`
- `api.`, `api2.`, `rest.`, `graphql.`
- `staging.`, `stage.`, `uat.`, `qa.`, `dev.`, `test.`, `sandbox.`
- `vpn.`, `mail.`, `smtp.`, `jenkins.`, `jira.`, `confluence.`
- `status.`, `monitor.`, `metrics.`, `grafana.`, `kibana.`

## Output

Use `create_note` to record findings after validation:

```
Title: Subdomain Enumeration — target.com

## Stats
- Passive sources: subfinder + crt.sh → 312 candidates
- DNS brute-force: +47 additional
- Live hosts (httpx): 89 responding

## Live Subdomains — In Scope
| Subdomain | IP | Status | Tech |
|---|---|---|---|
| app.target.com | 1.2.3.4 | 200 | React, Nginx |
| api.target.com | 1.2.3.5 | 200 | Node.js |
| admin.target.com | 1.2.3.6 | 302→/login | PHP |
| staging.target.com | 1.2.3.7 | 200 | Same stack as prod |
| jenkins.target.com | 1.2.3.8 | 200 | Jenkins 2.387 |

## Cloud Assets
- target-uploads.s3.amazonaws.com → 200 (LIST enabled — bucket public!)
- target.blob.core.windows.net → 404

## Takeover Candidates
- legacy.target.com → CNAME → target.ghost.io → NXDOMAIN (investigate)

## Out-of-Scope (noted for context)
- mail.target.com, vpn.target.com (not in scope)

## Next Steps
- Test staging.target.com for weaker auth / debug features
- Check Jenkins for unauthenticated access / script console
- File S3 bucket exposure as a finding
- Investigate legacy.target.com takeover
```

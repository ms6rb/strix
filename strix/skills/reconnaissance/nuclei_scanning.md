---
name: nuclei_scanning
description: Automated vulnerability scanning with Nuclei templates — template selection, execution, result validation, and report filing
---

# Nuclei Scanning

Nuclei is a template-driven scanner that detects known vulnerabilities, misconfigurations, exposed panels, and technology fingerprints across large target sets. Use it systematically during Phase 0 recon and again after discovering new attack surfaces.

## Template Categories

| Category | Path | Use Case |
|---|---|---|
| `cves` | `nuclei-templates/cves/` | Known CVEs with public exploits |
| `exposures` | `nuclei-templates/exposures/` | Exposed files, configs, credentials |
| `misconfigurations` | `nuclei-templates/misconfigurations/` | Security header failures, open redirects |
| `vulnerabilities` | `nuclei-templates/vulnerabilities/` | App-level vulns (SQLi, SSRF, XSS) |
| `technologies` | `nuclei-templates/technologies/` | Tech fingerprinting |
| `default-logins` | `nuclei-templates/default-logins/` | Default credentials on admin panels |
| `takeovers` | `nuclei-templates/takeovers/` | Subdomain takeover detection |
| `network` | `nuclei-templates/network/` | Port-level service checks |

## Command Patterns

**Broad scan (all templates, one target):**
```bash
nuclei -u https://target.com -o nuclei_full.json -jsonl \
  -stats -retries 2 -t /opt/nuclei-templates/
```

**Targeted scan by category:**
```bash
# High-signal categories first
nuclei -u https://target.com \
  -t /opt/nuclei-templates/exposures/ \
  -t /opt/nuclei-templates/misconfigurations/ \
  -t /opt/nuclei-templates/default-logins/ \
  -o nuclei_targeted.json -jsonl

# CVE scan only
nuclei -u https://target.com -t /opt/nuclei-templates/cves/ \
  -severity critical,high -o nuclei_cves.json -jsonl
```

**Multi-target scan from subdomain list:**
```bash
nuclei -l live_hosts.txt \
  -t /opt/nuclei-templates/exposures/ \
  -t /opt/nuclei-templates/misconfigurations/ \
  -t /opt/nuclei-templates/technologies/ \
  -o nuclei_multi.json -jsonl -stats
```

**Rate-limited scan for sensitive targets:**
```bash
nuclei -u https://target.com -t /opt/nuclei-templates/ \
  -rate-limit 30 -concurrency 10 -bulk-size 10 \
  -o nuclei_ratelimited.json -jsonl
```

**Technology fingerprinting only (non-intrusive):**
```bash
nuclei -u https://target.com -t /opt/nuclei-templates/technologies/ \
  -o nuclei_tech.json -jsonl -silent
```

## Integration with `nuclei_scan` MCP Tool

The `nuclei_scan` MCP tool runs Nuclei inside the Docker sandbox and automatically files confirmed findings as vulnerability reports. Prefer this over manual execution when the sandbox is running:

```
nuclei_scan(
  target="https://target.com",
  templates=["exposures", "misconfigurations", "default-logins"],
  severity=["critical", "high", "medium"]
)
```

The tool:
1. Runs Nuclei with the specified templates
2. Parses JSONL output
3. Calls `create_vulnerability_report` for each confirmed finding
4. Returns a summary of filed reports

## Manual JSONL Parsing (fallback)

When running Nuclei manually via `terminal_execute`, parse the output yourself:

```bash
# Run scan and save JSONL
nuclei -u https://target.com -o nuclei_out.json -jsonl -t /opt/nuclei-templates/

# Parse results
cat nuclei_out.json | jq -r '. | select(.info.severity == "critical" or .info.severity == "high") |
  "[" + .info.severity + "] " + .info.name + " — " + .matched-at'

# Extract unique finding types
cat nuclei_out.json | jq -r '.info.name' | sort | uniq -c | sort -rn | head -20
```

**File reports for confirmed findings:**
For each real finding (after validation), use `create_vulnerability_report` with:
- Title from `nuclei_out.json[].info.name`
- Evidence from `nuclei_out.json[].matched-at` + `nuclei_out.json[].response`

## Validating True Positives

Nuclei has false positives. Always validate before filing:

**For exposures (config files, backups):**
```bash
# Manually fetch the URL and confirm sensitive content
curl -s "https://target.com/.env" | head -20
```

**For default credentials:**
```bash
# Replay the request manually
send_request(method="POST", url="https://target.com/admin/login",
  body={"username": "admin", "password": "admin"})
```

**For CVEs:**
- Check the server version against the CVE's affected range
- Try a PoC request and confirm the expected response
- Never file based on version fingerprint alone — confirm exploitability

**Common false positive sources:**
- Version-based CVE detections when the server header is wrong
- Exposure templates matching custom 404 pages that echo the path
- Default login templates against custom login pages
- Security header findings that are informational at best

## Interpreting Severity

| Nuclei Severity | Action |
|---|---|
| critical | Validate and file immediately |
| high | Validate before filing |
| medium | Validate; file if confirmed |
| low | Note in recon; low priority |
| info | Use for tech stack context only |

## Output

Use `create_note` to summarize scan results:

```
Title: Nuclei Scan — target.com

## Scan Config
- Templates: exposures, misconfigurations, default-logins, cves
- Severity filter: critical, high, medium
- Rate limit: 50 req/s

## Results Summary
- Templates executed: 1,847
- Findings: 12 total (2 critical, 4 high, 6 medium)
- Confirmed true positives: 8

## Filed Vulnerability Reports
1. [CRITICAL] Exposed .env file — /api/.env (DB credentials visible)
2. [CRITICAL] Redis unauthenticated access — :6379
3. [HIGH] Prometheus metrics exposed — :9090/metrics
4. [HIGH] Swagger UI exposed with no auth — /swagger-ui.html
5. [HIGH] Missing HSTS header — informational but policy requires it
6. [MEDIUM] Nginx version disclosure in Server header

## False Positives (not filed)
- CVE-2021-44228 Log4Shell: fingerprint matched but target is Node.js (not Java)
- Default creds for Grafana: custom login page, not Grafana

## Next Steps
- Enumerate OpenAPI spec via exposed Swagger UI
- Test Redis for session data / credential storage
- Review .env file contents for additional secrets
```

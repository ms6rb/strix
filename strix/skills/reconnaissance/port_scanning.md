---
name: port_scanning
description: Port scanning for exposed services, admin interfaces, dev servers, databases, and internal infrastructure
---

# Port Scanning

Web applications rarely live on ports 80 and 443 alone. Dev servers, metrics endpoints, databases, and admin dashboards are routinely reachable on non-standard ports — often without authentication. Port scanning during recon reveals these forgotten surfaces before any deeper testing.

## Scope and Rate Considerations

Always confirm the target IP range is in scope before scanning. Port scanning generates significant traffic — use `-T3` or lower for production hosts. Many bug bounty programs prohibit aggressive scanning; read the policy first.

```bash
# Resolve target to IP first
dig +short target.com
nslookup target.com
```

## Quick Top-1000 Scan

Fast initial sweep to find open ports without service detection:

```bash
nmap -sS -T3 --top-ports 1000 -oN nmap_quick.txt 1.2.3.4

# For web targets — focus on common web/app ports
nmap -sS -T3 -p 80,443,8080,8443,8888,3000,4000,4443,5000,9000,9090 \
  --open -oN nmap_web.txt 1.2.3.4
```

## Service Detection Scan

Once open ports are identified, detect versions and run default scripts:

```bash
# Full service + script scan on discovered ports
nmap -sV -sC -p 22,80,443,8080,8443,3000 -oN nmap_services.txt 1.2.3.4

# Aggressive detection on a single port
nmap -sV --version-intensity 9 -p 8080 1.2.3.4

# UDP scan for common services (slower)
nmap -sU -T3 -p 53,67,123,161,500 1.2.3.4
```

## Broader Port Range

For thorough coverage when time permits:

```bash
# All 65535 TCP ports (slow — use sparingly)
nmap -sS -T2 -p- --open -oN nmap_full.txt 1.2.3.4

# Masscan for speed on large ranges (use carefully)
masscan 1.2.3.4 -p1-65535 --rate=1000 -oL masscan_out.txt
```

## Common Interesting Ports

| Port | Service | Why It Matters |
|---|---|---|
| 3000 | Node.js / Grafana | Dev server, Grafana unauthenticated |
| 4000 | Various dev servers | Often dev/staging with debug enabled |
| 4200 | Angular dev server | Source maps, full debug mode |
| 5000 | Flask / Docker Registry | Debug mode common, registry auth issues |
| 5432 | PostgreSQL | Unauthenticated access or weak creds |
| 6379 | Redis | Often unauthenticated, full RW access |
| 8080 | HTTP alt / Tomcat | Manager console, Jenkins, default apps |
| 8443 | HTTPS alt | Often dev/admin interfaces |
| 8888 | Jupyter Notebook | Frequently unauthenticated |
| 9000 | SonarQube / PHP-FPM | Admin panels, code quality dashboards |
| 9090 | Prometheus | Metrics exposure, target configuration |
| 9200 | Elasticsearch | Unauthenticated read/write on older versions |
| 9300 | Elasticsearch (cluster) | Internal transport — should never be public |
| 2375 | Docker daemon (HTTP) | Full container control without auth |
| 2376 | Docker daemon (TLS) | Container control with TLS |
| 10250 | Kubernetes kubelet | Exec into pods, read secrets |
| 10255 | Kubernetes kubelet (RO) | Pod/node info, environment variables |
| 2379 | etcd | Kubernetes secrets store, often unauthenticated |
| 11211 | Memcached | Usually unauthenticated |
| 27017 | MongoDB | Often unauthenticated on older deployments |

## Acting on Findings

**Unauthenticated services:**
```bash
# Redis — check if auth required
redis-cli -h 1.2.3.4 ping
redis-cli -h 1.2.3.4 info server
redis-cli -h 1.2.3.4 keys '*'

# MongoDB — unauthenticated connection
mongo 1.2.3.4:27017 --eval "db.adminCommand('listDatabases')"

# Elasticsearch — check for open access
curl http://1.2.3.4:9200/_cat/indices?v
curl http://1.2.3.4:9200/_cluster/health
```

**Docker daemon exposure:**
```bash
curl http://1.2.3.4:2375/version
curl http://1.2.3.4:2375/containers/json
# If accessible: full container control, host escape potential
```

**Prometheus metrics (info disclosure):**
```bash
curl http://1.2.3.4:9090/metrics
curl http://1.2.3.4:9090/targets  # May expose internal service IPs
```

**Jupyter Notebook:**
```bash
curl http://1.2.3.4:8888/api/kernels
# If accessible without token: arbitrary code execution on the host
```

**Kubernetes kubelet:**
```bash
curl -k https://1.2.3.4:10250/pods
curl -k https://1.2.3.4:10255/pods  # Read-only port
# Pod exec (kubelet RCE):
curl -k https://1.2.3.4:10250/run/default/pod-name/container-name \
  -d "cmd=id"
```

## Output

Use `create_note` to document port scan results:

```
Title: Port Scan — 1.2.3.4 (target.com)

## Scan Summary
- Quick scan: nmap top-1000 + targeted web ports
- Full scan: -p- TCP (completed)

## Open Ports
| Port | Service | Version | Notes |
|---|---|---|---|
| 22 | SSH | OpenSSH 8.9p1 | Standard |
| 80 | HTTP | Nginx 1.24 | Redirects to 443 |
| 443 | HTTPS | Nginx 1.24 | Main app |
| 6379 | Redis | 7.0.8 | NO AUTH — file finding |
| 9090 | HTTP | Prometheus 2.42 | Metrics exposed — no auth |
| 9200 | HTTP | Elasticsearch 7.17 | Unauthenticated — check indices |

## Critical Findings
- Redis on :6379 — no authentication, full access (immediate report)
- Prometheus on :9090 — metrics + /targets exposed (info disclosure)
- Elasticsearch on :9200 — unauthenticated, checking for sensitive data

## Next Steps
- File Redis as critical: unauthenticated access
- Enumerate Elasticsearch indices for PII
- Check Prometheus /targets for internal service discovery
```

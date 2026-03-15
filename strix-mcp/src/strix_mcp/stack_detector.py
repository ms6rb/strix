"""Stack detection and scan plan generation.

Pure-logic module that parses raw string signals from container commands
and returns structured stack information and a scan plan.
"""

from __future__ import annotations

import json
import re
from typing import Any


# ---------------------------------------------------------------------------
# Module rules: trigger -> list of recommended security modules
# ---------------------------------------------------------------------------
MODULE_RULES: dict[str, list[str]] = {
    "always": ["idor", "business_logic", "authentication_jwt"],
    "sql": ["sql_injection"],
    "postgresql": ["sql_injection"],
    "mysql": ["sql_injection"],
    "sqlite": ["sql_injection"],
    "nestjs": ["nestjs", "mass_assignment"],
    "fastapi": ["fastapi", "mass_assignment"],
    "nextjs": ["nextjs", "ssrf"],
    "file_upload": ["insecure_file_uploads", "path_traversal_lfi_rfi"],
    "graphql": ["graphql"],
    "firebase": ["firebase_firestore"],
    "supabase": ["supabase"],
    "django": ["csrf", "mass_assignment", "authentication_jwt"],
    "flask": ["authentication_jwt", "mass_assignment"],
    "laravel": ["csrf", "mass_assignment", "sql_injection"],
    "wordpress": ["xss", "sql_injection", "authentication_jwt", "path_traversal_lfi_rfi"],
    "rails": ["csrf", "mass_assignment", "sql_injection"],
    "express": ["authentication_jwt", "mass_assignment"],
    "domain": ["subdomain_takeover"],
    "web_app": [
        "xss",
        "csrf",
        "ssrf",
        "xxe",
        "rce",
        "race_conditions",
        "broken_function_level_authorization",
        "information_disclosure",
        "open_redirect",
        "path_traversal_lfi_rfi",
    ],
}

# ---------------------------------------------------------------------------
# Agent templates
# ---------------------------------------------------------------------------
_AGENT_TEMPLATES: list[dict[str, Any]] = [
    {
        "task": "Test authentication and JWT security",
        "modules": ["authentication_jwt"],
        "priority": "high",
        "triggers": ["always"],
        "signal_strength": "generic",
    },
    {
        "task": "Test authorization, IDOR, and access control",
        "modules": ["idor", "broken_function_level_authorization"],
        "priority": "high",
        "triggers": ["always"],
        "signal_strength": "generic",
    },
    {
        "task": "Test business logic and mass assignment",
        "modules": ["business_logic", "mass_assignment"],
        "priority": "high",
        "triggers": ["always"],
        "signal_strength": "generic",
    },
    {
        "task": "Test injection vectors (SQLi, XSS, SSRF, XXE)",
        "modules": ["sql_injection", "xss", "ssrf", "xxe"],
        "priority": "medium",
        "triggers": ["web_app"],
        "signal_strength": "generic",
    },
    {
        "task": "Test file uploads and path traversal",
        "modules": ["insecure_file_uploads", "path_traversal_lfi_rfi"],
        "priority": "medium",
        "triggers": ["file_upload"],
        "signal_strength": "specific",
    },
    {
        "task": "Test race conditions and CSRF",
        "modules": ["race_conditions", "csrf"],
        "priority": "medium",
        "triggers": ["web_app"],
        "signal_strength": "generic",
    },
    {
        "task": "Test RCE vectors",
        "modules": ["rce"],
        "priority": "medium",
        "triggers": ["web_app"],
        "signal_strength": "generic",
    },
    {
        "task": "Test FastAPI-specific vulnerabilities (dependency injection, Pydantic bypass, middleware issues)",
        "modules": ["fastapi"],
        "priority": "high",
        "triggers": ["fastapi"],
        "signal_strength": "specific",
    },
    {
        "task": "Test Next.js-specific vulnerabilities (SSR injection, API routes, middleware bypass)",
        "modules": ["nextjs"],
        "priority": "high",
        "triggers": ["nextjs"],
        "signal_strength": "specific",
    },
    {
        "task": "Test GraphQL-specific vulnerabilities",
        "modules": ["graphql", "idor"],
        "priority": "high",
        "triggers": ["graphql"],
        "signal_strength": "specific",
    },
    {
        "task": "Test Firebase/Firestore security rules",
        "modules": ["firebase_firestore"],
        "priority": "high",
        "triggers": ["firebase"],
        "signal_strength": "specific",
    },
    {
        "task": "Test Supabase RLS and auth",
        "modules": ["supabase"],
        "priority": "high",
        "triggers": ["supabase"],
        "signal_strength": "specific",
    },
    {
        "task": "Test NestJS-specific vulnerabilities (guard bypass, validation pipes, module boundaries, cross-transport auth)",
        "modules": ["nestjs", "mass_assignment"],
        "priority": "high",
        "triggers": ["nestjs"],
        "signal_strength": "specific",
    },
    {
        "task": "Test information disclosure, security headers, and open redirects",
        "modules": ["information_disclosure", "open_redirect"],
        "priority": "medium",
        "triggers": ["web_app"],
        "signal_strength": "generic",
    },
    {
        "task": "Test path traversal and file inclusion (LFI/RFI)",
        "modules": ["path_traversal_lfi_rfi"],
        "priority": "medium",
        "triggers": ["web_app"],
        "signal_strength": "generic",
    },
    {
        "task": "Test subdomain takeover vulnerabilities",
        "modules": ["subdomain_takeover"],
        "priority": "medium",
        "triggers": ["domain"],
        "signal_strength": "specific",
    },
    {
        "task": "Test Django-specific vulnerabilities (ORM injection, CSRF bypass, template injection, admin panel, serialization)",
        "modules": ["csrf", "mass_assignment", "authentication_jwt", "sql_injection"],
        "priority": "high",
        "triggers": ["django"],
        "signal_strength": "specific",
    },
    {
        "task": "Test WordPress-specific vulnerabilities (plugin/theme exploits, SQLi, XSS, auth bypass, file upload abuse)",
        "modules": ["xss", "sql_injection", "authentication_jwt", "path_traversal_lfi_rfi", "insecure_file_uploads"],
        "priority": "high",
        "triggers": ["wordpress"],
        "signal_strength": "specific",
    },
    {
        "task": "Test Laravel-specific vulnerabilities (mass assignment, CSRF bypass, Eloquent injection, debug mode exposure)",
        "modules": ["csrf", "mass_assignment", "sql_injection", "information_disclosure"],
        "priority": "high",
        "triggers": ["laravel"],
        "signal_strength": "specific",
    },
    {
        "task": "Test Rails-specific vulnerabilities (mass assignment, CSRF bypass, ActiveRecord injection, deserialization)",
        "modules": ["csrf", "mass_assignment", "sql_injection"],
        "priority": "high",
        "triggers": ["rails"],
        "signal_strength": "specific",
    },
    {
        "task": "Test Express.js-specific vulnerabilities (middleware bypass, prototype pollution, NoSQL injection, session handling)",
        "modules": ["authentication_jwt", "mass_assignment", "business_logic"],
        "priority": "high",
        "triggers": ["express"],
        "signal_strength": "specific",
    },
]


# ---------------------------------------------------------------------------
# detect_stack
# ---------------------------------------------------------------------------
def detect_stack(signals: dict[str, str]) -> dict[str, Any]:
    """Parse raw string signals and return structured stack information.

    Parameters
    ----------
    signals:
        Dict with keys ``package_json``, ``requirements``, ``pyproject``,
        ``go_mod``, ``env_files``, ``structure``.  Each value is a raw
        string (file contents, possibly empty or containing errors).

    Returns
    -------
    dict with keys ``runtime``, ``framework``, ``database``, ``auth``,
    ``features``, ``api_style``, ``infrastructure`` — each a ``list[str]``.
    """
    runtime: list[str] = []
    framework: list[str] = []
    database: list[str] = []
    auth: list[str] = []
    features: list[str] = []
    infrastructure: list[str] = []

    # -- package.json ---------------------------------------------------------
    pkg = signals.get("package_json", "")
    if pkg.strip():
        _detect_package_json(pkg, runtime, framework, database, auth, features)

    # -- requirements.txt / pyproject.toml ------------------------------------
    reqs = signals.get("requirements", "")
    pyproj = signals.get("pyproject", "")
    python_text = f"{reqs}\n{pyproj}"
    if python_text.strip():
        _detect_python(python_text, runtime, framework, database, auth, features)

    # -- go.mod ---------------------------------------------------------------
    go_mod = signals.get("go_mod", "")
    if go_mod.strip():
        _detect_go(go_mod, runtime, framework, database, auth)

    # -- .env files -----------------------------------------------------------
    env_files = signals.get("env_files", "")
    if env_files.strip():
        _detect_env(env_files, database, auth, infrastructure)

    # -- file structure -------------------------------------------------------
    structure = signals.get("structure", "")
    if structure.strip():
        _detect_structure(structure, features)

    # -- api_style inference --------------------------------------------------
    api_style: list[str] = []
    if "graphql" in features:
        api_style.append("graphql")
    if "grpc" in features:
        api_style.append("grpc")
    if not api_style:
        api_style.append("rest")

    return {
        "runtime": _dedup(runtime),
        "framework": _dedup(framework),
        "database": _dedup(database),
        "auth": _dedup(auth),
        "features": _dedup(features),
        "api_style": _dedup(api_style),
        "infrastructure": _dedup(infrastructure),
    }


# ---------------------------------------------------------------------------
# generate_plan
# ---------------------------------------------------------------------------
# Triggers that are only reliable when confirmed by HTTP probes
_PROBE_CONFIRMED_TRIGGERS = {"graphql", "swagger", "file_upload", "spring_actuator",
                              "env_exposed", "wordpress_admin", "nextjs_data"}


def generate_plan(
    stack: dict[str, Any],
    probe_results: str | None = None,
) -> list[dict[str, Any]]:
    """Generate a list of agent assignments from a detected stack.

    Parameters
    ----------
    stack:
        Output of :func:`detect_stack` or :func:`detect_stack_from_http`.
    probe_results:
        Raw probe results string (e.g. "/graphql: 200\\n/.env: 404").
        When provided, used to verify probe-dependent detections.
        When empty string, probe-dependent templates are downgraded to low confidence.
        When None (default), probe status is unknown — no downgrade applied.
    """
    # Build active triggers
    active_triggers: set[str] = {"always", "web_app"}
    for key in ("runtime", "framework", "database", "auth", "features", "infrastructure"):
        active_triggers.update(stack.get(key, []))
    # Include target-type triggers passed through stack metadata
    active_triggers.update(stack.get("target_types", []))

    # Determine if probes were stale
    probes_were_stale = probe_results is not None and not probe_results.strip()

    # Build the set of all recommended modules from active triggers
    recommended_modules: set[str] = set()
    for trigger in active_triggers:
        recommended_modules.update(MODULE_RULES.get(trigger, []))

    plan: list[dict[str, Any]] = []
    for template in _AGENT_TEMPLATES:
        # Include template only if any of its triggers are active
        if not any(t in active_triggers for t in template["triggers"]):
            continue

        # Filter modules to only those in recommended set
        filtered_modules = [m for m in template["modules"] if m in recommended_modules]
        if not filtered_modules:
            continue

        # Determine confidence
        if template.get("signal_strength") == "specific":
            # Check if any trigger depends on probe confirmation
            probe_dependent = any(t in _PROBE_CONFIRMED_TRIGGERS for t in template["triggers"])
            if probe_dependent and probes_were_stale:
                confidence = "low"
            else:
                confidence = "high"
        else:
            confidence = "medium"

        plan.append({
            "task": template["task"],
            "modules": filtered_modules,
            "priority": template["priority"],
            "confidence": confidence,
        })

    return plan


# ---------------------------------------------------------------------------
# Internal detection helpers
# ---------------------------------------------------------------------------
def _dedup(lst: list[str]) -> list[str]:
    """Return a deduplicated list preserving insertion order."""
    seen: set[str] = set()
    result: list[str] = []
    for item in lst:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def _has_dep(text: str, name: str) -> bool:
    """Check whether *name* appears as a dependency in text (case-insensitive)."""
    return name.lower() in text.lower()


def _detect_package_json(
    raw: str,
    runtime: list[str],
    framework: list[str],
    database: list[str],
    auth: list[str],
    features: list[str],
) -> None:
    """Detect stack from package.json content."""
    # Try JSON parse first; fall back to raw text search
    try:
        data = json.loads(raw)
        # Combine all dependency sections into a set of exact package names
        deps: dict[str, Any] = {}
        for section in ("dependencies", "devDependencies", "peerDependencies"):
            deps.update(data.get(section, {}))
        dep_keys: set[str] = {k.lower() for k in deps}
        _detect_package_json_exact(dep_keys, runtime, framework, database, auth, features)
    except (json.JSONDecodeError, AttributeError):
        _detect_package_json_fuzzy(raw, runtime, framework, database, auth, features)


def _has_exact_dep(dep_keys: set[str], name: str) -> bool:
    """Check whether *name* matches exactly in the dependency key set."""
    return name.lower() in dep_keys


def _has_prefix_dep(dep_keys: set[str], prefix: str) -> bool:
    """Check whether any dependency key starts with *prefix* (case-insensitive)."""
    prefix_lower = prefix.lower()
    return any(k.startswith(prefix_lower) for k in dep_keys)


def _detect_package_json_exact(
    dep_keys: set[str],
    runtime: list[str],
    framework: list[str],
    database: list[str],
    auth: list[str],
    features: list[str],
) -> None:
    """Detect stack from parsed package.json dependency keys (exact matching)."""
    found_any = False

    # Framework
    if _has_exact_dep(dep_keys, "@nestjs/core") or _has_exact_dep(dep_keys, "@nestjs/common"):
        framework.append("nestjs")
        found_any = True
    if _has_exact_dep(dep_keys, "express"):
        framework.append("express")
        found_any = True
    if _has_exact_dep(dep_keys, "next"):
        framework.append("nextjs")
        found_any = True
    if _has_exact_dep(dep_keys, "fastify"):
        framework.append("fastify")
        found_any = True

    # Database
    if _has_exact_dep(dep_keys, "mongoose") or _has_exact_dep(dep_keys, "mongodb"):
        database.append("mongodb")
        found_any = True
    if _has_exact_dep(dep_keys, "typeorm") or _has_exact_dep(dep_keys, "prisma") or _has_exact_dep(dep_keys, "sequelize"):
        database.append("sql")
        found_any = True
    if _has_exact_dep(dep_keys, "pg"):
        database.append("postgresql")
        found_any = True
    if _has_exact_dep(dep_keys, "mysql2"):
        database.append("mysql")
        found_any = True
    if _has_exact_dep(dep_keys, "better-sqlite3"):
        database.append("sqlite")
        found_any = True
    if _has_exact_dep(dep_keys, "ioredis") or _has_exact_dep(dep_keys, "redis") or _has_exact_dep(dep_keys, "@redis/client"):
        database.append("redis")
        found_any = True
    if _has_exact_dep(dep_keys, "@supabase/supabase-js"):
        database.append("supabase")
        found_any = True

    # Auth
    if _has_exact_dep(dep_keys, "@nestjs/jwt") or _has_exact_dep(dep_keys, "jsonwebtoken"):
        auth.append("jwt")
        found_any = True
    if _has_exact_dep(dep_keys, "passport"):
        auth.append("passport")
        found_any = True
    if _has_prefix_dep(dep_keys, "@auth0/"):
        auth.append("auth0")
        found_any = True
    if _has_exact_dep(dep_keys, "firebase-admin"):
        auth.append("firebase")
        found_any = True
    if _has_exact_dep(dep_keys, "@supabase/supabase-js"):
        auth.append("supabase")
        found_any = True

    # Features
    if _has_exact_dep(dep_keys, "multer"):
        features.append("file_upload")
        found_any = True
    if (
        _has_exact_dep(dep_keys, "@nestjs/platform-socket.io")
        or _has_exact_dep(dep_keys, "socket.io")
        or _has_exact_dep(dep_keys, "ws")
    ):
        features.append("websocket")
        found_any = True
    if (
        _has_exact_dep(dep_keys, "@nestjs/graphql")
        or _has_exact_dep(dep_keys, "type-graphql")
        or _has_exact_dep(dep_keys, "graphql")
    ):
        features.append("graphql")
        found_any = True
    if _has_exact_dep(dep_keys, "@grpc/grpc-js"):
        features.append("grpc")
        found_any = True

    if found_any or dep_keys:
        runtime.append("node")


def _detect_package_json_fuzzy(
    text: str,
    runtime: list[str],
    framework: list[str],
    database: list[str],
    auth: list[str],
    features: list[str],
) -> None:
    """Detect stack from raw package.json text (substring fallback when JSON parsing fails)."""
    found_any = False

    # Framework
    if _has_dep(text, "@nestjs/core") or _has_dep(text, "@nestjs/common"):
        framework.append("nestjs")
        found_any = True
    if re.search(r'["\s]express["\s,@:]', text, re.IGNORECASE):
        framework.append("express")
        found_any = True
    if re.search(r'["\s]next["\s,@:]', text, re.IGNORECASE):
        framework.append("nextjs")
        found_any = True
    if _has_dep(text, "fastify"):
        framework.append("fastify")
        found_any = True

    # Database
    if _has_dep(text, "mongoose") or _has_dep(text, "mongodb"):
        database.append("mongodb")
        found_any = True
    if _has_dep(text, "typeorm") or _has_dep(text, "prisma") or _has_dep(text, "sequelize"):
        database.append("sql")
        found_any = True
    if re.search(r'["\s]pg["\s,@]', text, re.IGNORECASE):
        database.append("postgresql")
        found_any = True
    if _has_dep(text, "mysql2"):
        database.append("mysql")
        found_any = True
    if _has_dep(text, "better-sqlite3"):
        database.append("sqlite")
        found_any = True
    if _has_dep(text, "ioredis") or _has_dep(text, "@redis/client") or re.search(r'["\s]redis["\s,@:]', text, re.IGNORECASE):
        database.append("redis")
        found_any = True
    if _has_dep(text, "@supabase/supabase-js"):
        database.append("supabase")
        found_any = True

    # Auth
    if _has_dep(text, "@nestjs/jwt") or _has_dep(text, "jsonwebtoken"):
        auth.append("jwt")
        found_any = True
    if _has_dep(text, "passport"):
        auth.append("passport")
        found_any = True
    if _has_dep(text, "@auth0/"):
        auth.append("auth0")
        found_any = True
    if _has_dep(text, "firebase-admin"):
        auth.append("firebase")
        found_any = True
    if _has_dep(text, "@supabase/supabase-js"):
        auth.append("supabase")
        found_any = True

    # Features
    if _has_dep(text, "multer"):
        features.append("file_upload")
        found_any = True
    if (
        _has_dep(text, "@nestjs/platform-socket.io")
        or _has_dep(text, "socket.io")
        or re.search(r'["\s]ws["\s,@]', text, re.IGNORECASE)
    ):
        features.append("websocket")
        found_any = True
    if (
        _has_dep(text, "@nestjs/graphql")
        or _has_dep(text, "type-graphql")
        or _has_dep(text, "graphql")
    ):
        features.append("graphql")
        found_any = True
    if _has_dep(text, "@grpc/grpc-js"):
        features.append("grpc")
        found_any = True

    if found_any:
        runtime.append("node")


def _detect_python(
    text: str,
    runtime: list[str],
    framework: list[str],
    database: list[str],
    auth: list[str],
    features: list[str],
) -> None:
    """Detect stack from requirements.txt / pyproject.toml content."""
    found_any = False

    # Framework
    if _has_dep(text, "fastapi"):
        framework.append("fastapi")
        found_any = True
    if _has_dep(text, "django"):
        framework.append("django")
        found_any = True
    if _has_dep(text, "flask"):
        framework.append("flask")
        found_any = True

    # Database
    if _has_dep(text, "sqlalchemy"):
        database.append("sql")
        found_any = True
    if _has_dep(text, "psycopg"):
        database.append("postgresql")
        found_any = True
    if _has_dep(text, "pymongo") or _has_dep(text, "motor"):
        database.append("mongodb")
        found_any = True
    if _has_dep(text, "redis"):
        database.append("redis")
        found_any = True

    # Auth
    if _has_dep(text, "pyjwt") or _has_dep(text, "python-jose") or _has_dep(text, "authlib"):
        auth.append("jwt")
        found_any = True
    if _has_dep(text, "firebase-admin"):
        auth.append("firebase")
        found_any = True

    # Features
    if _has_dep(text, "python-multipart"):
        features.append("file_upload")
        found_any = True
    if (
        _has_dep(text, "strawberry-graphql")
        or _has_dep(text, "ariadne")
        or _has_dep(text, "graphene")
    ):
        features.append("graphql")
        found_any = True
    if _has_dep(text, "grpcio"):
        features.append("grpc")
        found_any = True

    if found_any:
        runtime.append("python")


def _detect_go(
    text: str,
    runtime: list[str],
    framework: list[str],
    database: list[str],
    auth: list[str],
) -> None:
    """Detect stack from go.mod content."""
    found_any = False

    # Framework
    if "github.com/gin-gonic/gin" in text:
        framework.append("gin")
        found_any = True
    if "github.com/labstack/echo" in text:
        framework.append("echo")
        found_any = True
    if "github.com/gofiber/fiber" in text:
        framework.append("fiber")
        found_any = True

    # Auth
    if "github.com/golang-jwt/jwt" in text:
        auth.append("jwt")
        found_any = True

    # Database
    if "go.mongodb.org/mongo-driver" in text:
        database.append("mongodb")
        found_any = True
    if "gorm.io/gorm" in text:
        database.append("sql")
        found_any = True

    if found_any:
        runtime.append("go")


def _detect_env(
    text: str,
    database: list[str],
    auth: list[str],
    infrastructure: list[str],
) -> None:
    """Detect stack from .env file content."""
    # Database
    if re.search(r"MONGO", text, re.IGNORECASE):
        database.append("mongodb")
    if re.search(r"DATABASE_URL\s*=\s*postgres", text, re.IGNORECASE):
        database.append("postgresql")
    if re.search(r"DATABASE_URL\s*=\s*mysql", text, re.IGNORECASE):
        database.append("mysql")
    if re.search(r"REDIS_URL|REDIS_HOST", text, re.IGNORECASE):
        database.append("redis")

    # Auth
    if re.search(r"JWT_SECRET|JWT_KEY", text, re.IGNORECASE):
        auth.append("jwt")
    if re.search(r"AUTH0_DOMAIN|AUTH0_CLIENT", text, re.IGNORECASE):
        auth.append("auth0")
    if re.search(r"FIREBASE", text, re.IGNORECASE):
        auth.append("firebase")
    if re.search(r"SUPABASE", text, re.IGNORECASE):
        auth.append("supabase")

    # Infrastructure
    if re.search(r"AWS_ACCESS_KEY|AWS_REGION", text, re.IGNORECASE):
        infrastructure.append("aws")
    if re.search(r"GOOGLE_CLOUD|GCP_PROJECT", text, re.IGNORECASE):
        infrastructure.append("gcp")


def _detect_structure(text: str, features: list[str]) -> None:
    """Detect features from file structure listing."""
    if re.search(r"\.graphql\b|\.gql\b", text, re.IGNORECASE):
        features.append("graphql")
    if re.search(r"\.proto\b", text, re.IGNORECASE):
        features.append("grpc")


# ---------------------------------------------------------------------------
# HTTP-based stack detection (for web-only targets)
# ---------------------------------------------------------------------------
def detect_stack_from_http(signals: dict[str, str]) -> dict[str, Any]:
    """Parse HTTP response signals and return structured stack information.

    Parameters
    ----------
    signals:
        Dict with optional keys: ``headers`` (raw response headers),
        ``cookies`` (raw Set-Cookie values), ``body_signals`` (HTML snippets),
        ``probe_results`` (results of probing common paths like /graphql).

    Returns
    -------
    Same structure as :func:`detect_stack`.
    """
    runtime: list[str] = []
    framework: list[str] = []
    database: list[str] = []
    auth: list[str] = []
    features: list[str] = []
    infrastructure: list[str] = []

    headers = signals.get("headers", "").lower()
    cookies = signals.get("cookies", "").lower()
    body = signals.get("body_signals", "").lower()
    probes = signals.get("probe_results", "").lower()

    _detect_http_headers(headers, runtime, framework, infrastructure)
    _detect_http_cookies(cookies, runtime, framework, auth)
    _detect_http_body(body, framework, features)
    _detect_http_probes(probes, features)

    api_style: list[str] = []
    if "graphql" in features:
        api_style.append("graphql")
    if "grpc" in features:
        api_style.append("grpc")
    if not api_style:
        api_style.append("rest")

    return {
        "runtime": _dedup(runtime),
        "framework": _dedup(framework),
        "database": _dedup(database),
        "auth": _dedup(auth),
        "features": _dedup(features),
        "api_style": _dedup(api_style),
        "infrastructure": _dedup(infrastructure),
    }


def _detect_http_headers(
    headers: str,
    runtime: list[str],
    framework: list[str],
    infrastructure: list[str],
) -> None:
    """Detect stack from HTTP response headers."""
    if "x-powered-by: php" in headers or "php/" in headers:
        runtime.append("php")
    if "x-aspnet-version" in headers or "asp.net" in headers:
        runtime.append("dotnet")
    if "x-powered-by: express" in headers:
        runtime.append("node")
        framework.append("express")
    if "x-powered-by: next.js" in headers or "x-nextjs" in headers:
        runtime.append("node")
        framework.append("nextjs")

    if "server: nginx" in headers:
        infrastructure.append("nginx")
    if "server: apache" in headers:
        infrastructure.append("apache")
    if "server: microsoft-iis" in headers:
        infrastructure.append("iis")
    if "server: cloudflare" in headers or "cf-ray" in headers:
        infrastructure.append("cloudflare")

    if "x-amz-" in headers or "x-amzn-" in headers:
        infrastructure.append("aws")
    if "x-goog-" in headers or "x-cloud-trace" in headers:
        infrastructure.append("gcp")
    if "x-azure-" in headers or "x-ms-" in headers:
        infrastructure.append("azure")


def _detect_http_cookies(
    cookies: str,
    runtime: list[str],
    framework: list[str],
    auth: list[str],
) -> None:
    """Detect stack from Set-Cookie values."""
    if "jsessionid" in cookies:
        runtime.append("java")
    if "phpsessid" in cookies:
        runtime.append("php")
    if "asp.net_sessionid" in cookies or "aspxauth" in cookies:
        runtime.append("dotnet")
    if "csrftoken" in cookies and "sessionid" in cookies:
        framework.append("django")
        runtime.append("python")
    if "laravel_session" in cookies:
        framework.append("laravel")
        runtime.append("php")
    if "_rails_session" in cookies:
        framework.append("rails")
        runtime.append("ruby")
    if re.search(r"connect\.sid", cookies):
        runtime.append("node")

    if "jwt" in cookies or "access_token" in cookies:
        auth.append("jwt")


def _detect_http_body(
    body: str,
    framework: list[str],
    features: list[str],
) -> None:
    """Detect stack from HTML body content."""
    if "__next_data__" in body or "_next/static" in body:
        framework.append("nextjs")
    if "wp-content" in body or "wp-includes" in body or 'generator" content="wordpress' in body:
        framework.append("wordpress")
    if "drupal" in body and "sites/default" in body:
        framework.append("drupal")
    if "__nuxt" in body or "_nuxt/" in body:
        framework.append("nuxtjs")

    if 'type="file"' in body or "multipart/form-data" in body:
        features.append("file_upload")
    if "websocket" in body or "socket.io" in body:
        features.append("websocket")


def _probe_has_status(probes: str, path: str, status: str = "200") -> bool:
    """Check if a specific probe path returned the given status code.

    Probe results are formatted as '/path: status_code' per line.
    Uses exact path matching to avoid substring false positives.
    """
    for line in probes.splitlines():
        parts = line.split(": ", 1)
        if len(parts) == 2 and parts[0].strip() == path and parts[1].strip() == status:
            return True
    return False


def _detect_http_probes(
    probes: str,
    features: list[str],
) -> None:
    """Detect features from probing common paths."""
    if _probe_has_status(probes, "/graphql"):
        features.append("graphql")
    if _probe_has_status(probes, "/api/graphql") and "graphql" not in features:
        features.append("graphql")
    if any(_probe_has_status(probes, p) for p in ("/api/swagger", "/api-docs", "/api-json", "/swagger", "/docs", "/redoc")):
        features.append("swagger")
    if _probe_has_status(probes, "/wp-admin") or _probe_has_status(probes, "/wp-admin", "302"):
        features.append("wordpress_admin")
    if _probe_has_status(probes, "/actuator"):
        features.append("spring_actuator")
    if _probe_has_status(probes, "/_next/data"):
        features.append("nextjs_data")
    if _probe_has_status(probes, "/.env"):
        features.append("env_exposed")

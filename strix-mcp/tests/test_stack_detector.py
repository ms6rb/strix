import pytest
from strix_mcp.stack_detector import detect_stack, generate_plan, detect_stack_from_http


EMPTY_SIGNALS = {
    "package_json": "",
    "requirements": "",
    "pyproject": "",
    "go_mod": "",
    "env_files": "",
    "structure": "",
}


class TestDetectStack:
    def test_detects_nestjs_from_package_json(self):
        """NestJS app with mongoose and JWT should detect node runtime, nestjs framework, mongodb, jwt."""
        signals = {
            **EMPTY_SIGNALS,
            "package_json": '{"dependencies": {"@nestjs/core": "^10.0.0", "@nestjs/common": "^10.0.0", "mongoose": "^7.0.0", "@nestjs/jwt": "^10.0.0"}}',
        }
        stack = detect_stack(signals)
        assert "node" in stack["runtime"]
        assert "nestjs" in stack["framework"]
        assert "mongodb" in stack["database"]
        assert "jwt" in stack["auth"]

    def test_detects_fastapi_from_requirements(self):
        """FastAPI app with SQLAlchemy and PyJWT should detect python runtime, fastapi framework, jwt auth."""
        signals = {
            **EMPTY_SIGNALS,
            "requirements": "fastapi==0.104.0\nsqlalchemy==2.0.0\npyjwt==2.8.0\nuvicorn==0.24.0\n",
        }
        stack = detect_stack(signals)
        assert "python" in stack["runtime"]
        assert "fastapi" in stack["framework"]
        assert "sql" in stack["database"]
        assert "jwt" in stack["auth"]

    def test_detects_nextjs_from_package_json(self):
        """Next.js app with Supabase should detect node runtime, nextjs framework, supabase in auth/database."""
        signals = {
            **EMPTY_SIGNALS,
            "package_json": '{"dependencies": {"next": "14.0.0", "react": "18.0.0", "@supabase/supabase-js": "^2.0.0"}}',
        }
        stack = detect_stack(signals)
        assert "node" in stack["runtime"]
        assert "nextjs" in stack["framework"]
        assert "supabase" in stack["auth"] or "supabase" in stack["database"]

    def test_detects_file_upload_feature(self):
        """Express app with multer should detect file_upload in features."""
        signals = {
            **EMPTY_SIGNALS,
            "package_json": '{"dependencies": {"express": "^4.18.0", "multer": "^1.4.0"}}',
        }
        stack = detect_stack(signals)
        assert "file_upload" in stack["features"]

    def test_detects_graphql_feature(self):
        """NestJS app with GraphQL should detect graphql in features."""
        signals = {
            **EMPTY_SIGNALS,
            "package_json": '{"dependencies": {"@nestjs/graphql": "^12.0.0", "apollo-server-express": "^3.0.0"}}',
        }
        stack = detect_stack(signals)
        assert "graphql" in stack["features"]
        assert "graphql" in stack["api_style"]

    def test_empty_signals_returns_empty_stack(self):
        """All empty signals should produce empty lists everywhere."""
        stack = detect_stack(EMPTY_SIGNALS)
        assert stack["runtime"] == []
        assert stack["framework"] == []
        assert stack["database"] == []
        assert stack["auth"] == []
        assert stack["features"] == []
        assert stack["infrastructure"] == []
        # api_style should still default to rest when nothing detected
        assert "rest" in stack["api_style"]

    def test_detects_go_from_go_mod(self):
        """Go app with gin, JWT, and MongoDB should detect go runtime, gin framework, jwt auth, mongodb."""
        signals = {
            **EMPTY_SIGNALS,
            "go_mod": "module example.com/app\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.0\n\tgithub.com/golang-jwt/jwt v3.2.2\n\tgo.mongodb.org/mongo-driver v1.12.0\n)",
        }
        stack = detect_stack(signals)
        assert "go" in stack["runtime"]
        assert "gin" in stack["framework"]
        assert "jwt" in stack["auth"]
        assert "mongodb" in stack["database"]

    def test_env_file_database_detection(self):
        """DATABASE_URL=postgresql and REDIS_URL should detect postgresql and redis."""
        signals = {
            **EMPTY_SIGNALS,
            "env_files": "DATABASE_URL=postgresql://user:pass@localhost:5432/db\nREDIS_URL=redis://localhost:6379\n",
        }
        stack = detect_stack(signals)
        assert "postgresql" in stack["database"]
        assert "redis" in stack["database"]


class TestGeneratePlan:
    def _nestjs_stack(self):
        """Helper: return a typical NestJS+MongoDB+JWT stack."""
        signals = {
            **EMPTY_SIGNALS,
            "package_json": '{"dependencies": {"@nestjs/core": "^10.0.0", "mongoose": "^7.0.0", "@nestjs/jwt": "^10.0.0"}}',
        }
        return detect_stack(signals)

    def test_always_includes_core_agents(self):
        """NestJS+MongoDB+JWT stack should always include auth, IDOR, business logic agents."""
        stack = self._nestjs_stack()
        plan = generate_plan(stack)
        tasks = [entry["task"] for entry in plan]
        assert any("authentication" in t.lower() or "jwt" in t.lower() for t in tasks)
        assert any("idor" in t.lower() or "authorization" in t.lower() for t in tasks)
        assert any("business logic" in t.lower() for t in tasks)

    def test_file_upload_agent_only_when_detected(self):
        """File upload agent should only appear when file_upload feature is detected."""
        # Without file upload
        stack_no_upload = self._nestjs_stack()
        plan_no_upload = generate_plan(stack_no_upload)
        upload_tasks_no = [e for e in plan_no_upload if "file upload" in e["task"].lower()]
        assert len(upload_tasks_no) == 0

        # With file upload
        signals_upload = {
            **EMPTY_SIGNALS,
            "package_json": '{"dependencies": {"@nestjs/core": "^10.0.0", "multer": "^1.4.0"}}',
        }
        stack_upload = detect_stack(signals_upload)
        plan_upload = generate_plan(stack_upload)
        upload_tasks_yes = [e for e in plan_upload if "file upload" in e["task"].lower()]
        assert len(upload_tasks_yes) == 1

    def test_plan_entries_have_required_fields(self):
        """Every plan entry must have task, modules, and priority fields."""
        stack = self._nestjs_stack()
        plan = generate_plan(stack)
        assert len(plan) > 0
        for entry in plan:
            assert "task" in entry, f"Entry missing 'task': {entry}"
            assert "modules" in entry, f"Entry missing 'modules': {entry}"
            assert "priority" in entry, f"Entry missing 'priority': {entry}"
            assert isinstance(entry["modules"], list)
            assert len(entry["modules"]) > 0
            assert entry["priority"] in ("high", "medium", "low")

    def test_empty_stack_returns_generic_plan(self):
        """Even an empty stack should return at least 3 core agents (always + web_app triggers)."""
        stack = detect_stack(EMPTY_SIGNALS)
        plan = generate_plan(stack)
        assert len(plan) >= 3


class TestDetectStackFromHttp:
    def test_detects_php_from_server_header(self):
        signals = {"headers": "Server: Apache\nX-Powered-By: PHP/8.2.0"}
        stack = detect_stack_from_http(signals)
        assert "php" in stack["runtime"]

    def test_detects_aspnet_from_header(self):
        signals = {"headers": "X-AspNet-Version: 4.0.30319\nServer: Microsoft-IIS/10.0"}
        stack = detect_stack_from_http(signals)
        assert "dotnet" in stack["runtime"]

    def test_detects_nextjs_from_headers(self):
        signals = {"headers": "x-powered-by: Next.js"}
        stack = detect_stack_from_http(signals)
        assert "nextjs" in stack["framework"]

    def test_detects_django_from_cookie(self):
        signals = {"cookies": "csrftoken=abc123; sessionid=xyz789"}
        stack = detect_stack_from_http(signals)
        assert "django" in stack["framework"]

    def test_detects_java_from_jsessionid(self):
        signals = {"cookies": "JSESSIONID=ABC123DEF456"}
        stack = detect_stack_from_http(signals)
        assert "java" in stack["runtime"]

    def test_detects_laravel_from_cookie(self):
        signals = {"cookies": "laravel_session=abc; XSRF-TOKEN=xyz"}
        stack = detect_stack_from_http(signals)
        assert "laravel" in stack["framework"]

    def test_detects_graphql_from_probe(self):
        signals = {"probe_results": "/graphql: 200"}
        stack = detect_stack_from_http(signals)
        assert "graphql" in stack["features"]

    def test_detects_wordpress_from_meta(self):
        signals = {"body_signals": '<meta name="generator" content="WordPress 6.4">'}
        stack = detect_stack_from_http(signals)
        assert "wordpress" in stack["framework"]

    def test_empty_http_signals(self):
        stack = detect_stack_from_http({})
        assert stack["runtime"] == []
        assert stack["framework"] == []
        assert "rest" in stack["api_style"]

    def test_detects_express_from_header(self):
        signals = {"headers": "X-Powered-By: Express"}
        stack = detect_stack_from_http(signals)
        assert "express" in stack["framework"]
        assert "node" in stack["runtime"]

    def test_detects_nextjs_from_body(self):
        signals = {"body_signals": '<script id="__NEXT_DATA__" type="application/json">'}
        stack = detect_stack_from_http(signals)
        assert "nextjs" in stack["framework"]

    def test_detects_aws_from_headers(self):
        signals = {"headers": "x-amz-request-id: ABC123\nServer: AmazonS3"}
        stack = detect_stack_from_http(signals)
        assert "aws" in stack["infrastructure"]

    def test_detects_cloudflare_from_headers(self):
        signals = {"headers": "Server: cloudflare\ncf-ray: abc123"}
        stack = detect_stack_from_http(signals)
        assert "cloudflare" in stack["infrastructure"]

    def test_detects_actuator_from_probe(self):
        signals = {"probe_results": "/actuator: 200\n/actuator/health: 200"}
        stack = detect_stack_from_http(signals)
        assert "spring_actuator" in stack["features"]

    def test_detects_env_exposed_from_probe(self):
        signals = {"probe_results": "/.env: 200"}
        stack = detect_stack_from_http(signals)
        assert "env_exposed" in stack["features"]

    def test_detects_swagger_from_api_docs_probe(self):
        signals = {"probe_results": "/api-docs: 200"}
        stack = detect_stack_from_http(signals)
        assert "swagger" in stack["features"]


class TestPlanConfidence:
    def test_plan_entries_have_confidence(self):
        """Every plan entry should include a confidence field."""
        stack = {
            "runtime": ["node"], "framework": ["nestjs"], "database": ["sql"],
            "auth": ["jwt"], "features": [], "api_style": ["rest"],
            "infrastructure": [],
        }
        plan = generate_plan(stack)
        for entry in plan:
            assert "confidence" in entry, f"Entry missing 'confidence': {entry}"
            assert entry["confidence"] in ("high", "medium", "low")

    def test_generic_triggers_are_medium_confidence(self):
        """Phase-1 templates triggered only by 'always' or 'web_app' (generic) should be medium confidence."""
        # Empty stack — only 'always' and 'web_app' triggers fire
        stack = detect_stack(EMPTY_SIGNALS)
        plan = generate_plan(stack)
        # Only check phase-1 (vuln) agents — phase-0 recon agents have high confidence by design
        vuln_agents = [e for e in plan if e.get("phase") == 1]
        for entry in vuln_agents:
            assert entry["confidence"] == "medium", f"Expected medium for generic trigger: {entry}"

    def test_framework_trigger_is_high_confidence(self):
        """Templates triggered by specific framework should be high confidence."""
        stack = {
            "runtime": ["node"], "framework": ["nestjs"], "database": [],
            "auth": [], "features": [], "api_style": ["rest"],
            "infrastructure": [],
        }
        plan = generate_plan(stack)
        nestjs_entries = [e for e in plan if "NestJS" in e["task"]]
        assert len(nestjs_entries) > 0
        for entry in nestjs_entries:
            assert entry["confidence"] == "high"

    def test_stale_probes_downgrade_confidence(self):
        """When probe_results are empty (stale/failed probes), HTTP-detected features should be low confidence."""
        # Stack detected from HTTP but probes returned nothing useful
        stack = {
            "runtime": ["node"], "framework": ["express"], "database": [],
            "auth": [], "features": ["graphql"], "api_style": ["graphql"],
            "infrastructure": [],
        }
        # Pass empty probe_results — signals were stale/timed out
        plan = generate_plan(stack, probe_results="")
        graphql_entries = [e for e in plan if "GraphQL" in e["task"]]
        assert len(graphql_entries) > 0
        for entry in graphql_entries:
            assert entry["confidence"] == "low", f"Stale probe should downgrade to low: {entry}"

    def test_successful_probes_keep_high_confidence(self):
        """When probe_results confirm features, confidence stays high."""
        stack = {
            "runtime": ["node"], "framework": ["express"], "database": [],
            "auth": [], "features": ["graphql"], "api_style": ["graphql"],
            "infrastructure": [],
        }
        plan = generate_plan(stack, probe_results="/graphql: 200")
        graphql_entries = [e for e in plan if "GraphQL" in e["task"]]
        for entry in graphql_entries:
            assert entry["confidence"] == "high"


class TestGeneratePlanNewTemplates:
    def test_nestjs_triggers_nestjs_agent(self):
        stack = {
            "runtime": ["node"], "framework": ["nestjs"], "database": ["sql"],
            "auth": ["jwt"], "features": [], "api_style": ["rest"],
            "infrastructure": [],
        }
        plan = generate_plan(stack)
        tasks = [p["task"] for p in plan]
        assert any("NestJS" in t for t in tasks)

    def test_web_app_triggers_info_disclosure_agent(self):
        stack = {
            "runtime": [], "framework": [], "database": [],
            "auth": [], "features": [], "api_style": ["rest"],
            "infrastructure": [],
        }
        plan = generate_plan(stack)
        tasks = [p["task"] for p in plan]
        assert any("information disclosure" in t for t in tasks)

    def test_web_app_triggers_path_traversal_agent(self):
        stack = {
            "runtime": [], "framework": [], "database": [],
            "auth": [], "features": [], "api_style": ["rest"],
            "infrastructure": [],
        }
        plan = generate_plan(stack)
        tasks = [p["task"] for p in plan]
        assert any("path traversal" in t.lower() for t in tasks)

    def test_domain_target_triggers_subdomain_takeover(self):
        stack = {
            "runtime": [], "framework": [], "database": [],
            "auth": [], "features": [], "api_style": ["rest"],
            "infrastructure": [], "target_types": ["domain"],
        }
        plan = generate_plan(stack)
        tasks = [p["task"] for p in plan]
        assert any("subdomain" in t.lower() for t in tasks)

    def test_nestjs_module_in_rules(self):
        """nestjs trigger should include the nestjs module."""
        from strix_mcp.stack_detector import MODULE_RULES
        assert "nestjs" in MODULE_RULES["nestjs"]

    def test_django_triggers_django_agent(self):
        stack = {
            "runtime": ["python"], "framework": ["django"], "database": ["sql"],
            "auth": [], "features": [], "api_style": ["rest"],
            "infrastructure": [],
        }
        plan = generate_plan(stack)
        tasks = [p["task"] for p in plan]
        assert any("Django" in t for t in tasks)

    def test_wordpress_triggers_wordpress_agent(self):
        stack = {
            "runtime": ["php"], "framework": ["wordpress"], "database": [],
            "auth": [], "features": [], "api_style": ["rest"],
            "infrastructure": [],
        }
        plan = generate_plan(stack)
        tasks = [p["task"] for p in plan]
        assert any("WordPress" in t for t in tasks)

    def test_laravel_triggers_laravel_agent(self):
        stack = {
            "runtime": ["php"], "framework": ["laravel"], "database": ["sql"],
            "auth": [], "features": [], "api_style": ["rest"],
            "infrastructure": [],
        }
        plan = generate_plan(stack)
        tasks = [p["task"] for p in plan]
        assert any("Laravel" in t for t in tasks)

    def test_rails_triggers_rails_agent(self):
        stack = {
            "runtime": ["ruby"], "framework": ["rails"], "database": ["sql"],
            "auth": [], "features": [], "api_style": ["rest"],
            "infrastructure": [],
        }
        plan = generate_plan(stack)
        tasks = [p["task"] for p in plan]
        assert any("Rails" in t for t in tasks)

    def test_express_triggers_express_agent(self):
        stack = {
            "runtime": ["node"], "framework": ["express"], "database": [],
            "auth": ["jwt"], "features": [], "api_style": ["rest"],
            "infrastructure": [],
        }
        plan = generate_plan(stack)
        tasks = [p["task"] for p in plan]
        assert any("Express" in t for t in tasks)

    def test_framework_rules_exist(self):
        """All framework triggers should have MODULE_RULES entries."""
        from strix_mcp.stack_detector import MODULE_RULES
        for fw in ["django", "flask", "laravel", "wordpress", "rails", "express"]:
            assert fw in MODULE_RULES, f"Missing MODULE_RULES for {fw}"


class TestReconPhase:
    def test_web_app_plan_includes_recon_agents(self):
        """Web app targets should get phase-0 recon agents."""
        stack = detect_stack(EMPTY_SIGNALS)
        plan = generate_plan(stack)
        recon_agents = [e for e in plan if e.get("phase") == 0]
        assert len(recon_agents) >= 2, f"Expected >=2 recon agents, got {len(recon_agents)}"
        # Should have surface discovery and infrastructure
        tasks = [a["task"].lower() for a in recon_agents]
        assert any("directory" in t or "ffuf" in t or "surface" in t for t in tasks)
        assert any("nmap" in t or "nuclei" in t or "infrastructure" in t for t in tasks)

    def test_domain_plan_includes_subdomain_enum(self):
        """Domain targets should get subdomain enumeration agent."""
        stack = detect_stack(EMPTY_SIGNALS)
        stack["target_types"] = ["domain"]
        plan = generate_plan(stack)
        recon_agents = [e for e in plan if e.get("phase") == 0]
        tasks = [a["task"].lower() for a in recon_agents]
        assert any("subdomain" in t for t in tasks), f"No subdomain agent in: {tasks}"

    def test_web_app_no_subdomain_enum(self):
        """Web app targets (no domain type) should NOT get subdomain enumeration."""
        stack = detect_stack(EMPTY_SIGNALS)
        # No target_types set — pure web_app
        plan = generate_plan(stack)
        recon_agents = [e for e in plan if e.get("phase") == 0]
        tasks = [a["task"].lower() for a in recon_agents]
        assert not any("subdomain" in t for t in tasks), f"Unexpected subdomain agent in: {tasks}"

    def test_all_plan_entries_have_phase(self):
        """Every plan entry must have a 'phase' field (0 or 1)."""
        stack = detect_stack(EMPTY_SIGNALS)
        plan = generate_plan(stack)
        for entry in plan:
            assert "phase" in entry, f"Entry missing 'phase': {entry}"
            assert entry["phase"] in (0, 1), f"Invalid phase: {entry['phase']}"

    def test_vuln_agents_have_phase_1(self):
        """Existing vulnerability agents should have phase 1."""
        stack = detect_stack(EMPTY_SIGNALS)
        plan = generate_plan(stack)
        vuln_agents = [e for e in plan if e.get("phase") == 1]
        assert len(vuln_agents) >= 3, "Should have at least 3 phase-1 vuln agents"

    def test_recon_modules_not_filtered_by_module_rules(self):
        """Recon agent modules should survive even though they're not in MODULE_RULES."""
        stack = detect_stack(EMPTY_SIGNALS)
        plan = generate_plan(stack)
        recon_agents = [e for e in plan if e.get("phase") == 0]
        for agent in recon_agents:
            assert len(agent["modules"]) > 0, f"Recon agent has no modules: {agent}"

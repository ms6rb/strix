import pytest
from strix_mcp.chaining import CHAIN_RULES, ChainRule, detect_chains, build_agent_prompt, reason_cross_tool_chains


class TestChainRules:
    def test_chain_rules_is_list(self):
        """CHAIN_RULES should be a non-empty list of ChainRule."""
        assert isinstance(CHAIN_RULES, list)
        assert len(CHAIN_RULES) >= 10

    def test_chain_rules_have_required_fields(self):
        """Every rule should have all required fields."""
        for rule in CHAIN_RULES:
            assert isinstance(rule, ChainRule)
            assert len(rule.finding_a) > 0
            assert len(rule.finding_b) > 0
            assert rule.chain_name
            assert rule.priority in ("critical", "high")
            assert rule.agent_task
            assert len(rule.modules) > 0

    def test_chain_rules_no_duplicate_names(self):
        """Chain names should be unique."""
        names = [r.chain_name for r in CHAIN_RULES]
        assert len(names) == len(set(names))


class TestDetectChains:
    def test_detects_xss_httponly_chain(self):
        """XSS + missing HttpOnly should trigger session hijack chain."""
        reports = [
            {"title": "Stored XSS in /comments", "severity": "high"},
            {"title": "Session cookies missing HttpOnly flag", "severity": "medium"},
        ]
        chains = detect_chains(reports, fired=set())
        assert len(chains) >= 1
        names = [c["chain_name"] for c in chains]
        assert any("session hijack" in n.lower() for n in names)

    def test_detects_ssrf_internal_chain(self):
        """SSRF + internal endpoints should trigger internal exploitation chain."""
        reports = [
            {"title": "SSRF via image URL parameter", "severity": "high"},
            {"title": "Internal API endpoints discovered", "severity": "info"},
        ]
        chains = detect_chains(reports, fired=set())
        names = [c["chain_name"] for c in chains]
        assert any("internal" in n.lower() for n in names)

    def test_detects_sqli_auth_chain(self):
        """SQL injection + auth system should trigger auth bypass chain."""
        reports = [
            {"title": "SQL Injection in search parameter", "severity": "critical"},
            {"title": "JWT authentication system identified", "severity": "info"},
        ]
        chains = detect_chains(reports, fired=set())
        names = [c["chain_name"] for c in chains]
        assert any("auth bypass" in n.lower() or "credential" in n.lower() for n in names)

    def test_no_chain_with_single_finding(self):
        """A single finding should not trigger any chain."""
        reports = [
            {"title": "Stored XSS in /comments", "severity": "high"},
        ]
        chains = detect_chains(reports, fired=set())
        assert len(chains) == 0

    def test_no_chain_with_unrelated_findings(self):
        """Unrelated findings should not trigger chains."""
        reports = [
            {"title": "Missing CSP header", "severity": "low"},
            {"title": "Server version disclosed", "severity": "info"},
        ]
        chains = detect_chains(reports, fired=set())
        assert len(chains) == 0

    def test_fired_chains_not_repeated(self):
        """Already-fired chains should not appear again."""
        reports = [
            {"title": "Stored XSS in /comments", "severity": "high"},
            {"title": "Session cookies missing HttpOnly flag", "severity": "medium"},
        ]
        # First call fires the chain
        fired: set[str] = set()
        chains1 = detect_chains(reports, fired=fired)
        assert len(chains1) >= 1

        # Second call with same fired set returns nothing new
        chains2 = detect_chains(reports, fired=fired)
        assert len(chains2) == 0

    def test_chain_result_has_dispatch_payload(self):
        """Each detected chain should include a dispatch payload with task and modules."""
        reports = [
            {"title": "Stored XSS in /comments", "severity": "high"},
            {"title": "Session cookies missing HttpOnly flag", "severity": "medium"},
        ]
        chains = detect_chains(reports, fired=set())
        for chain in chains:
            assert "chain_name" in chain
            assert "priority" in chain
            assert "finding_a" in chain
            assert "finding_b" in chain
            assert "dispatch" in chain
            assert "task" in chain["dispatch"]
            assert "modules" in chain["dispatch"]

    def test_chain_finding_references_actual_titles(self):
        """finding_a and finding_b should reference the actual report titles that matched."""
        reports = [
            {"title": "Reflected XSS in search", "severity": "medium"},
            {"title": "Cookies without HttpOnly", "severity": "low"},
        ]
        chains = detect_chains(reports, fired=set())
        if chains:
            chain = chains[0]
            assert chain["finding_a"] in [r["title"] for r in reports]
            assert chain["finding_b"] in [r["title"] for r in reports]


class TestBuildAgentPrompt:
    def test_code_target_prompt_contains_agent_id(self):
        """Code target prompt should include the agent_id."""
        prompt = build_agent_prompt(
            task="Test IDOR",
            modules=["idor"],
            agent_id="mcp_agent_1",
        )
        assert 'agent_id="mcp_agent_1"' in prompt

    def test_code_target_prompt_contains_modules(self):
        """Prompt should include load_skill with comma-separated modules."""
        prompt = build_agent_prompt(
            task="Test auth",
            modules=["authentication_jwt", "idor"],
            agent_id="mcp_agent_1",
        )
        assert 'load_skill("authentication_jwt,idor")' in prompt

    def test_code_target_prompt_contains_task(self):
        """Prompt should include the task description."""
        prompt = build_agent_prompt(
            task="Test SQL injection in login",
            modules=["sql_injection"],
            agent_id="mcp_agent_2",
        )
        assert "Test SQL injection in login" in prompt

    def test_code_target_prompt_has_workspace(self):
        """Default (code target) prompt should reference /workspace."""
        prompt = build_agent_prompt(
            task="Test XSS",
            modules=["xss"],
            agent_id="mcp_agent_1",
        )
        assert "/workspace" in prompt

    def test_web_only_prompt_no_workspace_analysis(self):
        """Web-only prompt should NOT tell agent to analyze source code."""
        prompt = build_agent_prompt(
            task="Test XSS",
            modules=["xss"],
            agent_id="mcp_agent_1",
            is_web_only=True,
        )
        assert "source code" not in prompt.lower() or "no source code" in prompt.lower()
        assert "browser_action" in prompt

    def test_web_only_prompt_mentions_live_target(self):
        """Web-only prompt should mention live web application."""
        prompt = build_agent_prompt(
            task="Test SSRF",
            modules=["ssrf"],
            agent_id="mcp_agent_1",
            is_web_only=True,
        )
        assert "LIVE" in prompt or "live" in prompt

    def test_chain_prompt_includes_context(self):
        """When chain_context is provided, prompt should include Phase 1 findings."""
        prompt = build_agent_prompt(
            task="Chain: XSS + HttpOnly → session hijack",
            modules=["xss", "authentication_jwt"],
            agent_id="mcp_agent_3",
            chain_context={
                "finding_a": "Stored XSS in /comments",
                "finding_b": "Session cookies missing HttpOnly",
                "chain_name": "Account takeover via session hijack",
            },
        )
        assert "Stored XSS in /comments" in prompt
        assert "Session cookies missing HttpOnly" in prompt
        assert "session hijack" in prompt.lower()


class TestDispatchAgentPromptIntegration:
    def test_dispatch_builds_valid_prompt(self):
        """Simulating what dispatch_agent does: register + build prompt."""
        agent_id = "mcp_agent_1"
        task = "Test IDOR and access control"
        modules = ["idor", "broken_function_level_authorization"]

        prompt = build_agent_prompt(task=task, modules=modules, agent_id=agent_id)

        # The prompt should be a non-empty string with all key pieces
        assert isinstance(prompt, str)
        assert len(prompt) > 200
        assert agent_id in prompt
        assert task in prompt
        for m in modules:
            assert m in prompt

    def test_dispatch_chain_agent_builds_context_prompt(self):
        """Chain dispatch should include both findings in the prompt."""
        agent_id = "mcp_agent_5"
        chain = {
            "chain_name": "Account takeover via session hijack",
            "priority": "critical",
            "finding_a": "Stored XSS in /comments",
            "finding_b": "Session cookies missing HttpOnly",
            "dispatch": {
                "task": "Chain: XSS + HttpOnly → session hijack",
                "modules": ["xss", "authentication_jwt"],
            },
        }

        prompt = build_agent_prompt(
            task=chain["dispatch"]["task"],
            modules=chain["dispatch"]["modules"],
            agent_id=agent_id,
            chain_context={
                "finding_a": chain["finding_a"],
                "finding_b": chain["finding_b"],
                "chain_name": chain["chain_name"],
            },
        )

        assert "Stored XSS in /comments" in prompt
        assert "Session cookies missing HttpOnly" in prompt
        assert agent_id in prompt


class TestDetectChainsIntegration:
    def test_chains_detected_after_second_finding(self):
        """When two findings match a chain rule, detect_chains should return the chain."""
        from strix_mcp.chaining import detect_chains

        fired: set[str] = set()

        # First finding — no chain yet
        reports = [{"title": "Stored XSS in /comments", "severity": "high"}]
        chains = detect_chains(reports, fired=fired)
        assert len(chains) == 0

        # Second finding completes the chain
        reports.append({"title": "Session cookies missing HttpOnly flag", "severity": "medium"})
        chains = detect_chains(reports, fired=fired)
        assert len(chains) >= 1
        assert chains[0]["dispatch"]["modules"] == ["xss", "authentication_jwt"]

    def test_multiple_chains_from_multiple_findings(self):
        """Multiple chains can fire from a set of findings."""
        from strix_mcp.chaining import detect_chains

        fired: set[str] = set()
        reports = [
            {"title": "Stored XSS in /comments", "severity": "high"},
            {"title": "Session cookies missing HttpOnly flag", "severity": "medium"},
            {"title": "SSRF via image URL parameter", "severity": "high"},
            {"title": "Internal API endpoints discovered", "severity": "info"},
        ]
        chains = detect_chains(reports, fired=fired)
        assert len(chains) >= 2
        names = {c["chain_name"] for c in chains}
        assert any("session hijack" in n.lower() for n in names)
        assert any("internal" in n.lower() for n in names)


class TestPendingChainsTracking:
    def test_fired_chains_tracks_dispatched(self):
        """fired_chains set should grow as chains are detected."""
        from strix_mcp.chaining import detect_chains

        fired: set[str] = set()
        reports = [
            {"title": "Stored XSS in /comments", "severity": "high"},
            {"title": "Session cookies missing HttpOnly flag", "severity": "medium"},
        ]
        detect_chains(reports, fired=fired)
        assert len(fired) >= 1
        assert any("session hijack" in name.lower() for name in fired)

    def test_pending_count_decreases_after_firing(self):
        """After chains fire, they should be in fired set and not fire again."""
        from strix_mcp.chaining import detect_chains

        fired: set[str] = set()
        reports = [
            {"title": "Stored XSS in /comments", "severity": "high"},
            {"title": "Session cookies missing HttpOnly flag", "severity": "medium"},
        ]

        # First detection
        chains1 = detect_chains(reports, fired=fired)
        count1 = len(chains1)
        assert count1 >= 1

        # Second detection — all fired, nothing new
        chains2 = detect_chains(reports, fired=fired)
        assert len(chains2) == 0


class TestReasonCrossToolChains:
    """Tests for cross-tool chain reasoning."""

    def test_firebase_writable_plus_js_collection(self):
        """Writable Firestore collection + JS bundle reads from it = data injection chain."""
        firebase = {
            "firestore": {
                "acl_matrix": {
                    "users": {
                        "anonymous": {"list": "allowed (3 docs)", "get": "allowed", "create": "allowed", "delete": "denied"},
                    },
                },
            },
            "auth": {"anonymous_signup": "open"},
        }
        js = {"collection_names": ["users", "settings"]}

        chains = reason_cross_tool_chains(firebase_results=firebase, js_analysis=js)
        chain_names = [c["name"] for c in chains]
        assert any("writable" in n and "users" in n for n in chain_names)

    def test_open_signup_plus_writable_collection(self):
        """Open signup + writable collection = unauthenticated write chain."""
        firebase = {
            "firestore": {
                "acl_matrix": {
                    "posts": {
                        "anonymous": {"list": "denied", "get": "denied", "create": "allowed", "delete": "denied"},
                    },
                },
            },
            "auth": {"anonymous_signup": "open"},
        }

        chains = reason_cross_tool_chains(firebase_results=firebase)
        chain_names = [c["name"] for c in chains]
        assert any("Unauthenticated write" in n for n in chain_names)

    def test_sanity_accessible(self):
        """Accessible Sanity CMS = data exposure chain."""
        services = {
            "discovered_services": {"sanity": ["e5fj2khm"]},
            "probes": {
                "sanity_e5fj2khm": {
                    "status": "accessible",
                    "document_types": ["article", "skill", "config"],
                },
            },
        }

        chains = reason_cross_tool_chains(services=services)
        assert any("Sanity CMS" in c["name"] for c in chains)

    def test_session_divergent_endpoints(self):
        """Divergent session comparison results = access control chain."""
        session = {
            "results": [
                {"classification": "divergent", "method": "GET", "path": "/api/admin"},
                {"classification": "same", "method": "GET", "path": "/api/public"},
            ],
        }

        chains = reason_cross_tool_chains(session_comparison=session)
        assert any("divergence" in c["name"].lower() for c in chains)

    def test_graphql_introspection_chain(self):
        """GraphQL introspection enabled = schema exposure chain."""
        api = {
            "graphql": {"introspection": "enabled", "types": ["Query", "User"]},
        }

        chains = reason_cross_tool_chains(api_discovery=api)
        assert any("GraphQL" in c["name"] for c in chains)

    def test_js_secrets_chain(self):
        """Secrets in JS bundles = credential exposure chain."""
        js = {"secrets": ["AIzaSy...abc (20 chars) in /app.js"], "collection_names": []}

        chains = reason_cross_tool_chains(js_analysis=js)
        assert any("Secrets" in c["name"] for c in chains)

    def test_ssrf_plus_internal_hosts(self):
        """SSRF vuln + internal hosts from JS = targeted SSRF chain."""
        js = {"internal_hostnames": ["https://10.0.1.50:8080"], "collection_names": [], "secrets": []}
        vulns = [{"title": "SSRF in /api/proxy", "severity": "high"}]

        chains = reason_cross_tool_chains(js_analysis=js, vuln_reports=vulns)
        assert any("SSRF" in c["name"] for c in chains)

    def test_no_inputs_returns_empty(self):
        """No tool results = no chains."""
        chains = reason_cross_tool_chains()
        assert chains == []

    def test_chain_structure(self):
        """Each chain should have the required fields."""
        firebase = {
            "firestore": {"acl_matrix": {
                "users": {"unauthenticated": {"list": "allowed (1 docs)", "get": "allowed", "create": "denied", "delete": "denied"}},
            }},
            "auth": {},
        }

        chains = reason_cross_tool_chains(firebase_results=firebase)
        for chain in chains:
            assert "name" in chain
            assert "severity" in chain
            assert "evidence" in chain
            assert "chain_description" in chain
            assert "missing" in chain
            assert "next_action" in chain
            assert isinstance(chain["evidence"], list)
            assert isinstance(chain["missing"], list)

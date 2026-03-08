import pytest
from strix_mcp.chaining import CHAIN_RULES, ChainRule, detect_chains, build_agent_prompt


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
        """Prompt should list get_module calls for each module."""
        prompt = build_agent_prompt(
            task="Test auth",
            modules=["authentication_jwt", "idor"],
            agent_id="mcp_agent_1",
        )
        assert 'get_module("authentication_jwt")' in prompt
        assert 'get_module("idor")' in prompt

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

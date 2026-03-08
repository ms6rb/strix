import pytest
from strix_mcp.chaining import CHAIN_RULES, ChainRule, detect_chains


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

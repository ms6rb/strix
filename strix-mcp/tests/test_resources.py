import json

import pytest
from strix_mcp.resources import get_methodology, get_module, list_modules


def test_list_modules_returns_descriptions():
    """Each module should have a category and a non-empty description."""
    result = json.loads(list_modules())
    assert len(result) > 0

    has_description = 0
    for name, info in result.items():
        assert "category" in info, f"Module '{name}' missing category"
        assert "description" in info, f"Module '{name}' missing description"
        assert isinstance(info["category"], str)
        assert isinstance(info["description"], str)
        if len(info["description"]) > 10:
            has_description += 1

    # Most modules should have descriptions from YAML frontmatter
    assert has_description >= len(result) - 2, (
        f"Too few modules with descriptions: {has_description}/{len(result)}"
    )


def test_list_modules_includes_known_modules():
    """Spot-check that well-known modules are present."""
    result = json.loads(list_modules())
    for expected in ["idor", "xss", "authentication_jwt", "business_logic"]:
        assert expected in result, f"Expected module '{expected}' not found"


def test_list_modules_idor_description_content():
    """IDOR description should come from YAML frontmatter."""
    result = json.loads(list_modules())
    desc = result["idor"]["description"]
    assert "BOLA" in desc or "IDOR" in desc or "authorization" in desc.lower()


def test_get_methodology_returns_content():
    """Methodology should return non-empty string."""
    content = get_methodology()
    assert isinstance(content, str)
    assert len(content) > 100


def test_get_module_returns_idor_content():
    """get_module should return the module content without frontmatter."""
    content = get_module("idor")
    assert "# IDOR" in content
    assert len(content) > 500
    # Should NOT contain YAML frontmatter
    assert not content.startswith("---")


def test_get_module_returns_nestjs_content():
    """get_module should return the NestJS module content."""
    content = get_module("nestjs")
    assert "# NestJS" in content
    assert "guard" in content.lower()
    assert len(content) > 500


def test_get_module_invalid_name_raises():
    """get_module should raise ValueError for unknown module names."""
    with pytest.raises(ValueError, match="not found"):
        get_module("nonexistent_module_xyz")


def test_list_modules_filter_by_category():
    """list_modules with category filter should return only modules in that category."""
    # Get all modules to find a real category
    all_modules = json.loads(list_modules())
    first_module = next(iter(all_modules.values()))
    category = first_module["category"]

    # Filter by that category
    filtered = json.loads(list_modules(category=category))
    assert len(filtered) > 0
    assert len(filtered) <= len(all_modules)
    for name, info in filtered.items():
        assert info["category"] == category


def test_list_modules_invalid_category_returns_empty():
    """list_modules with unknown category should return empty dict."""
    result = json.loads(list_modules(category="nonexistent_category_xyz"))
    assert result == {}

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

logger = logging.getLogger(__name__)

METHODOLOGY_PATH = Path(__file__).parent / "methodology.md"

_FRONTMATTER_PATTERN = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.DOTALL)


def _get_skills_dir() -> Path:
    """Resolve strix skills directory from the installed strix package."""
    from strix.utils.resource_paths import get_strix_resource_path

    skills_dir = get_strix_resource_path("skills")
    if not skills_dir.exists():
        raise FileNotFoundError(
            f"Strix skills directory not found at {skills_dir}. "
            "Is strix installed?"
        )
    return skills_dir


def get_methodology() -> str:
    """Return the adapted penetration testing methodology."""
    return METHODOLOGY_PATH.read_text()


def _extract_description(name: str, category: str) -> str:
    """Extract the description from YAML frontmatter."""
    skills_dir = _get_skills_dir()
    skill_path = skills_dir / category / f"{name}.md"

    if not skill_path.exists():
        return ""

    content = skill_path.read_text(encoding="utf-8")
    match = _FRONTMATTER_PATTERN.match(content)
    if match:
        frontmatter = match.group(1)
        for line in frontmatter.splitlines():
            if line.startswith("description:"):
                return line.split(":", 1)[1].strip()
    return ""


def list_modules() -> str:
    """List all available security knowledge modules with category and description."""
    from strix.skills import get_available_skills

    modules = get_available_skills()
    result = {}

    for category, names in modules.items():
        for name in names:
            description = _extract_description(name, category)
            result[name] = {
                "category": category,
                "description": description,
            }

    return json.dumps(result, indent=2)


def get_module(name: str) -> str:
    """Load a security knowledge module by name.

    Reads the markdown file, strips YAML frontmatter, and returns content.
    """
    from strix.skills import get_all_skill_names, get_available_skills

    available = get_all_skill_names()
    if name not in available:
        raise ValueError(
            f"Module '{name}' not found. Available: {', '.join(sorted(available))}"
        )

    skills_dir = _get_skills_dir()
    modules = get_available_skills()

    for category, names in modules.items():
        if name in names:
            skill_path = skills_dir / category / f"{name}.md"
            content = skill_path.read_text(encoding="utf-8")
            # Strip YAML frontmatter
            content = _FRONTMATTER_PATTERN.sub("", content).lstrip()
            return content

    raise ValueError(f"Module file not found for '{name}'")

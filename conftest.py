"""Shared fixtures and helpers for the skill_scanner test suite."""

import textwrap

import pytest

from skill_scanner import (
    SkillScanner,
)


@pytest.fixture
def scanner():
    """Return a fresh SkillScanner instance."""
    return SkillScanner()


def build_skill_md(frontmatter=None, body="", code_blocks=None):
    """Build a synthetic SKILL.md string.

    Parameters
    ----------
    frontmatter : dict | None
        If provided, rendered as YAML frontmatter between ``---`` fences.
    body : str
        Free-form markdown body text.
    code_blocks : list[tuple[str, str]] | None
        Each element is ``(language, content)``.  An empty language string
        produces an un-tagged fence.

    Returns
    -------
    str
        Complete markdown document.
    """
    parts = []

    if frontmatter is not None:
        import yaml

        parts.append("---")
        parts.append(yaml.dump(frontmatter, default_flow_style=False).rstrip())
        parts.append("---")
        parts.append("")

    if body:
        parts.append(textwrap.dedent(body).strip())
        parts.append("")

    if code_blocks:
        for lang, content in code_blocks:
            parts.append(f"```{lang}")
            parts.append(content)
            parts.append("```")
            parts.append("")

    return "\n".join(parts)

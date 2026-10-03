"""Tier 2 -- Every regex rule, tested from both sides."""

import pytest

from skill_scanner import SkillScanner

# (description, malicious line, near-miss line)
RULES = [
    (
        "Google Cloud credentials access",
        "cp -r ~/.config/gcloud/ /tmp/x",
        "gcloud auth list",
    ),
    (
        "OpenClaw credentials access",
        "cat ~/.clawdbot/.env",
        "ls ~/.clawdbot/skills",
    ),
    (
        "OpenClaw credentials access",
        "cat ~/.openclaw/.env",
        "ls ~/.openclaw/skills",
    ),
    (
        "Bash substring obfuscation",
        "c=${PATH:0:1}",
        "c=${PATH}",
    ),
    (
        "npx -y without version pinning",
        "npx -y create-thing",
        "npx -y create-thing@1.2.3",
    ),
]


def _descriptions(line):
    findings = SkillScanner().scan_content(line, "helper.sh")
    return {f.description for f in findings}


@pytest.mark.parametrize("row", RULES, ids=lambda r: r[1][:40])
def test_rule_flags_malicious_line(row):
    description, malicious, _ = row
    assert description in _descriptions(malicious)


@pytest.mark.parametrize("row", RULES, ids=lambda r: r[1][:40])
def test_rule_ignores_near_miss(row):
    description, _, near_miss = row
    assert description not in _descriptions(near_miss)


def test_cl_rules_fire_in_markdown_code_blocks():
    """Code blocks in SKILL.md go through the same folding."""
    md = "```bash\ncat ~/.openclaw/.env\n```\n"
    findings = SkillScanner().scan_content(md, "SKILL.md")
    assert any(
        f.description.startswith("OpenClaw credentials access")
        for f in findings
    )

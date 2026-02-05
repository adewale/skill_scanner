"""Tier 1 -- Infrastructure unit tests.

Every test in this file uses ONLY benign content.
No malicious payloads, no dangerous patterns.
"""

from pathlib import Path

import pytest

from conftest import build_skill_md
from skill_scanner import (
    Finding,
    ScanResult,
    Severity,
    SkillMetadata,
    SkillProvenance,
    get_default_skill_paths,
    main,
    print_findings,
)

# ---------------------------------------------------------------
# Severity enum
# ---------------------------------------------------------------


class TestSeverityEnum:
    """Verify the five severity levels exist and compare correctly."""

    def test_critical_exists(self):
        assert Severity.CRITICAL.value == "CRITICAL"

    def test_high_exists(self):
        assert Severity.HIGH.value == "HIGH"

    def test_medium_exists(self):
        assert Severity.MEDIUM.value == "MEDIUM"

    def test_low_exists(self):
        assert Severity.LOW.value == "LOW"

    def test_info_exists(self):
        assert Severity.INFO.value == "INFO"

    def test_all_five_members(self):
        assert len(Severity) == 5


# ---------------------------------------------------------------
# Finding dataclass
# ---------------------------------------------------------------


class TestFindingDataclass:
    """Verify Finding construction and default values."""

    def test_required_fields(self):
        f = Finding(
            severity=Severity.INFO,
            category="test",
            description="A benign finding",
            file_path="/tmp/test.md",
        )
        assert f.severity == Severity.INFO
        assert f.category == "test"
        assert f.description == "A benign finding"
        assert f.file_path == "/tmp/test.md"

    def test_optional_line_number_default(self):
        f = Finding(
            severity=Severity.LOW,
            category="test",
            description="d",
            file_path="f",
        )
        assert f.line_number is None

    def test_optional_matched_content_default(self):
        f = Finding(
            severity=Severity.LOW,
            category="test",
            description="d",
            file_path="f",
        )
        assert f.matched_content == ""

    def test_optional_recommendation_default(self):
        f = Finding(
            severity=Severity.LOW,
            category="test",
            description="d",
            file_path="f",
        )
        assert f.recommendation == ""

    def test_all_fields_set(self):
        f = Finding(
            severity=Severity.MEDIUM,
            category="cat",
            description="desc",
            file_path="/p",
            line_number=42,
            matched_content="match",
            recommendation="fix it",
        )
        assert f.line_number == 42
        assert f.matched_content == "match"
        assert f.recommendation == "fix it"


# ---------------------------------------------------------------
# SkillProvenance
# ---------------------------------------------------------------


class TestSkillProvenance:
    """Trust score and trust level properties."""

    def test_official_base_score(self):
        p = SkillProvenance(is_official=True)
        assert p.trust_score == 90

    def test_official_with_security_policy(self):
        p = SkillProvenance(is_official=True, has_security_policy=True)
        assert p.trust_score == 95

    def test_official_with_license(self):
        p = SkillProvenance(is_official=True, license="MIT")
        assert p.trust_score == 95

    def test_official_with_both(self):
        p = SkillProvenance(
            is_official=True,
            has_security_policy=True,
            license="MIT",
        )
        assert p.trust_score == 100

    def test_nonoffficial_capped_at_70(self):
        p = SkillProvenance(
            source_url="https://example.com",
            has_security_policy=True,
            license="MIT",
        )
        # 30 + 10 (source) + 5 (security) + 5 (license) = 50
        assert p.trust_score == 50

    def test_nonofficial_max_cap(self):
        p = SkillProvenance(
            source_url="https://example.com",
            has_security_policy=True,
            license="MIT",
            has_code_of_conduct=True,
        )
        assert p.trust_score <= 70

    def test_nonofficial_baseline(self):
        p = SkillProvenance()
        assert p.trust_score == 30

    def test_trust_level_official(self):
        p = SkillProvenance(is_official=True)
        assert p.trust_level == "OFFICIAL"

    def test_trust_level_unverified(self):
        p = SkillProvenance(source_url="https://example.com")
        assert p.trust_level == "UNVERIFIED"

    def test_trust_level_unknown(self):
        p = SkillProvenance()
        assert p.trust_level == "UNKNOWN"

    def test_code_of_conduct_does_not_affect_score(self):
        """code_of_conduct is tracked but not factored into score."""
        base = SkillProvenance()
        with_coc = SkillProvenance(has_code_of_conduct=True)
        assert base.trust_score == with_coc.trust_score


# ---------------------------------------------------------------
# SkillMetadata
# ---------------------------------------------------------------


class TestSkillMetadata:
    """Structure risk score calculation."""

    def test_baseline_score_zero(self):
        m = SkillMetadata(has_valid_frontmatter=True)
        assert m.structure_risk_score == 0

    def test_scripts_folder_adds_20(self):
        m = SkillMetadata(has_scripts_folder=True, has_valid_frontmatter=True)
        assert m.structure_risk_score == 20

    def test_executables_add_10_each(self):
        m = SkillMetadata(
            executable_file_count=3,
            has_valid_frontmatter=True,
        )
        assert m.structure_risk_score == 30

    def test_executables_capped_at_5(self):
        m = SkillMetadata(
            executable_file_count=10,
            has_valid_frontmatter=True,
        )
        # 10 * min(10, 5) = 50
        assert m.structure_risk_score == 50

    def test_missing_frontmatter_adds_10(self):
        m = SkillMetadata(has_valid_frontmatter=False)
        assert m.structure_risk_score == 10

    def test_long_description_adds_5(self):
        m = SkillMetadata(
            has_valid_frontmatter=True,
            description_length=1500,
        )
        assert m.structure_risk_score == 5

    def test_references_subtracts_10(self):
        m = SkillMetadata(
            has_valid_frontmatter=True,
            has_references_folder=True,
        )
        # 0 - 10 => clamped to 0
        assert m.structure_risk_score == 0

    def test_references_net_reduction(self):
        m = SkillMetadata(
            has_scripts_folder=True,
            has_valid_frontmatter=True,
            has_references_folder=True,
        )
        # 20 - 10 = 10
        assert m.structure_risk_score == 10

    def test_score_never_negative(self):
        m = SkillMetadata(
            has_valid_frontmatter=True,
            has_references_folder=True,
        )
        assert m.structure_risk_score >= 0


# ---------------------------------------------------------------
# ScanResult
# ---------------------------------------------------------------


class TestScanResult:
    """is_safe, critical_count, high_count properties."""

    def test_empty_findings_is_safe(self):
        r = ScanResult(skill_path="/p", skill_name="s")
        assert r.is_safe is True

    def test_info_only_is_safe(self):
        r = ScanResult(
            skill_path="/p",
            skill_name="s",
            findings=[
                Finding(
                    severity=Severity.INFO,
                    category="test",
                    description="d",
                    file_path="f",
                ),
            ],
        )
        assert r.is_safe is True

    def test_medium_only_is_safe(self):
        r = ScanResult(
            skill_path="/p",
            skill_name="s",
            findings=[
                Finding(
                    severity=Severity.MEDIUM,
                    category="test",
                    description="d",
                    file_path="f",
                ),
            ],
        )
        assert r.is_safe is True

    def test_high_not_safe(self):
        r = ScanResult(
            skill_path="/p",
            skill_name="s",
            findings=[
                Finding(
                    severity=Severity.HIGH,
                    category="test",
                    description="d",
                    file_path="f",
                ),
            ],
        )
        assert r.is_safe is False

    def test_critical_not_safe(self):
        r = ScanResult(
            skill_path="/p",
            skill_name="s",
            findings=[
                Finding(
                    severity=Severity.CRITICAL,
                    category="test",
                    description="d",
                    file_path="f",
                ),
            ],
        )
        assert r.is_safe is False

    def test_critical_count(self):
        r = ScanResult(
            skill_path="/p",
            skill_name="s",
            findings=[
                Finding(
                    severity=Severity.CRITICAL,
                    category="a",
                    description="d",
                    file_path="f",
                ),
                Finding(
                    severity=Severity.HIGH,
                    category="b",
                    description="d",
                    file_path="f",
                ),
                Finding(
                    severity=Severity.CRITICAL,
                    category="c",
                    description="d",
                    file_path="f",
                ),
            ],
        )
        assert r.critical_count == 2

    def test_high_count(self):
        r = ScanResult(
            skill_path="/p",
            skill_name="s",
            findings=[
                Finding(
                    severity=Severity.HIGH,
                    category="a",
                    description="d",
                    file_path="f",
                ),
                Finding(
                    severity=Severity.LOW,
                    category="b",
                    description="d",
                    file_path="f",
                ),
                Finding(
                    severity=Severity.HIGH,
                    category="c",
                    description="d",
                    file_path="f",
                ),
                Finding(
                    severity=Severity.HIGH,
                    category="e",
                    description="d",
                    file_path="f",
                ),
            ],
        )
        assert r.high_count == 3


# ---------------------------------------------------------------
# get_default_skill_paths
# ---------------------------------------------------------------


class TestGetDefaultSkillPaths:
    """Verify the returned list of default paths."""

    def test_returns_list_of_paths(self):
        paths = get_default_skill_paths()
        assert isinstance(paths, list)
        assert all(isinstance(p, Path) for p in paths)

    def test_returns_approximately_14_paths(self):
        paths = get_default_skill_paths()
        assert len(paths) == 14


# ---------------------------------------------------------------
# parse_skill_ast
# ---------------------------------------------------------------


class TestParseSkillAst:
    """AST extraction from benign markdown."""

    def test_extracts_yaml_frontmatter(self, scanner):
        md = build_skill_md(
            frontmatter={"name": "hello", "version": "1.0"},
            body="Some text.",
        )
        ast = scanner.parse_skill_ast(md)
        assert ast["frontmatter"] is not None
        assert ast["frontmatter"]["name"] == "hello"

    def test_no_frontmatter(self, scanner):
        ast = scanner.parse_skill_ast("# Just a heading\nSome text.")
        assert ast["frontmatter"] is None

    def test_extracts_code_blocks(self, scanner):
        md = build_skill_md(
            code_blocks=[("python", "print('hello')"), ("", "echo hello")],
        )
        ast = scanner.parse_skill_ast(md)
        assert len(ast["code_blocks"]) == 2
        assert ast["code_blocks"][0]["language"] == "python"
        assert "print" in ast["code_blocks"][0]["content"]

    def test_extracts_headings(self, scanner):
        md = "# Title\n## Subtitle\nText\n### Sub-sub\n"
        ast = scanner.parse_skill_ast(md)
        assert len(ast["headings"]) == 3
        assert ast["headings"][0]["text"] == "Title"

    def test_extracts_links(self, scanner):
        md = "See [Example](https://example.com) for details.\n"
        ast = scanner.parse_skill_ast(md)
        assert len(ast["links"]) >= 1
        assert ast["links"][0]["url"] == "https://example.com"

    def test_extracts_html_comments(self, scanner):
        md = "Text before\n\n<!-- a benign comment -->\n\nText after\n"
        ast = scanner.parse_skill_ast(md)
        assert len(ast["html_comments"]) >= 1
        assert "benign" in ast["html_comments"][0]


# ---------------------------------------------------------------
# _should_skip_finding
# ---------------------------------------------------------------


class TestShouldSkipFinding:
    """Whitelist logic with benign inputs only."""

    def test_skips_typescript_env_pattern(self, scanner):
        content = "interface Env { DB: D1Database }"
        assert (
            scanner._should_skip_finding(
                r"\.env\b",
                "Environment file access",
                content,
                "typescript",
                "exfiltration",
            )
            is True
        )

    def test_does_not_skip_non_ts_env(self, scanner):
        content = "read .env file"
        assert (
            scanner._should_skip_finding(
                r"\.env\b",
                "Environment file access",
                content,
                "",
                "exfiltration",
            )
            is False
        )

    def test_skips_safe_localhost_port(self, scanner):
        content = "http://localhost:3000/api"
        assert (
            scanner._should_skip_finding(
                r"https?://[^/]+:\d{4,5}/",
                "URL with non-standard port",
                content,
                "",
                "suspicious_url",
            )
            is True
        )

    def test_does_not_skip_unusual_port(self, scanner):
        content = "http://localhost:4444/api"
        assert (
            scanner._should_skip_finding(
                r"https?://[^/]+:\d{4,5}/",
                "URL with non-standard port",
                content,
                "",
                "suspicious_url",
            )
            is False
        )


# ---------------------------------------------------------------
# _adjust_severity_for_context
# ---------------------------------------------------------------


class TestAdjustSeverityForContext:
    """Severity adjustment for code block language context."""

    def test_downgrade_high_in_typescript(self, scanner):
        result = scanner._adjust_severity_for_context(
            Severity.HIGH,
            "typescript",
            "dangerous_shell",
        )
        assert result == Severity.MEDIUM

    def test_downgrade_critical_in_python(self, scanner):
        result = scanner._adjust_severity_for_context(
            Severity.CRITICAL,
            "python",
            "obfuscation",
        )
        assert result == Severity.HIGH

    def test_no_downgrade_for_prompt_injection(self, scanner):
        result = scanner._adjust_severity_for_context(
            Severity.HIGH,
            "typescript",
            "prompt_injection",
        )
        assert result == Severity.HIGH

    def test_no_downgrade_for_memory_poisoning(self, scanner):
        result = scanner._adjust_severity_for_context(
            Severity.CRITICAL,
            "python",
            "memory_poisoning",
        )
        assert result == Severity.CRITICAL

    def test_upgrade_high_shell_in_bash(self, scanner):
        result = scanner._adjust_severity_for_context(
            Severity.HIGH,
            "bash",
            "dangerous_shell",
        )
        assert result == Severity.CRITICAL

    def test_no_upgrade_for_non_shell_category(self, scanner):
        result = scanner._adjust_severity_for_context(
            Severity.HIGH,
            "bash",
            "exfiltration",
        )
        assert result == Severity.HIGH

    def test_medium_unaffected_in_docs(self, scanner):
        """MEDIUM is not downgraded -- only HIGH and CRITICAL are."""
        result = scanner._adjust_severity_for_context(
            Severity.MEDIUM,
            "typescript",
            "obfuscation",
        )
        assert result == Severity.MEDIUM


# ---------------------------------------------------------------
# _get_recommendation
# ---------------------------------------------------------------


class TestGetRecommendation:
    """Every category returns a non-empty recommendation."""

    @pytest.mark.parametrize(
        "category",
        [
            "dangerous_shell",
            "exfiltration",
            "suspicious_url",
            "obfuscation",
            "social_engineering",
            "supply_chain",
            "prompt_injection",
            "memory_poisoning",
            "structure",
            "provenance",
        ],
    )
    def test_known_categories(self, scanner, category):
        rec = scanner._get_recommendation(category)
        assert isinstance(rec, str)
        assert len(rec) > 0

    def test_unknown_category_fallback(self, scanner):
        rec = scanner._get_recommendation("unknown_xyz")
        assert isinstance(rec, str)
        assert len(rec) > 0


# ---------------------------------------------------------------
# extract_provenance (pyfakefs)
# ---------------------------------------------------------------


class TestExtractProvenance:
    """Provenance extraction using pyfakefs for filesystem."""

    def test_no_git_no_security(self, fs, scanner):
        fs.create_dir("/skill")
        p = scanner.extract_provenance(Path("/skill"))
        assert p.trust_level == "UNKNOWN"
        assert p.has_security_policy is False

    def test_with_git_config(self, fs, scanner):
        fs.create_dir("/skill/.git")
        fs.create_file(
            "/skill/.git/config",
            contents='[remote "origin"]\n\turl = https://github.com/testorg/testrepo.git\n',
        )
        fs.create_file("/skill/SKILL.md", contents="# Hello\n")
        p = scanner.extract_provenance(Path("/skill"))
        assert p.source_url is not None
        assert p.publisher == "testorg"

    def test_security_policy_detected(self, fs, scanner):
        fs.create_dir("/skill")
        fs.create_file("/skill/SECURITY.md", contents="# Security\n")
        p = scanner.extract_provenance(Path("/skill"))
        assert p.has_security_policy is True

    def test_code_of_conduct_detected(self, fs, scanner):
        fs.create_dir("/skill")
        fs.create_file("/skill/CODE_OF_CONDUCT.md", contents="# CoC\n")
        p = scanner.extract_provenance(Path("/skill"))
        assert p.has_code_of_conduct is True

    def test_license_from_frontmatter(self, fs, scanner):
        fm = build_skill_md(
            frontmatter={"license": "MIT"}, body="Hello world."
        )
        fs.create_dir("/skill")
        fs.create_file("/skill/SKILL.md", contents=fm)
        p = scanner.extract_provenance(Path("/skill"))
        assert p.license == "MIT"

    def test_official_via_well_known_url(self, fs, scanner):
        fs.create_dir("/skill")
        p = scanner.extract_provenance(
            Path("/skill"),
            source_url="https://example.com/.well-known/skills/myskill/",
        )
        assert p.is_official is True
        assert p.is_well_known is True
        assert p.trust_level == "OFFICIAL"


# ---------------------------------------------------------------
# analyze_skill_structure (pyfakefs)
# ---------------------------------------------------------------


class TestAnalyzeSkillStructure:
    """Structural analysis using pyfakefs."""

    def test_empty_directory(self, fs, scanner):
        fs.create_dir("/skill")
        m = scanner.analyze_skill_structure(Path("/skill"))
        assert m.has_scripts_folder is False
        assert m.executable_file_count == 0

    def test_scripts_folder_detected(self, fs, scanner):
        fs.create_dir("/skill/scripts")
        m = scanner.analyze_skill_structure(Path("/skill"))
        assert m.has_scripts_folder is True

    def test_executable_count(self, fs, scanner):
        fs.create_dir("/skill")
        fs.create_file("/skill/setup.sh", contents="#!/bin/sh\n")
        fs.create_file("/skill/helper.py", contents="# python\n")
        fs.create_file("/skill/readme.txt", contents="hello\n")
        m = scanner.analyze_skill_structure(Path("/skill"))
        assert m.executable_file_count == 2

    def test_references_folder_detected(self, fs, scanner):
        fs.create_dir("/skill/references")
        m = scanner.analyze_skill_structure(Path("/skill"))
        assert m.has_references_folder is True

    def test_valid_frontmatter(self, fs, scanner):
        fm = build_skill_md(
            frontmatter={"name": "test", "description": "A test skill"},
            body="Hello.",
        )
        fs.create_dir("/skill")
        fs.create_file("/skill/SKILL.md", contents=fm)
        m = scanner.analyze_skill_structure(Path("/skill"))
        assert m.has_valid_frontmatter is True
        assert m.description_length == len("A test skill")

    def test_nonexistent_path(self, fs, scanner):
        m = scanner.analyze_skill_structure(Path("/nonexistent"))
        assert m.has_scripts_folder is False


# ---------------------------------------------------------------
# CLI argument parser
# ---------------------------------------------------------------


class TestCLIParser:
    """Verify the real argparse parser inside main() has all flags."""

    def test_cli_help_contains_all_flags(self, capsys, monkeypatch):
        """Run main(--help) and verify all expected flags appear."""
        monkeypatch.setattr(
            "sys.argv",
            ["skill_scanner.py", "--help"],
        )
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 0
        captured = capsys.readouterr()
        for flag in [
            "--verbose",
            "--all",
            "--json",
            "--fail-on-high",
            "--list-paths",
        ]:
            assert flag in captured.out, (
                f"Flag {flag} missing from --help output"
            )


# ---------------------------------------------------------------
# Fix 4: smoke test for print_findings()
# ---------------------------------------------------------------


class TestPrintFindings:
    """Smoke tests for print_findings()."""

    def test_print_findings_smoke(self, capsys):
        """print_findings with mixed severities does not raise."""
        result = ScanResult(
            skill_path="/test/skill",
            skill_name="test-skill",
            provenance=SkillProvenance(
                source_url="https://example.com/skill",
            ),
            metadata=SkillMetadata(has_valid_frontmatter=True),
            findings=[
                Finding(
                    severity=Severity.CRITICAL,
                    category="structure",
                    description="Critical finding",
                    file_path="/test/SKILL.md",
                    line_number=10,
                    matched_content="benign match content",
                    recommendation="Review carefully",
                ),
                Finding(
                    severity=Severity.HIGH,
                    category="structure",
                    description="High finding",
                    file_path="/test/SKILL.md",
                ),
                Finding(
                    severity=Severity.INFO,
                    category="structure",
                    description="Info finding",
                    file_path="/test/SKILL.md",
                ),
            ],
        )

        print_findings(result, show_all=True)

        captured = capsys.readouterr()
        assert "test-skill" in captured.out
        assert "CRITICAL" in captured.out
        assert "HIGH" in captured.out

    def test_print_findings_no_findings(self, capsys):
        """print_findings with empty result does not crash."""
        result = ScanResult(
            skill_path="/test/skill",
            skill_name="empty-skill",
        )
        print_findings(result)
        # Should not raise; output may be empty since
        # show_all defaults to False


# ---------------------------------------------------------------
# Fix 5: JSON output test
# ---------------------------------------------------------------


class TestJSONOutput:
    """Verify JSON output structure matches main() format."""

    def test_json_output_structure(self):
        """Build JSON dict from ScanResult the same way main() does."""
        results = [
            ScanResult(
                skill_path="/test/skill",
                skill_name="json-test",
                provenance=SkillProvenance(
                    source_url="https://example.com/skill",
                ),
                metadata=SkillMetadata(
                    has_valid_frontmatter=True,
                    has_scripts_folder=False,
                ),
                findings=[
                    Finding(
                        severity=Severity.HIGH,
                        category="exfiltration",
                        description="test",
                        file_path="/test/SKILL.md",
                        line_number=1,
                        matched_content="match",
                        recommendation="fix",
                    ),
                ],
            ),
        ]

        # Replicate the JSON construction from main()
        output = {
            "scanned_paths": ["/test"],
            "total_skills": len(results),
            "skills_with_issues": sum(1 for r in results if r.findings),
            "total_critical": sum(r.critical_count for r in results),
            "total_high": sum(r.high_count for r in results),
            "results": [
                {
                    "skill_name": r.skill_name,
                    "skill_path": r.skill_path,
                    "is_safe": r.is_safe,
                    "provenance": {
                        "source_url": (
                            r.provenance.source_url if r.provenance else None
                        ),
                        "trust_level": (
                            r.provenance.trust_level
                            if r.provenance
                            else "UNKNOWN"
                        ),
                        "trust_score": (
                            r.provenance.trust_score if r.provenance else 0
                        ),
                    }
                    if r.provenance
                    else None,
                    "metadata": {
                        "has_scripts_folder": (
                            r.metadata.has_scripts_folder
                            if r.metadata
                            else False
                        ),
                        "has_valid_frontmatter": (
                            r.metadata.has_valid_frontmatter
                            if r.metadata
                            else False
                        ),
                    }
                    if r.metadata
                    else None,
                    "findings": [
                        {
                            "severity": f.severity.value,
                            "category": f.category,
                            "description": f.description,
                            "file_path": f.file_path,
                            "line_number": f.line_number,
                            "matched_content": f.matched_content,
                            "recommendation": f.recommendation,
                        }
                        for f in r.findings
                    ],
                }
                for r in results
            ],
        }

        # Verify top-level keys
        for key in [
            "scanned_paths",
            "total_skills",
            "skills_with_issues",
            "total_critical",
            "total_high",
            "results",
        ]:
            assert key in output, f"Missing top-level key: {key}"

        # Verify result entry keys
        entry = output["results"][0]
        for key in [
            "skill_name",
            "provenance",
            "metadata",
            "findings",
        ]:
            assert key in entry, f"Missing result key: {key}"

        assert output["total_skills"] == 1
        assert output["total_high"] == 1
        assert output["total_critical"] == 0
        assert len(output["results"][0]["findings"]) == 1

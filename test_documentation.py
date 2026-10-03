"""Tier 3 -- Documentation-vs-code consistency tests.

Verify that README.md, HOW_IT_WORKS.md, and skill_threats_analysis.md
accurately describe what the code actually does.
"""

import re
from pathlib import Path

import pytest

from skill_scanner import (
    SkillScanner,
    get_default_skill_paths,
)

PROJECT_DIR = Path(__file__).resolve().parent


def _read(name: str) -> str:
    """Read a project-root file and return its contents."""
    return (PROJECT_DIR / name).read_text(encoding="utf-8", errors="ignore")


# ---------------------------------------------------------------
# README.md
# ---------------------------------------------------------------


class TestReadmeDetectionCategories:
    """README lists all 8 detection categories."""

    EXPECTED_CATEGORIES = [
        "dangerous_shell",
        "exfiltration",
        "suspicious_url",
        "obfuscation",
        "social_engineering",
        "prompt_injection",
        "memory_poisoning",
        "supply_chain",
    ]

    def test_readme_lists_all_categories(self):
        readme = _read("README.md")
        for cat in self.EXPECTED_CATEGORIES:
            assert cat in readme, f"README.md missing category: {cat}"

    def test_scanner_has_all_categories(self):
        """Cross-reference: scanner patterns cover every documented category."""
        scanner = SkillScanner()
        pattern_categories = {tup[-1] for tup in scanner.all_patterns}
        for cat in self.EXPECTED_CATEGORIES:
            assert cat in pattern_categories, (
                f"Scanner patterns missing documented category: {cat}"
            )


def _readme_table(heading: str) -> str:
    """Return the README section under ``## heading`` (up to the next
    ``##``)."""
    readme = _read("README.md")
    section = readme.split(f"## {heading}\n", 1)[1]
    return section.split("\n## ", 1)[0]


class TestReadmeDefaultPaths:
    """README's default-location table lists exactly the paths that
    get_default_skill_paths() scans."""

    def test_table_matches_scanned_paths(self, monkeypatch, tmp_path):
        home = tmp_path / "home"
        cwd = tmp_path / "work"
        cwd.mkdir()
        monkeypatch.setattr(Path, "home", lambda: home)
        monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
        monkeypatch.chdir(cwd)

        def as_documented(path: Path) -> str:
            if path.is_relative_to(home):
                return f"~/{path.relative_to(home).as_posix()}/"
            rel = path.relative_to(cwd).as_posix()
            return f"{rel}/" if rel.startswith(".") else f"./{rel}/"

        scanned = {as_documented(p) for p in get_default_skill_paths()}
        documented = set(
            re.findall(r"`([^`]+/)`", _readme_table("Default scan locations"))
        )
        assert documented == scanned


class TestReadmeCLIFlags:
    """README's Options table documents exactly the flags the real
    argument parser accepts."""

    def test_options_table_matches_help(self, capsys, monkeypatch):
        import skill_scanner

        monkeypatch.setattr("sys.argv", ["skill_scanner.py", "--help"])
        with pytest.raises(SystemExit):
            skill_scanner.main()
        out = re.sub(r"\x1b\[[0-9;]*m", "", capsys.readouterr().out)
        usage = out.split("Default locations")[0]
        accepted = set(re.findall(r"(?<![\w-])--?[a-z][a-z-]*", usage))
        accepted -= {"-h", "--help"}

        documented = set(
            re.findall(r"`(--?[a-z][a-z-]*)", _readme_table("Usage"))
        )
        assert documented == accepted


# ---------------------------------------------------------------
# HOW_IT_WORKS.md
# ---------------------------------------------------------------


class TestHowItWorksPatternCount:
    """HOW_IT_WORKS.md's "N+ regex patterns" claim is a true lower
    bound."""

    def test_claimed_pattern_count_is_a_lower_bound(self):
        doc = _read("HOW_IT_WORKS.md")
        match = re.search(r"(\d+)\+ regex patterns", doc)
        assert match, "HOW_IT_WORKS.md no longer states a pattern count"
        scanner = SkillScanner()
        actual = len(scanner.all_patterns) + len(
            scanner.GLOBAL_MEMORY_PATTERNS
        )
        assert int(match.group(1)) <= actual


class TestHowItWorksFunctionReferences:
    """HOW_IT_WORKS.md names specific functions that must exist."""

    EXPECTED_FUNCTIONS = [
        "get_default_skill_paths",
        "parse_skill_ast",
        "_should_skip_finding",
        "_adjust_severity_for_context",
        "_check_base64_blobs",
        "extract_provenance",
        "analyze_skill_structure",
    ]

    def test_functions_mentioned_in_doc(self):
        doc = _read("HOW_IT_WORKS.md")
        for fn in self.EXPECTED_FUNCTIONS:
            assert fn in doc, f"HOW_IT_WORKS.md missing function: {fn}"

    def test_functions_exist_as_callables(self):
        import skill_scanner as mod

        scanner = SkillScanner()
        for fn in self.EXPECTED_FUNCTIONS:
            # Check module-level or instance methods
            obj = getattr(mod, fn, None) or getattr(scanner, fn, None)
            assert obj is not None, f"Function {fn} not found"
            assert callable(obj), f"{fn} is not callable"


# ---------------------------------------------------------------
# skill_threats_analysis.md
# ---------------------------------------------------------------


class TestThreatAnalysisCoverage:
    """Coverage table category counts match actual pattern list lengths.

    Each test extracts the exact number from the coverage table row
    using a regex, then compares it against the code with ==.
    This catches doc drift in either direction.
    """

    # Map from doc row name to (pattern list attribute, doc "Detects" column)
    CATEGORIES = {
        "Dangerous Shell": "DANGEROUS_SHELL_PATTERNS",
        "Data Exfiltration": "EXFILTRATION_PATTERNS",
        "Suspicious URL": "SUSPICIOUS_URL_PATTERNS",
        "Obfuscation": "OBFUSCATION_PATTERNS",
        "Supply Chain": "SUPPLY_CHAIN_PATTERNS",
        "Prompt Injection": "PROMPT_INJECTION_PATTERNS",
        "Memory Poisoning": "MEMORY_POISONING_PATTERNS",
        "Social Engineering": "SOCIAL_ENGINEERING_PATTERNS",
    }

    def _extract_row(self, doc, row_name):
        """Extract (threats_identified, scanner_detects) from a coverage row."""
        pattern = re.escape(row_name) + r"[^|]*\|\s*(\d+)\s*\|\s*(\d+)\s*\|"
        match = re.search(pattern, doc)
        assert match, f"Coverage row '{row_name}' not found in table"
        return int(match.group(1)), int(match.group(2))

    def test_coverage_table_exists(self):
        doc = _read("skill_threats_analysis.md")
        assert "Coverage Summary" in doc

    @pytest.mark.parametrize("row_name", list(CATEGORIES))
    def test_category_count_matches_code(self, row_name):
        doc = _read("skill_threats_analysis.md")
        _, doc_detects = self._extract_row(doc, row_name)
        code_count = len(getattr(SkillScanner, self.CATEGORIES[row_name]))
        assert code_count == doc_detects, (
            f"{row_name}: code has {code_count}, doc claims {doc_detects}"
        )

    def test_total_all_patterns(self):
        """all_patterns combines all categories; verify total."""
        scanner = SkillScanner()
        expected = (
            len(scanner.DANGEROUS_SHELL_PATTERNS)
            + len(scanner.EXFILTRATION_PATTERNS)
            + len(scanner.SUSPICIOUS_URL_PATTERNS)
            + len(scanner.OBFUSCATION_PATTERNS)
            + len(scanner.SOCIAL_ENGINEERING_PATTERNS)
            + len(scanner.PROMPT_INJECTION_PATTERNS)
            + len(scanner.MEMORY_POISONING_PATTERNS)
            + len(scanner.SUPPLY_CHAIN_PATTERNS)
        )
        assert len(scanner.all_patterns) == expected

    def test_doc_total_detected(self):
        """The coverage summary Total row detected count matches code."""
        doc = _read("skill_threats_analysis.md")
        # Extract total from the **bold** Total row
        match = re.search(
            r"\*\*Total\*\*[^|]*\|[^|]*\|\s*\*\*(\d+)\*\*",
            doc,
        )
        assert match, "Total row not found in coverage table"
        doc_total = int(match.group(1))
        # The doc total counts all detections including AST-based
        # checks that are not in pattern lists, so verify it is
        # consistent with the sum of all "Scanner Detects" column
        # values from per-category rows.
        row_sum = 0
        for row_name in self.CATEGORIES:
            _, detects = self._extract_row(doc, row_name)
            row_sum += detects
        assert doc_total == row_sum, (
            f"Total row ({doc_total}) != sum of rows ({row_sum})"
        )

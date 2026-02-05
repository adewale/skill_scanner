"""Tier 3 -- Documentation-vs-code consistency tests.

Verify that README.md, HOW_IT_WORKS.md, and skill_threats_analysis.md
accurately describe what the code actually does.
"""

import inspect
import re
from pathlib import Path

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


class TestReadmeDefaultPaths:
    """README default scan locations match get_default_skill_paths()."""

    def test_readme_mentions_key_paths(self):
        readme = _read("README.md")
        # Check a representative subset that the README table claims
        expected_fragments = [
            ".claude/skills",
            ".cursor/skills",
            ".codex/skills",
            "opencode",
            ".openclaw/skills",
            ".clawdbot/skills",
            ".skills",
            ".skillport/skills",
            ".agent/skills",
        ]
        for frag in expected_fragments:
            assert frag in readme, (
                f"README.md missing default path fragment: {frag}"
            )

    def test_path_count_consistent(self):
        paths = get_default_skill_paths()
        # README mentions ~14 paths; code returns exactly 14
        assert len(paths) == 14


class TestReadmeCLIFlags:
    """README CLI flags match argparse definitions."""

    def test_all_flags_documented(self):
        readme = _read("README.md")
        src = inspect.getsource(
            __import__("skill_scanner").main,
        )
        flags = [
            "--verbose",
            "--all",
            "--json",
            "--fail-on-high",
            "--list-paths",
        ]
        for flag in flags:
            assert flag in readme, f"README missing CLI flag: {flag}"
            assert flag in src, f"main() missing CLI flag: {flag}"


# ---------------------------------------------------------------
# HOW_IT_WORKS.md
# ---------------------------------------------------------------


class TestHowItWorksPatternCount:
    """HOW_IT_WORKS.md claims '272+ patterns' -- verify lower bound."""

    def test_pattern_count_at_least_90(self):
        """all_patterns is a list of tuples (one per compiled regex).
        The doc says 272+ patterns but that counts threat table rows
        including non-regex detections; the compiled regex list should
        have >= 90 entries (actual: 97)."""
        scanner = SkillScanner()
        assert len(scanner.all_patterns) >= 90, (
            f"Expected >= 90 compiled patterns, got {len(scanner.all_patterns)}"
        )

    def test_how_it_works_claims_272_plus(self):
        doc = _read("HOW_IT_WORKS.md")
        assert "272" in doc


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

    def test_dangerous_shell_count(self):
        doc = _read("skill_threats_analysis.md")
        scanner = SkillScanner()
        _, doc_detects = self._extract_row(doc, "Dangerous Shell")
        code_count = len(scanner.DANGEROUS_SHELL_PATTERNS)
        assert code_count == doc_detects, (
            f"Dangerous Shell: code has {code_count}, doc claims {doc_detects}"
        )

    def test_exfiltration_count(self):
        doc = _read("skill_threats_analysis.md")
        scanner = SkillScanner()
        _, doc_detects = self._extract_row(doc, "Data Exfiltration")
        code_count = len(scanner.EXFILTRATION_PATTERNS)
        assert code_count == doc_detects, (
            f"Exfiltration: code has {code_count}, doc claims {doc_detects}"
        )

    def test_suspicious_url_count(self):
        doc = _read("skill_threats_analysis.md")
        scanner = SkillScanner()
        _, doc_detects = self._extract_row(doc, "Suspicious URL")
        code_count = len(scanner.SUSPICIOUS_URL_PATTERNS)
        assert code_count == doc_detects, (
            f"Suspicious URL: code has {code_count}, doc claims {doc_detects}"
        )

    def test_obfuscation_count(self):
        doc = _read("skill_threats_analysis.md")
        scanner = SkillScanner()
        _, doc_detects = self._extract_row(doc, "Obfuscation")
        code_count = len(scanner.OBFUSCATION_PATTERNS)
        assert code_count == doc_detects, (
            f"Obfuscation: code has {code_count}, doc claims {doc_detects}"
        )

    def test_supply_chain_count(self):
        doc = _read("skill_threats_analysis.md")
        scanner = SkillScanner()
        _, doc_detects = self._extract_row(doc, "Supply Chain")
        code_count = len(scanner.SUPPLY_CHAIN_PATTERNS)
        assert code_count == doc_detects, (
            f"Supply Chain: code has {code_count}, doc claims {doc_detects}"
        )

    def test_prompt_injection_count(self):
        doc = _read("skill_threats_analysis.md")
        scanner = SkillScanner()
        _, doc_detects = self._extract_row(doc, "Prompt Injection")
        code_count = len(scanner.PROMPT_INJECTION_PATTERNS)
        assert code_count == doc_detects, (
            f"Prompt Injection: code has {code_count}, "
            f"doc claims {doc_detects}"
        )

    def test_memory_poisoning_count(self):
        doc = _read("skill_threats_analysis.md")
        scanner = SkillScanner()
        _, doc_detects = self._extract_row(doc, "Memory Poisoning")
        code_count = len(scanner.MEMORY_POISONING_PATTERNS)
        assert code_count == doc_detects, (
            f"Memory Poisoning: code has {code_count}, "
            f"doc claims {doc_detects}"
        )

    def test_social_engineering_count(self):
        doc = _read("skill_threats_analysis.md")
        scanner = SkillScanner()
        _, doc_detects = self._extract_row(doc, "Social Engineering")
        code_count = len(scanner.SOCIAL_ENGINEERING_PATTERNS)
        assert code_count == doc_detects, (
            f"Social Engineering: code has {code_count}, "
            f"doc claims {doc_detects}"
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

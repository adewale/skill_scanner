# Testing Philosophy

Skill Scanner is a security tool that contains regex patterns for detecting
malware. This creates a unique testing challenge: the test suite itself must
avoid becoming a repository of malicious payloads while still verifying that
detection works.

We solve this with a **three-tier testing architecture** where each tier has
strict rules about what content it may contain.

## The Three Tiers

### Tier 1: Infrastructure (`test_infrastructure.py`)

**Rule: Benign content only. No malicious payloads, no dangerous patterns.**

Tier 1 tests verify that the scanner's building blocks work correctly
in isolation: dataclasses construct properly, trust scores calculate as
expected, the AST parser extracts frontmatter and code blocks, whitelists
accept what they should, and severity adjustment follows the documented
rules.

Every input in Tier 1 is ordinary, harmless text. If a test needs a
SKILL.md, it uses `build_skill_md()` with content like `"Hello world."`.
If it needs a provenance object, it constructs one with `example.com`
URLs. Nothing in Tier 1 would trigger a detection if scanned.

**Covers:** `Severity`, `Finding`, `SkillProvenance`, `SkillMetadata`,
`ScanResult`, `get_default_skill_paths()`, `parse_skill_ast()`,
`_should_skip_finding()`, `_adjust_severity_for_context()`,
`_get_recommendation()`, `extract_provenance()`,
`analyze_skill_structure()`, `print_findings()`, CLI argument parsing,
JSON output structure.

### Tier 2: Detection (`test_scanning.py`)

**Rule: Minimal synthetic triggers. Shortest non-functional fragment
that exercises the regex. Safe addresses only.**

Tier 2 tests verify that patterns actually detect what they claim to
detect, and equally important, that they do *not* fire on benign content.
Every detection category has both positive and false-positive tests.

Trigger strings are deliberately minimal and non-functional. Instead of
a complete reverse shell command, we use the shortest fragment that
matches the regex. Instead of real IP addresses, we use RFC 5737
documentation addresses (`192.0.2.x`). Instead of real domains, we use
RFC 2606 reserved names (`example.com`).

**Covers:** All 8 detection categories (positive + false-positive),
AST-aware severity context, hidden content in HTML comments, base64 blob
heuristic, whitelist integration, self-scan safety gate, filesystem
integration via `pyfakefs` (`scan_file()`, `scan_skill()`,
`scan_directory()`), non-markdown line-by-line scanning, suspicious
metadata detection.

#### Safe address conventions

| Type | Convention | Reference |
|------|-----------|-----------|
| IP addresses | `192.0.2.x` | RFC 5737 (TEST-NET-1) |
| Domains | `example.com` | RFC 2606 |
| Ports | Standard dev ports or `4444` for suspicious | IANA |

#### Self-scan safety gate

The test suite includes a self-scan that runs the scanner against its
own source files. Files that contain pattern definitions or trigger
strings (`skill_scanner.py`, `test_scanning.py`,
`test_infrastructure.py`) will self-match by design -- we verify the
count is bounded (< 200 findings each). Other project files
(`conftest.py`, `test_documentation.py`) must produce zero HIGH/CRITICAL
findings.

### Tier 3: Documentation consistency (`test_documentation.py`)

**Rule: Cross-reference documentation against code. No scanning, no
payloads.**

Tier 3 tests verify that what the documentation claims matches what the
code actually does. If `README.md` lists 8 detection categories, the
code must have patterns for all 8. If `HOW_IT_WORKS.md` names a
function, that function must exist and be callable. If
`skill_threats_analysis.md` claims 17 dangerous shell detections, the
pattern list must have exactly 17 entries.

These tests catch documentation drift automatically -- adding a pattern
without updating the threat matrix, or removing a CLI flag without
updating the README, will fail CI.

**Covers:** README detection categories, default path list, CLI flags;
HOW_IT_WORKS pattern counts, function references;
skill_threats_analysis.md coverage table counts, total row consistency.

## Shared Infrastructure (`conftest.py`)

Two shared helpers support all three tiers:

- **`scanner` fixture** -- returns a fresh `SkillScanner()` instance per
  test.
- **`build_skill_md()`** -- assembles a synthetic SKILL.md string from
  optional frontmatter (dict), body text, and code blocks
  (`[(language, content), ...]`). This keeps test setup consistent and
  readable across all tiers.

## Running Tests

```bash
# All tests
uv run --extra dev pytest

# Single tier
uv run --extra dev pytest test_infrastructure.py
uv run --extra dev pytest test_scanning.py
uv run --extra dev pytest test_documentation.py

# With coverage
uv run --extra dev pytest --cov --cov-report=term-missing
```

## Coverage

Coverage is measured on `skill_scanner.py` only (test files and
`conftest.py` are excluded). The threshold is **80%**, enforced in
`pyproject.toml`.

Lines excluded from coverage measurement:
- `pragma: no cover`
- `if __name__ == "__main__":`
- `raise NotImplementedError`

## Adding New Tests

When adding tests, place them in the correct tier:

1. **Testing a dataclass, helper, or utility?** Tier 1. Use only benign
   content.
2. **Testing that a pattern detects (or doesn't detect) something?**
   Tier 2. Use the shortest trigger that exercises the regex. Add a
   matching false-positive test. Use RFC 5737/2606 for any
   addresses.
3. **Adding or changing a doc claim?** Add a Tier 3 test that
   cross-references the claim against the code.

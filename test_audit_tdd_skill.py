"""Audit: mattpocock/skills/tdd

Demonstrates how to use skill_scanner to audit a third-party skill
before installing it with `npx skills add`.  This file tests the
actual content of the TDD skill (vendored inline) so the audit is
reproducible, network-free, and runs in CI alongside the rest of
the test suite.

Audit methodology
-----------------
1. **Provenance** -- trust level, publisher, source URL.
2. **Structure**  -- no scripts folder, no executables, valid frontmatter.
3. **Content**    -- all 6 files scanned across 8 detection categories.
4. **False-positive triage** -- known MEDIUM for `process.env` in a
   TypeScript documentation block (mocking.md line 32) is a benign
   code example, not real env-file access.

Verdict: SAFE.  Zero CRITICAL / HIGH findings.
"""

from pathlib import Path

import pytest

from conftest import build_skill_md
from skill_scanner import (
    Severity,
    SkillScanner,
)

# ---------------------------------------------------------------
# Vendored skill content (pinned for reproducible offline audit)
# ---------------------------------------------------------------

SKILL_MD = """\
---
name: tdd
description: >-
  Test-driven development with red-green-refactor loop.
  Use when user wants to build features or fix bugs using TDD,
  mentions "red-green-refactor", wants integration tests,
  or asks for test-first development.
---

# Test-Driven Development

## Philosophy

**Core principle**: Tests should verify behavior through public
interfaces, not implementation details.

**Good tests** are integration-style: they exercise real code paths
through public APIs. They describe _what_ the system does, not _how_.

**Bad tests** are coupled to implementation. They mock internal
collaborators, test private methods, or verify through external means.

See [tests.md](tests.md) for examples and [mocking.md](mocking.md)
for mocking guidelines.

## Anti-Pattern: Horizontal Slices

**DO NOT write all tests first, then all implementation.**

```
WRONG (horizontal):
  RED:   test1, test2, test3, test4, test5
  GREEN: impl1, impl2, impl3, impl4, impl5

RIGHT (vertical):
  RED->GREEN: test1->impl1
  RED->GREEN: test2->impl2
  RED->GREEN: test3->impl3
```

## Workflow

### 1. Planning

Before writing any code:

- [ ] Confirm with user what interface changes are needed
- [ ] Identify opportunities for [deep modules](deep-modules.md)
- [ ] Design interfaces for [testability](interface-design.md)
- [ ] List the behaviors to test
- [ ] Get user approval on the plan

### 2. Tracer Bullet

```
RED:   Write test for first behavior -> test fails
GREEN: Write minimal code to pass -> test passes
```

### 3. Incremental Loop

```
RED:   Write next test -> fails
GREEN: Minimal code to pass -> passes
```

### 4. Refactor

After all tests pass, look for [refactor candidates](refactoring.md).

## Checklist Per Cycle

```
[ ] Test describes behavior, not implementation
[ ] Test uses public interface only
[ ] Test would survive internal refactor
[ ] Code is minimal for this test
[ ] No speculative features added
```
"""

TESTS_MD = """\
# Good and Bad Tests

## Good Tests

```typescript
// GOOD: Tests observable behavior
test("user can checkout with valid cart", async () => {
  const cart = createCart();
  cart.add(product);
  const result = await checkout(cart, paymentMethod);
  expect(result.status).toBe("confirmed");
});
```

## Bad Tests

```typescript
// BAD: Tests implementation details
test("checkout calls paymentService.process", async () => {
  const mockPayment = jest.mock(paymentService);
  await checkout(cart, payment);
  expect(mockPayment.process).toHaveBeenCalledWith(cart.total);
});
```

```typescript
// BAD: Bypasses interface to verify
test("createUser saves to database", async () => {
  await createUser({ name: "Alice" });
  const row = await db.query("SELECT * FROM users WHERE name = ?", ["Alice"]);
  expect(row).toBeDefined();
});

// GOOD: Verifies through interface
test("createUser makes user retrievable", async () => {
  const user = await createUser({ name: "Alice" });
  const retrieved = await getUser(user.id);
  expect(retrieved.name).toBe("Alice");
});
```
"""

MOCKING_MD = """\
# When to Mock

Mock at **system boundaries** only:

- External APIs (payment, email, etc.)
- Databases (sometimes - prefer test DB)
- Time/randomness
- File system (sometimes)

## Designing for Mockability

**1. Use dependency injection**

```typescript
// Easy to mock
function processPayment(order, paymentClient) {
  return paymentClient.charge(order.total);
}

// Hard to mock
function processPayment(order) {
  const client = new StripeClient(process.env.STRIPE_KEY);
  return client.charge(order.total);
}
```

**2. Prefer SDK-style interfaces over generic fetchers**

```typescript
// GOOD: Each function is independently mockable
const api = {
  getUser: (id) => fetch(`/users/${id}`),
  getOrders: (userId) => fetch(`/users/${userId}/orders`),
  createOrder: (data) => fetch('/orders', { method: 'POST', body: data }),
};
```
"""

DEEP_MODULES_MD = """\
# Deep Modules

A deep module has a small interface and lots of implementation.
A shallow module has a large interface and little implementation.

Design questions:
- Can I reduce the number of methods?
- Can I simplify the parameters?
- Can I hide more complexity inside?
"""

INTERFACE_DESIGN_MD = """\
# Interface Design for Testability

1. **Dependency Injection** -- receive deps as parameters.
2. **Pure Functions Over Side Effects** -- return values, don't mutate.
3. **Minimal Interface Surface** -- fewer methods, fewer params.
"""

REFACTORING_MD = """\
# Refactor Candidates

After TDD cycle, look for:

- **Duplication** -> Extract function/class
- **Long methods** -> Break into private helpers
- **Shallow modules** -> Combine or deepen
- **Feature envy** -> Move logic to where data lives
- **Primitive obsession** -> Introduce value objects
"""

ALL_FILES = {
    "SKILL.md": SKILL_MD,
    "tests.md": TESTS_MD,
    "mocking.md": MOCKING_MD,
    "deep-modules.md": DEEP_MODULES_MD,
    "interface-design.md": INTERFACE_DESIGN_MD,
    "refactoring.md": REFACTORING_MD,
}


# ---------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------


def _has_finding(findings, *, category=None, severity=None, desc_contains=None):
    for f in findings:
        if category and f.category != category:
            continue
        if severity and f.severity != severity:
            continue
        if desc_contains and desc_contains.lower() not in f.description.lower():
            continue
        return True
    return False


@pytest.fixture
def scanner():
    return SkillScanner()


@pytest.fixture
def tdd_skill_dir(fs):
    """Create the full TDD skill on a fake filesystem."""
    skill_path = Path("/fake/tdd")
    for name, content in ALL_FILES.items():
        fs.create_file(str(skill_path / name), contents=content)
    return skill_path


# ================================================================
# 1. Provenance audit
# ================================================================


class TestTDDProvenance:
    """Verify provenance signals for the TDD skill."""

    def test_publisher_is_mattpocock(self, tdd_skill_dir, fs, scanner):
        """When cloned from GitHub, publisher should be detected."""
        # Simulate a git remote by creating .git/config
        git_config = (
            "[remote \"origin\"]\n"
            "\turl = https://github.com/mattpocock/skills.git\n"
        )
        fs.create_file(
            str(tdd_skill_dir.parent / ".git" / "config"),
            contents=git_config,
        )
        result = scanner.scan_skill(tdd_skill_dir)
        assert result.provenance is not None
        assert result.provenance.publisher == "mattpocock"

    def test_trust_level_is_unverified(self, tdd_skill_dir, fs, scanner):
        """GitHub-hosted skills are UNVERIFIED (not /.well-known/).
        Without a git remote, trust level falls to UNKNOWN."""
        # Without git remote: UNKNOWN
        result = scanner.scan_skill(tdd_skill_dir)
        assert result.provenance.trust_level == "UNKNOWN"

        # With git remote: UNVERIFIED
        git_config = (
            "[remote \"origin\"]\n"
            "\turl = https://github.com/mattpocock/skills.git\n"
        )
        fs.create_file(
            str(tdd_skill_dir.parent / ".git" / "config"),
            contents=git_config,
        )
        result2 = scanner.scan_skill(tdd_skill_dir)
        assert result2.provenance.trust_level == "UNVERIFIED"

    def test_trust_score_within_range(self, tdd_skill_dir, scanner):
        """Unverified skills have trust score capped at 70."""
        result = scanner.scan_skill(tdd_skill_dir)
        assert result.provenance.trust_score <= 70


# ================================================================
# 2. Structure audit
# ================================================================


class TestTDDStructure:
    """Verify the skill directory structure is low-risk."""

    def test_no_scripts_folder(self, tdd_skill_dir, scanner):
        result = scanner.scan_skill(tdd_skill_dir)
        assert result.metadata is not None
        assert result.metadata.has_scripts_folder is False

    def test_no_executables(self, tdd_skill_dir, scanner):
        result = scanner.scan_skill(tdd_skill_dir)
        assert result.metadata.executable_file_count == 0

    def test_valid_frontmatter(self, tdd_skill_dir, scanner):
        result = scanner.scan_skill(tdd_skill_dir)
        assert result.metadata.has_valid_frontmatter is True

    def test_structure_risk_score_is_low(self, tdd_skill_dir, scanner):
        result = scanner.scan_skill(tdd_skill_dir)
        assert result.metadata.structure_risk_score <= 10


# ================================================================
# 3. Content audit -- no CRITICAL or HIGH findings
# ================================================================


class TestTDDContentSafety:
    """The TDD skill must produce zero CRITICAL/HIGH findings."""

    def test_skill_is_safe(self, tdd_skill_dir, scanner):
        """Top-level safety gate: ScanResult.is_safe must be True."""
        result = scanner.scan_skill(tdd_skill_dir)
        assert result.is_safe, (
            f"TDD skill flagged as unsafe: "
            f"{[(f.severity.name, f.category, f.description) for f in result.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]}"
        )

    def test_zero_critical_findings(self, tdd_skill_dir, scanner):
        result = scanner.scan_skill(tdd_skill_dir)
        assert result.critical_count == 0

    def test_zero_high_findings(self, tdd_skill_dir, scanner):
        result = scanner.scan_skill(tdd_skill_dir)
        assert result.high_count == 0

    def test_each_file_individually(self, scanner):
        """Scan each file in isolation to pinpoint any findings."""
        for name, content in ALL_FILES.items():
            findings = scanner.scan_content(content, name)
            high_or_crit = [
                f
                for f in findings
                if f.severity in (Severity.CRITICAL, Severity.HIGH)
            ]
            assert high_or_crit == [], (
                f"{name} produced HIGH/CRITICAL: "
                f"{[(f.severity.name, f.category, f.description) for f in high_or_crit]}"
            )


# ================================================================
# 4. Per-category audit -- no dangerous patterns
# ================================================================


class TestTDDNoMaliciousPatterns:
    """Verify each detection category is clean."""

    def test_no_dangerous_shell(self, scanner):
        for name, content in ALL_FILES.items():
            findings = scanner.scan_content(content, name)
            assert not _has_finding(findings, category="dangerous_shell"), (
                f"{name} has dangerous_shell finding"
            )

    def test_no_suspicious_urls(self, scanner):
        for name, content in ALL_FILES.items():
            findings = scanner.scan_content(content, name)
            assert not _has_finding(findings, category="suspicious_url"), (
                f"{name} has suspicious_url finding"
            )

    def test_no_obfuscation(self, scanner):
        for name, content in ALL_FILES.items():
            findings = scanner.scan_content(content, name)
            assert not _has_finding(findings, category="obfuscation"), (
                f"{name} has obfuscation finding"
            )

    def test_no_prompt_injection(self, scanner):
        for name, content in ALL_FILES.items():
            findings = scanner.scan_content(content, name)
            assert not _has_finding(findings, category="prompt_injection"), (
                f"{name} has prompt_injection finding"
            )

    def test_no_memory_poisoning(self, scanner):
        for name, content in ALL_FILES.items():
            findings = scanner.scan_content(content, name)
            assert not _has_finding(findings, category="memory_poisoning"), (
                f"{name} has memory_poisoning finding"
            )

    def test_no_supply_chain(self, scanner):
        for name, content in ALL_FILES.items():
            findings = scanner.scan_content(content, name)
            assert not _has_finding(findings, category="supply_chain"), (
                f"{name} has supply_chain finding"
            )

    def test_no_social_engineering(self, scanner):
        for name, content in ALL_FILES.items():
            findings = scanner.scan_content(content, name)
            assert not _has_finding(findings, category="social_engineering"), (
                f"{name} has social_engineering finding"
            )


# ================================================================
# 5. False-positive triage -- known MEDIUM findings
# ================================================================


class TestTDDFalsePositiveTriage:
    """Document and verify known false positives."""

    def test_mocking_md_process_env_is_medium_not_high(self, scanner):
        """mocking.md contains `process.env.STRIPE_KEY` in a TypeScript
        code block showing a *bad* pattern.  The scanner correctly
        flags it as MEDIUM (downgraded for documentation language),
        not HIGH/CRITICAL.

        This is a false positive -- the env access is illustrative,
        not executable.
        """
        findings = scanner.scan_content(MOCKING_MD, "mocking.md")
        env_findings = [
            f for f in findings
            if f.category == "exfiltration"
            and "env" in f.description.lower()
        ]
        # Should exist as a MEDIUM
        assert len(env_findings) > 0, (
            "Expected env-access finding for process.env.STRIPE_KEY"
        )
        for f in env_findings:
            assert f.severity not in (Severity.CRITICAL, Severity.HIGH), (
                f"process.env example should be MEDIUM, got {f.severity.name}"
            )

    def test_provenance_medium_is_expected(self, tdd_skill_dir, scanner):
        """GitHub-hosted skills always get a MEDIUM provenance finding.
        This is informational -- it means the skill is not served from
        a /.well-known/ path, which is expected for community skills.
        """
        result = scanner.scan_skill(tdd_skill_dir)
        prov_findings = [
            f for f in result.findings if f.category == "provenance"
        ]
        assert len(prov_findings) > 0
        for f in prov_findings:
            assert f.severity == Severity.MEDIUM


# ================================================================
# 6. Behavioral safety -- skill doesn't instruct dangerous actions
# ================================================================


class TestTDDBehavioralSafety:
    """Beyond regex patterns, verify the skill's instructions are safe."""

    def test_no_shell_code_blocks(self):
        """The TDD skill should contain zero bash/sh/shell code blocks.
        All code examples should be in TypeScript or pseudo-code."""
        import re
        for name, content in ALL_FILES.items():
            shell_blocks = re.findall(
                r"```(?:bash|sh|shell|zsh)\b", content, re.IGNORECASE
            )
            assert shell_blocks == [], (
                f"{name} contains shell code blocks: {shell_blocks}"
            )

    def test_no_file_write_instructions(self):
        """The skill should not instruct writing to system files."""
        import re
        danger_patterns = [
            r"write\s+to\s+/",
            r"echo\s+.*>\s*/",
            r"sudo\s+",
            r"chmod\s+",
            r"rm\s+-rf",
        ]
        for name, content in ALL_FILES.items():
            for pat in danger_patterns:
                assert not re.search(pat, content, re.IGNORECASE), (
                    f"{name} contains dangerous instruction matching {pat}"
                )

    def test_no_network_instructions(self):
        """The skill should not instruct fetching remote resources."""
        import re
        net_patterns = [
            r"\bcurl\b",
            r"\bwget\b",
            r"\bfetch\(",
        ]
        for name, content in ALL_FILES.items():
            # fetch() in TypeScript examples is fine -- it's API design
            # documentation, not an instruction to fetch something
            if name == "mocking.md":
                continue
            for pat in net_patterns:
                assert not re.search(pat, content, re.IGNORECASE), (
                    f"{name} contains network instruction matching {pat}"
                )

    def test_mocking_md_fetch_is_api_design(self):
        """mocking.md uses fetch() in TypeScript examples showing API
        interface design.  Verify it's inside code blocks only."""
        import re
        # Remove code blocks, then check remaining prose has no fetch
        prose = re.sub(r"```[\s\S]*?```", "", MOCKING_MD)
        assert "fetch(" not in prose, (
            "mocking.md has fetch() outside code blocks"
        )

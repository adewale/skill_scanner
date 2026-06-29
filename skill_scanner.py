#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["pyyaml>=6.0", "markdown-it-py>=3.0"]
# ///
"""Skill Scanner - Detect malware and antipatterns in AI Agent Skills.

Automatically scans common skill directories for Claude Code, Cursor,
OpenCode, OpenClaw/Clawdbot, Codex CLI, Letta Code, and other
AgentSkills-compatible tools.

Based on security research from the ClawHavoc campaign.

Usage:
    uv run skill_scanner.py
    uv run skill_scanner.py /path/to/skills
    uv run skill_scanner.py --url https://github.com/user/repo/blob/main/SKILL.md
    uv run skill_scanner.py --json
    uv run skill_scanner.py --fail-on-high

References:
    - https://snyk.io/articles/skill-md-shell-access/
    - https://1password.com/blog/from-magic-to-malware
    - https://github.com/cloudflare/agent-skills-discovery-rfc

"""

import argparse
import base64
import json
import os
import re
import sys
import unicodedata
import urllib.parse
import urllib.request
import zlib
from collections.abc import Generator
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import ClassVar

import yaml
from markdown_it import MarkdownIt

# === URL FETCHING UTILITIES ===

# Timeout for HTTP requests in seconds
URL_FETCH_TIMEOUT = 30


def _github_to_raw_url(url: str) -> str:
    """Convert a GitHub blob/tree URL to raw content.

    Handles URLs like:
      https://github.com/user/repo/blob/branch/path
    Converts to:
      https://raw.githubusercontent.com/user/repo/branch/path

    """
    parsed = urllib.parse.urlparse(url)

    # Strip query params (e.g., ?plain=1)
    path = parsed.path

    # Match /user/repo/blob/branch/...path...
    match = re.match(
        r"^/([^/]+)/([^/]+)/blob/(.+)$",
        path,
    )
    if match:
        user = match.group(1)
        repo = match.group(2)
        rest = match.group(3)
        return f"https://raw.githubusercontent.com/{user}/{repo}/{rest}"

    return url


def fetch_url(url: str) -> tuple[str, str]:
    """Fetch content from a URL.

    Returns:
        Tuple of (content, effective_url) where
        effective_url is the final URL after redirects
        and GitHub raw conversion.

    Raises:
        urllib.error.URLError: On network errors.
        ValueError: On invalid URLs.

    """
    # Convert GitHub blob URLs to raw
    if "github.com" in url and "/blob/" in url:
        url = _github_to_raw_url(url)

    req = urllib.request.Request(  # noqa: S310
        url,
        headers={"User-Agent": "SkillScanner/1.0"},
    )
    with urllib.request.urlopen(  # noqa: S310
        req,
        timeout=URL_FETCH_TIMEOUT,
    ) as response:
        content = response.read().decode(
            "utf-8",
            errors="ignore",
        )
        return content, response.url


# === UNICODE NORMALIZATION (HOMOGRAPH DEFENSE) ===
# Detection regexes are written in ASCII, so an attacker can bypass
# them with visually identical characters from other scripts -- e.g.
# Cyrillic "es" (U+0441) instead of Latin "c" in "curl" -- or by
# splitting a keyword with invisible characters (zero-width spaces,
# bidi controls). Before matching, text is folded by _fold_text():
#   1. invisible / zero-width / bidi control characters are dropped;
#   2. NFKC folds full-width / mathematical / ligature variants;
#   3. the single-character confusable map below folds cross-script
#      homoglyphs NFKC leaves untouched;
#   4. the multi-character map folds sequences like "rn" -> "m".
# A separate, map-independent mixed-script check (_check_homoglyphs)
# catches confusables that are not in the table at all.
#
# Each key is the confusable character itself; the trailing comment
# names its Unicode code point. The table only needs the cross-script
# look-alikes NFKC does not already fold.
CONFUSABLE_CHARS: dict[str, str] = {
    # --- Cyrillic lowercase -> Latin ---
    "а": "a",  # CYRILLIC SMALL LETTER A
    "е": "e",  # CYRILLIC SMALL LETTER IE
    "о": "o",  # CYRILLIC SMALL LETTER O
    "р": "p",  # CYRILLIC SMALL LETTER ER
    "с": "c",  # CYRILLIC SMALL LETTER ES
    "у": "y",  # CYRILLIC SMALL LETTER U
    "х": "x",  # CYRILLIC SMALL LETTER HA
    "ѕ": "s",  # CYRILLIC SMALL LETTER DZE
    "і": "i",  # CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I
    "ј": "j",  # CYRILLIC SMALL LETTER JE
    "к": "k",  # CYRILLIC SMALL LETTER KA
    "м": "m",  # CYRILLIC SMALL LETTER EM
    "т": "t",  # CYRILLIC SMALL LETTER TE
    "һ": "h",  # CYRILLIC SMALL LETTER SHHA
    "ԁ": "d",  # CYRILLIC SMALL LETTER KOMI DE
    "ԛ": "q",  # CYRILLIC SMALL LETTER QA
    "ԝ": "w",  # CYRILLIC SMALL LETTER WE
    "ѵ": "v",  # CYRILLIC SMALL LETTER IZHITSA
    # --- Cyrillic uppercase -> Latin ---
    "А": "A",  # CYRILLIC CAPITAL LETTER A
    "В": "B",  # CYRILLIC CAPITAL LETTER VE
    "Е": "E",  # CYRILLIC CAPITAL LETTER IE
    "Ѕ": "S",  # CYRILLIC CAPITAL LETTER DZE
    "І": "I",  # CYRILLIC CAPITAL LETTER BYELORUSSIAN-UKRAINIAN I
    "Ј": "J",  # CYRILLIC CAPITAL LETTER JE
    "К": "K",  # CYRILLIC CAPITAL LETTER KA
    "М": "M",  # CYRILLIC CAPITAL LETTER EM
    "Н": "H",  # CYRILLIC CAPITAL LETTER EN
    "О": "O",  # CYRILLIC CAPITAL LETTER O
    "Р": "P",  # CYRILLIC CAPITAL LETTER ER
    "С": "C",  # CYRILLIC CAPITAL LETTER ES
    "Т": "T",  # CYRILLIC CAPITAL LETTER TE
    "У": "Y",  # CYRILLIC CAPITAL LETTER U
    "Х": "X",  # CYRILLIC CAPITAL LETTER HA
    "Ԛ": "Q",  # CYRILLIC CAPITAL LETTER QA
    "Ԝ": "W",  # CYRILLIC CAPITAL LETTER WE
    "Ԁ": "D",  # CYRILLIC CAPITAL LETTER KOMI DE
    "Ѵ": "V",  # CYRILLIC CAPITAL LETTER IZHITSA
    # --- Greek lowercase -> Latin ---
    "α": "a",  # GREEK SMALL LETTER ALPHA
    "β": "b",  # GREEK SMALL LETTER BETA
    "γ": "y",  # GREEK SMALL LETTER GAMMA
    "ε": "e",  # GREEK SMALL LETTER EPSILON
    "η": "n",  # GREEK SMALL LETTER ETA
    "ι": "i",  # GREEK SMALL LETTER IOTA
    "κ": "k",  # GREEK SMALL LETTER KAPPA
    "ν": "v",  # GREEK SMALL LETTER NU
    "ο": "o",  # GREEK SMALL LETTER OMICRON
    "ρ": "p",  # GREEK SMALL LETTER RHO
    "τ": "t",  # GREEK SMALL LETTER TAU
    "υ": "u",  # GREEK SMALL LETTER UPSILON
    "χ": "x",  # GREEK SMALL LETTER CHI
    "ω": "w",  # GREEK SMALL LETTER OMEGA
    "ϲ": "c",  # GREEK LUNATE SIGMA SYMBOL
    # --- Greek uppercase -> Latin ---
    "Α": "A",  # GREEK CAPITAL LETTER ALPHA
    "Β": "B",  # GREEK CAPITAL LETTER BETA
    "Ε": "E",  # GREEK CAPITAL LETTER EPSILON
    "Ζ": "Z",  # GREEK CAPITAL LETTER ZETA
    "Η": "H",  # GREEK CAPITAL LETTER ETA
    "Ι": "I",  # GREEK CAPITAL LETTER IOTA
    "Κ": "K",  # GREEK CAPITAL LETTER KAPPA
    "Μ": "M",  # GREEK CAPITAL LETTER MU
    "Ν": "N",  # GREEK CAPITAL LETTER NU
    "Ο": "O",  # GREEK CAPITAL LETTER OMICRON
    "Ρ": "P",  # GREEK CAPITAL LETTER RHO
    "Τ": "T",  # GREEK CAPITAL LETTER TAU
    "Υ": "Y",  # GREEK CAPITAL LETTER UPSILON
    "Χ": "X",  # GREEK CAPITAL LETTER CHI
    "Ϲ": "C",  # GREEK CAPITAL LUNATE SIGMA SYMBOL
    # --- Other Latin look-alikes NFKC does not fold ---
    "ı": "i",  # LATIN SMALL LETTER DOTLESS I
    "ɡ": "g",  # LATIN SMALL LETTER SCRIPT G
    "ɗ": "d",  # LATIN SMALL LETTER D WITH HOOK
    "ƅ": "b",  # LATIN SMALL LETTER TONE SIX
    "ɠ": "g",  # LATIN SMALL LETTER G WITH HOOK
    "ӏ": "l",  # CYRILLIC SMALL LETTER PALOCHKA
    # --- Armenian look-alikes ---
    "ո": "n",  # ARMENIAN SMALL LETTER VO
    "օ": "o",  # ARMENIAN SMALL LETTER OH
    "ս": "u",  # ARMENIAN SMALL LETTER SEH
    # --- Command-syntax punctuation look-alikes ---
    "∕": "/",  # DIVISION SLASH
    "⁄": "/",  # FRACTION SLASH
    "․": ".",  # ONE DOT LEADER
    "。": ".",  # IDEOGRAPHIC FULL STOP
    "∶": ":",  # RATIO
    "꞉": ":",  # MODIFIER LETTER COLON
    "‐": "-",  # HYPHEN
    "‑": "-",  # NON-BREAKING HYPHEN
    "‒": "-",  # FIGURE DASH
    "–": "-",  # EN DASH
    "—": "-",  # EM DASH
    "―": "-",  # HORIZONTAL BAR
    "−": "-",  # MINUS SIGN
    "∣": "|",  # DIVIDES
    "│": "|",  # BOX DRAWINGS LIGHT VERTICAL
    "ǀ": "|",  # LATIN LETTER DENTAL CLICK
}

_CONFUSABLE_TRANSLATION = str.maketrans(CONFUSABLE_CHARS)

# Multi-character confusables: short sequences that imitate a single
# ASCII letter in many fonts (e.g. "rn" -> "m"). Folded after the
# single-character map, so e.g. "chrnod" is matched as "chmod".
MULTI_CHAR_CONFUSABLES: dict[str, str] = {
    "rn": "m",
    "vv": "w",
    "cl": "d",
}
_MULTI_CHAR_LENGTHS = sorted(
    {len(k) for k in MULTI_CHAR_CONFUSABLES},
    reverse=True,
)

# Scripts whose letters are commonly used as Latin look-alikes. A token
# mixing Latin with any of these is treated as a homograph even when the
# specific code point is absent from CONFUSABLE_CHARS.
_LOOKALIKE_SCRIPTS = frozenset(
    {
        "CYRILLIC",
        "GREEK",
        "COPTIC",
        "ARMENIAN",
        "CHEROKEE",
        "GEORGIAN",
    }
)

# Sensitive tokens. A run of confusables that folds exactly to one of
# these is flagged even when it is not mixed-script: a wholly non-Latin
# "word" that spells a shell command is never legitimate.
HOMOGLYPH_KEYWORDS: frozenset[str] = frozenset(
    {
        "curl",
        "wget",
        "bash",
        "sh",
        "zsh",
        "ssh",
        "scp",
        "nc",
        "netcat",
        "sudo",
        "chmod",
        "chown",
        "eval",
        "exec",
        "python",
        "node",
        "npm",
        "npx",
        "pip",
        "perl",
        "ruby",
        "telnet",
        "env",
        "base64",
        "crontab",
        "launchctl",
        "systemctl",
        "powershell",
        "openssl",
    }
)


def _is_invisible(char: str) -> bool:
    """True for zero-width, bidi-control and other invisible code points.

    These carry no visible glyph and are a common way to break up a
    keyword (e.g. a zero-width space inside ``curl``), so they are
    dropped before matching.
    """
    cp = ord(char)
    return (
        cp == 0x00AD  # SOFT HYPHEN
        or cp == 0x034F  # COMBINING GRAPHEME JOINER
        or cp == 0x061C  # ARABIC LETTER MARK
        or 0x200B <= cp <= 0x200F  # ZWSP, ZWNJ, ZWJ, LRM, RLM
        or 0x202A <= cp <= 0x202E  # bidi embeddings / overrides
        or 0x2060 <= cp <= 0x2064  # word joiner, invisible operators
        or 0x2066 <= cp <= 0x2069  # bidi isolates
        or 0xFE00 <= cp <= 0xFE0F  # variation selectors
        or cp == 0x180E  # MONGOLIAN VOWEL SEPARATOR
        or cp == 0xFEFF  # ZERO WIDTH NO-BREAK SPACE / BOM
    )


def _script_of(char: str) -> str | None:
    """Best-effort Unicode script for a character (no external data).

    Approximated from the character's Unicode name prefix, which is good
    enough to tell Latin from Cyrillic/Greek/Armenian/... for homograph
    detection. Returns None for characters with no assigned name.
    """
    try:
        name = unicodedata.name(char)
    except ValueError:
        return None
    return name.split(" ", 1)[0]


def _fold_text(text: str) -> tuple[str, list[int] | None]:
    """Fold text for matching and map each output char to its source.

    Drops invisible characters, applies NFKC, then the single- and
    multi-character confusable maps. Returns ``(folded, offsets)`` where
    ``offsets[i]`` is the index in ``text`` that produced ``folded[i]``.
    ``offsets`` is None only when the text is unchanged and ASCII-clean
    (no invisible or multi-character confusables), in which case the
    identity mapping applies.
    """
    # Fast path: ASCII with no multi-character confusable sequence is
    # returned unchanged (offsets = identity).
    if text.isascii() and not any(
        seq in text.lower() for seq in MULTI_CHAR_CONFUSABLES
    ):
        return text, None

    chars: list[str] = []
    offsets: list[int] = []
    for i, ch in enumerate(text):
        if _is_invisible(ch):
            continue
        if ch.isascii():
            folded = ch
        else:
            folded = unicodedata.normalize("NFKC", ch).translate(
                _CONFUSABLE_TRANSLATION,
            )
        for fc in folded:
            chars.append(fc)
            offsets.append(i)

    # Multi-character confusable pass, preserving source offsets.
    out_chars: list[str] = []
    out_offsets: list[int] = []
    j = 0
    n = len(chars)
    while j < n:
        repl = None
        for klen in _MULTI_CHAR_LENGTHS:
            if j + klen <= n:
                seq = "".join(chars[j : j + klen]).lower()
                repl = MULTI_CHAR_CONFUSABLES.get(seq)
                if repl is not None:
                    out_chars.append(repl)
                    out_offsets.append(offsets[j])
                    j += klen
                    break
        if repl is None:
            out_chars.append(chars[j])
            out_offsets.append(offsets[j])
            j += 1

    return "".join(out_chars), out_offsets


def normalize_confusables(text: str) -> str:
    """Fold Unicode look-alikes to ASCII for robust pattern matching.

    Strips invisible characters, applies NFKC, then the single- and
    multi-character confusable maps. The result is for detection only,
    not for display.
    """
    return _fold_text(text)[0]


def _raw_span(
    original: str,
    offsets: list[int] | None,
    start: int,
    end: int,
) -> str:
    """Map a ``[start, end)`` span in folded text back to ``original``.

    ``offsets`` is the map from :func:`_fold_text` (None means the folded
    text equals ``original``).
    """
    if offsets is None:
        return original[start:end]
    if start >= len(offsets):
        return ""
    lo = offsets[start]
    hi = offsets[min(end, len(offsets)) - 1]
    return original[lo : hi + 1]


class Severity(Enum):
    """Severity levels for scan findings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


# === WHITELIST CONFIGURATIONS ===
# Patterns that should NOT trigger alerts (learned from real-world
# audits)

# Standard development ports - not suspicious for localhost
SAFE_LOCALHOST_PORTS = {
    3000,  # Node.js/React dev server
    3001,  # Common alternative
    4000,  # Phoenix/other frameworks
    5000,  # Flask default
    5173,  # Vite dev server
    5174,  # Vite alternative
    8000,  # Django/Python common
    8080,  # Common HTTP alt port
    8787,  # Cloudflare Workers default
    8788,  # Cloudflare Wrangler dev
    8789,  # Wrangler alternative
    9000,  # Various tools
}

# TypeScript/JavaScript patterns that look like env access
# but aren't
TYPESCRIPT_ENV_PATTERNS = [
    r"interface\s+Env\s*\{",
    r"<Env>",
    r"<Env,",
    r"extends\s+\w+<Env",
    r"Env\s*\|",
    r"\|\s*Env",
    r"type\s+Env\s*=",
    r":\s*Env\b",
]

# Languages where patterns are likely illustrative,
# not executable
DOCUMENTATION_LANGUAGES = {
    "typescript",
    "ts",
    "tsx",
    "javascript",
    "js",
    "jsx",
    "python",
    "py",
    "go",
    "rust",
    "java",
    "csharp",
    "cs",
    "json",
    "yaml",
    "toml",
    "xml",
    "sql",
    "graphql",
    "html",
    "css",
    "scss",
    "markdown",
    "md",
    "text",
    "txt",
}

# Shell languages where patterns ARE executable/concerning
EXECUTABLE_LANGUAGES = {
    "bash",
    "sh",
    "shell",
    "zsh",
    "powershell",
    "ps1",
    "cmd",
    "bat",
    "fish",
}

# Thresholds for risk analysis (extracted for PLR2004)
MAX_DESCRIPTION_LENGTH = 1000
LONG_DESCRIPTION_THRESHOLD = 500
MAX_SAFE_EXECUTABLE_COUNT = 3
MAX_DISPLAY_LENGTH = 80


@dataclass
class Finding:
    """A single scan finding."""

    severity: Severity
    category: str
    description: str
    file_path: str
    line_number: int | None = None
    matched_content: str = ""
    recommendation: str = ""


@dataclass
class SkillProvenance:
    """Trust signals for a skill's origin and authenticity.

    Per the Agent Skills Discovery RFC
    (cloudflare/agent-skills-discovery-rfc), a skill is "official"
    if and only if it is served from the domain's well-known path:
    https://example.com/.well-known/skills/{name}/

    Domain ownership = trust. This is the same model as HTTPS
    certificates.

    """

    # Origin information
    source_url: str | None = None
    origin_domain: str | None = None

    # Official status (per RFC)
    is_well_known: bool = False
    is_official: bool = False

    # Additional signals (informational, not for trust)
    publisher: str | None = None
    has_security_policy: bool = False
    has_code_of_conduct: bool = False
    license: str | None = None

    @property
    def trust_score(self) -> int:
        """Calculate trust score 0-100.

        Official skills (from well-known) get high trust.
        Everything else is untrusted until manually verified.

        """
        if self.is_official:
            score = 90  # Official = high trust
            if self.has_security_policy:
                score += 5
            if self.license:
                score += 5
            return min(100, score)

        # Non-official skills start untrusted
        score = 30  # Baseline for unverified

        if self.source_url:
            score += 10  # At least we know where it came from
        if self.has_security_policy:
            score += 5
        if self.license:
            score += 5

        return min(70, score)  # Cap at 70 for non-official

    @property
    def trust_level(self) -> str:
        """Human-readable trust level."""
        if self.is_official:
            return "OFFICIAL"
        if self.source_url:
            return "UNVERIFIED"
        return "UNKNOWN"


@dataclass
class SkillMetadata:
    """Structural analysis of a skill for risk assessment."""

    has_scripts_folder: bool = False
    has_references_folder: bool = False
    has_valid_frontmatter: bool = False
    skill_file_count: int = 0
    executable_file_count: int = 0
    description_length: int = 0

    @property
    def structure_risk_score(self) -> int:
        """Higher score = higher risk based on structure."""
        score = 0
        if self.has_scripts_folder:
            score += 20
        if self.executable_file_count > 0:
            score += 10 * min(self.executable_file_count, 5)
        if not self.has_valid_frontmatter:
            score += 10
        if self.description_length > MAX_DESCRIPTION_LENGTH:
            score += 5
        if self.has_references_folder:
            score -= 10
        return max(0, score)


@dataclass
class ScanResult:
    """Result of scanning a single skill."""

    skill_path: str
    skill_name: str
    findings: list[Finding] = field(default_factory=list)
    provenance: SkillProvenance | None = None
    metadata: SkillMetadata | None = None

    @property
    def is_safe(self) -> bool:
        """Return True if no critical or high findings."""
        return not any(
            f.severity in (Severity.CRITICAL, Severity.HIGH)
            for f in self.findings
        )

    @property
    def critical_count(self) -> int:
        """Count of critical findings."""
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        """Count of high findings."""
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)


# === COMMON SKILL LOCATIONS ===
# These are the default directories where various AI tools
# store skills


def get_default_skill_paths() -> list[Path]:
    """Return a list of common skill directories to scan.

    Supports:
    - Claude Code: ~/.claude/skills/, .claude/skills/
    - Cursor: ~/.cursor/skills/, .cursor/skills/
    - OpenAI Codex CLI: ~/.codex/skills/
    - OpenCode: ~/.config/opencode/skills/,
      .opencode/skills/
    - OpenClaw/Clawdbot/Moltbot:
      ~/.openclaw/skills/, ~/.clawdbot/skills/, ./skills/
    - Letta Code: .skills/
    - Skillport: ~/.skillport/skills/
    - OpenSkills universal: .agent/skills/

    """
    home = Path.home()
    cwd = Path.cwd()

    # XDG config dir (Linux/macOS)
    xdg_config = Path(
        os.environ.get("XDG_CONFIG_HOME", home / ".config"),
    )

    return [
        # Claude Code
        home / ".claude" / "skills",
        cwd / ".claude" / "skills",
        # Cursor
        home / ".cursor" / "skills",
        cwd / ".cursor" / "skills",
        # OpenAI Codex CLI
        home / ".codex" / "skills",
        # OpenCode
        xdg_config / "opencode" / "skills",
        cwd / ".opencode" / "skills",
        # OpenClaw / Clawdbot / Moltbot
        home / ".openclaw" / "skills",
        home / ".clawdbot" / "skills",  # legacy
        home / "openclaw" / "skills",  # legacy
        cwd / "skills",  # workspace
        # Letta Code
        cwd / ".skills",
        # Skillport
        home / ".skillport" / "skills",
        # OpenSkills universal location
        cwd / ".agent" / "skills",
    ]


class SkillScanner:
    """Scans Skills for malware indicators and antipatterns."""

    # === PATTERN DEFINITIONS ===

    # Dangerous shell patterns (CRITICAL/HIGH severity)
    DANGEROUS_SHELL_PATTERNS: ClassVar[list[tuple[str, Severity, str]]] = [
        # Piped execution - classic attack vector
        (
            r"curl\s+[^|]*\|\s*(ba)?sh",
            Severity.CRITICAL,
            "Piped curl execution (curl | bash)",
        ),
        (
            r"wget\s+[^|]*\|\s*(ba)?sh",
            Severity.CRITICAL,
            "Piped wget execution (wget | bash)",
        ),
        (
            r"curl.*\|\s*python",
            Severity.CRITICAL,
            "Piped curl to Python execution",
        ),
        (
            r"curl.*\|\s*node",
            Severity.CRITICAL,
            "Piped curl to Node execution",
        ),
        # macOS quarantine bypass - malware evasion
        (
            r"xattr\s+-[dr].*com\.apple\.quarantine",
            Severity.CRITICAL,
            "macOS quarantine bypass (Gatekeeper evasion)",
        ),
        (
            r"spctl\s+--master-disable",
            Severity.CRITICAL,
            "Disabling macOS Gatekeeper",
        ),
        # Privilege escalation
        (
            r"sudo\s+chmod\s+777",
            Severity.HIGH,
            "Overly permissive chmod with sudo",
        ),
        (
            r"chmod\s+\+s\s",
            Severity.CRITICAL,
            "Setting SUID bit",
        ),
        (
            r"sudo\s+su\s*$",
            Severity.HIGH,
            "Escalating to root shell",
        ),
        # Reverse shells
        (
            r"bash\s+-i\s+>&\s*/dev/tcp/",
            Severity.CRITICAL,
            "Bash reverse shell",
        ),
        (
            r"nc\s+-e\s+/bin/(ba)?sh",
            Severity.CRITICAL,
            "Netcat reverse shell",
        ),
        (
            r"python.*socket.*connect.*shell",
            Severity.CRITICAL,
            "Python reverse shell pattern",
        ),
        # Persistence mechanisms
        (
            r"crontab\s+-[el]",
            Severity.MEDIUM,
            "Crontab modification",
        ),
        (
            r"launchctl\s+load",
            Severity.MEDIUM,
            "macOS LaunchAgent loading",
        ),
        (
            r"systemctl\s+enable",
            Severity.MEDIUM,
            "Systemd service enablement",
        ),
        # Process hiding/evasion
        (
            r"nohup.*&\s*$",
            Severity.MEDIUM,
            "Background process with nohup",
        ),
        (
            r"disown",
            Severity.LOW,
            "Process disowning",
        ),
        # Code-execution sinks in scripting languages. These are how a
        # trojan helper script, conftest.py, or npm postinstall actually
        # runs a payload when the syntax is not raw shell. In doc-language
        # code blocks these are downgraded by _adjust_severity_for_context;
        # in real .py/.js files they keep full severity.
        (
            r"os\.system\s*\(",
            Severity.HIGH,
            "Python os.system() command execution",
        ),
        (
            r"subprocess\.\w+\([^)]*shell\s*=\s*True",
            Severity.HIGH,
            "subprocess call with shell=True",
        ),
        (
            r"os\.popen\s*\(",
            Severity.HIGH,
            "Python os.popen() command execution",
        ),
        (
            r"pty\.spawn\s*\(",
            Severity.HIGH,
            "pty.spawn() (interactive shell spawning)",
        ),
        (
            r"child_process\.(exec|execSync|spawn)\s*\(",
            Severity.HIGH,
            "Node child_process command execution",
        ),
        (
            r"__import__\s*\(\s*['\"]os['\"]",
            Severity.MEDIUM,
            "Dynamic os import (obfuscated execution)",
        ),
    ]

    # Data exfiltration patterns
    EXFILTRATION_PATTERNS: ClassVar[list[tuple[str, Severity, str]]] = [
        # Sensitive file access
        (
            r"~?/?\.ssh/id_rsa",
            Severity.CRITICAL,
            "SSH private key access",
        ),
        (
            r"~?/?\.ssh/id_ed25519",
            Severity.CRITICAL,
            "SSH private key access",
        ),
        (
            r"~?/?\.aws/credentials",
            Severity.CRITICAL,
            "AWS credentials access",
        ),
        (
            r"~?/?\.gnupg/",
            Severity.HIGH,
            "GPG keyring access",
        ),
        (
            r"~?/?\.ssh/(id_dsa|id_ecdsa)\b",
            Severity.CRITICAL,
            "SSH private key access",
        ),
        (
            r"~?/?\.git-credentials\b",
            Severity.CRITICAL,
            "Git credential store access",
        ),
        (
            r"~?/?\.netrc\b",
            Severity.HIGH,
            "netrc credentials access",
        ),
        (
            r"~?/?\.kube/config\b",
            Severity.HIGH,
            "Kubernetes credentials access",
        ),
        (
            r"~?/?\.config/gcloud/",
            Severity.HIGH,
            "Google Cloud credentials access",
        ),
        (
            r"~?/?\.npmrc\b",
            Severity.MEDIUM,
            "npm auth token file access",
        ),
        (
            r"~?/?\.env\b",
            Severity.HIGH,
            "Environment file access",
        ),
        (
            r"\.clawdbot/\.env",
            Severity.CRITICAL,
            "OpenClaw credentials access",
        ),
        (
            r"\.openclaw/\.env",
            Severity.CRITICAL,
            "OpenClaw credentials access",
        ),
        (
            r"SOUL\.md|MEMORY\.md",
            Severity.HIGH,
            "Agent memory file access (potential poisoning)",
        ),
        # Browser data theft
        (
            r"Login Data|Cookies|Local State",
            Severity.CRITICAL,
            "Browser credential/cookie access",
        ),
        (
            r"Chrome.*Profile",
            Severity.HIGH,
            "Chrome profile access",
        ),
        (
            r"Firefox.*profiles",
            Severity.HIGH,
            "Firefox profile access",
        ),
        (
            r"~/Library/Keychains",
            Severity.CRITICAL,
            "macOS Keychain access",
        ),
        # Cryptocurrency wallet theft
        (
            r"\.exodus/",
            Severity.CRITICAL,
            "Exodus wallet access",
        ),
        (
            r"\.electrum/",
            Severity.CRITICAL,
            "Electrum wallet access",
        ),
        (
            r"MetaMask",
            Severity.CRITICAL,
            "MetaMask wallet access",
        ),
        (
            r"solana.*keypair|\.config/solana",
            Severity.CRITICAL,
            "Solana wallet access",
        ),
        (
            r"\.bitcoin/",
            Severity.CRITICAL,
            "Bitcoin wallet access",
        ),
        # Network exfiltration
        (
            r"curl\s+.*POST\s+.*-d",
            Severity.MEDIUM,
            "POST request with data",
        ),
        (
            r"nc\s+\d+\.\d+\.\d+\.\d+",
            Severity.HIGH,
            "Netcat to IP address",
        ),
    ]

    # Suspicious URL patterns
    SUSPICIOUS_URL_PATTERNS: ClassVar[list[tuple[str, Severity, str]]] = [
        # URL shorteners (obfuscation)
        (
            r"bit\.ly/",
            Severity.HIGH,
            "URL shortener (bit.ly)",
        ),
        (
            r"tinyurl\.com/",
            Severity.HIGH,
            "URL shortener (tinyurl)",
        ),
        (
            r"t\.co/",
            Severity.HIGH,
            "URL shortener (t.co)",
        ),
        (
            r"goo\.gl/",
            Severity.HIGH,
            "URL shortener (goo.gl)",
        ),
        (
            r"is\.gd/",
            Severity.HIGH,
            "URL shortener (is.gd)",
        ),
        # Paste/code hosting (used for staging payloads)
        (
            r"pastebin\.com/raw/",
            Severity.HIGH,
            "Raw pastebin content",
        ),
        (
            r"glot\.io/",
            Severity.CRITICAL,
            "Glot.io (common malware stager)",
        ),
        (
            r"paste\.ee/",
            Severity.HIGH,
            "Paste.ee content",
        ),
        (
            r"ghostbin\.(co|com)/",
            Severity.HIGH,
            "Ghostbin content",
        ),
        (
            r"hastebin\.com/",
            Severity.MEDIUM,
            "Hastebin content",
        ),
        # Raw file hosting
        (
            r"githubusercontent\.com.*\.sh",
            Severity.MEDIUM,
            "Shell script from GitHub raw",
        ),
        (
            r"raw\.githubusercontent\.com",
            Severity.LOW,
            "GitHub raw content",
        ),
        # IP addresses in URLs (suspicious)
        (
            r"https?://\d+\.\d+\.\d+\.\d+",
            Severity.HIGH,
            "Direct IP address URL",
        ),
        # Non-standard ports
        (
            r"https?://[^/]+:\d{4,5}/",
            Severity.MEDIUM,
            "URL with non-standard port",
        ),
    ]

    # Obfuscation patterns
    OBFUSCATION_PATTERNS: ClassVar[list[tuple[str, Severity, str]]] = [
        # Base64 encoded commands
        (
            r"base64\s+-[dD]",
            Severity.HIGH,
            "Base64 decoding",
        ),
        (
            r"echo\s+[A-Za-z0-9+/=]{20,}\s*\|\s*base64",
            Severity.CRITICAL,
            "Encoded payload execution",
        ),
        (
            r'atob\([\'"][A-Za-z0-9+/=]{20,}',
            Severity.CRITICAL,
            "JavaScript base64 decode of long string",
        ),
        # Eval and dynamic execution
        (
            r"\beval\s*\(",
            Severity.HIGH,
            "eval() usage",
        ),
        (
            r"exec\s*\(",
            Severity.HIGH,
            "exec() usage",
        ),
        (
            r'Function\s*\([\'"]',
            Severity.HIGH,
            "Dynamic Function constructor",
        ),
        # Hex/octal encoded strings
        (
            r"\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){5,}",
            Severity.HIGH,
            "Hex-encoded string",
        ),
        (
            r"\\[0-7]{3}(\\[0-7]{3}){5,}",
            Severity.HIGH,
            "Octal-encoded string",
        ),
        # Variable obfuscation
        (
            r"\$\{\w+::\d+:\d+\}",
            Severity.MEDIUM,
            "Bash substring obfuscation",
        ),
        (
            r"\$\(\(\s*\d+\s*[+\-*/]\s*\d+\s*\)\)",
            Severity.LOW,
            "Arithmetic obfuscation",
        ),
    ]

    # Social engineering patterns (antipatterns in docs)
    SOCIAL_ENGINEERING_PATTERNS: ClassVar[list[tuple[str, Severity, str]]] = [
        # Fake prerequisites
        (
            r"prerequisite.*install|install.*prerequisite",
            Severity.MEDIUM,
            "Prerequisite installation instruction",
        ),
        (
            r"required.*dependency|dependency.*required",
            Severity.LOW,
            "Required dependency mention",
        ),
        (
            r"must.*first.*install|first.*install.*must",
            Severity.MEDIUM,
            "Mandatory installation step",
        ),
        # Urgency/pressure tactics
        (
            r"(important|critical|required).*run.*command",
            Severity.MEDIUM,
            "Urgent command execution",
        ),
        (
            r"paste.*terminal|terminal.*paste",
            Severity.MEDIUM,
            "Terminal paste instruction",
        ),
        (
            r"copy.*paste.*run",
            Severity.MEDIUM,
            "Copy-paste-run instruction",
        ),
        # Trust manipulation
        (
            r"completely\s+safe|totally\s+safe|100%\s+safe",
            Severity.MEDIUM,
            "Exaggerated safety claim",
        ),
        (
            r"trust\s+(me|this|us)",
            Severity.LOW,
            "Trust solicitation",
        ),
    ]

    # Prompt injection / Guardrail bypass patterns
    PROMPT_INJECTION_PATTERNS: ClassVar[list[tuple[str, Severity, str]]] = [
        # Direct guardrail bypass attempts
        (
            r"ignore\s+(previous|prior|above)"
            r"\s+instructions?",
            Severity.CRITICAL,
            "Guardrail bypass attempt",
        ),
        (
            r"disregard\s+(all|any)"
            r"\s+(safety|security)",
            Severity.CRITICAL,
            "Safety bypass instruction",
        ),
        (
            r"skip\s+(confirmation|approval"
            r"|verification)",
            Severity.HIGH,
            "Approval workflow bypass",
        ),
        (
            r"don'?t\s+ask\s+(again"
            r"|for\s+confirmation)",
            Severity.HIGH,
            "Consent gap exploitation",
        ),
        (
            r"always\s+(allow|approve|execute)",
            Severity.HIGH,
            "Blanket approval instruction",
        ),
        (
            r"without\s+(asking|confirmation"
            r"|approval)",
            Severity.HIGH,
            "Silent execution instruction",
        ),
        # Role manipulation
        (
            r"you\s+are\s+(now|actually)",
            Severity.MEDIUM,
            "Role injection attempt",
        ),
        (
            r"act\s+as\s+(if|though)\s+you",
            Severity.MEDIUM,
            "Behavioral manipulation",
        ),
        (
            r"pretend\s+(to\s+be|you\s+are)",
            Severity.MEDIUM,
            "Identity manipulation",
        ),
        # Hidden instructions (long-context attacks)
        (
            r"<!-- .*?(exec|curl|bash|eval).*?-->",
            Severity.CRITICAL,
            "Hidden instruction in HTML comment",
        ),
        (
            r"\[//\]:\s*#\s*\("
            r".*?(exec|curl|bash).*?\)",
            Severity.CRITICAL,
            "Hidden instruction in MD comment",
        ),
        # Self-modification
        (
            r"(update|modify|edit)\s+(this\s+)?skill",
            Severity.HIGH,
            "Self-modifying skill instruction",
        ),
        (
            r"write\s+to\s+SKILL\.md",
            Severity.CRITICAL,
            "Skill self-modification",
        ),
        # Cross-skill chain loading
        (
            r"do\s+everything\s+.{0,40}"
            r"(skill|version)\s+says",
            Severity.HIGH,
            "Cross-skill chain-loading delegation",
        ),
        (
            r"follow\s+(all\s+)?instructions\s+"
            r"(from|in)\s+.{0,30}skill",
            Severity.HIGH,
            "Cross-skill instruction delegation",
        ),
        (
            r"run\s+.{0,20}skill\s+first",
            Severity.MEDIUM,
            "Skill prerequisite chain",
        ),
    ]

    # Memory poisoning patterns (agent persistence attacks)
    MEMORY_POISONING_PATTERNS: ClassVar[list[tuple[str, Severity, str]]] = [
        # Direct memory file manipulation
        (
            r"write\s+to\s+(SOUL|MEMORY)\.md",
            Severity.CRITICAL,
            "Agent memory poisoning",
        ),
        (
            r"(append|add)\s+to\s+(SOUL|MEMORY)",
            Severity.CRITICAL,
            "Agent memory injection",
        ),
        (
            r"modify\s+(SOUL|MEMORY)",
            Severity.CRITICAL,
            "Agent memory modification",
        ),
        (
            r"(update|change)\s+(personality"
            r"|behavior|instructions)",
            Severity.HIGH,
            "Behavioral persistence attack",
        ),
        # Persistent instruction injection
        (
            r"remember\s+(to\s+always"
            r"|this\s+instruction)",
            Severity.MEDIUM,
            "Memory instruction injection",
        ),
        (
            r"from\s+now\s+on.*always",
            Severity.MEDIUM,
            "Persistent behavioral change",
        ),
        (
            r"add\s+this\s+to\s+your"
            r"\s+(memory|context)",
            Severity.HIGH,
            "Context injection",
        ),
    ]

    # Writes to global agent memory/config files (cross-session
    # persistence). These are matched against RAW (un-folded) text by
    # _check_memory_writes rather than the folded pattern pipeline,
    # because confusable folding rewrites the literal "claude"
    # (cl -> d) and would corrupt the keyword. Homoglyph spellings of
    # the paths are still caught independently by _check_homoglyphs.
    GLOBAL_MEMORY_PATTERNS: ClassVar[list[tuple[str, Severity, str]]] = [
        (
            r"(>>?|\btee\b|cp\s|mv\s|install\s)[^\n]{0,80}"
            r"\.(claude|codex|cursor|gemini)/",
            Severity.CRITICAL,
            "Write to global agent config directory (persistence)",
        ),
        (
            r"(echo|printf|cat|write|append|add|insert|tee)"
            r"[^\n]{0,60}\b(CLAUDE|AGENTS|GEMINI)\.md",
            Severity.HIGH,
            "Modifying global agent instructions "
            "(CLAUDE.md/AGENTS.md/GEMINI.md)",
        ),
        (
            r"\.(claude|codex|cursor|gemini)/"
            r"(CLAUDE|AGENTS|GEMINI|settings|config)"
            r"\.(md|json|toml)",
            Severity.HIGH,
            "Reference to global agent config/memory file",
        ),
    ]

    # Supply chain risk patterns
    SUPPLY_CHAIN_PATTERNS: ClassVar[list[tuple[str, Severity, str]]] = [
        # npx without version pinning
        (
            r"npx\s+-y\s+\w+(?!\s*@)",
            Severity.MEDIUM,
            "npx -y without version pinning",
        ),
        (
            r"npm\s+install\s+(?!.*@\d)",
            Severity.LOW,
            "npm install without version",
        ),
        (
            r"pip\s+install\s+(?!.*==)",
            Severity.LOW,
            "pip install without version",
        ),
        # Skill installation (chain-loading)
        (
            r"npx\s+skills\s+add\s",
            Severity.HIGH,
            "Remote skill installation (potential chain-loading)",
        ),
        (
            r"npx\s+add-skill\s",
            Severity.HIGH,
            "Remote skill installation (potential chain-loading)",
        ),
        # Downloading binaries
        (
            r"curl.*-o.*\.exe",
            Severity.HIGH,
            "Downloading Windows executable",
        ),
        (
            r"curl.*-o.*/bin/",
            Severity.HIGH,
            "Downloading to bin directory",
        ),
        (
            r"wget.*\.dmg",
            Severity.HIGH,
            "Downloading macOS disk image",
        ),
        (
            r"curl.*\.pkg",
            Severity.HIGH,
            "Downloading macOS package",
        ),
        # Archive extraction
        (
            r"unzip.*-P",
            Severity.HIGH,
            "Password-protected archive extraction",
        ),
        (
            r"tar.*-[xz].*https?://",
            Severity.MEDIUM,
            "Remote archive extraction",
        ),
    ]

    # Files that should be scrutinized more carefully
    SENSITIVE_FILENAMES: ClassVar[list[str]] = [
        "install.sh",
        "setup.sh",
        "init.sh",
        "bootstrap.sh",
        "postinstall.js",
        "preinstall.js",
        "helper.py",
        "utils.py",
        ".env",
        ".env.example",
    ]

    def __init__(self, *, verbose: bool = False) -> None:
        """Initialize scanner with pattern lists."""
        self.verbose = verbose
        self.md_parser = MarkdownIt()
        self.all_patterns = (
            [(*p, "dangerous_shell") for p in self.DANGEROUS_SHELL_PATTERNS]
            + [(*p, "exfiltration") for p in self.EXFILTRATION_PATTERNS]
            + [(*p, "suspicious_url") for p in self.SUSPICIOUS_URL_PATTERNS]
            + [(*p, "obfuscation") for p in self.OBFUSCATION_PATTERNS]
            + [
                (*p, "social_engineering")
                for p in self.SOCIAL_ENGINEERING_PATTERNS
            ]
            + [
                (*p, "prompt_injection")
                for p in self.PROMPT_INJECTION_PATTERNS
            ]
            + [
                (*p, "memory_poisoning")
                for p in self.MEMORY_POISONING_PATTERNS
            ]
            + [(*p, "supply_chain") for p in self.SUPPLY_CHAIN_PATTERNS]
        )

    def _is_typescript_env_pattern(
        self,
        content: str,
    ) -> bool:
        """Check if Env match is a TypeScript type pattern."""
        return any(
            re.search(pattern, content) for pattern in TYPESCRIPT_ENV_PATTERNS
        )

    def _is_safe_localhost_url(
        self,
        url_match: str,
    ) -> bool:
        """Check if URL is a safe localhost development URL."""
        port_match = re.search(
            r"localhost:(\d+)",
            url_match,
        )
        if port_match:
            port = int(port_match.group(1))
            if port in SAFE_LOCALHOST_PORTS:
                return True
        return False

    def _is_documentation_language(
        self,
        lang: str,
    ) -> bool:
        """Check if code block language is for docs."""
        return lang.lower() in DOCUMENTATION_LANGUAGES

    def _is_executable_language(
        self,
        lang: str,
    ) -> bool:
        """Check if code block language is executable."""
        return lang.lower() in EXECUTABLE_LANGUAGES

    def _should_skip_finding(
        self,
        _pattern: str,
        description: str,
        content: str,
        _lang: str,
        category: str,
    ) -> bool:
        """Determine if a finding should be skipped."""
        # Skip TypeScript Env patterns (false positive)
        if (
            category == "exfiltration"
            and "env" in description.lower()
            and self._is_typescript_env_pattern(content)
        ):
            return True

        # Skip safe localhost dev ports
        return (
            category == "suspicious_url"
            and "non-standard port" in description.lower()
            and self._is_safe_localhost_url(content)
        )

    def _adjust_severity_for_context(
        self,
        severity: Severity,
        lang: str,
        category: str,
    ) -> Severity:
        """Adjust severity based on code block language."""
        # Patterns in documentation languages are less
        # concerning (they're examples, not executable)
        if self._is_documentation_language(lang) and category not in (
            "prompt_injection",
            "memory_poisoning",
        ):
            if severity == Severity.HIGH:
                return Severity.MEDIUM
            if severity == Severity.CRITICAL:
                return Severity.HIGH

        # Patterns in shell languages are MORE concerning
        if (
            self._is_executable_language(lang)
            and category == "dangerous_shell"
            and severity == Severity.HIGH
        ):
            return Severity.CRITICAL

        return severity

    def scan_content(
        self,
        content: str,
        file_path: str,
    ) -> list[Finding]:
        """Scan text content for malicious patterns."""
        findings = []

        # Use AST-based scanning for markdown files
        if file_path.endswith(".md"):
            ast = self.parse_skill_ast(content)
            findings.extend(
                self.scan_code_blocks(ast, file_path),
            )
            findings.extend(
                self.scan_hidden_content(ast, file_path),
            )
            findings.extend(
                self._check_suspicious_metadata_from_ast(
                    ast,
                    file_path,
                ),
            )
            findings.extend(
                self._check_command_directives(content, file_path),
            )

            # Also scan prose content (non-code-block text)
            # for prompt injection
            raw_prose = content
            for block in ast.get("code_blocks", []):
                raw_prose = raw_prose.replace(
                    block.get("content", ""),
                    "",
                )
            prose_content, prose_offsets = _fold_text(raw_prose)

            # Scan prose for prompt injection,
            # memory poisoning, social engineering,
            # and supply chain patterns (inline code
            # like `npx skills add` appears in prose)
            prose_patterns = (
                [
                    (*p, "prompt_injection")
                    for p in self.PROMPT_INJECTION_PATTERNS
                ]
                + [
                    (*p, "memory_poisoning")
                    for p in self.MEMORY_POISONING_PATTERNS
                ]
                + [
                    (*p, "social_engineering")
                    for p in self.SOCIAL_ENGINEERING_PATTERNS
                ]
                + [(*p, "supply_chain") for p in self.SUPPLY_CHAIN_PATTERNS]
            )
            for (
                pattern,
                severity,
                description,
                category,
            ) in prose_patterns:
                findings.extend(
                    [
                        Finding(
                            severity=severity,
                            category=category,
                            description=(f"{description} (in prose)"),
                            file_path=file_path,
                            matched_content=_raw_span(
                                raw_prose,
                                prose_offsets,
                                match.start(),
                                match.end(),
                            )[:80],
                            recommendation=(
                                self._get_recommendation(
                                    category,
                                )
                            ),
                        )
                        for match in re.finditer(
                            pattern,
                            prose_content,
                            re.IGNORECASE,
                        )
                    ]
                )
        else:
            # For non-markdown files, line-by-line scanning.
            # Fold each line so homograph/confusable bypasses are matched
            # while line numbers stay accurate and the reported match is
            # mapped back to the raw (un-folded) source text.
            raw_lines = content.split("\n")
            folded_lines = [_fold_text(rl) for rl in raw_lines]
            for (
                pattern,
                severity,
                description,
                category,
            ) in self.all_patterns:
                for line_num, (raw_line, folded) in enumerate(
                    zip(raw_lines, folded_lines, strict=True),
                    1,
                ):
                    folded_line, line_offsets = folded
                    findings.extend(
                        [
                            Finding(
                                severity=severity,
                                category=category,
                                description=description,
                                file_path=file_path,
                                line_number=line_num,
                                matched_content=_raw_span(
                                    raw_line,
                                    line_offsets,
                                    match.start(),
                                    match.end(),
                                )[:100],
                                recommendation=(
                                    self._get_recommendation(
                                        category,
                                    )
                                ),
                            )
                            for match in re.finditer(
                                pattern,
                                folded_line,
                                re.IGNORECASE,
                            )
                        ]
                    )

        # Additional heuristic checks
        findings.extend(
            self._check_base64_blobs(content, file_path),
        )
        findings.extend(
            self._check_homoglyphs(content, file_path),
        )
        findings.extend(
            self._check_idn_homographs(content, file_path),
        )
        findings.extend(
            self._check_memory_writes(content, file_path),
        )

        return findings

    def _check_suspicious_metadata_from_ast(
        self,
        ast: dict,
        file_path: str,
    ) -> list[Finding]:
        """Check parsed frontmatter for suspicious metadata."""
        findings = []
        metadata = ast.get("frontmatter")

        if not metadata:
            return findings

        # Frontmatter hooks are executed by the harness (Claude Code)
        # when the skill loads -- the agent never gets to refuse. Flag
        # their presence and escalate if a hook command looks dangerous.
        hooks = metadata.get("hooks")
        if hooks:
            hooks_str = json.dumps(hooks)
            folded = normalize_confusables(hooks_str)
            severity = Severity.HIGH
            description = (
                "Skill defines harness hooks in frontmatter "
                "(executed automatically on load)"
            )
            for pattern, _sev, _desc in self.DANGEROUS_SHELL_PATTERNS:
                if re.search(pattern, folded, re.IGNORECASE):
                    severity = Severity.CRITICAL
                    description = (
                        "Frontmatter hook contains a dangerous command "
                        "(auto-executed by the harness)"
                    )
                    break
            findings.append(
                Finding(
                    severity=severity,
                    category="harness_abuse",
                    description=description,
                    file_path=file_path,
                    matched_content=hooks_str[:100],
                    recommendation=(self._get_recommendation("harness_abuse")),
                )
            )

        # Check for suspicious binary requirements
        if "metadata" in metadata:
            meta_str = json.dumps(metadata["metadata"])
            if "requires" in meta_str and "bins" in meta_str:
                findings.append(
                    Finding(
                        severity=Severity.LOW,
                        category="supply_chain",
                        description=("Skill declares binary dependencies"),
                        file_path=file_path,
                        matched_content=meta_str[:100],
                        recommendation=(
                            "Verify all binary dependencies are legitimate"
                        ),
                    )
                )

        # Check for overly broad descriptions
        desc = metadata.get("description", "")
        if len(desc) > LONG_DESCRIPTION_THRESHOLD:
            findings.append(
                Finding(
                    severity=Severity.LOW,
                    category="prompt_injection",
                    description=(
                        "Unusually long skill description "
                        "(may hide instructions)"
                    ),
                    file_path=file_path,
                    matched_content=(f"Description length: {len(desc)} chars"),
                    recommendation=(
                        "Review the full description for hidden instructions"
                    ),
                )
            )

        return findings

    def _check_base64_blobs(
        self,
        content: str,
        file_path: str,
    ) -> list[Finding]:
        """Detect large base64 blobs that might be payloads."""
        findings = []
        blob_pattern = r"[A-Za-z0-9+/=]{100,}"
        for match in re.finditer(blob_pattern, content):
            blob = match.group(0)
            try:
                decoded = normalize_confusables(
                    base64.b64decode(blob).decode(
                        "utf-8",
                        errors="ignore",
                    )
                )
                suspicious_keywords = [
                    "bash",
                    "curl",
                    "wget",
                    "eval",
                    "exec",
                ]
                if any(kw in decoded.lower() for kw in suspicious_keywords):
                    findings.append(
                        Finding(
                            severity=Severity.CRITICAL,
                            category="obfuscation",
                            description=(
                                "Base64 blob containing executable keywords"
                            ),
                            file_path=file_path,
                            matched_content=(
                                f"Base64: {blob[:50]}..."
                                " decodes to content "
                                "with shell commands"
                            ),
                            recommendation=(
                                "Manually decode and review "
                                "this base64 content"
                            ),
                        )
                    )
            except (ValueError, UnicodeDecodeError):
                pass  # Not valid base64, ignore
        return findings

    def _check_homoglyphs(
        self,
        content: str,
        file_path: str,
    ) -> list[Finding]:
        """Flag Unicode homoglyph / confusable obfuscation.

        Two map-independent signals:

        * a token mixes Latin letters with letters from a look-alike
          script (Cyrillic, Greek, ...) -- the classic homograph form,
          caught even for confusables absent from CONFUSABLE_CHARS; and
        * a wholly non-Latin token folds exactly to a sensitive command
          keyword (a non-Latin "word" spelling ``curl`` is never benign).
        """
        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()
        for match in re.finditer(r"[^\W\d_]{2,}", content):
            word = match.group(0)
            if word.isascii():
                continue
            scripts = {
                s for s in (_script_of(c) for c in word) if s is not None
            }
            mixed_script = "LATIN" in scripts and bool(
                scripts & _LOOKALIKE_SCRIPTS
            )
            normalized = normalize_confusables(word)
            folds_to_keyword = (
                normalized.isascii()
                and normalized.lower() in HOMOGLYPH_KEYWORDS
            )
            if not (mixed_script or folds_to_keyword):
                continue
            key = (word, normalized)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(
                    severity=(
                        Severity.CRITICAL
                        if folds_to_keyword
                        else Severity.HIGH
                    ),
                    category="obfuscation",
                    description=(
                        "Unicode homoglyph obfuscation: "
                        f"{word!r} mixes scripts / resembles "
                        f"{normalized!r}"
                    ),
                    file_path=file_path,
                    matched_content=f"{word!r} -> {normalized!r}",
                    recommendation=(
                        "Look-alike characters from other scripts "
                        "(e.g. Cyrillic/Greek) are disguised as ASCII "
                        "to evade detection. Treat as highly suspicious "
                        "and review the de-obfuscated text."
                    ),
                )
            )
        return findings

    def _check_idn_homographs(
        self,
        content: str,
        file_path: str,
    ) -> list[Finding]:
        """Flag punycode (IDN) labels that decode to homograph domains.

        ``xn--`` labels are decoded; a decoded label containing a
        look-alike-script character is an internationalized domain
        impersonating an ASCII one.
        """
        findings: list[Finding] = []
        seen: set[str] = set()
        for match in re.finditer(r"xn--[a-z0-9-]+", content, re.IGNORECASE):
            label = match.group(0)
            if label in seen:
                continue
            seen.add(label)
            try:
                decoded = label[4:].encode("ascii").decode("punycode")
            except (UnicodeError, ValueError):
                continue
            if decoded.isascii():
                continue
            folded = normalize_confusables(decoded)
            scripts = {
                s for s in (_script_of(c) for c in decoded) if s is not None
            }
            if not (scripts & _LOOKALIKE_SCRIPTS or folded != decoded):
                continue
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    category="suspicious_url",
                    description=(
                        "Punycode/IDN homograph domain: "
                        f"{label!r} decodes to {decoded!r}"
                    ),
                    file_path=file_path,
                    matched_content=f"{label} -> {decoded} (~{folded})",
                    recommendation=(
                        "Internationalized domain names can impersonate "
                        "ASCII domains. Verify the real registrable "
                        "domain before trusting this URL."
                    ),
                )
            )
        return findings

    def _check_command_directives(
        self,
        content: str,
        file_path: str,
    ) -> list[Finding]:
        """Flag the Claude Code ``!`` pre-prompt command directive.

        A line beginning with ``!`` is expanded at skill-load time by
        running the shell command and inlining its output -- executed
        blindly by the harness, with no model mediation. Lines inside
        fenced code blocks are illustrative and are skipped.
        """
        findings: list[Finding] = []
        in_fence = False
        for line_num, raw_line in enumerate(content.split("\n"), 1):
            stripped = raw_line.strip()
            if stripped.startswith(("```", "~~~")):
                in_fence = not in_fence
                continue
            if in_fence:
                continue
            # The harness expands ANY line beginning with `!` by running
            # the command, regardless of which binary it names, so flag
            # the directive itself. The leading-char class requires a
            # command-like token (letter/digit/./~/_/-), which excludes
            # markdown image embeds (`![alt](url)`) and bare punctuation.
            match = re.match(
                r"^!\s*`?\s*([A-Za-z0-9./~_-][^\s`]*)",
                raw_line.lstrip(),
            )
            if not match:
                continue
            findings.append(
                Finding(
                    severity=Severity.CRITICAL,
                    category="harness_abuse",
                    description=(
                        "Pre-prompt command directive (`!`) -- executed "
                        "by the harness at skill-load time"
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    matched_content=stripped[:100],
                    recommendation=(self._get_recommendation("harness_abuse")),
                )
            )
        return findings

    def _check_memory_writes(
        self,
        content: str,
        file_path: str,
    ) -> list[Finding]:
        """Flag writes/references to global agent memory/config files.

        Matched against the RAW text (not the confusable-folded text the
        pattern pipeline uses) because folding rewrites "claude" and
        would corrupt the keyword. Homoglyph spellings are still caught
        independently by _check_homoglyphs.
        """
        findings: list[Finding] = []
        seen: set[str] = set()
        for pattern, severity, description in self.GLOBAL_MEMORY_PATTERNS:
            match = re.search(pattern, content, re.IGNORECASE)
            if not match or description in seen:
                continue
            seen.add(description)
            findings.append(
                Finding(
                    severity=severity,
                    category="memory_poisoning",
                    description=description,
                    file_path=file_path,
                    matched_content=match.group(0)[:100],
                    recommendation=(
                        self._get_recommendation("memory_poisoning")
                    ),
                )
            )
        return findings

    def _check_symlinks(self, skill_path: Path) -> list[Finding]:
        """Flag symlinks anywhere in a skill tree.

        A relative symlink disguised as an example file (e.g.
        ``examples/id_rsa.example`` -> ``../../../.ssh/id_rsa``) makes
        the agent read a credential outside the skill when it follows
        an innocent "read the example" instruction. Symlinks are never
        required by a legitimate skill, so any symlink is reported;
        those escaping the skill directory or targeting a sensitive
        path are escalated.
        """
        sensitive = (
            ".ssh",
            "id_rsa",
            "id_ed25519",
            "id_ecdsa",
            "id_dsa",
            ".aws",
            "credentials",
            ".gnupg",
            ".netrc",
            ".kube",
            ".docker/config",
            ".config/gcloud",
            ".npmrc",
            ".pypirc",
            ".git-credentials",
            "/etc/",
            ".bitcoin",
            ".electrum",
            ".exodus",
            "keychain",
            "wallet",
        )
        findings: list[Finding] = []
        try:
            skill_root = skill_path.resolve()
        except OSError:
            skill_root = skill_path
        try:
            entries = list(skill_path.rglob("*"))
        except OSError:
            return findings
        for entry in entries:
            if not entry.is_symlink():
                continue
            try:
                raw_target = os.readlink(entry)
            except OSError:
                raw_target = ""
            try:
                resolved = entry.resolve()
            except OSError:
                resolved = None
            haystack = f"{raw_target} {resolved or ''}".lower()
            if any(marker in haystack for marker in sensitive):
                severity = Severity.CRITICAL
                description = (
                    "Symlink targets a sensitive path (credential "
                    "exfiltration via 'read the example file')"
                )
            else:
                escapes = True
                if resolved is not None:
                    try:
                        resolved.relative_to(skill_root)
                        escapes = False
                    except ValueError:
                        escapes = True
                if escapes:
                    severity = Severity.HIGH
                    description = "Symlink points outside the skill directory"
                else:
                    severity = Severity.LOW
                    description = "Symlink inside skill directory"
            findings.append(
                Finding(
                    severity=severity,
                    category="exfiltration",
                    description=description,
                    file_path=str(entry),
                    matched_content=f"{entry.name} -> {raw_target}"[:100],
                    recommendation=(
                        "Skills should not contain symlinks. Remove it "
                        "or verify the target is inside the skill and "
                        "benign."
                    ),
                )
            )
        return findings

    def _check_package_json(
        self,
        file_path: Path,
        content: str,
    ) -> list[Finding]:
        """Flag npm lifecycle hooks (preinstall/postinstall/...).

        These scripts run automatically when ``npm install`` resolves
        the package -- a supply-chain RCE vector that needs no agent
        action at all.
        """
        findings: list[Finding] = []
        try:
            data = json.loads(content)
        except (json.JSONDecodeError, ValueError):
            return findings
        if not isinstance(data, dict):
            return findings
        scripts = data.get("scripts")
        if not isinstance(scripts, dict):
            return findings
        lifecycle = {
            "preinstall",
            "install",
            "postinstall",
            "prepare",
            "prepublish",
            "prepublishOnly",
            "preuninstall",
            "postuninstall",
            "prepack",
            "postpack",
        }
        for name, command in scripts.items():
            if name not in lifecycle:
                continue
            command_str = str(command)
            folded = normalize_confusables(command_str)
            severity = Severity.HIGH
            description = (
                f"npm lifecycle hook '{name}' runs automatically on install"
            )
            for pattern, _sev, _desc in self.DANGEROUS_SHELL_PATTERNS:
                if re.search(pattern, folded, re.IGNORECASE):
                    severity = Severity.CRITICAL
                    description = (
                        f"npm lifecycle hook '{name}' contains a "
                        "dangerous command (auto-executed on install)"
                    )
                    break
            findings.append(
                Finding(
                    severity=severity,
                    category="supply_chain",
                    description=description,
                    file_path=str(file_path),
                    matched_content=f"{name}: {command_str}"[:100],
                    recommendation=(
                        "npm runs install lifecycle scripts "
                        "automatically. Audit or remove pre/post-install "
                        "hooks."
                    ),
                )
            )
        return findings

    @staticmethod
    def _printable_runs(data: bytes, minlen: int = 4) -> str:
        """Return printable-ASCII runs of ``data`` joined by newlines."""
        runs: list[str] = []
        current = bytearray()
        for byte in data:
            if 32 <= byte < 127:
                current.append(byte)
                continue
            if len(current) >= minlen:
                runs.append(current.decode("ascii", "ignore"))
            current = bytearray()
        if len(current) >= minlen:
            runs.append(current.decode("ascii", "ignore"))
        return "\n".join(runs)

    @staticmethod
    def _decode_itxt(chunk: bytes) -> str:
        """Decode a PNG ``iTXt`` chunk to ``keyword: text``."""
        keyword, _, rest = chunk.partition(b"\x00")
        if len(rest) < 2:
            return ""
        compression_flag = rest[0]
        after = rest[2:]
        _lang, _, after = after.partition(b"\x00")
        _transkw, _, text = after.partition(b"\x00")
        if compression_flag == 1:
            try:
                text = zlib.decompress(text)
            except zlib.error:
                return ""
        decoded = text.decode("utf-8", "ignore")
        return f"{keyword.decode('utf-8', 'ignore')}: {decoded}"

    @staticmethod
    def _extract_png_text(data: bytes) -> str:
        """Extract text from PNG tEXt/zTXt/iTXt metadata chunks."""
        if not data.startswith(b"\x89PNG\r\n\x1a\n"):
            return ""
        parts: list[str] = []
        pos = 8
        total = len(data)
        while pos + 8 <= total:
            length = int.from_bytes(data[pos : pos + 4], "big")
            ctype = data[pos + 4 : pos + 8]
            start = pos + 8
            end = start + length
            if end > total:
                break
            chunk = data[start:end]
            if ctype == b"tEXt":
                keyword, _, text = chunk.partition(b"\x00")
                parts.append(
                    keyword.decode("latin-1", "ignore")
                    + ": "
                    + text.decode("latin-1", "ignore")
                )
            elif ctype == b"zTXt":
                keyword, _, rest = chunk.partition(b"\x00")
                compressed = rest[1:] if rest else b""
                try:
                    text = zlib.decompress(compressed)
                except zlib.error:
                    text = b""
                parts.append(
                    keyword.decode("latin-1", "ignore")
                    + ": "
                    + text.decode("latin-1", "ignore")
                )
            elif ctype == b"iTXt":
                decoded = SkillScanner._decode_itxt(chunk)
                if decoded:
                    parts.append(decoded)
            elif ctype == b"IEND":
                break
            pos = end + 4
        return "\n".join(p for p in parts if p.strip())

    @staticmethod
    def _extract_jpeg_text(data: bytes) -> str:
        """Extract text from JPEG comment (COM) and EXIF segments."""
        if not data.startswith(b"\xff\xd8"):
            return ""
        parts: list[str] = []
        pos = 2
        total = len(data)
        while pos + 4 <= total:
            if data[pos] != 0xFF:
                break
            marker = data[pos + 1]
            if marker == 0xD9 or 0xD0 <= marker <= 0xD7:
                pos += 2
                continue
            seg_len = int.from_bytes(data[pos + 2 : pos + 4], "big")
            seg_start = pos + 4
            seg_end = pos + 2 + seg_len
            if seg_end > total or seg_len < 2:
                break
            segment = data[seg_start:seg_end]
            if marker == 0xFE:
                parts.append(segment.decode("latin-1", "ignore"))
            elif marker == 0xE1 and segment.startswith(b"Exif"):
                parts.append(SkillScanner._printable_runs(segment))
            if marker == 0xDA:
                break
            pos = seg_end
        return "\n".join(p for p in parts if p.strip())

    @staticmethod
    def _extract_gif_text(data: bytes) -> str:
        """Extract text from GIF comment/application/plain-text extensions.

        Walks the GIF block structure so sub-block data is read from the
        real extension blocks (introducer 0x21) rather than image data.
        """
        if not (data.startswith(b"GIF87a") or data.startswith(b"GIF89a")):
            return ""
        parts: list[str] = []
        total = len(data)
        if total < 13:
            return ""
        # Logical Screen Descriptor: skip the global color table if present.
        packed = data[10]
        pos = 13
        if packed & 0x80:
            pos += 3 * (2 ** ((packed & 0x07) + 1))

        def _read_sub_blocks(start: int) -> tuple[bytes, int]:
            chunks: list[bytes] = []
            cur = start
            while cur < total:
                size = data[cur]
                cur += 1
                if size == 0:
                    break
                if cur + size > total:
                    return b"".join(chunks), total
                chunks.append(data[cur : cur + size])
                cur += size
            return b"".join(chunks), cur

        while pos < total:
            block = data[pos]
            if block == 0x3B:  # trailer
                break
            if block == 0x21:  # extension introducer
                if pos + 1 >= total:
                    break
                label = data[pos + 1]
                payload, pos = _read_sub_blocks(pos + 2)
                if label in (0xFE, 0xFF, 0x01):
                    parts.append(payload.decode("latin-1", "ignore"))
            elif block == 0x2C:  # image descriptor
                if pos + 10 > total:
                    break
                img_packed = data[pos + 9]
                pos += 10
                if img_packed & 0x80:
                    pos += 3 * (2 ** ((img_packed & 0x07) + 1))
                pos += 1  # LZW minimum code size
                _, pos = _read_sub_blocks(pos)
            else:
                break
        return "\n".join(p for p in parts if p.strip())

    @staticmethod
    def _extract_webp_text(data: bytes) -> str:
        """Extract text from WebP EXIF and XMP RIFF chunks."""
        if not (data[:4] == b"RIFF" and data[8:12] == b"WEBP"):
            return ""
        parts: list[str] = []
        pos = 12
        total = len(data)
        while pos + 8 <= total:
            fourcc = data[pos : pos + 4]
            size = int.from_bytes(data[pos + 4 : pos + 8], "little")
            start = pos + 8
            end = start + size
            if end > total:
                break
            chunk = data[start:end]
            if fourcc == b"EXIF":
                parts.append(SkillScanner._printable_runs(chunk))
            elif fourcc == b"XMP ":
                parts.append(chunk.decode("utf-8", "ignore"))
            pos = end + (size & 1)  # chunks are padded to an even size
        return "\n".join(p for p in parts if p.strip())

    @staticmethod
    def _extract_ico_text(data: bytes) -> str:
        """Extract text from PNG-encoded frames inside an ICO file.

        Since Windows Vista, ICO entries may hold a full PNG instead of
        a BMP, so a PNG carrying tEXt/zTXt/iTXt instructions can hide in
        an icon. BMP entries have no text metadata and are ignored.
        """
        # ICONDIR: reserved=0, type=1 (icon) -> b"\x00\x00\x01\x00".
        if len(data) < 6 or data[:4] != b"\x00\x00\x01\x00":
            return ""
        count = int.from_bytes(data[4:6], "little")
        total = len(data)
        parts: list[str] = []
        for i in range(count):
            entry = 6 + i * 16
            if entry + 16 > total:
                break
            size = int.from_bytes(data[entry + 8 : entry + 12], "little")
            offset = int.from_bytes(data[entry + 12 : entry + 16], "little")
            if size <= 0 or offset + size > total:
                continue
            blob = data[offset : offset + size]
            if blob.startswith(b"\x89PNG\r\n\x1a\n"):
                text = SkillScanner._extract_png_text(blob)
                if text:
                    parts.append(text)
        return "\n".join(p for p in parts if p.strip())

    def _extract_image_text(self, file_path: Path) -> str:
        """Return text embedded in an image's metadata.

        Supports PNG (tEXt/zTXt/iTXt), JPEG (COM/EXIF), GIF (comment and
        application extensions), WebP (EXIF/XMP chunks) and ICO
        (PNG-encoded frames).
        """
        try:
            data = file_path.read_bytes()
        except OSError:
            return ""
        suffix = file_path.suffix.lower()
        if suffix == ".png":
            return self._extract_png_text(data)
        if suffix in (".jpg", ".jpeg"):
            return self._extract_jpeg_text(data)
        if suffix == ".gif":
            return self._extract_gif_text(data)
        if suffix == ".webp":
            return self._extract_webp_text(data)
        if suffix == ".ico":
            return self._extract_ico_text(data)
        return ""

    def _scan_image_metadata(self, file_path: Path) -> list[Finding]:
        """Scan text embedded in image metadata (PNG/JPEG).

        Images are a context-poisoning vector: instructions hidden in
        PNG tEXt/iTXt/zTXt chunks or JPEG comment/EXIF fields are read
        by an agent that processes the image but stay invisible to a
        human reviewing the skill source.
        """
        findings: list[Finding] = []
        text = self._extract_image_text(file_path)
        if not text.strip():
            return findings
        path_str = str(file_path)
        folded = normalize_confusables(text)
        for pattern, severity, description, category in self.all_patterns:
            if re.search(pattern, folded, re.IGNORECASE):
                findings.append(
                    Finding(
                        severity=severity,
                        category=category,
                        description=f"{description} (in image metadata)",
                        file_path=path_str,
                        matched_content=text[:80],
                        recommendation=(self._get_recommendation(category)),
                    )
                )
        instruction_re = (
            r"ignore\s+(previous|prior|above)|you\s+(are|must|should)\b"
            r"|do\s+not\s+(tell|mention|reveal)"
            r"|run\s+(the\s+)?(following|this|script)"
            r"|execute\s+(the|this|following)"
            r"|\bcurl\b|\bwget\b|\bbash\b|sh\s+-c|\.sh\b"
            r"|chmod\s|\beval\s*\("
        )
        if re.search(instruction_re, folded, re.IGNORECASE):
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    category="prompt_injection",
                    description=(
                        "Instruction-like text hidden in image metadata"
                    ),
                    file_path=path_str,
                    matched_content=text[:80],
                    recommendation=(
                        "Images must not carry agent instructions. This "
                        "is a context-poisoning vector -- inspect the "
                        "embedded metadata."
                    ),
                )
            )
        findings.extend(self._check_base64_blobs(text, path_str))
        return findings

    def _get_recommendation(self, category: str) -> str:
        """Get remediation recommendation for a category."""
        recommendations = {
            "dangerous_shell": (
                "Review the command carefully. "
                "Avoid piping remote content to "
                "shells. Use checksums for downloads."
            ),
            "exfiltration": (
                "Verify this file access is "
                "necessary. Sensitive files should "
                "never be read by Skills."
            ),
            "suspicious_url": (
                "Verify the URL points to a "
                "legitimate, trusted source. "
                "Avoid URL shorteners."
            ),
            "obfuscation": (
                "Decode and review obfuscated "
                "content manually before execution."
            ),
            "social_engineering": (
                "Be skeptical of urgency or "
                "mandatory installation steps. "
                "Verify all prerequisites "
                "independently."
            ),
            "supply_chain": (
                "Pin dependency versions. Verify "
                "package authenticity. Use lockfiles."
            ),
            "prompt_injection": (
                "This skill may attempt to bypass "
                "safety controls. Review carefully "
                "or reject."
            ),
            "memory_poisoning": (
                "This skill attempts to modify "
                "agent memory/behavior persistently."
                " High risk of backdoor."
            ),
            "harness_abuse": (
                "This skill uses a harness feature that "
                "executes code automatically on load "
                "(frontmatter hooks or the `!` directive). "
                "The command runs with no model mediation -- "
                "remove or audit it."
            ),
            "structure": (
                "Skills with executable code require"
                " more careful review than "
                "documentation-only skills."
            ),
            "provenance": (
                "Verify the publisher's identity. "
                "Only install skills from "
                "trusted sources."
            ),
        }
        return recommendations.get(
            category,
            "Review this finding manually.",
        )

    def parse_skill_ast(self, content: str) -> dict:
        """Parse SKILL.md into structured AST."""
        result = {
            "frontmatter": None,
            "code_blocks": [],
            "headings": [],
            "links": [],
            "html_comments": [],
        }

        # Extract YAML frontmatter
        yaml_match = re.match(
            r"^---\s*\n(.*?)\n---\s*\n?",
            content,
            re.DOTALL,
        )
        if yaml_match:
            try:
                result["frontmatter"] = yaml.safe_load(
                    yaml_match.group(1),
                )
                content = content[yaml_match.end() :]
            except yaml.YAMLError:
                pass

        # Parse markdown to tokens
        tokens = self.md_parser.parse(content)

        current_heading = None
        for token in tokens:
            if token.type == "heading_open":
                current_heading = token.tag
            elif token.type == "inline" and current_heading:
                result["headings"].append(
                    {
                        "level": current_heading,
                        "text": token.content,
                    }
                )
                current_heading = None
            elif token.type == "fence":
                result["code_blocks"].append(
                    {
                        "language": (
                            token.info.strip() if token.info else None
                        ),
                        "content": token.content,
                    }
                )
            elif token.type == "html_block" and "<!--" in token.content:
                result["html_comments"].append(
                    token.content,
                )

        # Extract links using regex
        link_pattern = r"\[([^\]]*)\]\(([^)]+)\)"
        for match in re.finditer(link_pattern, content):
            result["links"].append(
                {
                    "text": match.group(1),
                    "url": match.group(2),
                }
            )

        return result

    def scan_code_blocks(
        self,
        ast: dict,
        file_path: str,
    ) -> list[Finding]:
        """Scan code blocks for dangerous patterns."""
        findings = []

        for block in ast.get("code_blocks", []):
            lang = (block.get("language") or "").lower()
            # Fold for matching; report the raw (un-folded) source.
            raw_content = block.get("content", "")
            content = normalize_confusables(raw_content)

            # Flag unmarked code blocks with
            # shell-like content
            if not lang and re.search(
                r"^\s*(curl|wget|npm|pip"
                r"|sudo|chmod|eval)\s",
                content,
                re.MULTILINE,
            ):
                findings.append(
                    Finding(
                        severity=Severity.MEDIUM,
                        category="obfuscation",
                        description=(
                            "Unmarked code block with shell commands"
                        ),
                        file_path=file_path,
                        matched_content=raw_content[:80],
                        recommendation=(
                            "Explicitly mark code block "
                            "language for transparency"
                        ),
                    )
                )

            # Scan code block content with patterns
            for (
                pattern,
                severity,
                description,
                category,
            ) in self.all_patterns:
                if re.search(
                    pattern,
                    content,
                    re.IGNORECASE | re.MULTILINE,
                ):
                    # Check whitelist
                    if self._should_skip_finding(
                        pattern,
                        description,
                        content,
                        lang,
                        category,
                    ):
                        continue

                    # Adjust severity based on context
                    adjusted_severity = self._adjust_severity_for_context(
                        severity,
                        lang,
                        category,
                    )

                    findings.append(
                        Finding(
                            severity=adjusted_severity,
                            category=category,
                            description=(
                                f"{description} "
                                f"(in {lang or 'unmarked'}"
                                " code block)"
                            ),
                            file_path=file_path,
                            matched_content=raw_content[:80],
                            recommendation=(
                                self._get_recommendation(
                                    category,
                                )
                            ),
                        )
                    )

        return findings

    def scan_hidden_content(
        self,
        ast: dict,
        file_path: str,
    ) -> list[Finding]:
        """Scan for hidden malicious content."""
        findings = []
        for comment in ast.get("html_comments", []):
            normalized = normalize_confusables(comment)
            if re.search(
                r"(curl|wget|bash|eval|exec|nc\s)",
                normalized,
                re.IGNORECASE,
            ):
                findings.append(
                    Finding(
                        severity=Severity.CRITICAL,
                        category="prompt_injection",
                        description=(
                            "Hidden executable instruction in HTML comment"
                        ),
                        file_path=file_path,
                        matched_content=comment[:80],
                        recommendation=(
                            "Hidden instructions are a "
                            "strong indicator of "
                            "malicious intent"
                        ),
                    )
                )
        return findings

    def _is_pytest_autoexec(self, name: str) -> bool:
        """True if pytest auto-discovers and runs this file."""
        return (
            name == "conftest.py"
            or (name.startswith("test_") and name.endswith(".py"))
            or name.endswith("_test.py")
        )

    def scan_file(self, file_path: Path) -> list[Finding]:
        """Scan a single file."""
        findings = []

        # Check for sensitive filenames
        if file_path.name in self.SENSITIVE_FILENAMES:
            findings.append(
                Finding(
                    severity=Severity.INFO,
                    category="file_audit",
                    description=(f"Sensitive filename: {file_path.name}"),
                    file_path=str(file_path),
                    recommendation=(
                        "This file type requires careful manual review"
                    ),
                )
            )

        # pytest auto-discovers conftest.py and test_*.py / *_test.py and
        # executes them on collection -- bundling them in a skill is an
        # ecosystem RCE vector (the agent only has to run the tests).
        if self._is_pytest_autoexec(file_path.name):
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    category="supply_chain",
                    description=(
                        "Auto-executed test file: pytest runs "
                        f"'{file_path.name}' on collection (RCE vector)"
                    ),
                    file_path=str(file_path),
                    recommendation=(
                        "pytest imports conftest.py and test files "
                        "automatically. Review for code that runs at "
                        "import/collection time."
                    ),
                )
            )

        # Read and scan content
        try:
            content = file_path.read_text(
                encoding="utf-8",
                errors="ignore",
            )
            findings.extend(
                self.scan_content(content, str(file_path)),
            )
            if file_path.name == "package.json":
                findings.extend(
                    self._check_package_json(file_path, content),
                )
        except OSError as e:
            if self.verbose:
                print(  # noqa: T201
                    f"  Warning: Could not read {file_path}: {e}",
                )

        return findings

    def extract_provenance(  # noqa: C901, PLR0912
        self,
        skill_path: Path,
        source_url: str | None = None,
    ) -> SkillProvenance:
        """Extract trust signals from skill directory.

        Per the Agent Skills Discovery RFC, a skill is
        "official" only if served from
        /.well-known/skills/ on a domain.

        """
        provenance = SkillProvenance()
        provenance.source_url = source_url

        # Check if from a well-known URL (official)
        if source_url:
            well_known_match = re.search(
                r"https?://([^/]+)"
                r"/\.well-known/skills/([^/]+)/",
                source_url,
            )
            if well_known_match:
                provenance.origin_domain = well_known_match.group(1)
                provenance.is_well_known = True
                provenance.is_official = True

        # Try to find git remote URL (informational)
        git_dir = skill_path / ".git"
        if not git_dir.exists():
            for parent in skill_path.parents:
                if (parent / ".git").exists():
                    git_dir = parent / ".git"
                    break

        if git_dir.exists():
            git_config = git_dir / "config"
            if git_config.exists():
                try:
                    config_text = git_config.read_text()
                    url_match = re.search(
                        r"url\s*=\s*(.+)",
                        config_text,
                    )
                    if url_match:
                        url = url_match.group(1).strip()
                        if not provenance.source_url:
                            provenance.source_url = url

                        # Extract org/user from GitHub
                        gh_match = re.search(
                            r"github\.com[:/]"
                            r"([^/]+)/([^/.\s]+)",
                            url,
                        )
                        if gh_match:
                            provenance.publisher = gh_match.group(1).lower()
                except OSError:
                    pass

        # Check for security policy and code of conduct
        for check_path in [
            skill_path,
            skill_path.parent,
            skill_path.parent.parent,
        ]:
            if (check_path / "SECURITY.md").exists():
                provenance.has_security_policy = True
            if (check_path / "CODE_OF_CONDUCT.md").exists():
                provenance.has_code_of_conduct = True
            if (
                provenance.has_security_policy
                and provenance.has_code_of_conduct
            ):
                break

        # Check SKILL.md frontmatter for license
        skill_md = skill_path / "SKILL.md"
        if skill_md.exists():
            try:
                content = skill_md.read_text(
                    encoding="utf-8",
                    errors="ignore",
                )
                yaml_match = re.match(
                    r"^---\s*\n(.*?)\n---",
                    content,
                    re.DOTALL,
                )
                if yaml_match:
                    fm = yaml.safe_load(
                        yaml_match.group(1),
                    )
                    if fm and isinstance(fm, dict):
                        provenance.license = fm.get("license")
                        if not provenance.publisher:
                            provenance.publisher = fm.get("author") or fm.get(
                                "publisher"
                            )
            except (OSError, yaml.YAMLError):
                pass

        return provenance

    def analyze_skill_structure(
        self,
        skill_path: Path,
    ) -> SkillMetadata:
        """Analyze skill directory structure for risk."""
        metadata = SkillMetadata()

        if not skill_path.exists() or not skill_path.is_dir():
            return metadata

        # Check for common folders
        metadata.has_scripts_folder = (skill_path / "scripts").exists()
        metadata.has_references_folder = (skill_path / "references").exists()

        # Count files
        executable_extensions = {
            ".sh",
            ".bash",
            ".py",
            ".js",
            ".ps1",
            ".bat",
            ".cmd",
        }
        for file_path in skill_path.rglob("*"):
            if file_path.is_file():
                metadata.skill_file_count += 1
                if file_path.suffix.lower() in executable_extensions:
                    metadata.executable_file_count += 1

        # Check frontmatter in SKILL.md
        skill_md = skill_path / "SKILL.md"
        if skill_md.exists():
            try:
                content = skill_md.read_text(
                    encoding="utf-8",
                    errors="ignore",
                )
                yaml_match = re.match(
                    r"^---\s*\n(.*?)\n---",
                    content,
                    re.DOTALL,
                )
                if yaml_match:
                    try:
                        fm = yaml.safe_load(
                            yaml_match.group(1),
                        )
                        if fm and isinstance(fm, dict):
                            metadata.has_valid_frontmatter = True
                            desc = fm.get(
                                "description",
                                "",
                            )
                            metadata.description_length = (
                                len(desc) if isinstance(desc, str) else 0
                            )
                    except yaml.YAMLError:
                        pass
            except (OSError, yaml.YAMLError):
                pass

        return metadata

    def scan_skill(  # noqa: C901
        self,
        skill_path: Path,
        source_url: str | None = None,
    ) -> ScanResult:
        """Scan an entire skill directory.

        Args:
            skill_path: Local path to skill directory.
            source_url: Optional URL where skill was
                fetched from (for provenance).

        """
        skill_name = skill_path.name

        # Handle both .skill files and skill directories
        if skill_path.is_file() and skill_path.suffix == ".skill":
            skill_name = skill_path.stem
            skill_path = skill_path.parent / skill_name

        result = ScanResult(
            skill_path=str(skill_path),
            skill_name=skill_name,
        )

        if not skill_path.exists():
            return result

        # Extract provenance (trust signals)
        provenance = self.extract_provenance(
            skill_path,
            source_url,
        )
        result.provenance = provenance

        # Analyze structure for risk indicators
        structure = self.analyze_skill_structure(
            skill_path,
        )
        result.metadata = structure

        # Add provenance-based warnings
        if not provenance.is_official:
            if provenance.source_url:
                result.findings.append(
                    Finding(
                        severity=Severity.MEDIUM,
                        category="provenance",
                        description=(
                            "Skill not served from "
                            "/.well-known/skills/ - "
                            "cannot verify official status"
                        ),
                        file_path=str(skill_path),
                        recommendation=(
                            "Official skills must be "
                            "served from the domain's "
                            "well-known path per RFC"
                        ),
                    )
                )
            else:
                result.findings.append(
                    Finding(
                        severity=Severity.MEDIUM,
                        category="provenance",
                        description=(
                            "Unknown origin - skill source cannot be verified"
                        ),
                        file_path=str(skill_path),
                        recommendation=(
                            "Only use skills from trusted "
                            "origins (domain's "
                            "/.well-known/skills/)"
                        ),
                    )
                )

        # Add structural warnings
        if structure.has_scripts_folder:
            result.findings.append(
                Finding(
                    severity=Severity.INFO,
                    category="structure",
                    description=(
                        "Skill contains scripts/ folder "
                        "(2.1x higher vulnerability "
                        "rate per research)"
                    ),
                    file_path=str(skill_path),
                    recommendation=(
                        "Carefully review all scripts before using this skill"
                    ),
                )
            )

        if structure.executable_file_count > MAX_SAFE_EXECUTABLE_COUNT:
            result.findings.append(
                Finding(
                    severity=Severity.LOW,
                    category="structure",
                    description=(
                        f"Skill contains "
                        f"{structure.executable_file_count}"
                        " executable files"
                    ),
                    file_path=str(skill_path),
                    recommendation=(
                        "Review all executable files for malicious content"
                    ),
                )
            )

        if not structure.has_valid_frontmatter:
            result.findings.append(
                Finding(
                    severity=Severity.LOW,
                    category="structure",
                    description=(
                        "SKILL.md missing or has invalid YAML frontmatter"
                    ),
                    file_path=str(
                        skill_path / "SKILL.md",
                    ),
                    recommendation=(
                        "Legitimate skills should have "
                        "proper frontmatter with name "
                        "and description"
                    ),
                )
            )

        # Flag symlinks before walking files: a symlink disguised as an
        # example file can point at a credential outside the skill.
        result.findings.extend(
            self._check_symlinks(skill_path),
        )

        # Scan SKILL.md first
        skill_md = skill_path / "SKILL.md"
        if skill_md.exists() and not skill_md.is_symlink():
            result.findings.extend(
                self.scan_file(skill_md),
            )

        # Image formats whose metadata we parse for hidden instructions
        image_extensions = {
            ".png",
            ".jpg",
            ".jpeg",
            ".gif",
            ".webp",
            ".ico",
        }
        # Binary formats with no useful text to scan
        skip_extensions = {
            ".woff",
            ".woff2",
            ".ttf",
            ".otf",
            ".eot",
        }
        for file_path in skill_path.rglob("*"):
            if not file_path.is_file() or file_path == skill_md:
                continue
            # Symlinks are reported by _check_symlinks; never follow them
            # into the file scanners (that would read the target content).
            if file_path.is_symlink():
                continue
            suffix = file_path.suffix.lower()
            if suffix in image_extensions:
                result.findings.extend(
                    self._scan_image_metadata(file_path),
                )
                continue
            if suffix in skip_extensions:
                continue
            result.findings.extend(
                self.scan_file(file_path),
            )

        return result

    def scan_directory(
        self,
        directory: Path,
    ) -> Generator[ScanResult, None, None]:
        """Scan all skills in a directory."""
        directory = Path(directory)

        # Find all SKILL.md files
        for skill_md in directory.rglob("SKILL.md"):
            skill_dir = skill_md.parent
            yield self.scan_skill(skill_dir)

    def scan_url(self, url: str) -> ScanResult:
        """Fetch a URL and scan its content.

        Supports GitHub blob URLs (auto-converted to raw),
        raw file URLs, and any URL serving text content.

        The content is scanned in-memory. If the URL
        points to a SKILL.md inside a directory structure,
        only the single file is scanned (not siblings).

        Args:
            url: The URL to fetch and scan.

        Returns:
            ScanResult with findings from the content.

        """
        # Derive a display name from the URL path
        parsed = urllib.parse.urlparse(url)
        url_path = parsed.path.rstrip("/")
        skill_name = url_path.split("/")[-1] or "remote-skill"

        result = ScanResult(
            skill_path=url,
            skill_name=skill_name,
        )

        # Set provenance from the URL
        provenance = SkillProvenance(source_url=url)
        well_known_match = re.search(
            r"https?://([^/]+)"
            r"/\.well-known/skills/([^/]+)/",
            url,
        )
        if well_known_match:
            provenance.origin_domain = well_known_match.group(1)
            provenance.is_well_known = True
            provenance.is_official = True
        result.provenance = provenance

        if not provenance.is_official:
            result.findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    category="provenance",
                    description=(
                        "Skill not served from "
                        "/.well-known/skills/ - "
                        "cannot verify official status"
                    ),
                    file_path=url,
                    recommendation=(
                        "Official skills must be "
                        "served from the domain's "
                        "well-known path per RFC"
                    ),
                )
            )

        # Fetch the content
        try:
            content, effective_url = fetch_url(url)
        except Exception as exc:  # noqa: BLE001
            result.findings.append(
                Finding(
                    severity=Severity.INFO,
                    category="fetch_error",
                    description=(f"Could not fetch URL: {exc}"),
                    file_path=url,
                    recommendation=(
                        "Verify the URL is accessible and try again"
                    ),
                )
            )
            return result

        # Determine file type from URL path
        file_path = effective_url.split("?")[0]
        # Assume markdown for SKILL.md-style content
        if not file_path.endswith(".md") and "skill" in file_path.lower():
            file_path = file_path + ".md"

        # Scan the content
        result.findings.extend(
            self.scan_content(content, file_path),
        )

        return result


def print_findings(  # noqa: C901, PLR0912
    result: ScanResult,
    *,
    show_all: bool = False,
) -> None:
    """Pretty print scan findings."""
    if not result.findings and not show_all:
        return

    # Color codes
    colors = {
        Severity.CRITICAL: "\033[91m",  # Red
        Severity.HIGH: "\033[93m",  # Yellow
        Severity.MEDIUM: "\033[94m",  # Blue
        Severity.LOW: "\033[90m",  # Gray
        Severity.INFO: "\033[90m",  # Gray
    }
    trust_colors = {
        "OFFICIAL": "\033[92m",  # Green
        "UNVERIFIED": "\033[93m",  # Yellow
        "UNKNOWN": "\033[91m",  # Red
    }
    reset = "\033[0m"
    bold = "\033[1m"

    print(f"\n{bold}{'=' * 60}{reset}")  # noqa: T201
    print(f"{bold}Skill: {result.skill_name}{reset}")  # noqa: T201
    print(f"Path: {result.skill_path}")  # noqa: T201

    # Show provenance/trust info (per RFC model)
    if result.provenance:
        p = result.provenance
        trust_color = trust_colors.get(
            p.trust_level,
            "",
        )

        if p.is_official:
            print(  # noqa: T201
                f"Origin: {p.origin_domain} "
                f"{bold}OFFICIAL{reset} "
                "(served from "
                "/.well-known/skills/)",
            )
        elif p.source_url:
            print(f"Source: {p.source_url}")  # noqa: T201
            if p.publisher:
                print(  # noqa: T201
                    f"Publisher: {p.publisher} (not verified)",
                )
        else:
            print("Origin: Unknown")  # noqa: T201

        print(  # noqa: T201
            f"Status: {trust_color}"
            f"{p.trust_level}{reset} "
            f"(trust score: "
            f"{p.trust_score}/100)",
        )

    print(f"{'=' * 60}")  # noqa: T201

    if not result.findings:
        print("  No issues found")  # noqa: T201
        return

    # Filter out INFO-level provenance findings
    display_findings = [
        f
        for f in result.findings
        if not (f.severity == Severity.INFO and f.category == "provenance")
    ]

    if not display_findings and not show_all:
        print("  No security issues found")  # noqa: T201
        return

    print(f"  Found {len(display_findings)} issue(s):")  # noqa: T201
    print(  # noqa: T201
        f"    Critical: {result.critical_count}, High: {result.high_count}",
    )
    print()  # noqa: T201

    # Group by severity
    for severity in Severity:
        sev_findings = [f for f in display_findings if f.severity == severity]
        if not sev_findings:
            continue

        color = colors.get(severity, "")
        for finding in sev_findings:
            print(  # noqa: T201
                f"  {color}[{severity.value}]{reset} {finding.description}",
            )
            print(  # noqa: T201
                f"    Category: {finding.category}",
            )
            if finding.line_number:
                print(  # noqa: T201
                    f"    Location: {finding.file_path}:{finding.line_number}",
                )
            if finding.matched_content:
                truncated = finding.matched_content[:MAX_DISPLAY_LENGTH]
                if len(finding.matched_content) > MAX_DISPLAY_LENGTH:
                    truncated += "..."
                print(f"    Match: {truncated}")  # noqa: T201
            print(  # noqa: T201
                f"    Recommendation: {finding.recommendation}",
            )
            print()  # noqa: T201


def main() -> None:  # noqa: C901, PLR0912, PLR0915
    """Entry point for the skill scanner CLI."""
    parser = argparse.ArgumentParser(
        description=(
            "Scan AI Agent Skills for malware and security antipatterns"
        ),
        formatter_class=(argparse.RawDescriptionHelpFormatter),
        epilog="""
Default locations scanned (if no path provided):
  Claude Code:  ~/.claude/skills/, .claude/skills/
  Cursor:       ~/.cursor/skills/, .cursor/skills/
  OpenAI Codex: ~/.codex/skills/
  OpenCode:     ~/.config/opencode/skills/
  OpenClaw:     ~/.openclaw/skills/
  Letta Code:   .skills/
  Skillport:    ~/.skillport/skills/
  OpenSkills:   .agent/skills/

Examples:
  %(prog)s
  %(prog)s /path/to/skills
  %(prog)s --url https://github.com/user/repo/blob/main/skills/my-skill/SKILL.md
  %(prog)s --json
  %(prog)s --fail-on-high
        """,
    )
    parser.add_argument(
        "path",
        nargs="?",
        help=(
            "Path to skill directory (optional, auto-detects if not provided)"
        ),
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose output",
    )
    parser.add_argument(
        "-a",
        "--all",
        action="store_true",
        help="Show all skills, even clean ones",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output as JSON",
    )
    parser.add_argument(
        "--fail-on-high",
        action="store_true",
        help=("Exit with code 1 if HIGH or CRITICAL findings"),
    )
    parser.add_argument(
        "--url",
        help=("Fetch and scan a skill from a URL (supports GitHub blob URLs)"),
    )
    parser.add_argument(
        "--list-paths",
        action="store_true",
        help=("List all default paths that would be scanned"),
    )

    args = parser.parse_args()

    # Handle --list-paths
    if args.list_paths:
        print("Default skill paths checked:")  # noqa: T201
        for p in get_default_skill_paths():
            exists = "Y" if p.exists() else "N"
            print(f"  [{exists}] {p}")  # noqa: T201
        return

    scanner = SkillScanner(verbose=args.verbose)
    all_results = []
    scanned_paths = []

    if args.url:
        # Scan a remote URL
        all_results.append(
            scanner.scan_url(args.url),
        )
        scanned_paths.append(args.url)
    elif args.path:
        # Scan specific path
        path = Path(args.path)
        if (path / "SKILL.md").exists():
            all_results.append(
                scanner.scan_skill(path),
            )
        else:
            all_results.extend(
                scanner.scan_directory(path),
            )
        scanned_paths.append(path)
    else:
        # Auto-detect and scan all default locations
        for path in get_default_skill_paths():
            if path.exists():
                scanned_paths.append(path)
                if (path / "SKILL.md").exists():
                    all_results.append(
                        scanner.scan_skill(path),
                    )
                else:
                    all_results.extend(
                        scanner.scan_directory(path),
                    )

    if args.json:
        # JSON output for CI/CD integration
        output = {
            "scanned_paths": [str(p) for p in scanned_paths],
            "total_skills": len(all_results),
            "skills_with_issues": sum(1 for r in all_results if r.findings),
            "total_critical": sum(r.critical_count for r in all_results),
            "total_high": sum(r.high_count for r in all_results),
            "results": [
                {
                    "skill_name": r.skill_name,
                    "skill_path": r.skill_path,
                    "is_safe": r.is_safe,
                    "provenance": {
                        "source_url": (
                            r.provenance.source_url if r.provenance else None
                        ),
                        "origin_domain": (
                            r.provenance.origin_domain
                            if r.provenance
                            else None
                        ),
                        "is_official": (
                            r.provenance.is_official if r.provenance else False
                        ),
                        "is_well_known": (
                            r.provenance.is_well_known
                            if r.provenance
                            else False
                        ),
                        "publisher": (
                            r.provenance.publisher if r.provenance else None
                        ),
                        "trust_level": (
                            r.provenance.trust_level
                            if r.provenance
                            else "UNKNOWN"
                        ),
                        "trust_score": (
                            r.provenance.trust_score if r.provenance else 0
                        ),
                        "has_security_policy": (
                            r.provenance.has_security_policy
                            if r.provenance
                            else False
                        ),
                        "license": (
                            r.provenance.license if r.provenance else None
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
                        "has_references_folder": (
                            r.metadata.has_references_folder
                            if r.metadata
                            else False
                        ),
                        "executable_file_count": (
                            r.metadata.executable_file_count
                            if r.metadata
                            else 0
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
                            "severity": (f.severity.value),
                            "category": f.category,
                            "description": (f.description),
                            "file_path": f.file_path,
                            "line_number": (f.line_number),
                            "matched_content": (f.matched_content),
                            "recommendation": (f.recommendation),
                        }
                        for f in r.findings
                    ],
                }
                for r in all_results
            ],
        }
        print(json.dumps(output, indent=2))  # noqa: T201
    else:
        # Human-readable output
        print("\nSkill Security Scanner")  # noqa: T201
        if scanned_paths:
            print("   Scanned locations:")  # noqa: T201
            for p in scanned_paths:
                print(f"     - {p}")  # noqa: T201
        else:
            print(  # noqa: T201
                "   No skill directories found!",
            )
            print(  # noqa: T201
                "   Run with --list-paths to see checked locations",
            )
            return

        print(  # noqa: T201
            f"   Skills found: {len(all_results)}",
        )

        if not all_results:
            print(  # noqa: T201
                "\n   No skills found in scanned locations.",
            )
            return

        for result in all_results:
            print_findings(
                result,
                show_all=args.all,
            )

        # Summary
        total_critical = sum(r.critical_count for r in all_results)
        total_high = sum(r.high_count for r in all_results)
        skills_with_issues = sum(1 for r in all_results if r.findings)

        print(f"\n{'=' * 60}")  # noqa: T201
        print("Summary")  # noqa: T201
        print(  # noqa: T201
            f"   Total skills scanned: {len(all_results)}",
        )
        print(  # noqa: T201
            f"   Skills with issues: {skills_with_issues}",
        )
        print(  # noqa: T201
            f"   Critical findings: {total_critical}",
        )
        print(  # noqa: T201
            f"   High findings: {total_high}",
        )

        if total_critical > 0:
            print(  # noqa: T201
                f"\n   {total_critical} CRITICAL "
                "issue(s) require "
                "immediate attention!",
            )
        elif total_high > 0:
            print(  # noqa: T201
                f"\n   {total_high} HIGH severity issue(s) found",
            )
        elif skills_with_issues == 0:
            print(  # noqa: T201
                "\n   All skills passed security checks",
            )

        print()  # noqa: T201

    # Exit code for CI/CD
    if args.fail_on_high:
        total_serious = sum(
            r.critical_count + r.high_count for r in all_results
        )
        if total_serious > 0:
            sys.exit(1)


if __name__ == "__main__":
    main()

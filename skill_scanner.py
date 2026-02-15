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
import urllib.parse
import urllib.request
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


def _parse_github_tree_url(
    url: str,
) -> tuple[str, str, str, str] | None:
    """Parse a GitHub ``/tree/`` directory URL.

    Returns:
        ``(owner, repo, branch, path)`` or ``None`` if the URL
        is not a GitHub tree URL.

    """
    parsed = urllib.parse.urlparse(url)
    if "github.com" not in parsed.netloc:
        return None

    path = parsed.path.rstrip("/")
    match = re.match(
        r"^/([^/]+)/([^/]+)/tree/([^/]+)(?:/(.+))?$",
        path,
    )
    if not match:
        return None

    return (
        match.group(1),
        match.group(2),
        match.group(3),
        match.group(4) or "",
    )


def _parse_skill_ref(ref: str) -> tuple[str, str, str]:
    """Parse an npx skill reference into ``(owner, repo, path)``.

    Accepts:
    - ``owner/repo`` (repo root -- discovers skills automatically)
    - ``owner/repo/skill`` (specific subdirectory)
    - ``npx skills add owner/repo[/skill]``

    Raises:
        ValueError: If the ref does not contain at least 2 segments.

    """
    ref = ref.strip()

    # Strip ``npx skills add`` prefix if present
    npx_prefix = "npx skills add"
    if ref.lower().startswith(npx_prefix):
        ref = ref[len(npx_prefix) :].strip()

    parts = ref.split("/")
    if len(parts) < 2:  # noqa: PLR2004
        msg = (
            f"Skill ref must have at least 2 segments "
            f"(owner/repo), got: {ref!r}"
        )
        raise ValueError(msg)

    owner = parts[0]
    repo = parts[1]
    path = "/".join(parts[2:]) if len(parts) > 2 else ""  # noqa: PLR2004
    return (owner, repo, path)


def _skill_ref_to_github_tree_url(
    owner: str,
    repo: str,
    path: str,
) -> str:
    """Convert parsed skill ref parts to a GitHub tree URL.

    Assumes ``main`` branch (the standard for skills repos).
    """
    if path:
        return (
            f"https://github.com/{owner}/{repo}/tree/main/{path}"
        )
    return f"https://github.com/{owner}/{repo}/tree/main"


# === SOURCE TYPE CLASSIFICATION ===
# Matches the six source types recognised by the Vercel ``skills`` CLI:
# github, gitlab, well-known, huggingface, direct-url, git, local.


class SourceType(Enum):
    """Source types for skill references."""

    GITHUB_SHORTHAND = "github_shorthand"
    GITHUB_URL = "github_url"
    GITLAB_URL = "gitlab_url"
    WELL_KNOWN = "well_known"
    HUGGINGFACE = "huggingface"
    DIRECT_URL = "direct_url"
    LOCAL_PATH = "local_path"
    GIT_REPO = "git_repo"


def _strip_npx_prefix(ref: str) -> str:
    """Strip ``npx skills add`` prefix if present."""
    ref = ref.strip()
    npx_prefix = "npx skills add"
    if ref.lower().startswith(npx_prefix):
        ref = ref[len(npx_prefix) :].strip()
    return ref


def _classify_source(ref: str) -> SourceType:
    """Classify a skill reference into a source type.

    Matches the same source types as the Vercel ``skills`` CLI
    (``src/source-parser.ts``).
    """
    ref = _strip_npx_prefix(ref)

    # Local paths
    if ref.startswith(("./", "../", "/")):
        return SourceType.LOCAL_PATH
    if len(ref) >= 2 and ref[1] == ":":  # noqa: PLR2004
        return SourceType.LOCAL_PATH

    # URLs
    if ref.startswith(("http://", "https://")):
        parsed = urllib.parse.urlparse(ref)
        host = parsed.netloc.lower()
        path = parsed.path

        if "github.com" in host:
            return SourceType.GITHUB_URL
        if "/-/tree/" in path:
            return SourceType.GITLAB_URL
        if "gitlab" in host:
            return SourceType.GITLAB_URL
        if "huggingface.co" in host:
            return SourceType.HUGGINGFACE
        if path.lower().endswith("/skill.md"):
            return SourceType.DIRECT_URL
        if path.endswith(".git"):
            return SourceType.GIT_REPO
        # Generic URL: attempt well-known discovery
        return SourceType.WELL_KNOWN

    # Default: GitHub shorthand (owner/repo/path)
    return SourceType.GITHUB_SHORTHAND


# === GITLAB PARSING ===


def _parse_gitlab_tree_url(
    url: str,
) -> tuple[str, str, str, str] | None:
    """Parse a GitLab ``/-/tree/`` directory URL.

    Returns:
        ``(host, project_path, branch, subpath)``
        or ``None`` if the URL is not a GitLab tree URL.

    Handles nested groups, self-hosted instances, and
    custom ports.
    """
    parsed = urllib.parse.urlparse(url)
    path = parsed.path.rstrip("/")

    # Match: /project/path/-/tree/branch[/subpath]
    match = re.match(
        r"^(/[^/].+?)/-/tree/([^/]+)(?:/(.+))?$",
        path,
    )
    if not match:
        return None

    project_path = match.group(1).lstrip("/")
    branch = match.group(2)
    subpath = match.group(3) or ""

    return (parsed.netloc, project_path, branch, subpath)


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

            # Also scan prose content (non-code-block text)
            # for prompt injection
            prose_content = content
            for block in ast.get("code_blocks", []):
                prose_content = prose_content.replace(
                    block.get("content", ""),
                    "",
                )

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
                            matched_content=(match.group(0)[:80]),
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
            # For non-markdown files, line-by-line scanning
            lines = content.split("\n")
            for (
                pattern,
                severity,
                description,
                category,
            ) in self.all_patterns:
                for line_num, line in enumerate(
                    lines,
                    1,
                ):
                    findings.extend(
                        [
                            Finding(
                                severity=severity,
                                category=category,
                                description=description,
                                file_path=file_path,
                                line_number=line_num,
                                matched_content=(match.group(0)[:100]),
                                recommendation=(
                                    self._get_recommendation(
                                        category,
                                    )
                                ),
                            )
                            for match in re.finditer(
                                pattern,
                                line,
                                re.IGNORECASE,
                            )
                        ]
                    )

        # Additional heuristic checks
        findings.extend(
            self._check_base64_blobs(content, file_path),
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
                decoded = base64.b64decode(blob).decode(
                    "utf-8",
                    errors="ignore",
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
            content = block.get("content", "")

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
                        matched_content=content[:80],
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
                            matched_content=content[:80],
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
        return [
            Finding(
                severity=Severity.CRITICAL,
                category="prompt_injection",
                description=("Hidden executable instruction in HTML comment"),
                file_path=file_path,
                matched_content=comment[:80],
                recommendation=(
                    "Hidden instructions are a "
                    "strong indicator of "
                    "malicious intent"
                ),
            )
            for comment in ast.get(
                "html_comments",
                [],
            )
            if re.search(
                r"(curl|wget|bash|eval|exec"
                r"|nc\s)",
                comment,
                re.IGNORECASE,
            )
        ]

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

        # Read and scan content
        try:
            content = file_path.read_text(
                encoding="utf-8",
                errors="ignore",
            )
            findings.extend(
                self.scan_content(content, str(file_path)),
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

        # Scan SKILL.md first
        skill_md = skill_path / "SKILL.md"
        if skill_md.exists():
            result.findings.extend(
                self.scan_file(skill_md),
            )

        # Scan all other files
        skip_extensions = {
            ".png",
            ".jpg",
            ".jpeg",
            ".gif",
            ".ico",
            ".woff",
            ".ttf",
        }
        for file_path in skill_path.rglob("*"):
            if file_path.is_file() and file_path != skill_md:
                # Skip binary files
                if file_path.suffix.lower() in skip_extensions:
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

        Supports:
        - GitHub blob URLs (single file, auto-converted to raw)
        - GitHub tree URLs (directory -- lists files via API)
        - GitLab tree URLs (directory -- lists files via API)
        - Raw file URLs and any URL serving text content

        Args:
            url: The URL to fetch and scan.

        Returns:
            ScanResult with findings from the content.

        """
        # Detect GitHub tree (directory) URLs
        tree_info = _parse_github_tree_url(url)
        if tree_info:
            owner, repo, branch, path = tree_info
            if not path:
                # Repo root: use recursive discovery
                return self._scan_github_repo(
                    owner, repo, branch,
                )
            return self._scan_github_tree(url, *tree_info)

        # Detect GitLab tree (directory) URLs
        gitlab_info = _parse_gitlab_tree_url(url)
        if gitlab_info:
            return self._scan_gitlab_tree(url, *gitlab_info)

        # --- Single-file path (existing behaviour) ---

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

    def _scan_github_tree(  # noqa: C901
        self,
        url: str,
        owner: str,
        repo: str,
        branch: str,
        path: str,
    ) -> ScanResult:
        """Scan a full skill directory via the GitHub Contents API.

        Fetches the directory listing, then each file's content,
        and scans everything as a single skill.
        """
        skill_name = path.rstrip("/").split("/")[-1]

        result = ScanResult(
            skill_path=url,
            skill_name=skill_name,
        )

        # Provenance from GitHub URL
        provenance = SkillProvenance(source_url=url)
        provenance.publisher = owner
        result.provenance = provenance

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

        # Fetch directory listing from GitHub Contents API
        api_url = (
            f"https://api.github.com/repos/"
            f"{owner}/{repo}/contents/{path}"
            f"?ref={branch}"
        )
        try:
            listing_json, _ = fetch_url(api_url)
        except Exception as exc:  # noqa: BLE001
            result.findings.append(
                Finding(
                    severity=Severity.INFO,
                    category="fetch_error",
                    description=(
                        f"Could not fetch directory listing: {exc}"
                    ),
                    file_path=api_url,
                    recommendation=(
                        "Verify the URL is accessible. "
                        "GitHub API has rate limits "
                        "(60 req/hour unauthenticated)."
                    ),
                )
            )
            return result

        try:
            entries = json.loads(listing_json)
        except json.JSONDecodeError:
            result.findings.append(
                Finding(
                    severity=Severity.INFO,
                    category="fetch_error",
                    description=(
                        "GitHub API response was not valid JSON"
                    ),
                    file_path=api_url,
                    recommendation=(
                        "Check the URL and try again"
                    ),
                )
            )
            return result

        if not isinstance(entries, list):
            result.findings.append(
                Finding(
                    severity=Severity.INFO,
                    category="fetch_error",
                    description=(
                        "GitHub API did not return a directory listing"
                    ),
                    file_path=api_url,
                    recommendation=(
                        "Ensure the URL points to a directory, "
                        "not a single file"
                    ),
                )
            )
            return result

        # Build metadata from the listing
        executable_extensions = {
            ".sh", ".bash", ".py", ".js",
            ".ps1", ".bat", ".cmd",
        }
        metadata = SkillMetadata()
        for entry in entries:
            name = entry.get("name", "")
            entry_type = entry.get("type", "")
            if entry_type == "dir" and name == "scripts":
                metadata.has_scripts_folder = True
            if entry_type == "file":
                metadata.skill_file_count += 1
                suffix = (
                    "." + name.rsplit(".", 1)[-1]
                    if "." in name
                    else ""
                ).lower()
                if suffix in executable_extensions:
                    metadata.executable_file_count += 1

        # Fetch and scan each file
        skip_extensions = {
            ".png", ".jpg", ".jpeg", ".gif",
            ".ico", ".woff", ".ttf",
        }
        for entry in entries:
            if entry.get("type") != "file":
                continue
            name = entry.get("name", "")
            download_url = entry.get("download_url")
            if not download_url:
                continue

            suffix = (
                "." + name.rsplit(".", 1)[-1]
                if "." in name
                else ""
            ).lower()
            if suffix in skip_extensions:
                continue

            try:
                content, _ = fetch_url(download_url)
            except Exception:  # noqa: BLE001
                continue

            # Parse frontmatter from SKILL.md
            if name == "SKILL.md":
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
                            desc = fm.get("description", "")
                            metadata.description_length = (
                                len(desc)
                                if isinstance(desc, str)
                                else 0
                            )
                    except yaml.YAMLError:
                        pass

            result.findings.extend(
                self.scan_content(content, name),
            )

        result.metadata = metadata

        # Add structural warnings
        if metadata.has_scripts_folder:
            result.findings.append(
                Finding(
                    severity=Severity.INFO,
                    category="structure",
                    description=(
                        "Skill contains scripts/ folder "
                        "(2.1x higher vulnerability "
                        "rate per research)"
                    ),
                    file_path=url,
                    recommendation=(
                        "Carefully review all scripts "
                        "before using this skill"
                    ),
                )
            )

        if metadata.executable_file_count > MAX_SAFE_EXECUTABLE_COUNT:
            result.findings.append(
                Finding(
                    severity=Severity.LOW,
                    category="structure",
                    description=(
                        f"Skill contains "
                        f"{metadata.executable_file_count}"
                        " executable files"
                    ),
                    file_path=url,
                    recommendation=(
                        "Review all executable files "
                        "for malicious content"
                    ),
                )
            )

        if not metadata.has_valid_frontmatter:
            result.findings.append(
                Finding(
                    severity=Severity.LOW,
                    category="structure",
                    description=(
                        "SKILL.md missing or has invalid "
                        "YAML frontmatter"
                    ),
                    file_path=url,
                    recommendation=(
                        "Legitimate skills should have "
                        "proper frontmatter with name "
                        "and description"
                    ),
                )
            )

        return result

    def _scan_github_repo(  # noqa: C901
        self,
        owner: str,
        repo: str,
        branch: str = "main",
    ) -> ScanResult:
        """Scan all skills in a GitHub repo using the Git Trees API.

        Discovers all ``SKILL.md`` files recursively and scans
        each skill directory.  Returns a combined result.
        """
        repo_url = f"https://github.com/{owner}/{repo}"
        result = ScanResult(
            skill_path=repo_url,
            skill_name=repo,
        )

        provenance = SkillProvenance(source_url=repo_url)
        provenance.publisher = owner
        result.provenance = provenance

        result.findings.append(
            Finding(
                severity=Severity.MEDIUM,
                category="provenance",
                description=(
                    "Skill not served from "
                    "/.well-known/skills/ - "
                    "cannot verify official status"
                ),
                file_path=repo_url,
                recommendation=(
                    "Official skills must be "
                    "served from the domain's "
                    "well-known path per RFC"
                ),
            )
        )

        # Use Git Trees API for recursive listing
        tree_api_url = (
            f"https://api.github.com/repos/"
            f"{owner}/{repo}/git/trees/"
            f"{branch}?recursive=1"
        )
        try:
            tree_json, _ = fetch_url(tree_api_url)
        except Exception as exc:  # noqa: BLE001
            result.findings.append(
                Finding(
                    severity=Severity.INFO,
                    category="fetch_error",
                    description=(
                        f"Could not fetch repo tree: {exc}"
                    ),
                    file_path=tree_api_url,
                    recommendation=(
                        "Verify the repo exists and "
                        "is public. GitHub API has "
                        "rate limits (60 req/hour "
                        "unauthenticated)."
                    ),
                )
            )
            return result

        try:
            tree_data = json.loads(tree_json)
        except json.JSONDecodeError:
            result.findings.append(
                Finding(
                    severity=Severity.INFO,
                    category="fetch_error",
                    description=(
                        "Git Trees API response was "
                        "not valid JSON"
                    ),
                    file_path=tree_api_url,
                    recommendation="Check the URL and try again",
                )
            )
            return result

        tree_entries = tree_data.get("tree", [])

        # Find all SKILL.md files
        skill_dirs = []
        for entry in tree_entries:
            entry_path = entry.get("path", "")
            if (
                entry_path.endswith("/SKILL.md")
                or entry_path == "SKILL.md"
            ):
                parent = (
                    entry_path.rsplit("/", 1)[0]
                    if "/" in entry_path
                    else ""
                )
                skill_dirs.append(parent)

        if not skill_dirs:
            result.findings.append(
                Finding(
                    severity=Severity.INFO,
                    category="structure",
                    description=(
                        "No SKILL.md files found in "
                        "repository"
                    ),
                    file_path=repo_url,
                    recommendation=(
                        "Verify this is a skills repo"
                    ),
                )
            )
            return result

        # Scan each skill directory via the existing
        # tree scanner
        sub_results = []
        for skill_dir in skill_dirs:
            tree_url = (
                f"https://github.com/{owner}/{repo}"
                f"/tree/{branch}/{skill_dir}"
            )
            sub = self._scan_github_tree(
                tree_url, owner, repo, branch, skill_dir,
            )
            sub_results.append(sub)

        # Merge sub-results into the main result
        if len(sub_results) == 1:
            only = sub_results[0]
            only.skill_path = repo_url
            return only

        # Multiple skills: combine findings and metadata
        result.skill_name = (
            f"{repo} ({len(sub_results)} skills)"
        )
        total_files = 0
        total_executables = 0
        any_scripts = False
        any_valid_fm = False
        for sub in sub_results:
            for f in sub.findings:
                # Skip duplicate provenance findings
                if f.category == "provenance":
                    continue
                result.findings.append(f)
            if sub.metadata:
                total_files += sub.metadata.skill_file_count
                total_executables += (
                    sub.metadata.executable_file_count
                )
                if sub.metadata.has_scripts_folder:
                    any_scripts = True
                if sub.metadata.has_valid_frontmatter:
                    any_valid_fm = True

        result.metadata = SkillMetadata(
            skill_file_count=total_files,
            executable_file_count=total_executables,
            has_scripts_folder=any_scripts,
            has_valid_frontmatter=any_valid_fm,
        )

        # List discovered skills in an INFO finding
        skill_names = [s.skill_name for s in sub_results]
        result.findings.append(
            Finding(
                severity=Severity.INFO,
                category="structure",
                description=(
                    f"Repository contains "
                    f"{len(sub_results)} skills: "
                    + ", ".join(skill_names)
                ),
                file_path=repo_url,
                recommendation="Review each skill individually",
            )
        )

        return result

    def _scan_gitlab_tree(  # noqa: C901
        self,
        url: str,
        host: str,
        project_path: str,
        branch: str,
        path: str,
    ) -> ScanResult:
        """Scan a full skill directory via the GitLab Repository Tree API."""
        skill_name = (
            path.rstrip("/").split("/")[-1]
            if path
            else project_path.split("/")[-1]
        )

        result = ScanResult(skill_path=url, skill_name=skill_name)

        # Provenance from GitLab URL
        provenance = SkillProvenance(source_url=url)
        provenance.publisher = project_path.split("/")[0]
        result.provenance = provenance

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

        # Fetch directory listing from GitLab Repository Tree API
        encoded_project = urllib.parse.quote(
            project_path, safe="",
        )
        api_url = (
            f"https://{host}/api/v4/projects/"
            f"{encoded_project}/repository/tree"
            f"?path={urllib.parse.quote(path)}"
            f"&ref={urllib.parse.quote(branch)}"
        )
        try:
            listing_json, _ = fetch_url(api_url)
        except Exception as exc:  # noqa: BLE001
            result.findings.append(
                Finding(
                    severity=Severity.INFO,
                    category="fetch_error",
                    description=(
                        f"Could not fetch GitLab tree: {exc}"
                    ),
                    file_path=api_url,
                    recommendation=(
                        "Verify the URL is accessible"
                    ),
                )
            )
            return result

        try:
            entries = json.loads(listing_json)
        except json.JSONDecodeError:
            result.findings.append(
                Finding(
                    severity=Severity.INFO,
                    category="fetch_error",
                    description=(
                        "GitLab API response was not valid JSON"
                    ),
                    file_path=api_url,
                    recommendation=(
                        "Check the URL and try again"
                    ),
                )
            )
            return result

        if not isinstance(entries, list):
            return result

        # Build metadata from the listing
        executable_extensions = {
            ".sh", ".bash", ".py", ".js",
            ".ps1", ".bat", ".cmd",
        }
        metadata = SkillMetadata()
        for entry in entries:
            name = entry.get("name", "")
            entry_type = entry.get("type", "")
            if entry_type == "tree" and name == "scripts":
                metadata.has_scripts_folder = True
            if entry_type == "blob":
                metadata.skill_file_count += 1
                suffix = (
                    "." + name.rsplit(".", 1)[-1]
                    if "." in name
                    else ""
                ).lower()
                if suffix in executable_extensions:
                    metadata.executable_file_count += 1

        # Fetch and scan each file
        skip_extensions = {
            ".png", ".jpg", ".jpeg", ".gif",
            ".ico", ".woff", ".ttf",
        }
        for entry in entries:
            if entry.get("type") != "blob":
                continue
            name = entry.get("name", "")
            file_path_in_repo = entry.get("path", "")

            suffix = (
                "." + name.rsplit(".", 1)[-1]
                if "." in name
                else ""
            ).lower()
            if suffix in skip_extensions:
                continue

            # GitLab raw file API
            raw_url = (
                f"https://{host}/api/v4/projects/"
                f"{encoded_project}/repository/files/"
                f"{urllib.parse.quote(file_path_in_repo, safe='')}"
                f"/raw?ref={urllib.parse.quote(branch)}"
            )

            try:
                content, _ = fetch_url(raw_url)
            except Exception:  # noqa: BLE001
                continue

            # Parse frontmatter from SKILL.md
            if name == "SKILL.md":
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
                            desc = fm.get("description", "")
                            metadata.description_length = (
                                len(desc)
                                if isinstance(desc, str)
                                else 0
                            )
                    except yaml.YAMLError:
                        pass

            result.findings.extend(
                self.scan_content(content, name),
            )

        result.metadata = metadata
        return result

    def _scan_well_known(self, url: str) -> ScanResult:
        """Discover and scan skills via ``/.well-known/skills/``."""
        parsed = urllib.parse.urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        index_url = f"{base}/.well-known/skills/index.json"

        # Fetch the discovery index
        try:
            index_json, _ = fetch_url(index_url)
            index = json.loads(index_json)
        except Exception as exc:  # noqa: BLE001
            result = ScanResult(
                skill_path=url,
                skill_name="well-known",
            )
            result.findings.append(
                Finding(
                    severity=Severity.INFO,
                    category="fetch_error",
                    description=(
                        f"Could not fetch well-known index: {exc}"
                    ),
                    file_path=index_url,
                    recommendation=(
                        "Verify the domain serves "
                        "/.well-known/skills/index.json"
                    ),
                )
            )
            return result

        skills_list = index.get("skills", [])
        if not skills_list:
            result = ScanResult(
                skill_path=url,
                skill_name="well-known",
            )
            result.findings.append(
                Finding(
                    severity=Severity.INFO,
                    category="structure",
                    description="No skills found in index.json",
                    file_path=index_url,
                    recommendation="Check the index.json format",
                )
            )
            return result

        # Scan the first skill (most common: single-skill sites)
        first = skills_list[0]
        skill_name = first.get("name", "unknown")
        skill_path = first.get("path", "")
        skill_url = f"{base}{skill_path}"

        result = ScanResult(
            skill_path=skill_url,
            skill_name=skill_name,
        )

        # Well-known provenance is OFFICIAL
        provenance = SkillProvenance(source_url=skill_url)
        provenance.origin_domain = parsed.netloc
        provenance.is_well_known = True
        provenance.is_official = True
        result.provenance = provenance

        metadata = SkillMetadata()

        try:
            content, _ = fetch_url(skill_url)
        except Exception as exc:  # noqa: BLE001
            result.findings.append(
                Finding(
                    severity=Severity.INFO,
                    category="fetch_error",
                    description=(
                        f"Could not fetch skill: {exc}"
                    ),
                    file_path=skill_url,
                    recommendation=(
                        "Verify the skill URL is accessible"
                    ),
                )
            )
            return result

        metadata.skill_file_count = 1

        # Parse frontmatter
        yaml_match = re.match(
            r"^---\s*\n(.*?)\n---",
            content,
            re.DOTALL,
        )
        if yaml_match:
            try:
                fm = yaml.safe_load(yaml_match.group(1))
                if fm and isinstance(fm, dict):
                    metadata.has_valid_frontmatter = True
                    desc = fm.get("description", "")
                    metadata.description_length = (
                        len(desc)
                        if isinstance(desc, str)
                        else 0
                    )
            except yaml.YAMLError:
                pass

        result.metadata = metadata
        result.findings.extend(
            self.scan_content(content, "SKILL.md"),
        )

        return result

    def _scan_huggingface(self, url: str) -> ScanResult:
        """Scan a skill from a HuggingFace Spaces URL."""
        parsed = urllib.parse.urlparse(url)
        path = parsed.path.rstrip("/")

        # Extract owner/repo from /spaces/owner/repo/...
        match = re.match(
            r"^/spaces/([^/]+)/([^/]+)",
            path,
        )
        owner = match.group(1) if match else "unknown"
        repo = match.group(2) if match else "unknown"

        # Normalise to raw URL
        raw_url = url.replace("/blob/", "/raw/")
        if "/raw/main/SKILL.md" not in raw_url:
            # If no SKILL.md in URL, append it
            raw_url = raw_url.rstrip("/")
            if not raw_url.endswith("/SKILL.md"):
                raw_url += "/raw/main/SKILL.md"

        result = ScanResult(
            skill_path=url,
            skill_name=f"{owner}/{repo}",
        )

        provenance = SkillProvenance(source_url=url)
        provenance.publisher = owner
        result.provenance = provenance

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

        metadata = SkillMetadata()

        try:
            content, _ = fetch_url(raw_url)
        except Exception as exc:  # noqa: BLE001
            result.findings.append(
                Finding(
                    severity=Severity.INFO,
                    category="fetch_error",
                    description=(
                        f"Could not fetch HuggingFace skill: {exc}"
                    ),
                    file_path=raw_url,
                    recommendation=(
                        "Verify the HuggingFace space URL"
                    ),
                )
            )
            return result

        metadata.skill_file_count = 1

        # Parse frontmatter for skill name override
        yaml_match = re.match(
            r"^---\s*\n(.*?)\n---",
            content,
            re.DOTALL,
        )
        if yaml_match:
            try:
                fm = yaml.safe_load(yaml_match.group(1))
                if fm and isinstance(fm, dict):
                    metadata.has_valid_frontmatter = True
                    if fm.get("name"):
                        result.skill_name = fm["name"]
                    desc = fm.get("description", "")
                    metadata.description_length = (
                        len(desc)
                        if isinstance(desc, str)
                        else 0
                    )
            except yaml.YAMLError:
                pass

        result.metadata = metadata
        result.findings.extend(
            self.scan_content(content, "SKILL.md"),
        )

        return result

    def scan_skill_ref(self, ref: str) -> ScanResult:
        """Scan a skill from any supported source.

        Accepts all formats recognised by the Vercel ``skills``
        CLI: GitHub shorthand (``owner/repo/skill``), full
        GitHub/GitLab tree URLs, HuggingFace space URLs,
        well-known discovery URLs, direct ``skill.md`` URLs,
        and ``npx skills add`` commands.
        """
        clean_ref = _strip_npx_prefix(ref)
        source_type = _classify_source(ref)

        if source_type == SourceType.GITHUB_SHORTHAND:
            owner, repo, path = _parse_skill_ref(ref)
            if not path:
                # Repo-level ref: discover all skills
                return self._scan_github_repo(owner, repo)
            url = _skill_ref_to_github_tree_url(
                owner, repo, path,
            )
            return self.scan_url(url)

        if source_type in (
            SourceType.GITHUB_URL,
            SourceType.GITLAB_URL,
            SourceType.DIRECT_URL,
        ):
            return self.scan_url(clean_ref)

        if source_type == SourceType.WELL_KNOWN:
            return self._scan_well_known(clean_ref)

        if source_type == SourceType.HUGGINGFACE:
            return self._scan_huggingface(clean_ref)

        if source_type == SourceType.GIT_REPO:
            result = ScanResult(
                skill_path=clean_ref,
                skill_name="git-repo",
            )
            result.findings.append(
                Finding(
                    severity=Severity.INFO,
                    category="unsupported",
                    description=(
                        "Generic .git repo URLs require "
                        "clone and are not supported by "
                        "the scanner. Use "
                        "``npx skills add`` to install "
                        "locally, then scan the path."
                    ),
                    file_path=clean_ref,
                    recommendation=(
                        "Install the skill locally with "
                        "``npx skills add <url>`` then "
                        "scan with ``--path``"
                    ),
                )
            )
            return result

        if source_type == SourceType.LOCAL_PATH:
            path = Path(clean_ref)
            if (path / "SKILL.md").exists():
                return self.scan_skill(path)
            # Try scanning as directory
            results = list(self.scan_directory(path))
            if results:
                return results[0]
            result = ScanResult(
                skill_path=clean_ref,
                skill_name=path.name,
            )
            result.findings.append(
                Finding(
                    severity=Severity.INFO,
                    category="not_found",
                    description=(
                        "No SKILL.md found at local path"
                    ),
                    file_path=clean_ref,
                    recommendation=(
                        "Check the path contains a "
                        "valid skill directory"
                    ),
                )
            )
            return result

        # Fallback: try as GitHub shorthand
        owner, repo, path = _parse_skill_ref(ref)
        url = _skill_ref_to_github_tree_url(
            owner, repo, path,
        )
        return self.scan_url(url)


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
        help=(
            "Fetch and scan a skill from a URL "
            "(supports GitHub blob and tree URLs)"
        ),
    )
    parser.add_argument(
        "--skill",
        help=(
            "Scan a skill from any source: "
            "owner/repo/skill (GitHub shorthand), "
            "GitHub/GitLab tree URLs, "
            "HuggingFace space URLs, "
            "well-known discovery URLs, "
            "or 'npx skills add owner/repo/skill'"
        ),
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

    if args.skill:
        # Scan from any supported skill source
        all_results.append(
            scanner.scan_skill_ref(args.skill),
        )
        scanned_paths.append(args.skill)
    elif args.url:
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

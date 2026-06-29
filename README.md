# Skill Scanner
_This is not production ready._

A _very_ simple tool to detect malware and security antipatterns in AI agent skills. Scans skill directories for Claude Code, Cursor, OpenCode, Codex CLI, OpenClaw, Letta Code, and other AgentSkills-compatible tools.


## Quick start

```
uv run skill_scanner.py
```

Requires Python 3.11+. Dependencies (`pyyaml`, `markdown-it-py`) are managed automatically by `uv`.

## Usage

```
skill_scanner.py [OPTIONS] [PATH]
```

### Arguments

| Argument | Description |
|----------|-------------|
| `PATH`   | Path to a skill directory. Optional; when omitted the scanner checks all default locations. |

### Options

| Flag | Description |
|------|-------------|
| `-v`, `--verbose` | Show warnings for unreadable files and other diagnostics. |
| `-a`, `--all` | Show all skills in output, including clean ones. |
| `--json` | Output results as JSON (useful for CI/CD pipelines). |
| `--fail-on-high` | Exit with code 1 if any HIGH or CRITICAL findings exist. |
| `--list-paths` | Print every default skill path and whether it exists, then exit. |

### Examples

```sh
# Scan all default skill locations
uv run skill_scanner.py

# Scan a specific skill directory
uv run skill_scanner.py ~/.claude/skills

# JSON output for CI
uv run skill_scanner.py --json --fail-on-high

# See which paths would be scanned
uv run skill_scanner.py --list-paths
```

## Default scan locations

| Tool | Paths |
|------|-------|
| Claude Code | `~/.claude/skills/`, `.claude/skills/` |
| Cursor | `~/.cursor/skills/`, `.cursor/skills/` |
| OpenAI Codex CLI | `~/.codex/skills/` |
| OpenCode | `~/.config/opencode/skills/`, `.opencode/skills/` |
| OpenClaw / Clawdbot | `~/.openclaw/skills/`, `~/.clawdbot/skills/`, `./skills/` |
| Letta Code | `.skills/` |
| Skillport | `~/.skillport/skills/` |
| OpenSkills | `.agent/skills/` |

## Detection categories

- **dangerous_shell** -- piped execution, reverse shells, privilege escalation, scripting-language exec sinks (`os.system`, `subprocess(shell=True)`, `child_process`)
- **exfiltration** -- access to SSH keys, AWS/GCP/k8s credentials, `.netrc`/`.git-credentials`, browser data, crypto wallets
- **suspicious_url** -- URL shorteners, paste sites, direct IP URLs
- **obfuscation** -- base64 payloads, eval/exec, hex-encoded strings, Unicode homoglyphs
- **social_engineering** -- urgency tactics, copy-paste-run instructions
- **prompt_injection** -- guardrail bypass, role manipulation, hidden instructions
- **memory_poisoning** -- persistent agent memory/behavior modification, writes to global config (`~/.claude/CLAUDE.md`, `AGENTS.md`)
- **harness_abuse** -- frontmatter `hooks:` and the `!` pre-prompt directive that the harness executes automatically on skill load
- **supply_chain** -- unpinned dependencies, remote binary downloads, `npm` lifecycle hooks (`postinstall`), pytest-autorun `conftest.py`/`test_*.py`

## Beyond text patterns

Several high-impact attacks ([Dangerous Skills](https://gricha.dev/blog/dangerous-skills)) do not live in scannable prose, so dedicated structural detectors handle them:

- **Image metadata** -- PNG `tEXt`/`zTXt`/`iTXt` chunks, JPEG comment/EXIF fields, GIF comment/application extensions, and WebP EXIF/XMP chunks are decoded (pure stdlib) and scanned for hidden instructions.
- **Symlinks** -- any symlink in a skill is reported; ones escaping the skill directory or targeting a sensitive path (e.g. `~/.ssh/id_rsa`) are escalated, and their targets are never followed.
- **Harness features** -- frontmatter `hooks:` and `!` command directives are flagged because the harness runs them with no model mediation.
- **Ecosystem auto-run** -- `npm` install lifecycle hooks and pytest's `conftest.py`/`test_*.py` are flagged as code that executes without the agent choosing to run it.

## Evasion resistance

All text is Unicode-normalized before matching, so look-alike bypasses are caught: invisible/zero-width and bidi characters are stripped, NFKC folds full-width and mathematical variants, and cross-script homoglyphs (e.g. Cyrillic `с` for Latin `c` in `curl`) plus multi-character look-alikes (`rn` -> `m`) are folded back to ASCII. Mixed-script tokens and punycode (`xn--`) IDN homograph domains are flagged even when a specific look-alike is not in the map.

## References

- https://snyk.io/articles/skill-md-shell-access/
- https://1password.com/blog/from-magic-to-malware-how-openclaws-agent-skills-become-an-attack-surface
- https://github.com/cloudflare/agent-skills-discovery-rfc

# How It Works

## What It Does

Scans AI agent skill directories for malware and security antipatterns before they can execute. It supports Claude Code, Cursor, OpenCode, Codex CLI, OpenClaw, Letta Code, and others.

## Discovery

`get_default_skill_paths()` returns ~14 standard paths across all supported tools (e.g. `~/.claude/skills/`, `~/.cursor/skills/`). The scanner checks which exist and recursively finds all `SKILL.md` files within them. You can also pass a specific path.

## Parsing

For `.md` files, `parse_skill_ast()` uses **markdown-it-py** to extract structured data: YAML frontmatter (via `yaml.safe_load`), fenced code blocks with their language tags, headings, links, and HTML comments. Non-markdown files are scanned line-by-line.

## Detection Engine

The core is **272+ regex patterns across 9 categories**: dangerous shell commands, data exfiltration, suspicious URLs, obfuscation, social engineering, prompt injection, memory poisoning, config poisoning, and supply chain risks. Each pattern has a severity (CRITICAL through INFO).

Four layers reduce false positives:

1. **Whitelists** -- TypeScript `Env` type patterns and safe localhost dev ports (3000, 5173, 8787, etc.) are skipped via `_should_skip_finding()`.
2. **Severity adjustment** -- `_adjust_severity_for_context()` downgrades findings in documentation languages (TypeScript, Python examples) and upgrades findings in executable languages (bash, sh).
3. **AST-aware scanning** -- Code blocks, prose, and hidden content (HTML comments) are scanned separately with category-appropriate patterns. Prose gets checked for prompt injection, memory poisoning, config poisoning, and social engineering.
4. **Unicode analysis** -- `_check_unicode_obfuscation()` detects zero-width characters (U+200B-U+200D, U+2060, U+FEFF) and RTL override characters (U+202A-U+202E, U+2066-U+2069) used to hide content from human reviewers.

Additional heuristics: `_check_base64_blobs()` decodes any base64 string over 100 chars and checks if it contains shell keywords. `_check_description_body_overlap()` compares frontmatter description keywords against body content to detect misaligned skills. `_check_allowed_tools()` analyzes permission grants for least-privilege violations. `_check_name_mismatch()` verifies frontmatter name matches directory name.

## Provenance and Trust

Per the [Cloudflare Agent Skills Discovery RFC](https://github.com/cloudflare/agent-skills-discovery-rfc), `extract_provenance()` checks whether a skill was served from `https://domain/.well-known/skills/{name}/` -- the only way to be marked "OFFICIAL". It also extracts git remote publisher, checks for `SECURITY.md`/`CODE_OF_CONDUCT.md`, and reads license from frontmatter.

Trust scoring: official skills start at 90/100 (max 100), non-official cap at 70/100. Three trust levels: OFFICIAL, UNVERIFIED, UNKNOWN.

## Structural Analysis

`analyze_skill_structure()` checks the directory shape -- `scripts/` folder (+20 risk), executable file count (+10 each), missing frontmatter (+10), `references/` folder (-10, good signal) -- producing a `structure_risk_score`.

## Output

Human-readable mode uses color-coded severity with trust badges. `--json` emits structured JSON with per-skill provenance, metadata, and findings arrays. `--fail-on-high` exits with code 1 if any CRITICAL/HIGH findings exist, for CI pipelines.

## Data Flow

```
main() -> get_default_skill_paths() -> scan_skill() for each
  scan_skill():
    extract_provenance() -> trust score + official status
    analyze_skill_structure() -> risk score
    _check_name_mismatch() -> name vs directory validation
    _check_description_body_overlap() -> misalignment detection
    scan_file(SKILL.md) -> parse_skill_ast() -> scan_code_blocks()
                                             -> scan_hidden_content()
                                             -> _check_allowed_tools()
                                             -> scan prose
                                             -> check base64 blobs
                                             -> _check_unicode_obfuscation()
    scan_file() for all other files
  -> ScanResult with findings list
-> print or JSON output
```

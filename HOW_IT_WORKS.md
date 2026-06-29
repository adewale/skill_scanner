# How It Works

## What It Does

Scans AI agent skill directories for malware and security antipatterns before they can execute. It supports Claude Code, Cursor, OpenCode, Codex CLI, OpenClaw, Letta Code, and others.

## Discovery

`get_default_skill_paths()` returns ~14 standard paths across all supported tools (e.g. `~/.claude/skills/`, `~/.cursor/skills/`). The scanner checks which exist and recursively finds all `SKILL.md` files within them. You can also pass a specific path.

## Parsing

For `.md` files, `parse_skill_ast()` uses **markdown-it-py** to extract structured data: YAML frontmatter (via `yaml.safe_load`), fenced code blocks with their language tags, headings, links, and HTML comments. Non-markdown files are scanned line-by-line.

## Unicode Normalization (Homograph Defense)

Detection regexes are ASCII, so before matching, every chunk of text is folded by `normalize_confusables()` / `_fold_text()` to defeat look-alike bypasses:

1. **Invisible characters** -- zero-width spaces, joiners, and bidi controls are dropped (so `cu<ZWSP>rl` cannot hide a keyword).
2. **NFKC** -- folds full-width, mathematical, and ligature variants (e.g. full-width digits in an IP).
3. **Single-character confusables** -- a curated cross-script map folds homoglyphs NFKC leaves alone (Cyrillic `es` U+0441 -> Latin `c`).
4. **Multi-character confusables** -- short sequences like `rn` -> `m` (so `chrnod` is matched as `chmod`).

Matches are mapped back to the original bytes so findings still show the raw, obfuscated text. Two map-independent detectors add defense in depth: `_check_homoglyphs()` flags any token that mixes Latin with a look-alike script (Cyrillic/Greek/Armenian/...) even for confusables not in the map, and `_check_idn_homographs()` decodes `xn--` punycode labels to catch IDN homograph domains.

## Detection Engine

The core is **272+ regex patterns across 8 categories**: dangerous shell commands (including scripting-language exec sinks like `os.system`/`subprocess(shell=True)`), data exfiltration, suspicious URLs, obfuscation, social engineering, prompt injection, memory poisoning, and supply chain risks. Each pattern has a severity (CRITICAL through INFO). These 8 pattern-list categories are joined by a 9th, `harness_abuse`, raised only by the structural detectors below.

Three layers reduce false positives:

1. **Whitelists** -- TypeScript `Env` type patterns and safe localhost dev ports (3000, 5173, 8787, etc.) are skipped via `_should_skip_finding()`.
2. **Severity adjustment** -- `_adjust_severity_for_context()` downgrades findings in documentation languages (TypeScript, Python examples) and upgrades findings in executable languages (bash, sh). This is what lets `os.system(...)` be a low-noise example in a docs code block but a HIGH finding in a real `.py` file.
3. **AST-aware scanning** -- Code blocks, prose, and hidden content (HTML comments) are scanned separately with category-appropriate patterns. Prose only gets checked for prompt injection, memory poisoning, and social engineering.

A special heuristic (`_check_base64_blobs()`) decodes any base64 string over 100 chars and checks if it contains shell keywords (the decoded text is also confusable-folded first).

## Structural & Harness Detectors

Pattern matching only sees readable text in scanned files. The most effective real-world attacks ([Dangerous Skills](https://gricha.dev/blog/dangerous-skills)) hide elsewhere, so dedicated detectors run alongside the pattern engine:

- **Frontmatter hooks** (`_check_suspicious_metadata_from_ast`) -- a `hooks:` key in YAML frontmatter is executed by the harness on load; flagged HIGH, escalated to CRITICAL if a hook command matches a dangerous-shell pattern. Category `harness_abuse`.
- **`!` command directive** (`_check_command_directives`) -- a markdown line beginning with `! <command>` is expanded by running the command at skill-load time. Flagged CRITICAL; lines inside fenced code blocks are treated as documentation and skipped.
- **Symlinks** (`_check_symlinks`) -- every symlink in the tree is reported (LOW), escalated to HIGH when it resolves outside the skill directory and CRITICAL when it targets a sensitive path. Symlink targets are never followed into the file scanners.
- **Image metadata** (`_scan_image_metadata`) -- PNG `tEXt`/`zTXt`/`iTXt` chunks and JPEG `COM`/EXIF segments are decoded with the standard library (`zlib`), then run through the full pattern engine plus an instruction-shaped-text heuristic. Images are no longer skipped wholesale.
- **npm lifecycle hooks** (`_check_package_json`) -- `package.json` is parsed and `preinstall`/`postinstall`/`prepare`/... scripts are flagged HIGH (CRITICAL if the command is dangerous), because npm runs them automatically.
- **pytest auto-run** (`scan_file`) -- `conftest.py` and `test_*.py`/`*_test.py` are flagged HIGH because pytest imports and executes them on collection.
- **Global memory writes** (`_check_memory_writes`) -- writes/references to `~/.claude/CLAUDE.md`, `~/.codex/AGENTS.md`, and sibling config files are matched against the **raw** (un-folded) text, because confusable folding rewrites the literal `claude` (`cl` -> `d`). Homoglyph spellings are still caught by `_check_homoglyphs`.

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
    _check_symlinks() -> symlink findings (targets never followed)
    scan_file(SKILL.md) -> scan_content() -> parse_skill_ast()
                              -> scan_code_blocks()
                              -> scan_hidden_content()
                              -> _check_suspicious_metadata (hooks)
                              -> _check_command_directives (! directive)
                              -> scan prose
                              -> check base64 / homoglyphs / IDN
                              -> _check_memory_writes (global config)
    for each remaining file:
      *.png/.jpg/.jpeg -> _scan_image_metadata()
      package.json     -> scan_file() + _check_package_json()
      conftest.py/test_*.py -> scan_file() (pytest auto-run flag)
      symlinks         -> skipped (already reported above)
  -> ScanResult with findings list
-> print or JSON output
```

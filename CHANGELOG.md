# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- **PowerShell / Windows attack patterns** (issue #7): download-and-execute cradles (`Invoke-Expression (iwr ...)`, `iwr ... | iex`, `WebClient.DownloadString`), dynamic execution (`Invoke-Expression`/`iex`), encoded commands (`-EncodedCommand`, `FromBase64String`), and POST exfiltration (`iwr ... -Method POST -Body`).
- **Cloud credential path detection** (issue #7): GCP (`~/.config/gcloud/`, Windows `%APPDATA%\gcloud\`, `application_default_credentials.json`), Azure (`~/.azure/`), Kubernetes (`~/.kube/config`, `/var/run/secrets/kubernetes.io/`), Docker (`~/.docker/config.json`), and 1Password CLI (`~/.config/op/`, `~/.op/`). All cloud-credential patterns match both POSIX (`/`) and Windows (`\`) path separators.
- Tests covering the new Windows/PowerShell and cloud credential scenarios (positive detections plus false-positive guards for `iexplore`, Elixir's `iex` REPL, `gcloud`/`op`/`docker` CLI invocations, plain GET downloads, and benign base64/DownloadString usage).
- **Unicode homograph defense** (issue #6): all scanned text is folded
  before pattern matching so look-alike bypasses are caught. The pipeline
  (`normalize_confusables` / `_fold_text`) strips invisible/zero-width and
  bidi-control characters, applies NFKC (full-width, mathematical and
  ligature variants), folds a curated cross-script confusable map
  (Cyrillic/Greek/Armenian/punctuation, e.g. Cyrillic "es" U+0441 -> "c"),
  and folds multi-character look-alikes (`rn` -> `m`). Matches are mapped
  back to the original bytes so findings show the raw obfuscated text.
  Two map-independent detectors add defense in depth: `_check_homoglyphs`
  flags any token mixing Latin with a look-alike script (plus non-Latin
  words that spell a sensitive command), and `_check_idn_homographs`
  decodes `xn--` punycode labels to catch IDN homograph domains.
- **Test suite** with 175 tests across three tiers:
  - Tier 1 (`test_infrastructure.py`): Unit tests for dataclasses, trust/risk scoring, AST parsing, whitelists, severity adjustment, provenance/structure analysis
  - Tier 2 (`test_scanning.py`): Detection tests for all 8 pattern categories (positive + false-positive), integration tests via pyfakefs
  - Tier 3 (`test_documentation.py`): Cross-references docs against code to catch documentation drift
- **Testing philosophy** documented in `TESTING.md`: three-tier architecture, safe address conventions (RFC 5737/2606), self-scan safety gate, and guidelines for adding new tests.
- **Developer tooling**:
  - `pyproject.toml` with project metadata, `[dev]` extras, pytest/coverage/ruff configuration
  - `.pre-commit-config.yaml` with hooks for ruff lint/format, vulture, bandit, self-scan security gate, pytest
  - `.github/workflows/ci.yml` running tests on Python 3.11-3.13, linting, and self-scan
  - Coverage threshold set to 80%
- **Code quality tools**:
  - Vulture for dead code detection (pre-commit hook + CI)
  - Bandit for dedicated security linting (pre-commit hook + CI, with `B310` skipped for intentional `urlopen` usage)
  - Pyright for static type checking (CI, basic mode targeting Python 3.11)
- **Remote skill scanning** via `--url` flag to fetch and scan skills from URLs.
- **Supply chain patterns**: `npx skills add` and `npx add-skill` for detecting remote skill installation (chain-loading).
- **Prompt injection patterns**: Cross-skill chain-loading delegation, instruction delegation, and prerequisite chain detection.
- TypeScript `Env` pattern whitelist to avoid false positives from type definitions (`interface Env {}`, `<Env>`, etc.).
- Localhost dev port whitelist (`3000`, `5173`, `8787`, `8788`, etc.) to suppress false positives on standard dev server URLs.
- Language-aware severity adjustment: patterns in documentation languages (TypeScript, Python, etc.) are downgraded; patterns in shell languages are boosted.
- `SkillMetadata` dataclass for structural risk analysis of skill directories.
- Structural warnings for skills with a `scripts/` folder, many executable files, or missing YAML frontmatter.
- Whitelist helper methods: `_is_typescript_env_pattern`, `_is_safe_localhost_url`, `_is_documentation_language`, `_is_executable_language`, `_should_skip_finding`, `_adjust_severity_for_context`.

### Fixed

- False positive where Elixir's `iex` REPL (e.g. `iex -S mix`) was flagged as PowerShell `Invoke-Expression`; the `iex` alias now requires an execution argument (`(`, `$`, quote, `@`) or a pipe into it.
- Downgraded dual-use PowerShell `FromBase64String` (HIGH → MEDIUM) and standalone `WebClient.DownloadString` (HIGH → MEDIUM) to reduce noise on benign decode/fetch usage; the execute-the-download form (`iex (... DownloadString ...)`) remains CRITICAL.
- False positives on Cloudflare Workers skills where `interface Env` triggered "Environment file access" alerts.
- False positives on `localhost:8788` flagged as "URL with non-standard port".
- `curl | bash` in a TypeScript example code block no longer reported at the same severity as in a bash code block.

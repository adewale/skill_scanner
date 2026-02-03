# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- TypeScript `Env` pattern whitelist to avoid false positives from type definitions (`interface Env {}`, `<Env>`, etc.).
- Localhost dev port whitelist (`3000`, `5173`, `8787`, `8788`, etc.) to suppress false positives on standard dev server URLs.
- Language-aware severity adjustment: patterns in documentation languages (TypeScript, Python, etc.) are downgraded; patterns in shell languages are boosted.
- `SkillMetadata` dataclass for structural risk analysis of skill directories.
- Structural warnings for skills with a `scripts/` folder, many executable files, or missing YAML frontmatter.
- Whitelist helper methods: `_is_typescript_env_pattern`, `_is_safe_localhost_url`, `_is_documentation_language`, `_is_executable_language`, `_should_skip_finding`, `_adjust_severity_for_context`.

### Fixed

- False positives on Cloudflare Workers skills where `interface Env` triggered "Environment file access" alerts.
- False positives on `localhost:8788` flagged as "URL with non-standard port".
- `curl | bash` in a TypeScript example code block no longer reported at the same severity as in a bash code block.

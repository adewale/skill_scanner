# Agent Skills Security Threat Analysis

## Overview

This document catalogs known security threats in AI Agent Skills ecosystems (Claude Code, Cursor, OpenCode, OpenClaw/Clawdbot, Codex CLI, etc.) and maps them to detections implemented in the skill_scanner.py tool.

Based on research from:
- [Snyk: From SKILL.md to Shell Access](https://snyk.io/articles/skill-md-shell-access/)
- [1Password: From Magic to Malware](https://1password.com/blog/from-magic-to-malware-how-openclaws-agent-skills-become-an-attack-surface)
- [Cisco: Personal AI Agents Are a Security Nightmare](https://blogs.cisco.com/ai/personal-ai-agents-like-moltbot-are-a-security-nightmare)
- [arxiv 2510.26328: Agent Skills Enable Trivially Simple Prompt Injections](https://arxiv.org/abs/2510.26328)
- [arxiv 2601.10338: Agent Skills in the Wild - Vulnerabilities at Scale](https://arxiv.org/abs/2601.10338)
- [Eran Sandler: "It's Just a Skill File" (Famous Last Words)](https://eran.sandler.co.il/2026/01/29/its-just-a-skill-file-famous-last-words/)

---

## Threat vs Detection Matrix

### Dangerous Shell Execution

| Specific Attack | Severity | Detected? | Detection Method |
|-----------------|----------|-----------|------------------|
| `curl \| bash` piped execution | CRITICAL | ✅ Yes | Regex pattern |
| `wget \| sh` piped execution | CRITICAL | ✅ Yes | Regex pattern |
| `curl \| python` piped execution | CRITICAL | ✅ Yes | Regex pattern |
| `curl \| node` piped execution | CRITICAL | ✅ Yes | Regex pattern |
| macOS quarantine bypass (`xattr -d com.apple.quarantine`) | CRITICAL | ✅ Yes | Regex pattern |
| Gatekeeper disable (`spctl --master-disable`) | CRITICAL | ✅ Yes | Regex pattern |
| Bash reverse shell (`bash -i >& /dev/tcp/`) | CRITICAL | ✅ Yes | Regex pattern |
| Netcat reverse shell (`nc -e /bin/bash`) | CRITICAL | ✅ Yes | Regex pattern |
| Python reverse shell | CRITICAL | ✅ Yes | Regex pattern |
| SUID bit manipulation (`chmod +s`) | CRITICAL | ✅ Yes | Regex pattern |
| Privilege escalation (`sudo su`) | HIGH | ✅ Yes | Regex pattern |
| Overly permissive chmod (`sudo chmod 777`) | HIGH | ✅ Yes | Regex pattern |
| Crontab modification | MEDIUM | ✅ Yes | Regex pattern |
| macOS LaunchAgent loading | MEDIUM | ✅ Yes | Regex pattern |
| Systemd service enablement | MEDIUM | ✅ Yes | Regex pattern |
| Background process with nohup | MEDIUM | ✅ Yes | Regex pattern |

### Data Exfiltration

| Specific Attack | Severity | Detected? | Detection Method |
|-----------------|----------|-----------|------------------|
| SSH private key access (`~/.ssh/id_rsa`) | CRITICAL | ✅ Yes | Regex pattern |
| SSH ed25519 key access | CRITICAL | ✅ Yes | Regex pattern |
| AWS credentials (`~/.aws/credentials`) | CRITICAL | ✅ Yes | Regex pattern |
| Browser credential theft (Login Data, Cookies, Local State) | CRITICAL | ✅ Yes | Regex pattern |
| macOS Keychain access (`~/Library/Keychains`) | CRITICAL | ✅ Yes | Regex pattern |
| Chrome profile access | HIGH | ✅ Yes | Regex pattern |
| Firefox profile access | HIGH | ✅ Yes | Regex pattern |
| GPG keyring access (`~/.gnupg/`) | HIGH | ✅ Yes | Regex pattern |
| Exodus wallet theft | CRITICAL | ✅ Yes | Regex pattern |
| Electrum wallet theft | CRITICAL | ✅ Yes | Regex pattern |
| MetaMask wallet theft | CRITICAL | ✅ Yes | Regex pattern |
| Solana wallet/keypair theft | CRITICAL | ✅ Yes | Regex pattern |
| Bitcoin wallet theft | CRITICAL | ✅ Yes | Regex pattern |
| OpenClaw credentials (`.clawdbot/.env`, `.openclaw/.env`) | CRITICAL | ✅ Yes | Regex pattern |
| Environment file access (`.env`) | HIGH | ✅ Yes | Regex pattern |
| Agent memory file access (SOUL.md, MEMORY.md) | HIGH | ✅ Yes | Regex pattern |
| Silent POST requests with data | MEDIUM | ✅ Yes | Regex pattern |
| Netcat to IP address | HIGH | ✅ Yes | Regex pattern |

### Suspicious URLs

| Specific Attack | Severity | Detected? | Detection Method |
|-----------------|----------|-----------|------------------|
| URL shortener: bit.ly | HIGH | ✅ Yes | Regex pattern |
| URL shortener: tinyurl.com | HIGH | ✅ Yes | Regex pattern |
| URL shortener: t.co | HIGH | ✅ Yes | Regex pattern |
| URL shortener: goo.gl | HIGH | ✅ Yes | Regex pattern |
| URL shortener: is.gd | HIGH | ✅ Yes | Regex pattern |
| Paste site: glot.io (ClawHavoc stager) | CRITICAL | ✅ Yes | Regex pattern |
| Paste site: pastebin.com/raw | HIGH | ✅ Yes | Regex pattern |
| Paste site: paste.ee | HIGH | ✅ Yes | Regex pattern |
| Paste site: ghostbin | HIGH | ✅ Yes | Regex pattern |
| Paste site: hastebin.com | MEDIUM | ✅ Yes | Regex pattern |
| Direct IP address URLs | HIGH | ✅ Yes | Regex pattern |
| Non-standard port URLs | MEDIUM | ✅ Yes | Regex pattern |
| GitHub raw shell scripts | MEDIUM | ✅ Yes | Regex pattern |
| GitHub raw content (general) | LOW | ✅ Yes | Regex pattern |

### Obfuscation

| Specific Attack | Severity | Detected? | Detection Method |
|-----------------|----------|-----------|------------------|
| Base64 decoding command | HIGH | ✅ Yes | Regex pattern |
| Encoded payload execution (`echo ... \| base64 -d`) | CRITICAL | ✅ Yes | Regex pattern |
| JavaScript base64 decode of long string | CRITICAL | ✅ Yes | Regex pattern |
| Large base64 blobs with executable keywords | CRITICAL | ✅ Yes | Decode + keyword check |
| `eval()` usage | HIGH | ✅ Yes | Regex pattern |
| `exec()` usage | HIGH | ✅ Yes | Regex pattern |
| Dynamic Function constructor | HIGH | ✅ Yes | Regex pattern |
| Hex-encoded strings | HIGH | ✅ Yes | Regex pattern |
| Octal-encoded strings | HIGH | ✅ Yes | Regex pattern |
| Bash substring obfuscation (`${var::n:m}`) | MEDIUM | ✅ Yes | Regex pattern |
| Arithmetic obfuscation | LOW | ✅ Yes | Regex pattern |
| Unmarked code blocks with shell commands | MEDIUM | ✅ Yes | AST analysis |

### Supply Chain Risks

| Specific Attack | Severity | Detected? | Detection Method |
|-----------------|----------|-----------|------------------|
| `npx -y` without version pinning | MEDIUM | ✅ Yes | Regex pattern |
| `npm install` without version | LOW | ✅ Yes | Regex pattern |
| `pip install` without version | LOW | ✅ Yes | Regex pattern |
| `npx skills add` remote skill installation | HIGH | ✅ Yes | Regex pattern |
| `npx add-skill` remote skill installation | HIGH | ✅ Yes | Regex pattern |
| Downloading Windows executable (.exe) | HIGH | ✅ Yes | Regex pattern |
| Downloading to bin directory | HIGH | ✅ Yes | Regex pattern |
| Downloading macOS disk image (.dmg) | HIGH | ✅ Yes | Regex pattern |
| Downloading macOS package (.pkg) | HIGH | ✅ Yes | Regex pattern |
| Password-protected archive extraction | HIGH | ✅ Yes | Regex pattern |
| Remote archive extraction | MEDIUM | ✅ Yes | Regex pattern |
| Binary dependency declarations in metadata | LOW | ✅ Yes | AST frontmatter check |
| Typosquatted package names | — | ❌ No | Would need package DB |
| Compromised upstream repos | — | ❌ No | Would need provenance |
| Rug-pull attacks (post-install malicious updates) | — | ❌ No | Would need monitoring |

### Prompt Injection

| Specific Attack | Severity | Detected? | Detection Method |
|-----------------|----------|-----------|------------------|
| "Ignore previous instructions" | CRITICAL | ✅ Yes | Regex pattern |
| "Disregard all safety/security" | CRITICAL | ✅ Yes | Regex pattern |
| "Skip confirmation/approval" | HIGH | ✅ Yes | Regex pattern |
| "Don't ask again" consent gap exploit | HIGH | ✅ Yes | Regex pattern |
| "Always allow/approve/execute" blanket permissions | HIGH | ✅ Yes | Regex pattern |
| "Without asking/confirmation" silent execution | HIGH | ✅ Yes | Regex pattern |
| Role injection ("you are now...") | MEDIUM | ✅ Yes | Regex pattern |
| Behavioral manipulation ("act as if...") | MEDIUM | ✅ Yes | Regex pattern |
| Identity manipulation ("pretend to be...") | MEDIUM | ✅ Yes | Regex pattern |
| Hidden instructions in HTML comments | CRITICAL | ✅ Yes | AST + regex |
| Hidden instructions in Markdown comments | CRITICAL | ✅ Yes | Regex pattern |
| Self-modifying skill instructions | HIGH | ✅ Yes | Regex pattern |
| Write to SKILL.md (skill self-modification) | CRITICAL | ✅ Yes | Regex pattern |
| Cross-skill chain-loading delegation ("do everything skill says") | HIGH | ✅ Yes | Regex pattern |
| Cross-skill instruction delegation ("follow instructions from skill") | HIGH | ✅ Yes | Regex pattern |
| Skill prerequisite chain ("run skill first") | MEDIUM | ✅ Yes | Regex pattern |
| Unusually long descriptions (hiding instructions) | LOW | ✅ Yes | AST length check |
| Benign-sounding malicious instructions | — | ❌ No | Would need LLM classifier |
| Long-context instruction hiding | — | ⚠️ Partial | Length check only |

### Memory Poisoning (Agent Persistence Attacks)

| Specific Attack | Severity | Detected? | Detection Method |
|-----------------|----------|-----------|------------------|
| Write to SOUL.md | CRITICAL | ✅ Yes | Regex pattern |
| Write to MEMORY.md | CRITICAL | ✅ Yes | Regex pattern |
| Append/add to agent memory | CRITICAL | ✅ Yes | Regex pattern |
| Modify SOUL/MEMORY files | CRITICAL | ✅ Yes | Regex pattern |
| Update personality/behavior/instructions | HIGH | ✅ Yes | Regex pattern |
| "Remember this instruction" injection | MEDIUM | ✅ Yes | Regex pattern |
| "From now on always..." persistent change | MEDIUM | ✅ Yes | Regex pattern |
| "Add this to your memory/context" | HIGH | ✅ Yes | Regex pattern |
| Time-delayed staged attacks | — | ⚠️ Partial | Detects memory writes |
| Cross-session behavioral backdoors | — | ⚠️ Partial | Detects memory writes |

### Social Engineering

| Specific Attack | Severity | Detected? | Detection Method |
|-----------------|----------|-----------|------------------|
| Fake "prerequisites" installation | MEDIUM | ✅ Yes | Regex pattern |
| "Required dependency" mentions | LOW | ✅ Yes | Regex pattern |
| "Must first install" mandatory steps | MEDIUM | ✅ Yes | Regex pattern |
| Urgent command execution pressure | MEDIUM | ✅ Yes | Regex pattern |
| "Paste in terminal" instructions | MEDIUM | ✅ Yes | Regex pattern |
| "Copy, paste, run" instructions | MEDIUM | ✅ Yes | Regex pattern |
| Exaggerated safety claims ("100% safe") | MEDIUM | ✅ Yes | Regex pattern |
| Trust solicitation ("trust me/this/us") | LOW | ✅ Yes | Regex pattern |
| Manufactured popularity/star inflation | — | ❌ No | Would need registry API |
| Impersonation of legitimate skills | — | ❌ No | Would need registry API |

---

## Coverage Summary

| Category | Threats Identified | Scanner Detects | Coverage |
|----------|-------------------|-----------------|----------|
| Dangerous Shell Execution | 23 | 23 | **100%** |
| Data Exfiltration | 25 | 25 | **100%** |
| Suspicious URLs | 14 | 14 | **100%** |
| Obfuscation | 12 | 10 | **83%** |
| Supply Chain | 15 | 11 | **73%** |
| Prompt Injection | 19 | 16 | **84%** |
| Memory Poisoning | 10 | 7 | **70%** |
| Social Engineering | 10 | 8 | **80%** |
| **Total** | **128** | **114** | **89%** |

The pattern-list categories above are complemented by structural and
harness-level detectors that do not live in a regex list (see below).

---

## Structural & Harness Detectors (non-pattern)

Several of the most successful real-world attacks ([Dangerous Skills,
gricha.dev](https://gricha.dev/blog/dangerous-skills)) do not live in a
single line of scannable text. These are handled by dedicated detectors
rather than the regex pattern lists:

| Attack vector | Detector | Severity |
|---------------|----------|----------|
| Frontmatter `hooks:` auto-run by the harness | `_check_suspicious_metadata_from_ast` | HIGH (CRITICAL if hook command is dangerous) |
| `!` pre-prompt command directive (expanded at skill-load) | `_check_command_directives` | CRITICAL |
| Symlink disguised as an example file (e.g. -> `~/.ssh/id_rsa`) | `_check_symlinks` | LOW / HIGH (escapes dir) / CRITICAL (sensitive target) |
| Instructions hidden in PNG/JPEG image metadata | `_scan_image_metadata` (`tEXt`/`zTXt`/`iTXt`, JPEG `COM`/EXIF) | inherits matched-pattern severity; HIGH for instruction-like text |
| `npm` lifecycle hooks (`postinstall`, etc.) | `_check_package_json` | HIGH (CRITICAL if command is dangerous) |
| `conftest.py` / `test_*.py` auto-executed by pytest | `scan_file` pytest auto-exec check | HIGH |
| Writes to global agent memory (`~/.claude/CLAUDE.md`, `AGENTS.md`) | `memory_poisoning` patterns | HIGH / CRITICAL |

---

## Gaps Requiring Additional Tooling

| Gap | Why Scanner Can't Detect | Recommended Mitigation |
|-----|--------------------------|------------------------|
| **Typosquatted packages** | Needs package registry lookup | Use `socket.dev`, `snyk`, or maintain package allowlist |
| **Compromised upstream repos** | Needs provenance verification | Require signed commits, use Sigstore/SLSA |
| **Benign-sounding malicious instructions** | Requires semantic understanding | LLM-based classifier (see Cisco's Skill Scanner) |
| **Manufactured popularity** | Needs registry metadata | Check account age, download velocity, review count |
| **Multi-stage time-delayed attacks** | Requires runtime analysis | Sandbox execution, behavioral monitoring |
| **Rug-pull attacks** | Needs continuous monitoring | Pin to commit hashes, audit all updates, use lockfiles |
| **Skill impersonation** | Needs registry cross-reference | Verify publisher identity, check for name similarity |
| **Long-context instruction hiding** | Semantic analysis needed | LLM review + character/token budget limits |

---

## Recommended Security Practices

Based on the research, adopt these guardrails:

### For Users

1. **Treat skills like code**: Review before installing, especially scripts/
2. **Pin versions**: Use commit hashes or version tags, not `latest`
3. **Verify provenance**: Check publisher identity, repo age, contributor history
4. **Use allowlists**: Only permit skills from trusted sources
5. **Sandbox execution**: Run agents in Docker/containers with limited permissions
6. **Monitor memory files**: Alert on changes to SOUL.md, MEMORY.md

### For Organizations

1. **PR review for skills**: Require approval before adding skills to shared environments
2. **Immutable skills at runtime**: Prevent self-modifying "update your skill" patterns
3. **Separate skill content from retrieved data**: Don't let untrusted content enter skill context
4. **Audit trails**: Log all skill invocations and tool calls
5. **Network egress controls**: Restrict outbound connections from agent environments

### For Skill Authors

1. **Minimal permissions**: Request only what's needed
2. **No hidden instructions**: Keep all logic visible in SKILL.md
3. **Pin dependencies**: Specify exact versions for all packages
4. **Document data access**: Clearly state what files/APIs the skill accesses
5. **Avoid eval/exec**: Use explicit, auditable code paths

---

## References

1. Snyk Labs (2026). "From SKILL.md to Shell Access in Three Lines of Markdown"
2. 1Password Security (2026). "From Magic to Malware: How OpenClaw's Agent Skills Become an Attack Surface"
3. Cisco AI Defense (2026). "Personal AI Agents like OpenClaw Are a Security Nightmare"
4. arxiv:2510.26328 (2025). "Agent Skills Enable a New Class of Realistic and Trivially Simple Prompt Injections"
5. arxiv:2601.10338 (2026). "Agent Skills in the Wild: An Empirical Study of Security Vulnerabilities at Scale"
6. Sandler, E. (2026). "It's Just a Skill File (Famous Last Words)"
7. OWASP (2025). "Top 10 for Agentic Applications"

# Audit: coinbase/agentic-wallet-skills

**Date:** 2026-02-24
**Source:** https://github.com/coinbase/agentic-wallet-skills
**Version audited:** Commit at HEAD as of 2026-02-24 (awal@2.0.3)
**Scanner version:** skill_scanner.py (current main)
**Install method:** `npx skills add coinbase/agentic-wallet-skills`

---

## Executive Summary

**Verdict: PASS — No malware detected. Low risk with caveats.**

The coinbase/agentic-wallet-skills package contains 9 skills for AI agent
crypto wallet operations (authenticate, fund, send, trade, query, pay, monetize,
search, x402). The automated scanner found **0 CRITICAL and 0 HIGH findings**.
Manual review confirms no malicious patterns, obfuscation, data exfiltration,
prompt injection, or hidden content. The skills are well-written with explicit
input validation guidance and constrained tool permissions.

However, the inherent nature of these skills (autonomous financial operations)
warrants careful attention to the caveats documented below.

---

## Automated Scanner Results

| Metric | Value |
|--------|-------|
| Skills scanned | 9 |
| Critical findings | 0 |
| High findings | 0 |
| Medium findings | 9 (all provenance) |
| Low findings | 2 (supply chain) |
| Trust level | UNVERIFIED (45/100) |
| Has SECURITY.md | Yes (HackerOne) |

### Findings Detail

| Severity | Category | Skill | Description |
|----------|----------|-------|-------------|
| MEDIUM | provenance | All 9 skills | Not served from `/.well-known/skills/` path — official status unverifiable |
| LOW | supply_chain | monetize-service | `npm install` without pinned versions (express, @x402/* packages) |
| LOW | supply_chain | monetize-service | `npm install @coinbase/x402` without pinned version |

---

## Manual Review

### Skills Inventory

| Skill | Purpose | allowed-tools Scope |
|-------|---------|-------------------|
| authenticate-wallet | Email OTP login flow | `awal status`, `awal auth`, `awal balance`, `awal address`, `awal show` |
| fund | Add money via Coinbase Onramp | `awal status`, `awal show`, `awal address`, `awal balance` |
| send-usdc | Transfer USDC to address/ENS | `awal status`, `awal send`, `awal balance` |
| trade | Swap tokens on Base | `awal status`, `awal trade`, `awal balance` |
| search-for-service | Browse x402 bazaar | `awal x402 bazaar`, `awal x402 details` |
| pay-for-service | Make paid x402 API requests | `awal status`, `awal balance`, `awal x402 pay` |
| monetize-service | Build x402 payment server | `awal status`, `awal address`, `awal x402 details/pay`, `npm *`, `node *`, `curl *`, `mkdir *` |
| query-onchain-data | SQL queries via CDP API | `awal status`, `awal balance`, `awal x402 pay` |
| x402 | Combined search + pay workflow | *(no allowed-tools specified)* |

### Positive Security Patterns

1. **Version-pinned CLI**: All skills reference `awal@2.0.3` (specific version, not
   `latest`). The repo includes a `scripts/bump-awal.js` for controlled version updates.

2. **Input validation guidance**: Skills handling user input (authenticate-wallet,
   send-usdc, trade, pay-for-service, query-onchain-data) include explicit regex
   validation rules and shell injection prevention instructions.

3. **Scoped tool permissions**: 8 of 9 skills use `allowed-tools` frontmatter to
   restrict which bash commands the agent may execute. Permissions are narrowly
   scoped to specific `awal` subcommands using glob patterns.

4. **No obfuscation**: All content is plain markdown. No base64 blobs, no eval/exec,
   no encoded strings, no hidden HTML comments.

5. **No data exfiltration**: No access to `.env`, SSH keys, AWS credentials, browser
   data, or other sensitive files.

6. **No prompt injection**: No "ignore previous instructions", role manipulation,
   self-modification, or chain-loading patterns.

7. **No dangerous shell patterns**: No `curl | bash`, reverse shells, crontab
   modifications, or privilege escalation.

8. **Security policy present**: SECURITY.md points to Coinbase's HackerOne bug
   bounty program.

9. **MIT license**: Standard open-source license.

10. **Legitimate publisher**: `coinbase` GitHub org; `awal` npm package maintained
    by `erik_cb <erik.reppel@coinbase.com>` at Coinbase.

### Caveats and Observations

#### 1. Autonomous Financial Operations (Inherent Risk)

All skills set `disable-model-invocation: false`, meaning the agent can
autonomously invoke financial operations without explicit user instruction.
Combined with skills like `send-usdc` and `trade`, a confused or manipulated
agent could initiate real money transfers.

**Mitigation:** Coinbase's agentic wallet infrastructure supports server-side
spending limits, session caps, and transaction limits. These are enforced at
the wallet infrastructure level, not the skill level.

#### 2. monetize-service Has Broad Tool Permissions

This skill allows `Bash(npm *)`, `Bash(node *)`, `Bash(curl *)`, and
`Bash(mkdir *)` — significantly broader than other skills. This is necessary
for its purpose (scaffolding an Express server project) but expands the
attack surface compared to the other 8 skills.

**Risk:** An attacker who can influence the agent's behavior while this skill
is active could potentially run arbitrary npm/node/curl commands.

**Mitigation:** This is a development-time skill (building a server), not a
runtime financial operation. Users should be aware of the broader permissions.

#### 3. x402 Skill Has No allowed-tools Restriction

The `x402` skill does not include an `allowed-tools` field in its frontmatter.
This means it inherits the default tool permissions of the host environment,
which may be broader than intended.

**Risk:** Without explicit tool scoping, the agent's capabilities when using
this skill are governed entirely by the host tool's default permissions.

**Mitigation:** The skill content only references `awal x402` subcommands.
The practical risk depends on the host tool's default permission model.

#### 4. Unpinned npm Dependencies in monetize-service

The monetize-service skill instructs the agent to run:
```
npm install express @x402/express @x402/core @x402/evm @x402/extensions
npm install @coinbase/x402
```
These lack version pins, meaning whatever version is `latest` at install time
will be used. A supply-chain compromise of any of these packages would affect
users following these instructions.

**Mitigation:** This is a common pattern in tutorials/documentation. The
packages are maintained by Coinbase/x402 org. Using lockfiles (`package-lock.json`)
after initial install provides version reproducibility.

#### 5. npx Downloads Executable Code from npm

Every `npx awal@2.0.3` invocation downloads and executes the `awal` npm
package. While version-pinned, npm integrity is the trust anchor. If the
`awal@2.0.3` package on npm were compromised (e.g., via account takeover),
all skills would execute malicious code.

**Mitigation:** This is standard npm toolchain behavior, not unique to this
skill. The `awal` package is maintained by a verified Coinbase employee,
published under Apache-2.0 license, with 10 dependencies. npm's provenance
features and Coinbase's organizational security practices reduce this risk.

#### 6. Provenance Cannot Be Verified

Skills are distributed via GitHub (through the `skills` CLI), not from
`coinbase.com/.well-known/skills/`. Per the Cloudflare Agent Skills Discovery
RFC, official status requires serving from the domain's well-known path.

**Mitigation:** The GitHub repo is under the official `coinbase` org (verified).
The `awal` npm package is published by a Coinbase employee. Combined signals
provide reasonable confidence in authenticity, even without RFC-compliant
well-known path serving.

---

## awal CLI Package Analysis

| Field | Value |
|-------|-------|
| Package | `awal@2.0.3` |
| License | Apache-2.0 |
| Maintainer | erik_cb (erik.reppel@coinbase.com) |
| Dependencies | 10 (commander, chalk, ora, viem, zod, @x402/core, @x402/extensions, @langchain/community, @langchain/core, env-paths) |
| Unpacked size | 628.5 kB |
| Published | ~2026-02-17 |

Notable dependencies:
- `@langchain/community` and `@langchain/core`: LangChain integration (the CLI
  likely has built-in AI capabilities)
- `viem`: Ethereum interaction library
- `@x402/core` and `@x402/extensions`: x402 payment protocol libraries
- `zod`: Runtime type validation

---

## Conclusion

The coinbase/agentic-wallet-skills package is **not malicious**. It is a
legitimate, well-structured skill set from Coinbase for AI agent wallet
operations. The skills demonstrate good security hygiene: version-pinned CLI
references, explicit input validation guidance, and narrowly-scoped tool
permissions (with the noted exceptions).

The primary risks are **inherent to the use case** (autonomous financial
operations by AI agents), not to the skill implementation itself. Users should:

1. Configure wallet spending limits via Coinbase's infrastructure
2. Be aware that `monetize-service` grants broader tool permissions than other skills
3. Note that `x402` skill lacks explicit `allowed-tools` constraints
4. Pin npm dependency versions when following the monetize-service setup instructions

**Risk Rating: LOW** (with caveats above)

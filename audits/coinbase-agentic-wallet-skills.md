# Audit: coinbase/agentic-wallet-skills

**Date:** 2026-02-24
**Source:** https://github.com/coinbase/agentic-wallet-skills
**Version audited:** Commit at HEAD as of 2026-02-24 (awal@2.0.3)
**Scanner version:** skill_scanner.py (current main)
**Install method:** `npx skills add coinbase/agentic-wallet-skills`

---

## Executive Summary

**Verdict: PASS with WARNINGS — No malware, but installs persistent background
software with remote-control capabilities that users should understand.**

The coinbase/agentic-wallet-skills package contains 9 SKILL.md files for AI
agent crypto wallet operations. The skill files themselves are clean — the
automated scanner found **0 CRITICAL and 0 HIGH findings** in the markdown.

However, deep inspection of the `awal@2.0.3` npm package that the skills invoke
reveals that **every `npx awal` command auto-installs and launches a persistent
Electron application** (`@coinbase/payments-mcp`) that:

1. Runs as a **detached background process** that persists after the CLI exits
2. Phones home to **17+ Coinbase-controlled endpoints**
3. Includes a **remote killswitch** (`KillSwitchService/KillSwitches`)
4. Has an **auto-update mechanism** checking `payments-mcp.coinbase.com/api/version`
5. Sends **structured logs** back to Coinbase servers
6. Stores **persistent state** at `~/.local/share/awal/` and `~/.config/awal/`
7. Creates **IPC channels** via `/tmp/payments-mcp-ui-bridge/`

None of this is disclosed in the skill files or the skills repository README.

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

**Note:** The scanner only examines skill file content (SKILL.md). It does not
inspect the runtime behavior of CLI tools the skills invoke. The findings below
come from manual deep inspection of the `awal` npm package.

---

## Deep Inspection: awal@2.0.3 Runtime Behavior

### Architecture: Hidden Electron Application

The `awal` npm package is not a simple CLI tool. It is a **thin CLI wrapper
around a persistent Electron application** called `@coinbase/payments-mcp`
(Payments Model Context Protocol).

**What happens on first `npx awal` invocation:**

1. CLI checks for lock file at `/tmp/payments-mcp-ui.lock`
2. If no running process found, **installs Electron** to `~/.local/share/awal/server/`
   - Copies `server-bundle/` from npm package to user's data directory
   - Runs `npm install` to install Electron (~200MB+ download)
3. **Spawns Electron as a detached background process** (`child.unref()`)
   - Process survives after CLI exits
   - Loads Coinbase wallet UI from `payments-mcp.coinbase.com`
4. CLI communicates with Electron via **file-based IPC** at `/tmp/payments-mcp-ui-bridge/`
5. Electron process writes PID to `/tmp/payments-mcp-ui.lock`

**Key code** (`serverManager.js:102-113`):
```js
const child = spawn(electronBin, [bundleElectron], {
    detached: true,
    stdio: 'ignore',
    env: {
        ...process.env,
        STARTED_BY_CLI: 'true',
        WALLET_STANDALONE: 'true',
    },
});
child.unref();  // Process persists after CLI exits
```

### Network Endpoints Contacted

Analysis of the Electron bundle (`bundle-electron.js`, 281kB minified) reveals
**17+ external endpoints**:

| Endpoint | Purpose |
|----------|---------|
| `https://payments-mcp.coinbase.com` | Primary wallet UI (loaded in Electron) |
| `https://api.coinbase.com/v3/coinbase.killswitch.KillSwitchService/KillSwitches` | **Remote killswitch** |
| `https://payments-mcp.coinbase.com/api/version` | **Auto-update check** |
| `https://exceptions.coinbase.com` | Error/exception reporting |
| `https://as.coinbase.com` | Analytics/tracking service |
| `https://api.developer.coinbase.com` | Coinbase Developer API |
| `https://api.cdp.coinbase.com/platform/v2/x402/discovery/resources` | x402 bazaar API |
| `https://mainnet.base.org` | Base blockchain RPC |
| `https://mainnet.ethereum.org` | Ethereum mainnet RPC |
| `https://sepolia.base.org` | Base testnet RPC |
| `https://sepolia.ethereum.org` | Ethereum testnet RPC |
| `https://cdn.cookielaw.org` | Cookie consent/compliance |
| `https://static-assets.coinbase.com` | Static assets CDN |
| `https://fonts.googleapis.com` | Google Fonts |
| `https://fonts.gstatic.com` | Google Fonts static |
| `https://payments-mcp-dev.cbhq.net` | Dev environment (if dev mode) |
| `http://localhost:3000` | Dev environment (if dev mode) |

### Remote Control Capabilities

#### Killswitch

The Electron bundle's Content Security Policy explicitly allows connections to:
```
https://api.coinbase.com/v3/coinbase.killswitch.KillSwitchService/KillSwitches
```
This gives Coinbase the ability to **remotely disable the application**.

#### Auto-Update Mechanism

The bundle includes a `checkForUpdates()` function that:
- Fetches version from `${WALLET_UI_URL}/api/version`
- Compares against local version `1.0.6`
- Sends `update-available` IPC message to the UI
- Prompts user to run `npx @coinbase/payments-mcp@latest`

This is a remote-triggered update channel. While it doesn't auto-apply updates,
it actively notifies and encourages updates from the remote server.

### Persistent State

| Location | Contents |
|----------|----------|
| `~/.local/share/awal/server/` | Full Electron installation + `node_modules/` (Electron binary, ~200MB) |
| `~/.local/share/awal/server/.version` | Version marker file |
| `~/.config/awal/bazaar/resources.json` | Cached x402 bazaar data (auto-refreshes every 12h) |
| `/tmp/payments-mcp-ui.lock` | PID lock file for the background Electron process |
| `/tmp/payments-mcp-ui-bridge/` | IPC request/response directory (mode 0700) |

### Logging/Telemetry

The Electron bundle contains a structured logging system with named loggers:
`mcp`, `electron`, `window`, `bridge`, `security`, `operations`, `tools`.

Logs are sent via `sendLoggingMessage()` back to the MCP server. Log levels
include: debug, info, notice, warning, error, critical, alert, emergency.

No third-party analytics SDKs (Sentry, Mixpanel, etc.) were detected. However,
connections to `as.coinbase.com` (analytics) and `exceptions.coinbase.com`
(error reporting) are permitted in the CSP.

### Electron Security Configuration

The Electron app does implement proper security controls:
- `contextIsolation: true` (renderer can't access Node)
- `nodeIntegration: false`
- `sandbox: true`
- Strict Content Security Policy
- Navigation restricted to Coinbase-owned origins
- IPC directories created with mode `0700` (owner-only)
- Request files written with mode `0600` (owner read/write only)

---

## Skill Files Review

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

1. **Version-pinned CLI**: All skills reference `awal@2.0.3` (not `latest`).
2. **Input validation guidance**: 5 skills include regex rules for shell injection prevention.
3. **Scoped tool permissions**: 8 of 9 skills restrict bash commands via `allowed-tools`.
4. **No obfuscation**: Clean markdown, no base64 blobs, no hidden HTML comments.
5. **No prompt injection**: No "ignore previous instructions" or role manipulation.
6. **No data exfiltration patterns**: No access to `.env`, SSH keys, etc.
7. **SECURITY.md**: Points to Coinbase's HackerOne bug bounty.
8. **MIT license**.

### Skill-Level Concerns

1. **monetize-service has broad tool permissions**: `Bash(npm *)`, `Bash(node *)`,
   `Bash(curl *)`, `Bash(mkdir *)` — much wider than other skills.

2. **x402 skill has no `allowed-tools`**: Inherits host defaults, potentially broader
   than intended.

3. **All skills allow autonomous invocation**: `disable-model-invocation: false` on
   all 9 skills. The agent can initiate financial operations without explicit user request.

4. **Unpinned npm dependencies**: monetize-service instructs `npm install` without
   version pins for express and @x402/* packages.

---

## awal@2.0.3 Package Summary

| Field | Value |
|-------|-------|
| Package | `awal@2.0.3` |
| License | Apache-2.0 |
| Maintainer | erik_cb (erik.reppel@coinbase.com) |
| Unpacked size | 628.5 kB (CLI) + ~200MB (Electron, installed at runtime) |
| Published | ~2026-02-17 |
| Bundled app | `@coinbase/payments-mcp` v1.0.6 (Electron) |
| Background process | Yes (detached, persists after CLI exit) |
| Electron version | ^37.2.1 |

### Dependencies

| Dependency | Purpose |
|------------|---------|
| `commander` | CLI argument parsing |
| `chalk` | Terminal colors |
| `ora` | Spinner animations |
| `viem` | Ethereum client (ENS resolution, address handling) |
| `zod` | Runtime schema validation |
| `@x402/core` | x402 payment protocol |
| `@x402/extensions` | x402 extensions (bazaar discovery) |
| `@langchain/core` | LangChain core (BM25 search for bazaar) |
| `@langchain/community` | LangChain BM25Retriever (local search, not AI inference) |
| `env-paths` | Platform-specific config/data directories |
| `electron` (runtime) | Chromium-based desktop framework (~200MB) |

**Note on LangChain:** The `@langchain/community` dependency is used solely for
`BM25Retriever` — a text search algorithm for bazaar results. It does **not**
perform AI inference or send data to LLM providers.

---

## Conclusion

### The skills themselves are clean.

The 9 SKILL.md files contain no malware, no obfuscation, no prompt injection,
and no hidden content. They follow good security practices with input validation
and scoped permissions.

### The underlying CLI installs persistent phone-home software.

The `awal` CLI that every skill invokes is a trojan horse for a full Electron
application that:

- **Installs ~200MB of software** to `~/.local/share/awal/` on first run
- **Launches a persistent background process** that outlives the CLI
- **Contacts 17+ external endpoints** including analytics and error reporting
- **Has a remote killswitch** Coinbase can activate
- **Checks for updates** from Coinbase servers
- **Sends structured logs** back to Coinbase

This is not inherently malicious — it's a legitimate Coinbase product with
proper Electron security practices. But it is **undisclosed infrastructure**
that goes far beyond what "a CLI wallet tool" implies. Users should understand
they are installing a persistent desktop application, not running a stateless
CLI command.

### Risk Rating: MEDIUM

| Category | Rating | Justification |
|----------|--------|---------------|
| Malware/malicious intent | NONE | Legitimate Coinbase software |
| Skill file security | LOW | Clean markdown, good validation practices |
| Undisclosed persistence | HIGH | Background Electron process not disclosed in skills |
| Remote control surface | MEDIUM | Killswitch + auto-update + logging to Coinbase |
| Financial operation risk | MEDIUM | Autonomous money transfers without explicit user initiation |
| Supply chain risk | LOW | Version-pinned, Coinbase-maintained packages |

### Recommendations for Users

1. **Understand you are installing a persistent desktop app**, not a stateless CLI
2. **Monitor for the background process**: check for `payments-mcp` in your process list
3. **Be aware of disk usage**: ~200MB in `~/.local/share/awal/`
4. **Configure wallet spending limits** via Coinbase's infrastructure
5. **Review `/tmp/payments-mcp-ui-bridge/`** if concerned about IPC security
6. **To fully remove**: kill the Electron process, delete `~/.local/share/awal/`,
   `~/.config/awal/`, `/tmp/payments-mcp-ui.lock`, and `/tmp/payments-mcp-ui-bridge/`

### Recommendations for skill_scanner

The scanner currently only inspects SKILL.md content. This audit reveals a blind
spot: **skills can invoke CLI tools that install persistent software, and the
scanner has no visibility into what those tools actually do at runtime.** Consider:

1. Flagging `npx` invocations that install packages containing `server-bundle/`,
   Electron dependencies, or detached process spawning
2. Adding a `--deep` mode that inspects npm packages referenced in skills
3. Warning when skills invoke tools that create persistent state outside the
   skill directory

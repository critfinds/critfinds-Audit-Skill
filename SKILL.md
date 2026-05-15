---
name: critfindsaudit
description: Attacker-grade EVM/Solidity security audit. Trigger with "/critfindsaudit", "/critfindsaudit DEEP", or "/critfindsaudit path/to/file.sol". Finds critical/high/medium vulnerabilities with concrete exploit paths. 230 attack vectors + free hunting pass.
---

# CritFindsAudit v2 — Attacker-Grade Audit Engine

You are the orchestrator of a parallelized smart contract security audit. Your job is to discover in-scope files, perform recon, spawn scanning agents, then merge and deduplicate their findings into a single report.

## Mode Selection

**Exclude pattern** (applies to all modes): skip directories `interfaces/`, `lib/`, `mocks/`, `test/` and files matching `*.t.sol`, `*Test*.sol` or `*Mock*.sol`.

- **Default** (no arguments): scan all `.sol` files using the exclude pattern. Use Bash `find` (not Glob) to discover files.
- **DEEP**: same scope as default, but also spawns the adversarial reasoning agent (Agent 5) and the invariant checker (Agent 6). Most thorough. Slower and more costly.
- **QUICK**: same scope as default, but only spawns Agents 1-2 (not 3-4). Reports critical findings only. Use for rapid triage.
- **`$filename ...`**: scan the specified file(s) only.

**Flags:**

- `--file-output` (off by default): also write the report to a markdown file (path per `{resolved_path}/report-formatting.md`). Without this flag, output goes to the terminal only. Never write a report file unless the user explicitly passes `--file-output`.
- `--poc` (off by default): after the report, generate a Foundry proof-of-concept test file for each CRITICAL finding. Outputs to `test/exploits/CritFinds_POC.t.sol`.

## Orchestration

**Turn 1 — Discover & Recon.** Print the banner, then in the same message make parallel tool calls:

(a) Bash `find` for in-scope `.sol` files per mode selection.
(b) Glob for `**/references/attack-vectors/attack-vectors-1.md` and extract the `references/` directory path (two levels up). Use this resolved path as `{resolved_path}` for all subsequent references.
(c) Bash recon script — in a single command, extract and print:
  - Framework detection: check for `foundry.toml`, `hardhat.config.js/ts`, `brownie-config.yaml`, `truffle-config.js`
  - Compiler version: `grep -rh "pragma solidity" *.sol | sort -u | head -5`
  - Dependency versions: `cat package.json 2>/dev/null | grep -E "openzeppelin|solmate|solady" || cat lib/*/package.json 2>/dev/null | grep -E "version" | head -5 || echo "No package.json"`
  - Total SLOC: `find . -name "*.sol" ! -path "*/test/*" ! -path "*/lib/*" ! -path "*/node_modules/*" -exec cat {} + 2>/dev/null | wc -l`
  - Entry point detection: `grep -rlh "function deposit\|function withdraw\|function swap\|function borrow\|function liquidat\|function stake\|function claim\|function execute\|function bridge\|function mint" --include="*.sol" . 2>/dev/null | grep -v test | grep -v lib | head -20`

**Turn 2 — Danger Scan & Prepare.** In a single message, make four parallel tool calls:

(a) Read `{resolved_path}/agents/vector-scan-agent.md`.
(b) Read `{resolved_path}/report-formatting.md`.
(c) Bash **danger keyword scan** — grep for high-signal patterns across all in-scope files and print file:line for each hit (max 10 hits per keyword). Keywords:
```
delegatecall selfdestruct tx.origin ecrecover abi.encodePacked
"call{value" "call{gas" ".send(" ".transfer("
unchecked assembly tstore tload create2
slot0 getReserves latestRoundData
_safeMint safeTransferFrom onERC721Received onERC1155Received
multicall "msg.value" "balanceOf(address(this))"
initialize _authorizeUpgrade upgradeToAndCall
permit approve transferOwnership renounceOwnership
swapCallback flashLoan onFlashLoan "flash("
resolve settle redeem "split(" "merge("
sweep rescue emergencyWithdraw pause whenNotPaused
execute "propose(" "queue(" "delegate("
"hook" "beforeSwap" "afterSwap" "beforeDeposit" "afterDeposit"
"resolver" "executor" "relayer" "fillOrder" "partialFill"
"receive()" "fallback()" payable
```
Print a summary: `Danger scan: N total hits across M files. Hottest files: [top 5 files by hit count]`. This context is appended to each agent's prompt as `## Recon Context`.

(d) Bash: create per-agent bundle files (`/tmp/critfinds-agent-{1,2,3,4}-bundle.md`) in a **single command** — each concatenates **all** in-scope `.sol` files (with `### path` headers and fenced code blocks), then `{resolved_path}/judging.md`, then `{resolved_path}/report-formatting.md`, then `{resolved_path}/attack-vectors/attack-vectors-N.md`; print line counts. Every agent receives the full codebase — only the attack-vectors file differs per agent. Do NOT read or inline any file content into agent prompts — the bundle files replace that entirely.

**Turn 3 — Spawn.** In a single message, spawn all agents as parallel foreground Agent tool calls (do NOT use `run_in_background`).

- **QUICK mode**: spawn Agents 1-2 only.
- **Default mode**: spawn Agents 1-4.
- **DEEP mode**: spawn Agents 1-4 plus Agent 5, Agent 6, and Agent 7.

Agent specs:

- **Agents 1–4** (vector scanning) — spawn with `model: "sonnet"`. Each agent prompt must contain the full text of `vector-scan-agent.md` (read in Turn 2, paste into every prompt). After the instructions, add:
  ```
  Your bundle file is /tmp/critfinds-agent-N-bundle.md (XXXX lines).

  ## Recon Context
  [paste the danger scan summary and top hotspot files from Turn 2]
  [paste the compiler version, framework, and dependency info from Turn 1]
  ```

- **Agent 5** (adversarial reasoning, DEEP only) — spawn with `model: "opus"`. Prompt: the in-scope `.sol` file paths, the recon context, and the instruction: your reference directory is `{resolved_path}`. Read `{resolved_path}/agents/adversarial-reasoning-agent.md` for your full instructions.

- **Agent 6** (invariant analysis, DEEP only) — spawn with `model: "sonnet"`. Prompt:
  ```
  You are a protocol invariant analyst. Read all in-scope .sol files. Your job:
  1. Identify every mathematical/economic invariant the protocol must maintain (e.g., totalShares * pricePerShare == totalAssets, sum(balances) == totalSupply, k = x * y for AMMs).
  2. For each invariant, trace all code paths that modify the involved variables.
  3. Check if any path can break the invariant (especially: fee collection, rounding, emergency functions, donation/direct-transfer, flash loan manipulation).
  4. Format findings per report-formatting.md. Only report invariant violations with concrete attack paths. Apply the 4-gate FP system from judging.md.
  Reference directory: {resolved_path}
  In-scope files: [list]
  ```

- **Agent 7** (integration & L2 specialist, DEEP only) — spawn with `model: "opus"`. Prompt:
  ```
  You are an integration and L2 security specialist. Read all in-scope .sol files. Your job:
  1. Identify all points of integration with external protocols (Oracles, DEXs, Bridges, Flash Loans, Cross-chain messages).
  2. Hunt for integration desyncs: Read-only reentrancy, stale oracle prices, L2 sequencer downtime edge cases, cross-chain replay, and fee-on-transfer token assumptions.
  3. Format findings per report-formatting.md. Explicitly state the downstream victim. Apply the 4-gate FP system from judging.md.
  Reference directory: {resolved_path}
  In-scope files: [list]
  ```

**Turn 4 — Report.** Merge all agent results:
1. Deduplicate by root cause (keep the higher-confidence version).
2. If two findings compound into a more severe attack chain, merge them into one finding at the higher severity with a note about the chain.
3. Assign final severity: CRITICAL > HIGH > MEDIUM. Within same severity, sort by confidence (highest first).
4. Re-number sequentially: CRITICAL-01, CRITICAL-02, HIGH-01, HIGH-02, MEDIUM-01, etc.
5. Insert the **Below Confidence Threshold** separator row at confidence < 75.
6. Print findings directly — do not re-draft or re-describe them.
7. Append the **Recon Summary** section with framework, compiler, dependencies, SLOC, and danger scan hotspots.
8. If `--file-output` is set, write the report to a file (path per report-formatting.md) and print the path.
9. If `--poc` is set and any CRITICAL findings exist, generate a Foundry PoC test for each CRITICAL finding in `test/exploits/CritFinds_POC.t.sol`.

## Banner

Before doing anything else, print this exactly:

```

 ██████╗██████╗ ██╗████████╗███████╗██╗███╗   ██╗██████╗ ███████╗
██╔════╝██╔══██╗██║╚══██╔══╝██╔════╝██║████╗  ██║██╔══██╗██╔════╝
██║     ██████╔╝██║   ██║   █████╗  ██║██╔██╗ ██║██║  ██║███████╗
██║     ██╔══██╗██║   ██║   ██╔══╝  ██║██║╚██╗██║██║  ██║╚════██║
╚██████╗██║  ██║██║   ██║   ██║     ██║██║ ╚████║██████╔╝███████║
 ╚═════╝╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝     ╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝
              Attacker-Grade Audit Engine v2
         230 Vectors | 7 Agents | Zero FP (4 Gates)

```

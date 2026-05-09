# CritFindsAudit v2

Attacker-grade EVM/Solidity security audit skill for Claude Code.
200 attack vectors. 6 parallel agents. Automated recon. Zero false-positive tolerance.

## Install

```bash
# Clone and install
git clone git@github.com:critfinds/critfinds-Audit-Skill.git
cp -r critfinds-Audit-Skill/* ~/.claude/commands/critfindsaudit/

# Or manual: copy this entire directory to ~/.claude/commands/critfindsaudit/
```

Restart Claude Code after installation.

## Commands

| Command | Description |
|---------|-------------|
| `/critfindsaudit` | Full audit — 4 vector-scan agents, 200 vectors |
| `/critfindsaudit DEEP` | Full + adversarial reasoning (opus) + invariant analysis |
| `/critfindsaudit QUICK` | Rapid triage — 2 agents, criticals only |
| `/critfindsaudit path/to/File.sol` | Audit specific file(s) |
| `/critfindsaudit --file-output` | Save report to `assets/findings/` |
| `/critfindsaudit --poc` | Generate Foundry PoC for each CRITICAL |
| `/critfindsaudit DEEP --file-output --poc` | Everything — full audit, saved report, PoCs |

## Architecture

```
Turn 1: Discover .sol files + automated recon (framework, compiler, deps, SLOC, entry points)
Turn 2: Danger keyword scan (25+ patterns) + build per-agent code bundles
Turn 3: Spawn parallel agents (4 vector-scan + adversarial + invariant in DEEP)
Turn 4: Merge, deduplicate, severity-sort, compound attack chains, generate report + PoCs
```

## What Makes This Different

| Feature | CritFindsAudit v2 | Other tools |
|---------|-------------------|-------------|
| Attack vectors | **200** with D:/FP: format | 170 or fewer |
| Agents (DEEP mode) | **6** (4 scan + adversarial + invariant) | 5 or fewer |
| Automated recon | Framework, compiler, deps, SLOC, entry points, danger scan | None |
| Danger keyword scan | 25+ high-signal patterns with hotspot ranking | None |
| Severity classification | **CRITICAL / HIGH / MEDIUM** per finding | Confidence only |
| Attack scenarios | Numbered step-by-step exploit sequences | Not included |
| Impact quantification | Dollar-value estimates where possible | Not included |
| Root cause snippets | File:line with vulnerable code | Not included |
| Invariant analysis agent | Dedicated agent for mathematical invariants | Not included |
| PoC generation | `--poc` flag generates Foundry exploit tests | Not included |
| QUICK mode | 2-agent rapid triage for criticals only | Not available |
| Variant hunting | Each confirmed finding triggers codebase-wide variant search | Not included |
| Composability check | Findings combined into compound attack chains | Basic or none |
| Counter-argument testing | Adversarial agent challenges its own findings | Not included |
| Recon context sharing | Danger scan results fed to every agent | Not included |

## Attack Vector Coverage (200 vectors)

| File | Vectors | Categories |
|------|---------|-----------|
| attack-vectors-1.md | V1-V50 | Reentrancy (5 types), Access Control (8), Arithmetic (6), Oracle (7), Flash Loan (4), Signatures (6), EVM Core (7) |
| attack-vectors-2.md | V51-V100 | Token Integration (10), Proxy & Upgradeability (10), MEV (6), DeFi Protocol — Vaults, AMMs, Lending, Staking (24) |
| attack-vectors-3.md | V101-V150 | Cross-Chain & Bridge (10), Gas & DoS (9), EVM Hazards (10), Governance (7), NFT (9) |
| attack-vectors-4.md | V151-V200 | Compiler (5), Low-Level Assembly (10), Permit/Approval (5), Economic Attacks (10), Advanced (20) |

## Severity & Confidence

### Severity

| Level | Criteria |
|-------|---------|
| **CRITICAL** | Direct theft or permanent freeze. Permissionless. No unlikely conditions. |
| **HIGH** | Indirect theft, temp freeze >24h, >10% yield loss, privilege escalation. Realistic conditions. |
| **MEDIUM** | Edge-case loss, griefing, broken functionality. Uncommon but plausible conditions. |

### Confidence

Starts at 100. Deductions: privileged caller (-25), partial path (-20), self-contained (-15), external conditions (-10), multi-block coordination (-10), battle-tested pattern (-5).

Threshold: 75. Below = description only, no fix.

### FP Gate (3 checks, all must pass)

1. Concrete attack path traceable (caller -> call -> state change -> loss)
2. Entry point reachable by attacker
3. No existing guard prevents it

## Report Format

Findings use IDs: `CRITICAL-01`, `HIGH-01`, `MEDIUM-01`. Each includes:
- Description (1-2 sentences)
- Attack Scenario (numbered steps)
- Impact (quantified)
- Root Cause (file:line + code snippet)
- Recommendation (diff block, omitted below confidence 80)

## File Structure

```
~/.claude/commands/critfindsaudit/
  SKILL.md                              — Orchestrator (the brain)
  README.md                             — This file
  VERSION                               — Version number
  references/
    judging.md                          — FP gate + confidence scoring + severity rules
    report-formatting.md                — Report template with PoC section
    agents/
      vector-scan-agent.md              — Scanner agent instructions
      adversarial-reasoning-agent.md    — DEEP mode adversarial agent (7-pass)
    attack-vectors/
      attack-vectors-1.md               — V1-V50 (200 total)
      attack-vectors-2.md               — V51-V100
      attack-vectors-3.md               — V101-V150
      attack-vectors-4.md               — V151-V200
  assets/
    findings/                           — Saved audit reports
    docs/                               — Project context docs
```

## Requirements

- Claude Code CLI
- Solidity source files (`.sol`)
- Foundry/Hardhat/Brownie project (optional, for PoC generation)

## Disclaimer

AI-assisted security analysis for authorized testing, audit engagements, CTF competitions, and defensive research. Always verify findings with manual review and formal verification.

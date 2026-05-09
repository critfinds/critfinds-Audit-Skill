# Finding Validation

Each finding passes a false-positive gate, then gets a confidence score and severity classification.

## Severity Definitions

| Severity | Definition | Examples |
|----------|-----------|---------|
| **CRITICAL** | Direct theft of user funds, permanent freezing of funds, or complete protocol takeover. Exploitable without special permissions. No unlikely external conditions required. | Reentrancy drain, unprotected initialize, open delegatecall, unguarded selfdestruct |
| **HIGH** | Indirect theft via manipulation/MEV, temporary freezing of funds (>24h), significant yield loss (>10%), or privilege escalation. May require specific but realistic conditions. | Oracle manipulation, first-depositor inflation, missing slippage, cross-function reentrancy with limited impact |
| **MEDIUM** | Edge-case fund loss, griefing attacks with real cost to victims, broken functionality affecting protocol operation. Requires uncommon but plausible conditions. | Fee-on-transfer accounting, unbounded loop DoS, stale Chainlink without heartbeat check, rounding in attacker's favor |

## Severity Assignment Rules

1. If funds can be stolen by a permissionless attacker -> CRITICAL
2. If funds can be stolen but requires specific market conditions, token types, or timing -> HIGH
3. If funds can be locked temporarily or protocol functionality is broken -> HIGH
4. If impact requires admin/privileged compromise to exploit -> HIGH (not CRITICAL, deduct confidence)
5. If impact is griefing, DoS, or edge-case loss under unusual conditions -> MEDIUM
6. If you're unsure between two severities, choose the lower one.

## FP Gate

Every finding must pass all three checks. If any check fails, drop the finding — do not score or report it.

1. **Concrete attack path exists:** You can trace caller -> function call -> state change -> loss/impact. Evaluate what the code _allows_, not what the deployer _might choose_. If you cannot write the exact sequence of function calls an attacker would make, it is not a finding.
2. **Entry point is reachable:** The attack entry point is callable by the attacker (check modifiers, `msg.sender` guards, `onlyOwner`, `onlyRole`, access control). If the function is admin-only and the attacker needs admin access, the finding still passes but gets a -25 confidence deduction.
3. **No existing guard prevents it:** No `require`, `if`-revert, reentrancy lock, allowance check, or other mechanism already blocks the attack path. Check the FULL call chain, not just the immediate function.

## Confidence Score

Confidence measures certainty that the finding is real and exploitable — not how severe it is. Every finding that passes the FP gate starts at **100**.

**Deductions (apply all that fit, minimum score is 20):**

| Condition | Deduction |
|-----------|-----------|
| Privileged caller required (owner, admin, multisig, governance) | -25 |
| Attack path is partial (sound idea but cannot write exact tx sequence) | -20 |
| Impact is self-contained (only affects attacker's own funds) | -15 |
| Requires specific external conditions (token type, market state, oracle timing) | -10 |
| Requires multi-block coordination or validator collusion | -10 |
| Similar pattern exists in battle-tested protocols without known exploits | -5 |

Confidence indicator: `[score]` (e.g., `[95]`, `[75]`, `[60]`).

Findings below the confidence threshold (default 75) are still included in the report table but do not get a **Recommendation** section — description and attack scenario only.

## Do Not Report

- Anything a linter, compiler, or seasoned developer would dismiss — INFO-level notes, gas micro-optimizations, naming conventions, NatSpec, redundant comments, event ordering.
- Owner/admin can set fees, parameters, or pause — these are by-design privileges, not vulnerabilities. UNLESS: admin action can steal user funds beyond what users agreed to (e.g., unlimited fee setting, instant rug without timelock).
- Missing event emissions or insufficient logging.
- Centralization observations without a concrete exploit path (e.g., "owner could rug" with no specific mechanism beyond trust assumptions).
- Theoretical issues requiring implausible preconditions (e.g., compromised compiler, corrupt block producer, >50% token supply held by attacker).
- "Best practice" suggestions that don't correspond to an exploitable vulnerability.

**IMPORTANT exceptions — these ARE valid findings:**
- Common ERC20 behaviors (fee-on-transfer, rebasing, blacklisting, pausing) are NOT implausible — if the code accepts arbitrary tokens, these are valid attack surfaces.
- Admin actions without timelock that could drain user funds in a single transaction.
- Upgradeable contracts where the upgrade path has insufficient access control.

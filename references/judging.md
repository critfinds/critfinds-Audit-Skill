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

## "Investigate-First" FP Gate

Every finding must pass ALL FOUR gates of the zero-tolerance False Positive (FP) policy. If any gate fails, drop the finding — but internally you MUST name the specific reason or guard when dropping.

**Default posture: INVESTIGATE, not DROP.** Assume a finding is real until you can prove otherwise with a specific, named guard. The absence of the exact named pattern is NOT sufficient to drop — you must verify the underlying vulnerability concept is also inapplicable.

1. **GATE 1: THE EXECUTION PATHWAY:** Does a mathematically valid execution path exist that allows an external attacker to reach the vulnerable code? If the function is protected by `onlyOwner` or a trusted multisig, DISCARD immediately unless you can prove a concrete privilege escalation vector (e.g., signature replay, cross-chain bridge manipulation).
2. **GATE 2: THE ATOMIC REVERT CHECK:** If the exploit requires manipulating state out-of-order, does the transaction atomically revert if the final check fails? If standard EVM atomic rollbacks (like SafeMath underflows or end-of-execution require statements) protect the transaction, DISCARD the finding. It is visually suspicious but mathematically safe.
3. **GATE 3: THE FINANCIAL IMPACT MANDATE (PROOF OF DAMAGE):** Does this vulnerability lead to direct protocol insolvency, permanent locking of funds, or manipulation of an IN-SCOPE downstream integration? If the impact is "users might get confused," "event emitted late," or "theoretical loss of dust," DISCARD the finding. You only report blood.
4. **GATE 4: THE REPRODUCIBILITY REQUIREMENT:** Can this attack be mathematically proven using Foundry (via fuzzing) or Echidna (via invariant breaks)? You must be able to conceptualize a concrete PoC that proves the exploit on a live mainnet fork.

### Drop Justification Requirement

When dropping a finding via the FP gate, you MUST provide an explicit justification referencing the specific gate failed:

```
DROP: failed Gate X because [specific reason or guard] at [file:line]
```

Examples of valid drop justifications:
- `DROP: failed Gate 2 because transaction reverts on require(amountOut >= minOut) at Router.sol:L142`
- `DROP: failed Gate 1 because guarded by onlyOwner modifier at Vault.sol:L88`
- `DROP: failed Gate 3 because impact is only 1 wei of dust lost during division.`
- `DROP: failed Gate 1 because architectural — contract never holds ETH (no receive/fallback, no payable functions)`

**Invalid drop justifications (these CANNOT be used to drop):**
- "I don't see the exact pattern described in the vector"
- "The named construct isn't present in the codebase"
- "Pattern doesn't seem to apply" (vague, no specific guard named)

### Concept Over Pattern Rule

Vectors describe vulnerability concepts, not just specific code patterns. When evaluating a vector:

1. First, check if the literal named construct is present.
2. If NOT present, check if the **underlying vulnerability concept** could manifest through a different mechanism.
3. A vector is only droppable if BOTH the named construct AND the underlying concept are absent, OR if a specific guard prevents exploitation.

Example: Vector "msg.value reuse in multicall" — the concept is "ETH amount can be spent multiple times or exceeds what the caller sent." Even without multicall, if a payable function has a separate amount parameter that can diverge from msg.value, the concept applies.

## Confidence Score

Confidence measures certainty that the finding is real and exploitable — not how severe it is. Every finding that passes the FP gate starts at **100**.

### Confidence Floors

Certain finding types have minimum confidence floors that deductions cannot breach:

| Condition | Confidence Floor |
|-----------|-----------------|
| Agent can construct concrete 3+ step attack scenario with specific function calls and named parameters | Floor: 90 (deductions cannot reduce below 90) |
| Finding is "missing input validation on fund-critical path" — user-controlled parameter reaches fund transfer without validation | Floor: 85 (deductions cannot reduce below 85, UNLESS privileged caller required — then floor is 60) |

### Deductions

**Deductions (apply all that fit, but respect the floors above; absolute minimum score is 20):**

| Condition | Deduction |
|-----------|-----------|
| Privileged caller required (owner, admin, multisig, governance) | -25 |
| Attack path is partial (sound idea but cannot write exact tx sequence) | -20 |
| Impact is self-contained (only affects attacker's own funds) | -15 |
| Requires specific external conditions (token type, market state, oracle timing) | -10 |
| Requires multi-block coordination or validator collusion | -10 |
| Similar pattern exists in battle-tested protocols without known exploits | -5 |

**Only deduct confidence for specific mitigating factors the agent can name.** Generic uncertainty ("I'm not sure this works") is NOT a valid deduction reason. Each deduction must cite the specific mitigating factor.

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

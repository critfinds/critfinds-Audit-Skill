# Report Formatting

## Report Path

Save the report to `assets/findings/critfinds-audit-{project-name}-{timestamp}.md` where `{project-name}` is the repo root basename and `{timestamp}` is `YYYYMMDD-HHMMSS` at scan time.

## Output Format

````
# CritFinds Audit Report

> This review was performed by CritFindsAudit v2 — an attacker-grade AI audit engine with 200 attack vectors, 6 parallel agents, and zero false-positive tolerance. AI analysis cannot guarantee the complete absence of vulnerabilities. Manual review, formal verification, and bug bounty programs are strongly recommended.

---

## Scope

|                                  |                                                        |
| -------------------------------- | ------------------------------------------------------ |
| **Mode**                         | DEFAULT / DEEP / QUICK / filename                      |
| **Framework**                    | Foundry / Hardhat / Brownie                            |
| **Compiler**                     | solc 0.8.x                                             |
| **Files reviewed**               | `File1.sol` · `File2.sol`<br>`File3.sol` · `File4.sol` | <!-- list every file, 3 per line -->
| **Total SLOC**                   | N                                                      |
| **Agents deployed**              | 4 vector-scan + adversarial + invariant (DEEP)         |
| **Attack vectors checked**       | 200                                                    |
| **Confidence threshold (1-100)** | 75                                                     |

---

## Findings Summary

| # | ID | Confidence | Severity | Title |
|---|---|---|---|---|
| 1 | CRITICAL-01 | [95] | CRITICAL | <title> |
| 2 | HIGH-01 | [82] | HIGH | <title> |
| | | | | **Below Confidence Threshold** |
| 3 | MEDIUM-01 | [60] | MEDIUM | <title> |

---

## Detailed Findings

---

### CRITICAL-01: <Title>

`ContractName.functionName` · `path/to/file.sol:L42-L58` · Confidence: 95

**Severity:** CRITICAL

**Description**
<The vulnerable code pattern and why it is exploitable, in 1-2 sentences>

**Attack Scenario**
1. Attacker calls `functionA()` with parameter X
2. During callback / in same tx, attacker calls `functionB()` which reads stale state
3. State variable `balance` still reflects pre-withdrawal amount
4. Result: attacker extracts N tokens, draining the vault

**Impact**
<Quantified damage — e.g., "Complete drainage of vault funds (up to $X TVL)">

**Root Cause**
```solidity
// path/to/file.sol:L42-L58
function withdraw(uint256 amount) external {
    (bool success, ) = msg.sender.call{value: amount}("");  // L47: external call before state update
    require(success);
    balances[msg.sender] -= amount;  // L49: state update after external call
}
```

**Recommendation**
```diff
function withdraw(uint256 amount) external {
+   balances[msg.sender] -= amount;
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success);
-   balances[msg.sender] -= amount;
}
```

---

### HIGH-01: <Title>
...

````

## Recon Summary Section

At the end of the report, add:

```
## Recon Summary

| Metric | Value |
|--------|-------|
| Framework | Foundry / Hardhat |
| Compiler | solc 0.8.x (locked/floating) |
| Dependencies | OZ 4.9.x / Solmate / Solady |
| Total SLOC | N |
| Danger scan hits | N hits across M files |
| Hotspot files | file1.sol (N hits), file2.sol (N hits) |
```

## POC Section (when --poc flag is set)

For each CRITICAL finding, append:

```
## Proof of Concept

### CRITICAL-01 PoC

\`\`\`solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
// ... imports ...

contract CritFinds_CRITICAL_01_Test is Test {
    // Setup and exploit code
}
\`\`\`
```

## Rules

- Follow the template above exactly.
- Sort findings: all CRITICALs first, then HIGHs, then MEDIUMs. Within same severity, sort by confidence (highest first).
- Finding IDs: `CRITICAL-01`, `CRITICAL-02`, `HIGH-01`, `HIGH-02`, `MEDIUM-01`, etc.
- Findings below the threshold get a description but no **Recommendation** block.
- Draft findings directly in report format — do not re-generate or paraphrase agent output.
- **Attack Scenario** must have numbered steps showing exact transaction sequence.
- **Root Cause** must include file path and line numbers.
- **Impact** must quantify damage where possible.

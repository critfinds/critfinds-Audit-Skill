# Attack Vectors Reference (2/4)

200 total attack vectors — Token Integration, Proxy & Upgradeability, MEV & Front-Running, DeFi Protocol-Specific

---

**51. Fee-on-Transfer Token Accounting Error**

- **D:** Protocol assumes `transferFrom(from, to, amount)` delivers exactly `amount`. Fee-on-transfer tokens deliver less. Internal accounting inflated.
- **FP:** `balanceOf` before/after transfer compared. Only verified non-fee tokens accepted. Delta-based accounting.

**52. Rebasing Token Balance Desync**

- **D:** Token balance changes without transfers (stETH, AMPL). Cached balances become stale. Protocol holds more/less than tracked.
- **FP:** Live `balanceOf` calls used for accounting. Wrapped versions (wstETH) used. Only non-rebasing tokens accepted.

**53. Non-Standard ERC-20 (Missing Return Value)**

- **D:** Bare `transfer()` or `transferFrom()` without `SafeERC20`. USDT returns void, code expects bool — reverts or silently fails.
- **FP:** `SafeERC20` / `safeTransfer` used. Only standard-compliant tokens accepted.

**54. Token Approval Race Condition**

- **D:** `approve()` from non-zero to non-zero allows front-running double-spend. Spender spends old allowance, then new allowance.
- **FP:** `safeApprove` (reset to 0 first). `increaseAllowance`/`decreaseAllowance` used.

**55. Tokens with Multiple Entry Points**

- **D:** Some tokens (legacy TUSD) have multiple contract addresses for same balance. Hardcoded address comparisons fail to detect same token.
- **FP:** Token identified by canonical address. No address-based dedup logic.

**56. Low-Decimal / High-Decimal Token Precision Issues**

- **D:** Tokens with 2 decimals (GUSD) or 24+ decimals cause precision issues. Hardcoded `1e18` assumptions break.
- **FP:** `decimals()` queried and used in all calculations. Min/max decimal range validated on token registration.

**57. Blocklist/Pause Token DoS (USDC/USDT)**

- **D:** USDC/USDT can block addresses or pause globally. Push-model transfer to blocked address reverts entire batch/function.
- **FP:** Pull-over-push pattern (recipients withdraw own funds). `try/catch` on transfers. Skip-on-failure in batch operations.

**58. Zero-Amount Transfer Revert**

- **D:** Some tokens (LEND, early BNB) revert on zero-amount transfers. Rounded fees or unclaimed yield can be zero.
- **FP:** `if (amount > 0)` guard before all transfers. Minimum amount enforced.

**59. ERC-20 `approve` to Upgradeable Contract**

- **D:** `approve(MAX_UINT)` to a contract that can later be upgraded to steal all approved tokens.
- **FP:** Approval only for exact needed amount. Approved contract is immutable or behind timelock.

**60. Permit2 Over-Approval Risk**

- **D:** Permit2 signature-based spending without explicit `approve` transaction. Over-approval to router enables silent draining.
- **FP:** Permit2 approval scoped to specific amount and deadline. No blanket approvals.

---

**61. Proxy Storage Collision**

- **D:** Proxy and implementation share storage layout. Adding/reordering variables in upgrades corrupts data. Missing `__gap` or ERC-7201 storage namespaces.
- **FP:** `__gap` arrays maintained. ERC-7201 namespaced storage used. Storage layout verified by upgrade tooling.

**62. Function Selector Clash in Proxy**

- **D:** Proxy admin functions collide with implementation selectors. Call intended for implementation routes to proxy's function.
- **FP:** Transparent proxy pattern (admin/user routing separates namespaces). UUPS with no custom proxy functions.

**63. Uninitialized Implementation Contract**

- **D:** Implementation's `initialize()` callable directly on implementation address. Attacker initializes, becomes owner, calls `selfdestruct` via delegatecall.
- **FP:** Constructor calls `_disableInitializers()`. Implementation has no `selfdestruct` path.

**64. UUPS Missing `_authorizeUpgrade` Access Control**

- **D:** `_authorizeUpgrade` not overridden with access control in UUPS proxy. Anyone can upgrade to malicious implementation.
- **FP:** `_authorizeUpgrade` overridden with `onlyOwner` or equivalent. OZ UUPSUpgradeable used with override.

**65. Transparent Proxy Admin Mismatch**

- **D:** Admin calling implementation functions gets routed to proxy's admin fallback. Silent failures on legitimate admin operations.
- **FP:** Admin uses ProxyAdmin contract (never calls implementation directly). Admin != end user.

**66. Arbitrary `delegatecall` Target**

- **D:** `delegatecall` to user-supplied or attacker-controllable address. Storage hijacking via malicious implementation. Ref: Furucombo (2021).
- **FP:** Target is immutable/hardcoded. Whitelist of approved targets enforced. `call` used instead.

**67. Metamorphic / CREATE2 + selfdestruct Redeploy**

- **D:** `CREATE2` + `selfdestruct` allows deploying different code at same address. Trusted contract replaced with malicious version.
- **FP:** No `selfdestruct` in CREATE2-deployed contracts. Address verified by code hash not just address.

**68. Beacon Proxy Single-Point-of-Failure**

- **D:** Multiple proxies read implementation from single Beacon. Compromising Beacon owner upgrades all proxies at once.
- **FP:** Beacon owner is multisig + timelock. `Upgraded` events monitored.

**69. Re-initialization Attack on Upgrade**

- **D:** V2 uses `initializer` instead of `reinitializer(2)`. Or upgrade resets initialized counter.
- **FP:** `reinitializer(version)` with correctly incrementing versions. Tests verify `initialize()` reverts after first call.

**70. Immutable Variable in Proxy Context**

- **D:** Implementation uses `immutable` variables (in bytecode). Proxy `delegatecall` gets implementation's hardcoded values regardless of per-proxy needs.
- **FP:** Immutable values intentionally identical across all proxies. Per-proxy config uses storage.

---

**71. Sandwich Attack (Missing Slippage Protection)**

- **D:** User swaps without slippage protection. `amountOutMin = 0` or `type(uint256).max` deadline. Bot front-runs to move price, user gets worse rate.
- **FP:** User-provided `amountOutMin` enforced. Reasonable deadline parameter.

**72. Slippage Hardcoded to Zero**

- **D:** Contract hardcodes `amountOutMin = 0` in swap calls. Full sandwich vulnerability.
- **FP:** Slippage parameter passed through from user. Off-chain computation of min output.

**73. Missing Deadline in Swap/Liquidity Operations**

- **D:** No `deadline` parameter on swap/LP operations. Transactions held by validators and executed at unfavorable time.
- **FP:** User-provided `deadline` enforced. `block.timestamp` NOT used as deadline (that's same as no deadline).

**74. Block Timestamp Used as Deadline**

- **D:** `deadline = block.timestamp` is effectively no deadline — always passes. Transaction can be held indefinitely.
- **FP:** `deadline` is user-provided future timestamp. `require(block.timestamp <= deadline)` with external value.

**75. Transaction Ordering Dependence**

- **D:** Outcome changes based on transaction order. Commit-reveal missing in auction/game. Bid visibility enables front-running.
- **FP:** Commit-reveal scheme implemented. Batch auction (all bids processed at same price).

**76. MEV Extraction via Back-Running**

- **D:** Large state changes (oracle update, liquidation threshold change) can be back-run for profit. Arbitrage opportunities created by protocol operations.
- **FP:** State changes are gradual (not sudden). MEV protection (Flashbots Protect, private mempool).

---

**77. Vault Share Inflation (First Depositor Attack)**

- **D:** Attacker deposits 1 wei, donates large amount directly, new depositors get 0 shares due to rounding. ERC4626 `convertToShares` returns 0.
- **FP:** Virtual shares/offset (OZ ERC4626 `_decimalsOffset`). Minimum initial deposit enforced. Dead shares on first deposit.

**78. Vault Exchange Rate Manipulation**

- **D:** Direct token transfer to vault inflates `totalAssets()` without minting shares. Manipulation of share price.
- **FP:** Internal accounting independent of `balanceOf`. `totalAssets` uses tracked deposits, not balance.

**79. Liquidation Dust Positions (Bad Debt)**

- **D:** Positions below certain USD value cost more gas to liquidate than reward. Dust positions accumulate bad debt.
- **FP:** Minimum position size enforced at borrow time. Protocol-operated liquidation bot. Socialized bad debt mechanism.

**80. Self-Liquidation for Profit**

- **D:** User can liquidate their own position to extract liquidation bonus. Deposit, borrow max, self-liquidate for profit.
- **FP:** Self-liquidation disallowed (`require(liquidator != borrower)`). Liquidation bonus < protocol fee.

**81. Interest Rate Model Manipulation**

- **D:** Utilization-based rates manipulated via flash borrow — spike utilization to force liquidations of other borrowers.
- **FP:** Interest rate smoothing (time-weighted). Flash loan can't change utilization (borrow + repay in same tx).

**82. Yield Compounding Timing Manipulation**

- **D:** `harvest()` or `compound()` timing manipulated to steal yield. Deposit right before harvest, claim disproportionate yield.
- **FP:** Yield accrues continuously (per-second). Harvested yield distributed over time period. Minimum lock before yield claim.

**83. Incorrect Share Accounting on Fee Collection**

- **D:** Management/performance fees minted as shares dilute existing holders incorrectly. Fee shares inflated or deflated.
- **FP:** Fee shares computed against total supply pre-fee. Well-tested fee math matching specification.

**84. AMM Constant Product Formula Error**

- **D:** `k = x * y` not preserved after swap. Fee calculation breaks invariant. `getAmountOut` returns more than available.
- **FP:** `k` verified after every swap. Fee subtracted from input before output calculation.

**85. LP Token Pricing Vulnerability**

- **D:** Naive `totalValue / totalSupply` pricing of LP tokens is flash-loan manipulable. Ref: Warp Finance exploit.
- **FP:** Fair LP pricing (alpha-homogeneity). Reserve-weighted geometric mean pricing.

**86. ERC4626 Missing Allowance Check in withdraw/redeem**

- **D:** `withdraw(assets, receiver, owner)` where `msg.sender != owner` but no allowance check. Any address can burn others' shares.
- **FP:** `_spendAllowance(owner, caller, shares)` called when `caller != owner`. OZ ERC4626 unmodified.

**87. Vault Deposit/Withdraw in Same Block**

- **D:** No deposit delay allows flash loan exploitation of vault mechanics — deposit, manipulate yield source, withdraw in same block.
- **FP:** Minimum deposit-to-withdraw delay enforced. Share lock period after deposit.

**88. Reward Rate Manipulation (JIT Staking)**

- **D:** Depositing right before reward distribution, withdrawing right after. Captures disproportionate rewards.
- **FP:** Reward accrual is per-second over duration. Minimum staking period. Warm-up period for new deposits.

**89. Stuck Rewards (Missing notifyRewardAmount)**

- **D:** Reward tokens sent directly without calling `notifyRewardAmount` — tokens locked forever, never distributed.
- **FP:** Sweep function for excess tokens. Notification required for reward activation.

**90. Division by Zero on Empty Staking Pool**

- **D:** `rewardPerToken()` divides by `totalSupply`. If pool is empty, reverts. Blocks all subsequent operations.
- **FP:** `if (totalSupply == 0) return rewardPerTokenStored` guard. Default return on empty pool.

**91. Multi-Token Reward Accounting Mismatch**

- **D:** Mismatch between reward token arrays and per-token accounting state. Adding/removing reward tokens corrupts distribution.
- **FP:** Reward tokens immutable after initialization. Accounting verified in tests across all reward tokens.

**92. Depeg of Pegged Asset Breaking Protocol Assumptions**

- **D:** Protocol assumes 1:1 peg (stETH:ETH, WBTC:BTC, USDC:USD) in pricing. No depeg tolerance. During depeg, collateral overvalued.
- **FP:** Independent price feed per asset. Depeg threshold triggering protective measures. Risk acknowledged and documented.

**93. Invariant Enforced on One Path But Not Another**

- **D:** Constraint (pool cap, max supply, collateral ratio) enforced during `deposit()` but not during settlement, reward distribution, or emergency paths.
- **FP:** Invariant check in shared modifier called by all paths. Post-condition assertion after every state change.

**94. Solmate SafeTransferLib Missing Contract Existence Check**

- **D:** Solmate's `SafeTransferLib` doesn't verify target address contains code. Transfer to EOA or not-yet-deployed CREATE2 address returns success silently.
- **FP:** OZ `SafeERC20` used. Manual `require(token.code.length > 0)` check. Token addresses verified at construction.

**95. Batch Distribution Dust Residual**

- **D:** Loop distributes funds proportionally. Cumulative rounding causes `sum(shares) < total`, leaving dust locked.
- **FP:** Last recipient gets `total - sumOfPrevious`. Dust swept to treasury. Accumulator tracking.

**96. Liquidation Ordering Causes Bad Debt**

- **D:** Multiple undercollateralized positions. Liquidation order matters — liquidating one position can make another insolvent.
- **FP:** Positions liquidated independently. Insurance fund covers shortfall. Bad debt socialized.

**97. Interest Accrual Overflow**

- **D:** Compound interest calculation overflows with large principal, high rate, or long duration. Reverts permanently brick lending pool.
- **FP:** Rate and duration bounded. `mulDiv` used for intermediate calculations. Overflow-safe math.

**98. Yield Source Manipulation**

- **D:** Vault's yield source can be manipulated by attacker. Donate to yield source before harvest to inflate share price temporarily.
- **FP:** Yield source verified and trusted. Yield smoothed over time period. Internal accounting.

**99. Staking Lock Bypass**

- **D:** Token lock period bypassed via transfer to new account and re-stake, or via liquid staking derivative.
- **FP:** Transfer disabled during lock. Non-transferable staking receipt. Lock verified at withdrawal, not just deposit.

**100. Share Calculation Rounds to Zero on Small Deposits**

- **D:** `shares = deposit * totalShares / totalAssets` rounds to zero for small deposits. Depositor gets 0 shares, tokens stuck in vault.
- **FP:** Minimum deposit amount enforced. Virtual shares offset prevents zero-share deposits.

# Attack Vectors Reference (1/4)

230 total attack vectors — Reentrancy, Access Control, Arithmetic, Oracle & Price, Flash Loans, Callbacks & External Calls

---

**1. Classic Reentrancy (CEI Violation)**

- **D:** State update occurs **after** external `call`, `transfer`, or `send`. Pattern: `call{value:}` or `token.transfer()` followed by state write (balance decrement, status update).
- **FP:** Checks-Effects-Interactions pattern followed. `nonReentrant` modifier applied. State updated before external call.

**2. Cross-Function Reentrancy**

- **D:** Attacker re-enters a **different function** that reads stale state. Pattern: `withdraw()` calls out before updating balance; attacker re-enters `transfer()` which reads old balance.
- **FP:** All functions sharing state are protected by same `nonReentrant` lock. State committed before any external call across all functions.

**3. Cross-Contract Reentrancy**

- **D:** Contract A calls Contract B, which calls back into Contract A (or Contract C that reads A's stale state). Common in vault/strategy, lending, and callback-based designs.
- **FP:** Cross-contract reentrancy lock (shared lock across contracts). All state finalized before cross-contract calls.

**4. Read-Only Reentrancy**

- **D:** Attacker re-enters a `view` function on another contract that reads manipulated state mid-execution. Common in protocols exposing `getPrice()`, `totalAssets()`, `balanceOf()` used by external integrators. Ref: Curve/Vyper reentrancy (2023).
- **FP:** View functions do not read state from contracts that can be mid-execution. Reentrancy guard also protects view functions. Integrators use TWAP or cached values.

**5. ERC-721/ERC-1155 Callback Reentrancy**

- **D:** `onERC721Received` and `onERC1155Received` callbacks allow re-entry. Pattern: `_safeMint`, `_safeTransfer`, `safeTransferFrom` called before state update.
- **FP:** State committed before safe transfer. `nonReentrant` applied. Regular `_mint`/`_transfer` used (no callback).

**6. ERC-777 Transfer Hook Reentrancy**

- **D:** `tokensToSend` and `tokensReceived` hooks on ERC-777 enable reentrancy on every `transfer`/`transferFrom`.
- **FP:** Protocol only accepts known non-ERC-777 tokens. `nonReentrant` on all token-handling functions. Token whitelist enforced.

---

**7. Missing Access Control on Critical Function**

- **D:** State-changing function (`setOwner`, `withdrawFunds`, `mint`, `burn`, `pause`, `setOracle`, `upgradeTo`) has no access guard. `public`/`external` with no modifier.
- **FP:** Function is intentionally permissionless with non-critical worst-case outcome.

**8. Unprotected `initialize()` in Upgradeable Contract**

- **D:** Upgradeable contract with `initializer` modifier that can be front-run on deployment. Implementation contract's `initialize()` callable directly.
- **FP:** Constructor calls `_disableInitializers()`. Deployment script atomically deploys + initializes. `reinitializer(version)` used for V2+.

**9. `tx.origin` Authentication**

- **D:** Using `tx.origin` instead of `msg.sender` for access control. Phishing attack via malicious intermediary contract.
- **FP:** `tx.origin == msg.sender` used only as EOA check (not authorization). No `tx.origin` in auth logic.

**10. Default Visibility (Solidity < 0.5)**

- **D:** Functions without explicit visibility default to `public`. Internal functions accidentally exposed.
- **FP:** Solidity >= 0.5 (compiler requires explicit visibility). All functions have explicit visibility.

**11. Centralization Risk — Single Admin**

- **D:** Single owner/admin EOA can drain funds, pause indefinitely, change oracle, modify critical parameters. No timelock, no multisig.
- **FP:** Admin is multisig + timelock. Governance controls critical functions. Admin powers limited and well-documented.

**12. Missing Two-Step Ownership Transfer**

- **D:** `transferOwnership()` immediately changes owner. Typo in address permanently bricks access.
- **FP:** `Ownable2Step` or equivalent pending-accept pattern used.

**13. Unprotected `selfdestruct` in Implementation**

- **D:** Implementation contract contains `selfdestruct` callable by attacker. Proxy becomes permanently bricked.
- **FP:** `selfdestruct` removed or behind admin-only access. Constructor disables initializers.

**14. `renounceOwnership()` Available**

- **D:** `renounceOwnership()` can permanently remove admin access. If called accidentally or maliciously, admin-only functions become permanently unreachable.
- **FP:** `renounceOwnership` overridden to revert. Protocol designed to function without owner.

---

**15. Unchecked Overflow/Underflow in `unchecked` Block**

- **D:** Solidity 0.8+ reverts on overflow, but `unchecked {}` blocks bypass this. Arithmetic inside `unchecked` can silently wrap.
- **FP:** Values inside unchecked are provably bounded (loop counters, known-small values). Intentional wrapping (e.g., hash computation).

**16. Precision Loss — Division Before Multiplication**

- **D:** `(a / b) * c` — truncation before multiplication amplifies error. Pattern: `fee = (amount / 10000) * bps`.
- **FP:** `a` provably divisible by `b`. Correct order: `(a * c) / b`. `mulDiv` used.

**17. Rounding Direction Exploit**

- **D:** Protocol rounds in favor of the user (against the protocol) on deposits/withdrawals. Dust-amount extraction at scale via repeated deposit/withdraw cycles.
- **FP:** `mulDivUp` used for protocol-favorable rounding. Minimum deposit enforced. Rounding explicitly favors protocol.

**18. Phantom Overflow in Intermediate Calculations**

- **D:** `a * b` may overflow even if final result `a * b / c` fits in uint256. Pattern: large multiplications without `mulDiv` or `FullMath`.
- **FP:** `mulDiv` or `FullMath.mulDiv` used. Operands bounded to prevent intermediate overflow.

**19. Unsafe Downcasting**

- **D:** Downcasting `uint256` to `uint128`, `uint96`, `uint64` without range checks. Silent truncation.
- **FP:** `SafeCast` library used. `require(value <= type(uint128).max)` before cast. Value provably bounded.

**20. Small-Type Arithmetic Overflow Before Upcast**

- **D:** Arithmetic on `uint8`/`uint16`/`uint32` before assigning to wider type: `uint256 result = a * b` where `a`,`b` are `uint8`. Overflow in narrow type before widening.
- **FP:** Operands explicitly upcast before operation: `uint256(a) * uint256(b)`.

---

**21. Spot Price Manipulation via Flash Loan**

- **D:** Using `getReserves()`, `balanceOf()`, or Uniswap V3 `slot0` for pricing. Trivially manipulated via flash loans.
- **FP:** TWAP oracle used (>= 30 min window). Chainlink or other manipulation-resistant oracle. Price bounded by sanity checks.

**22. Stale Chainlink Oracle Data**

- **D:** `latestRoundData()` return values not validated. Missing checks: `updatedAt` staleness, `price > 0`, `answeredInRound >= roundId`.
- **FP:** All return values validated. Staleness threshold enforced. Fallback oracle on stale data.

**23. Oracle Decimal Mismatch**

- **D:** Chainlink feeds return different decimals (8 for USD, 18 for ETH pairs). Hardcoded `1e8` or `1e18` without checking `decimals()`.
- **FP:** `decimals()` called and used for normalization. All feeds verified to use same decimal base.

**24. TWAP Manipulation (Short Window)**

- **D:** TWAP window < 30 minutes can be manipulated across multiple blocks. Uniswap V3 `observe()` with insufficient `secondsAgo`.
- **FP:** TWAP window >= 30 minutes. Multiple oracle sources cross-validated.

**25. L2 Sequencer Downtime**

- **D:** On L2s (Arbitrum, Optimism), Chainlink sequencer uptime feed not checked. Oracle prices stale but appear fresh after sequencer recovers.
- **FP:** `sequencerUptimeFeed` checked. Grace period enforced after sequencer restart.

**26. Chainlink `latestRoundData` Partial Return Consumption**

- **D:** Only `price` consumed from `latestRoundData()`, ignoring `updatedAt`, `roundId`, `answeredInRound`. Stale or invalid price silently used.
- **FP:** All five return values destructured and validated.

**27. Hardcoded Oracle Address**

- **D:** Oracle address hardcoded. If oracle migrates or is deprecated, protocol permanently uses stale feed.
- **FP:** Oracle address updatable via governance. Fallback mechanism on oracle failure.

---

**28. Governance Flash Loan Attack**

- **D:** Borrowing governance tokens to pass proposals in a single block. No snapshot mechanism or snapshot at proposal time.
- **FP:** `getPastVotes(block.number - 1)` or equivalent past-block snapshot. Minimum proposal threshold with holding period.

**29. Price/Reserve Manipulation via Flash Loans**

- **D:** Any calculation relying on current pool state (`balanceOf`, reserves, `totalSupply` during mint) is manipulable. Pattern: `balanceOf(address(this))` used in accounting.
- **FP:** Internal accounting independent of `balanceOf`. Oracle-based pricing. Flash loan guard (`require(balance >= lastBalance)`).

**30. Flash Loan Callback Exploit**

- **D:** Unrestricted or improperly validated flash loan callbacks. `onFlashLoan` callable without real flash loan. Missing `msg.sender == lendingPool` or `initiator` check.
- **FP:** Both `msg.sender == address(lendingPool)` and `initiator == address(this)` validated.

**31. Same-Block Deposit-Withdraw Exploiting Snapshot Benefits**

- **D:** Protocol calculates yield, rewards, or voting power based on balance at a single snapshot point. No minimum lock period. Attacker flash-loans, deposits, triggers snapshot, claims benefit, withdraws — all in one tx.
- **FP:** `getPastVotes(block.number - 1)`. Minimum holding period enforced. Reward accrual requires multi-block time passage.

---

**32. Token Decimal Mismatch in Cross-Token Arithmetic**

- **D:** Cross-token math uses hardcoded `1e18` or assumes identical decimals. Pattern: collateral/LTV/rate calculations without per-token `decimals()` normalization.
- **FP:** Amounts normalized using each token's `decimals()`. Protocol only supports verified same-decimal tokens.

**33. `abi.encodePacked` Hash Collision**

- **D:** `abi.encodePacked` with two or more `string` or `bytes` arguments causes hash collisions. `abi.encodePacked("ab", "c") == abi.encodePacked("a", "bc")`.
- **FP:** `abi.encode` used instead. Only fixed-size types in `encodePacked`. Separator between dynamic types.

**34. Floating Pragma**

- **D:** `pragma solidity ^0.8.0` allows compilation with any 0.8.x. Known compiler bugs in specific versions (e.g., ABI encoder v2 bugs in 0.8.13-0.8.15).
- **FP:** Locked pragma `pragma solidity 0.8.20`. Version verified against known bug list.

**35. `immutable` Variables in Upgradeable Contracts**

- **D:** `immutable` values stored in bytecode, not storage. Proxy `delegatecall` reads implementation's bytecode values, which can't change on upgrade.
- **FP:** Immutable values intentionally identical across all versions. Storage variables used for per-proxy config.

**36. `delete` on Struct Containing Mapping**

- **D:** `delete myStruct` does not clear nested mappings inside the struct. Stale mapping data persists.
- **FP:** Mappings cleared manually before struct delete. No nested mappings in deleted structs.

**37. Enum Out-of-Range (Solidity < 0.8.0)**

- **D:** ABI decoding invalid enum value doesn't revert in older compilers. Undefined enum state.
- **FP:** Solidity >= 0.8.0 (reverts on invalid enum). Input validation before enum cast.

---

**38. Signature Malleability**

- **D:** Raw `ecrecover` without `s <= 0x7FFF...20A0` validation. Both `(v,r,s)` and `(v',r,s')` recover same address. Bypasses signature-based dedup.
- **FP:** OZ `ECDSA.recover()` used (validates `s` range). Message hash used as dedup key, not signature bytes.

**39. Signature Replay (Missing Nonce/ChainId)**

- **D:** Missing `nonce`, `chainId`, or `address(this)` in signed message. Signature valid on multiple chains or reusable after state changes.
- **FP:** EIP-712 domain separator includes `chainId` and `address(this)`. Nonce incremented per use.

**40. `ecrecover` Returns `address(0)` on Invalid Signature**

- **D:** `ecrecover` returns `address(0)` for invalid signatures. Missing `require(recovered != address(0))`. If `authorizedSigner` is uninitialized, garbage signature gains privileges.
- **FP:** OZ `ECDSA.recover()` used (reverts on address(0)). Explicit zero-address check.

**41. EIP-712 Domain Separator Caching**

- **D:** `DOMAIN_SEPARATOR` cached at deploy time. Breaks on chain forks — signatures valid on both chains.
- **FP:** `DOMAIN_SEPARATOR` recomputed dynamically (checks `block.chainid` vs cached). OZ EIP712 used.

**42. Permit / EIP-2612 Front-Run Griefing**

- **D:** `permit()` can be front-run. If contract's flow reverts on failed permit (already used nonce), attacker can grief every permit-based operation.
- **FP:** `try/catch` around permit calls. Fallback to standard `approve` flow.

**43. Commit-Reveal Not Bound to `msg.sender`**

- **D:** Commitment hash doesn't include `msg.sender`. Attacker copies victim's commitment from mempool and submits own reveal.
- **FP:** `keccak256(abi.encodePacked(msg.sender, value, salt))`. Reveal validates committer.

---

**44. msg.value Reuse in Loop / Multicall**

- **D:** `msg.value` read inside a loop or `delegatecall`-based multicall. Each iteration sees full original value — credits `n * msg.value`.
- **FP:** `msg.value` captured to local variable, decremented per iteration. Function non-payable. Multicall uses `call` not `delegatecall`.

**45. Multicall Delegatecall Context Preservation**

- **D:** `multicall` using `delegatecall` preserves `msg.sender` and `msg.value` — can bypass access controls or double-spend.
- **FP:** Multicall uses `call` (own context). Access controls not msg.sender-dependent in delegatecall context.

**46. `selfdestruct` Forced ETH**

- **D:** `selfdestruct(target)` forces ETH into a contract, bypassing `receive()` / `fallback()`. Breaks invariants relying on `address(this).balance == tracked_balance`.
- **FP:** Internal accounting used instead of `address(this).balance`. Protocol tolerates unexpected ETH.

**47. Empty Code Check Bypass via Constructor**

- **D:** `extcodesize` returns 0 during constructor execution. Attacker bypasses "no contract" checks by calling from constructor.
- **FP:** Check is non-security-critical. Protected by merkle proof or signed permit unsatisfiable from constructor.

**48. Dirty High Bits in Assembly**

- **D:** `calldataload` returns 32 bytes. Used for address (20 bytes), upper 12 bytes may be dirty. Address comparisons fail.
- **FP:** `and(calldataload(offset), 0xffffffffffffffffffffffffffffffffffffffff)` masks to 20 bytes.

**49. Transient Storage Persistence Across Internal Calls**

- **D:** EIP-1153 `tstore`/`tload` — transient storage resets per transaction, not per call. Unexpected persistence across internal calls within same transaction.
- **FP:** Transient storage explicitly cleared after use. Usage confined to single function scope.

**50. Return Bomb (Returndata Copy DoS)**

- **D:** `(bool success, bytes memory data) = target.call(payload)` where `target` is user-supplied. Malicious target returns huge returndata; copying costs enormous gas.
- **FP:** Returndata not copied (assembly call without copy). Gas-limited call. Target is hardcoded trusted contract.

---

**211. Callback Trust Without Sender Validation**

- **D:** Contract receives callbacks (swap callbacks, flash loan callbacks, hook calls, `onFlashLoan`, `uniswapV3SwapCallback`, `pancakeV3SwapCallback`) without validating the callback originates from the expected source. Attacker calls the callback function directly with fabricated data to credit themselves tokens, mint shares, or manipulate state. Pattern: `uniswapV3SwapCallback(int256, int256, bytes)` is `external` but doesn't check `msg.sender == expectedPool`.
- **FP:** `require(msg.sender == expectedPool/lender)` validated. Callback is `internal`/`private`. Callback validates a secret nonce or hash that only the real caller knows.

**212. Return Value Reliance Without Verification**

- **D:** Function trusts return values from external calls to untrusted/user-supplied contracts without independent verification. Pattern: DEX `swap()` returns `amountOut`, caller credits user `amountOut` tokens without checking actual balance change. Malicious pool returns inflated `amountOut`. Also: `decimals()` on untrusted token returns 0 or 77, breaking all math.
- **FP:** Balance-before/after check used instead of return value. Return value cross-validated against independent source. External contract is trusted/immutable. Return value not used for fund-critical decisions.

**213. Sweep/Rescue Function Draining User Funds**

- **D:** Admin `sweep(token)` or `rescueTokens(token, amount)` function intended for stuck/airdropped tokens can drain tokens that users have actively deposited. Function sends `balanceOf(address(this))` or arbitrary `amount` to admin without subtracting user-tracked balances. Pattern: `sweep(USDC)` drains all USDC including active user deposits because it uses raw `balanceOf`.
- **FP:** Sweep excludes staking/deposit token: `require(token != stakingToken)`. Amount limited to `balanceOf - totalDeposited`. Sweep token whitelist maintained. No sweep function exists.

**214. Emergency Pause Permanent Fund Lockup**

- **D:** Emergency pause blocks withdrawals indefinitely with no escape hatch, no time-limited pause duration, and no alternative withdrawal path. If admin key is lost, compromised, or admin maliciously pauses, user funds are permanently locked. Pattern: `whenNotPaused` modifier on all withdrawal functions, no `emergencyWithdraw()`, no auto-unpause timer.
- **FP:** Time-limited pause (auto-expires after N blocks). Emergency withdraw bypasses pause. Pause controlled by multisig + timelock. Alternative withdrawal path exists.

**215. Unchecked External Call Success With Side Effects**

- **D:** External call failure is silently ignored but subsequent code assumes it succeeded. Internal accounting already debited/credited the amount. Pattern: `(bool success, ) = token.call(abi.encodeWithSelector(IERC20.transfer.selector, to, amount));` without checking `success` — tokens not sent but balance mapping already decremented. Also: low-level call to a contract that doesn't exist returns `success=true` with no code execution (Solmate SafeTransferLib issue).
- **FP:** `require(success)` or `SafeERC20.safeTransfer` used. Return value checked. Contract existence verified via `code.length > 0`. Balance-before/after verification.


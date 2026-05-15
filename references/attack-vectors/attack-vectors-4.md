# Attack Vectors Reference (4/4)

230 total attack vectors — Compiler, Low-Level Assembly, Permit/Approval, Staking/Lending Advanced, Economic Attacks, Input Validation & Trust Boundaries

---

**151. Compiler Bug Exploitation (Version-Specific)**

- **D:** Solidity version in known-buggy range. ABI encoder v2 bugs (0.8.13-0.8.15), optimizer bugs, Yul IR codegen issues.
- **FP:** Compiler version verified against known bug list. No affected patterns used.

**152. `abi.decode` with Enum Out-of-Range**

- **D:** ABI decoding invalid enum value from external data. Pre-0.8.0: doesn't revert, produces invalid state. Post-0.8.0: reverts (DoS potential).
- **FP:** Solidity >= 0.8.0. Enum values validated after decode. Trusted data source.

**153. Via-IR Codegen Differences**

- **D:** Via-IR pipeline generates different code than legacy pipeline. Edge cases in memory layout, stack usage, optimizer behavior.
- **FP:** Tested with both pipelines. Via-IR not enabled. Known differences documented and avoided.

**154. Optimizer-Dependent Behavior**

- **D:** Contract behavior changes at different optimizer `runs` settings. Dead code elimination removes safety checks. Constant folding produces different results.
- **FP:** Tested at production optimizer settings. Safety checks not in optimizable patterns.

**155. Constructor vs Initializer Race**

- **D:** Time gap between proxy deployment and `initialize()` call. Attacker front-runs initialization.
- **FP:** Atomic deployment + initialization (factory pattern). `_disableInitializers()` in constructor.

---

**156. Unchecked Return Value on Low-Level `call`**

- **D:** `address.call{value:}("")` returns `(bool success, bytes data)`. Ignoring `success` silently loses ETH.
- **FP:** `require(success)` after call. `Address.sendValue` used. Return value checked.

**157. Incorrect `returndatasize` in Assembly**

- **D:** `returndatasize() == 0` check for non-standard ERC-20 support. Must also verify `success` from call.
- **FP:** Both `success` and return data validated. SafeERC20 used.

**158. Memory Corruption — Free Memory Pointer Not Updated**

- **D:** Assembly writes to memory without updating free memory pointer (`mstore(0x40, newPtr)`). Solidity-allocated memory overwrites assembly data.
- **FP:** Free memory pointer properly managed. Assembly block is self-contained.

**159. `sstore` in View/Pure Function via Assembly**

- **D:** `assembly { sstore(slot, val) }` in a `view` or `pure` function. Compiler doesn't prevent this. State modified in supposedly read-only function.
- **FP:** No `sstore` in view/pure functions. Assembly blocks audited for state changes.

**160. Unchecked `staticcall` Return**

- **D:** `staticcall` to external contract without checking return value. Silently returns stale/zero data on failure.
- **FP:** Return value and success checked. Known trusted target. Fallback on failure.

**161. Assembly `div` by Zero Returns Zero (No Revert)**

- **D:** EVM `div(a, 0)` returns 0 instead of reverting. Assembly division without zero-check produces silent wrong results.
- **FP:** Denominator validated non-zero before division. Solidity division used (auto-reverts on zero).

**162. `signextend` Misuse in Assembly**

- **D:** `signextend(b, x)` sign-extends `x` from `(b+1)*8` bits. Wrong `b` value corrupts the value. Common when converting between signed types in assembly.
- **FP:** `signextend` parameters verified. Solidity-level signed arithmetic used instead.

**163. `byte(n, x)` Extraction Error**

- **D:** `byte(n, x)` extracts the n-th byte from the left (big-endian). Common mistake: using it as little-endian byte extraction.
- **FP:** Byte order verified. Shift-and-mask used instead for clarity.

**164. Missing `iszero` Check After `call` in Assembly**

- **D:** Assembly `call(gas, to, val, in, insize, out, outsize)` returns 0 on failure. Missing `iszero` check after call.
- **FP:** `if iszero(call(...)) { revert(...) }` pattern used. Success checked.

**165. Misaligned Memory Access**

- **D:** EVM operates on 32-byte words. Misaligned `mload`/`mstore` reads/writes partial words, crossing word boundaries unexpectedly.
- **FP:** All memory access word-aligned. Offset calculations verified.

---

**166. Infinite Approve to Router/Aggregator**

- **D:** `approve(router, type(uint256).max)` to DEX router or aggregator. If router is compromised or has vulnerability, all approved tokens drainable.
- **FP:** Approval for exact amount needed per transaction. Router is battle-tested (Uniswap canonical).

**167. Permit Replay on Chain Fork**

- **D:** EIP-2612 permit signatures valid on both chains after fork if domain separator uses cached `chainId`.
- **FP:** Dynamic domain separator recomputation. Nonce tracked per-chain.

**168. Permit Front-Run Leading to Stuck Transaction**

- **D:** User submits tx relying on permit. Attacker front-runs the permit call. User's tx reverts because permit already consumed.
- **FP:** try/catch around permit. Check allowance before permit (skip if already approved).

**169. `increaseAllowance` / `decreaseAllowance` Not Standard**

- **D:** `increaseAllowance` and `decreaseAllowance` not part of ERC-20 standard. Some tokens don't implement them. Code assumes availability.
- **FP:** `approve` used with reset-to-zero pattern. Only known-compatible tokens used.

**170. Approval to Proxy/Upgradeable Contract**

- **D:** Approval given to upgradeable contract. Future upgrade can add token-draining functionality.
- **FP:** Approval to immutable contract. Timelock on upgrades provides reaction window.

---

**171. Interest-Free Flash Loan via Protocol Mechanics**

- **D:** Protocol's own deposit/withdraw or mint/burn can be used as free flash loan. Borrow via deposit, manipulate, return via withdraw in same tx.
- **FP:** Same-block deposit-withdraw prevented. Internal accounting immune to manipulation. Fee on same-block operations.

**172. Oracle Manipulation via Thin Liquidity Pool**

- **D:** Oracle price sourced from pool with low liquidity. Small trade moves price significantly. Attacker manipulates price cheaply.
- **FP:** Minimum liquidity threshold for oracle source. TWAP with sufficient depth. Multiple oracle sources.

**173. Liquidation Cascade / Death Spiral**

- **D:** Liquidating positions dumps collateral, crashing price, triggering more liquidations. Cascading failure drains protocol.
- **FP:** Circuit breakers on price drops. Gradual liquidation. Insurance fund absorbs initial losses.

**174. Borrow-Swap-Liquidate in Same Block**

- **D:** Attacker borrows, swaps collateral to crash its price, liquidates other users' positions, profits from liquidation bonus.
- **FP:** Oracle price independent of AMM (Chainlink). Anti-manipulation delay. Same-block liquidation prevention.

**175. Governance Token Distribution Attack**

- **D:** Governance tokens distributed proportional to deposit. Flash loan to deposit, claim disproportionate governance tokens, dump.
- **FP:** Distribution based on time-weighted average balance. Minimum holding period for eligibility.

**176. Price Manipulation via Donation**

- **D:** Attacker donates tokens to vault/pool to manipulate share price, exchange rate, or reward calculations. Related to first depositor attack.
- **FP:** Internal accounting independent of actual balance. Donation has no effect on accounting.

**177. Sandwich on Oracle Update**

- **D:** Oracle update transaction visible in mempool. Attacker front-runs with trade before update, back-runs after update.
- **FP:** Oracle updates via private mempool. Price change bounded per update. Cooldown between user actions around oracle updates.

**178. JIT Liquidity Attack**

- **D:** Attacker sees large swap in mempool. Provides concentrated liquidity at the exact tick, earns fees, removes liquidity — all in same block.
- **FP:** Minimum liquidity provision duration. Fee tier discourages JIT. Not relevant for non-AMM protocols.

**179. Toxic Liquidation Flow**

- **D:** Liquidation function requires paying debt in token that liquidator must acquire. Acquiring the token moves price unfavorably for the liquidation.
- **FP:** Multiple repayment token options. Protocol-facilitated liquidation with internal swaps.

**180. Share Inflation via Zero-Value First Deposit**

- **D:** First depositor deposits 0 or 1 wei, then donates large amount. Share price becomes enormous. Subsequent depositors get 0 shares.
- **FP:** Minimum first deposit. Virtual shares/offset. Dead shares pattern.

---

**181. Callback to Untrusted Contract**

- **D:** Contract makes callback to user-supplied address without reentrancy protection. Callback address can execute arbitrary logic.
- **FP:** `nonReentrant` modifier. Callback target validated. No state reads after callback.

**182. Incorrect Function Selector in Low-Level Call**

- **D:** Manual selector computation `bytes4(keccak256("functionName(uint256)"))` with typo or wrong parameter types. Silent wrong function call or fallback.
- **FP:** Interface-based calls. Selector constants verified against interface. Compiler-generated selectors.

**183. Storage vs Memory Confusion**

- **D:** `MyStruct storage s = structs[id]` vs `MyStruct memory s = structs[id]`. Memory copy doesn't update storage. Storage reference modifies state unexpectedly.
- **FP:** Storage/memory keywords explicitly chosen. Modifications go through intended path.

**184. Array `pop()` on Empty Array**

- **D:** `array.pop()` on empty array reverts (underflow on length). DoS if array can reach zero length.
- **FP:** Length check before pop. Array guaranteed non-empty by invariant.

**185. Uninitialized Storage Pointer (Solidity < 0.5)**

- **D:** Local `storage` variable without explicit assignment points to slot 0. Reads/writes corrupt slot 0 (often owner).
- **FP:** Solidity >= 0.5 (compiler error on uninitialized storage pointers).

**186. Off-by-One in Array Bounds**

- **D:** `for (uint i = 0; i <= array.length; i++)` — `<=` instead of `<`. Reads out-of-bounds element.
- **FP:** Standard `i < array.length` pattern. Compiler bounds checking in 0.8+.

**187. Unchecked Array Index**

- **D:** `array[userInput]` without bounds check. Pre-0.8: reads/writes arbitrary storage slot. Post-0.8: reverts (DoS).
- **FP:** `require(index < array.length)`. Mapping used instead of array for user-keyed data.

**188. Event Emission After State Change (Misleading Logs)**

- **D:** Event emitted with pre-update values instead of post-update. Off-chain systems track wrong state.
- **FP:** Event emitted after state update with correct values. Not security-critical.

**189. Incorrect Inheritance — Wrong Function Called**

- **D:** Multiple inheritance with same function name. C3 linearization calls unexpected parent's implementation.
- **FP:** `super.functionName()` used correctly. No ambiguous function names across parents.

**190. Ether Locked in Contract Without Withdrawal**

- **D:** Contract accepts ETH (payable functions, `receive()`) but has no withdrawal mechanism. ETH permanently locked.
- **FP:** `withdraw()` function exists. No payable functions (contract doesn't accept ETH). Sweep function for emergency.

---

**191. Cross-Contract View Function Dependency**

- **D:** Contract A's critical logic depends on Contract B's `view` function. If B is upgradeable, B's upgrade can make A return wrong values silently.
- **FP:** B is immutable. A validates B's return values. A has fallback oracle.

**192. Reentrancy via `create` / `create2`**

- **D:** Creating a contract via `create`/`create2` executes the constructor, which can call back into the creator. State stale during constructor execution.
- **FP:** State committed before create. No callbacks expected from created contract's constructor. Reentrancy guard.

**193. Signature Bundle — Multiple Operations in One Signature**

- **D:** Single signature authorizes multiple operations. Partial execution leaves inconsistent state. Signature valid for subset of operations.
- **FP:** Atomic execution of all operations. Nonce invalidates entire bundle. Each operation independently signed.

**194. `receive()` / `fallback()` Gas Limit with `transfer()`**

- **D:** `transfer()` and `send()` forward only 2300 gas. Complex `receive()` logic exceeds this limit, permanently blocking ETH receipt.
- **FP:** `call{value:}("")` used instead of `transfer`/`send`. `receive()` logic minimal.

**195. Unprotected Callback in Flash Mint/Loan**

- **D:** Flash mint/loan callback doesn't verify initiator. Attacker triggers unexpected callback execution path.
- **FP:** `require(msg.sender == flashLender)`. `require(initiator == address(this))`.

**196. Missing Reentrancy Guard on ETH Refund**

- **D:** Function refunds excess ETH to `msg.sender` via `call{value:}`. No reentrancy protection on the refund path.
- **FP:** `nonReentrant` on function. Refund is last operation (CEI pattern). Fixed refund amount.

**197. State Channel Force-Close Manipulation**

- **D:** Force-close with stale state. Challenge period too short for victim to respond. State hash doesn't include all relevant data.
- **FP:** Adequate challenge period. Full state in hash. On-chain dispute resolution with latest state.

**198. Token Permit Phishing via `eth_signTypedData`**

- **D:** User tricked into signing EIP-2612 permit via phishing site. Signature used to drain approved tokens without on-chain `approve` tx visible.
- **FP:** Not a smart contract vulnerability (UI/social engineering). Permit nonce prevents replay after cancel.

**199. Incorrect Merkle Proof Verification**

- **D:** Merkle proof verification uses `keccak256(abi.encodePacked(leaf))` where `leaf` is user-controlled. Second preimage attack: internal node passed as leaf.
- **FP:** Double-hash: `keccak256(abi.encodePacked(keccak256(abi.encodePacked(data))))`. Leaf structure includes length prefix. OZ `MerkleProof` used correctly.

**200. Try/Catch Swallows Revert Reason**

- **D:** `try target.call() {} catch {}` silently swallows all failures. Critical errors (out-of-gas, invalid opcode) handled same as expected failures. Missing error propagation.
- **FP:** Specific error types caught. Critical failures re-reverted. Error reason logged via event.

---

**201. Unvalidated Fund-Critical Parameter**

- **D:** User-supplied address or amount parameter is used directly in `transfer`, `safeTransfer`, `call{value:}`, or `safeTransferFrom` without validating it against protocol state, prior computation, or expected values. The function trusts a caller-supplied token address, recipient, or amount to be correct. Pattern: `_creditToken` passed by user, used in `safeTransfer(_creditToken, recipient, amount)` without checking `_creditToken == expectedOutputToken`.
- **FP:** Parameter is validated against on-chain state before use (e.g., `require(_token == pool.outputToken())`). Parameter is hardcoded or set by admin. Parameter is msg.sender (self-referential, no trust issue).

**202. msg.value vs Amount Parameter Mismatch**

- **D:** Payable function accepts both `msg.value` (ETH sent) and an `_amount` parameter (or similar), but never enforces `require(msg.value >= _amount)` or equivalent. The function uses `_amount` in `call{value: _amount}` or internal accounting, allowing the caller to specify an amount greater than the ETH they actually sent. If the contract has accumulated ETH (via `receive()`, prior transactions, or `selfdestruct` forcing), the caller drains the contract's balance. Pattern: `anyToAnySwap{value:0}(amount=contractBalance, nativeSend=true)` drains the Router.
- **FP:** `require(msg.value >= _amount)` or `require(msg.value == _amount)` enforced. Function is not payable. Amount derived from `msg.value` directly (not a separate parameter). Contract never holds ETH balance.

**203. Token Address Confusion in Multi-Hop Paths**

- **D:** In router/aggregator/multi-hop swap patterns, the output token of hop N does not match the input token of hop N+1, or the final credit/output token does not match the actual output of the last swap. User supplies the path or token addresses, and the contract does not verify continuity. Pattern: `swapPath = [TokenA→TokenB]` but `_creditToken = TokenC` — contract sends TokenC from its own balance instead of the actual swap output.
- **FP:** Path continuity validated: `require(path[i].outputToken == path[i+1].inputToken)`. Credit token derived from the actual swap output, not user-supplied. Single-hop only (no path confusion possible).

**204. Stranded Funds Drainage**

- **D:** Contract has `receive()` or `fallback()` (can receive ETH), or can accumulate tokens from failed transfers, rounding dust, direct sends, or `selfdestruct` forcing. An external function allows spending these accumulated balances on behalf of any caller. Pattern: Router accumulates ETH from partial swaps; `anyToAnySwap()` uses `address(this).balance` as spendable funds for the next caller.
- **FP:** No public function spends contract's own accumulated balance for callers. Sweep/rescue function is admin-only. Internal accounting tracks all balances — untracked funds are inaccessible. Contract cannot receive unexpected funds.

**205. Unchecked Native Value Forwarding**

- **D:** Contract forwards ETH to another contract via `call{value: amount}(data)` or `payable(to).transfer(amount)` where `amount` is derived from a parameter or storage, NOT from `msg.value`. The contract spends its own ETH balance without verifying the caller provided the funds. Pattern: `market.swap{value: _amount}(params)` where `_amount` is a user parameter and the Router pays from `address(this).balance`.
- **FP:** Amount is always `msg.value` or derived from `msg.value` with refund of excess. `require(msg.value >= amount)` before forwarding. Contract is sole owner of its ETH (no external callers can trigger spend).

**206. User-Controlled Token in Transfer**

- **D:** `safeTransfer`, `transfer`, or `safeTransferFrom` uses a token address supplied by the caller (calldata parameter) without verifying it matches the expected token for the operation. Attacker calls with an unrelated token the contract holds, draining that token's balance. Pattern: `IERC20(_creditToken).safeTransfer(msg.sender, amount)` where `_creditToken` is user-supplied and could be any token the contract holds.
- **FP:** Token address validated against pool/pair/vault's registered tokens. Token address is immutable/storage, not from calldata. Allowance-based transfer (contract can only send what it's approved for, which is limited to correct tokens).

**207. Missing msg.value Accounting in Payable Function**

- **D:** Payable function accepts ETH (`msg.value`) but does not debit or track the received amount. The ETH accumulates in the contract's balance and becomes spendable by subsequent callers via functions that use `address(this).balance` or `call{value:}` with contract funds. Pattern: payable function receives ETH for gas/fees but doesn't account for it; later function forwards contract balance elsewhere.
- **FP:** `msg.value` tracked in internal accounting (credited to user's balance mapping). Excess `msg.value` refunded. Contract never uses `address(this).balance` for operations (only internal tracked balances).

**208. Router/Aggregator Balance Theft**

- **D:** Intermediary contract (router, aggregator, relayer) transiently holds user funds during multi-step operations. If any code path uses `address(this).balance` or `IERC20(token).balanceOf(address(this))` as the amount to forward/transfer (instead of tracking the user's specific deposit), any subsequent caller can claim those funds. Pattern: Router holds TokenA from a failed swap; attacker calls swap with `_amount = balanceOf(router)` to steal it.
- **FP:** Router never holds funds beyond a single transaction (atomic execution guaranteed). All operations use `msg.value` or tracked per-user balances, never `address(this).balance`. Sweep function protected by admin-only access.

**209. Parameter Trust Boundary Violation**

- **D:** Function trusts a caller-supplied parameter for a security-critical decision — which token to send, which address to credit, which amount to use, which pool to interact with — without independently validating it against on-chain state or prior computation. The parameter crosses a trust boundary: external (untrusted caller) to internal (trusted operation). Pattern: user supplies `_outputToken` parameter, function calls `safeTransfer(_outputToken, user, amount)` without verifying `_outputToken` was actually produced by the swap.
- **FP:** All caller-supplied parameters used in fund operations are validated against protocol state (pool registries, path outputs, computed values). Function derives critical parameters internally rather than accepting them from caller.

**210. Payable Function Missing Value Check**

- **D:** Function marked `payable` but performs ETH-dependent operations without checking `msg.value`. If `msg.value == 0`, the function either: (a) proceeds with zero ETH but uses contract balance, (b) no-ops on the ETH portion but still performs token operations, creating an inconsistent state, or (c) allows a conditional branch (e.g., `if nativeSend`) to execute without the caller providing ETH. Pattern: `anyToAnySwap{value:0}(nativeSend=true, amount=X)` — nativeSend branch triggers, but msg.value is 0, so contract's own ETH is spent.
- **FP:** `require(msg.value > 0)` when ETH is expected. `require(msg.value == _amount)` enforced. Non-payable function (compiler rejects ETH). `msg.value` is the sole source of the amount (no separate parameter).

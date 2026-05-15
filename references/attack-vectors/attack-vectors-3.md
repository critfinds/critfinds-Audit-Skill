# Attack Vectors Reference (3/4)

230 total attack vectors — Cross-Chain & Bridge, Gas & DoS, EVM Hazards, Governance, NFT-Specific, L2 & Settlement

---

**101. Cross-Chain Message Replay**

- **D:** Cross-chain messages replayed on same or different chain. Missing nonce, chain ID, or message ID in validation.
- **FP:** Per-message nonce tracked. Chain ID in message hash. Message ID derived from unique parameters.

**102. Incomplete Bridge Message Validation**

- **D:** Bridge relayer forges or alters messages. Signature/proof verification flawed. Missing sender validation.
- **FP:** Merkle proof or multi-sig verification. Source contract address validated. Message hash includes all parameters.

**103. Stuck Funds on Failed Cross-Chain Call**

- **D:** Tokens locked on source chain but destination call reverts. No refund mechanism. Funds permanently stuck.
- **FP:** Fallback/rescue function for stuck funds. Retry mechanism. `emergencyWithdraw` for bridged assets.

**104. Chain-Specific `block.number` Assumptions**

- **D:** `block.number` means different things on L2s (Arbitrum uses L1 block number in some contexts). Code assumes L1-like block numbering.
- **FP:** Chain-specific block number handling. `arbBlockNumber()` used on Arbitrum.

**105. `PUSH0` Opcode Incompatibility**

- **D:** Solidity >= 0.8.20 generates `PUSH0` opcode. Not supported on all chains (pre-Shanghai). Deployment fails silently.
- **FP:** Target chain supports Shanghai. EVM version specified in compiler config. Tested on target chain.

**106. `prevrandao` / `difficulty` Post-Merge Behavior**

- **D:** `block.difficulty` (now `block.prevrandao`) behaves differently post-merge. Not truly random. Using for critical randomness.
- **FP:** VRF (Chainlink VRF) used for randomness. `prevrandao` used only for non-critical entropy. Commit-reveal scheme.

**107. Cross-Chain Deployment Replay**

- **D:** Deployment tx replayed on another chain. Same deployer nonce produces same CREATE address under different control. No EIP-155 protection.
- **FP:** EIP-155 signatures. CREATE2 via deterministic factory. Per-chain deployer addresses.

**108. LayerZero lzCompose Sender Impersonation**

- **D:** `lzCompose` doesn't validate `msg.sender == endpoint` or `_from` parameter. Attacker calls directly, impersonating OFT contract.
- **FP:** `msg.sender == address(endpoint)` and `_from == expectedOFT` validated. Standard OAppReceiver used.

**109. Ordered Message Channel Blocking (Nonce DoS)**

- **D:** Ordered nonce execution. One permanently reverting message blocks ALL subsequent messages from that source.
- **FP:** Unordered nonce mode. `_lzReceive` wrapped in try/catch. Admin can skip/clear payload.

**110. Cross-Chain Supply Invariant Violation**

- **D:** `total_locked_source >= total_minted_destination` violated. Decimal conversion errors, `_credit` callable without `_debit`, race conditions.
- **FP:** Invariant monitored. `_credit` only from verified `lzReceive`. Rate limits cap exposure.

---

**111. Unbounded Loop DoS**

- **D:** Loop over user-growable unbounded array: `for (uint i; i < users.length; i++)`. Exceeds block gas limit.
- **FP:** Array length capped: `require(arr.length < MAX)`. Loop iterates fixed small constant. Pagination implemented.

**112. External Call DoS in Loop**

- **D:** Single failing external call in a loop blocks all subsequent operations. Batch distribution halted by one bad recipient.
- **FP:** `try/catch` around each call. Skip-on-failure pattern. Pull-over-push for distributions.

**113. Block Gas Limit DoS (Queue Processing)**

- **D:** Functions processing all pending items bricked if queue grows too large. Permanently stuck.
- **FP:** Max items per batch. Cursor-based processing (resume from last position). Off-chain triggering with gas estimation.

**114. Griefing via Revert on ETH Receive**

- **D:** Attacker deploys contract with reverting `receive()` / `fallback()`. ETH push payments to this address always revert, blocking withdrawals.
- **FP:** Pull-over-push pattern. `call` with success check, skip on failure. WETH wrapping fallback.

**115. Storage Slot DoS via Mapping Pollution**

- **D:** Attacker fills mapping with dust entries using user-controlled keys. Iteration/cleanup impossible.
- **FP:** No iteration over mapping. Bounded key space. Off-chain indexing for enumeration.

**116. `returnbomb` Attack (Returndata DoS)**

- **D:** Malicious contract returns enormous data to consume caller's gas via `returndatacopy`. Low-level `call` without limiting `returndatasize`.
- **FP:** Assembly call without `returndatacopy`. Gas-limited call. Known trusted callee.

**117. Griefing via `SELFDESTRUCT` ETH Forcing**

- **D:** Attacker forces ETH into contract via `selfdestruct`. Breaks `address(this).balance`-based invariants. Can manipulate reward calculations, withdrawal limits.
- **FP:** Internal accounting, not `address(this).balance`. Protocol tolerates unexpected ETH. Sweep function for excess.

**118. Gas Limit on Subcall Insufficient**

- **D:** `call{gas: fixedGas}(data)` with insufficient fixed gas. Callee always reverts on complex operations but succeeds on simple ones.
- **FP:** No fixed gas limit on calls (forwards all available). Gas limit generous enough for worst-case callee execution.

**119. Out-of-Gas Griefing on 1/64 Rule**

- **D:** EIP-150: only 63/64 of remaining gas forwarded to subcall. Parent call may succeed (remaining 1/64 sufficient) even if subcall silently fails.
- **FP:** Return value checked: `require(success)`. Sufficient gas forwarded. Minimum gas assertion before call.

---

**120. `msg.value` in Loops (Double-Spend ETH)**

- **D:** `msg.value` reused across loop iterations. Each iteration credits full `msg.value` — allows spending same ETH multiple times.
- **FP:** `msg.value` captured to local variable, decremented per iteration. Total enforced after loop.

**121. Dirty Memory from Uninitialized Free Memory Pointer**

- **D:** Assembly writes to memory without updating free memory pointer (`0x40`). Subsequent Solidity code overwrites assembly data.
- **FP:** `mstore(0x40, newPtr)` after manual memory allocation. Memory used and consumed within assembly block only.

**122. Memory Corruption via `mstore8` Partial Write**

- **D:** `mstore8` writes single byte. Subsequent `mload` reads full 32-byte word with 31 stale bytes. Corrupts hashes and return values.
- **FP:** Full word zeroed with `mstore(ptr, 0)` before byte writes. Result masked after `mload`.

**123. `calldataload` Without Bounds Check**

- **D:** `calldataload(offset)` reads past actual calldata length. Returns zero-padded data. Unexpected behavior with short calldata.
- **FP:** `calldatasize()` checked before load. ABI decoder handles bounds (Solidity-generated code).

**124. Stack Too Deep via Inline Assembly**

- **D:** Manipulating stack items in `assembly` blocks corrupts Solidity's variable layout. Variables read wrong values.
- **FP:** Assembly uses `let` for local variables. No stack manipulation outside assembly. Compiler version handles via-IR.

**125. `abi.decode` Revert on Malformed Data**

- **D:** External/untrusted data ABI-decoded without try/catch. Malformed data permanently reverts critical path.
- **FP:** `try/catch` around decode of untrusted data. Data source is trusted (own contract, verified oracle).

**126. `addmod` / `mulmod` Edge Cases**

- **D:** `addmod(a, b, 0)` and `mulmod(a, b, 0)` revert (division by zero). Unchecked modulus parameter.
- **FP:** Modulus validated to be non-zero before call. Constant modulus used.

**127. `extcodecopy` on Self-Destructed Contract**

- **D:** `extcodecopy` on destroyed contract returns empty. Code-based verification fails silently.
- **FP:** Contract existence verified via `extcodesize` first. `extcodehash` used for verification.

**128. Incorrect `sload` / `sstore` Slot Calculation**

- **D:** Manual storage slot calculation in assembly misses Solidity's slot layout rules (mappings use `keccak256`, dynamic arrays use `keccak256(slot) + index`).
- **FP:** Storage slot computed correctly per Solidity layout. Verified against compiler output.

**129. Missing `fallback()` / `receive()` in ETH-Receiving Contract**

- **D:** Contract expects to receive ETH but has no `receive()` or `fallback()`. ETH transfers revert.
- **FP:** `receive()` or `payable fallback()` implemented. Contract never needs to receive ETH directly.

---

**130. Governance Proposal Front-Running**

- **D:** Attacker sees pending proposal, front-runs with token acquisition to vote. Snapshot at proposal time, not before.
- **FP:** `getPastVotes(block.number - 1)` snapshot. Minimum holding period before voting eligibility.

**131. Timelock Bypass**

- **D:** Admin functions that skip timelock. Timelock delay set to 0 or settable to 0.
- **FP:** All admin functions routed through timelock. `MIN_DELAY` enforced and non-zero. Delay change itself timelocked.

**132. Quorum Manipulation**

- **D:** `quorum` based on `totalSupply` at proposal time. Burning tokens after snapshot lowers effective quorum.
- **FP:** Quorum based on snapshot supply. Quorum denominator fixed at governance deployment.

**133. Governor Bravo Cancel Griefing**

- **D:** `cancel()` callable by anyone when proposer's votes drop below threshold. Attacker buys proposer's tokens and cancels.
- **FP:** Only proposer or guardian can cancel. Cancel threshold separate from proposal threshold.

**134. Proposal ID Collision**

- **D:** Proposal ID computed from parameters. Same parameters at different times produce same ID. Second proposal overwrites first.
- **FP:** Proposal ID includes description hash (OZ Governor). Nonce-based ID generation.

**135. Timelock Stale Proposal Execution**

- **D:** Proposal queued but not executed within grace period. Stale proposal executed after conditions changed significantly.
- **FP:** Grace period enforced. Proposal expires after timelock window. Guardian can veto stale proposals.

**136. Delegate Privilege Escalation**

- **D:** `setDelegate()` appoints address that can manage configurations, skip/clear payloads. Delegate set to insecure address.
- **FP:** Delegate == owner. Delegate is governance timelock. Same access controls as `setPeer`.

---

**137. Unrestricted NFT Mint**

- **D:** Missing supply caps or access control on `mint()` / `safeMint()`. Anyone can mint unlimited NFTs.
- **FP:** `maxSupply` enforced. Access control on mint function. Minting only through verified sale contract.

**138. NFT Metadata Manipulation (Rug Pull)**

- **D:** Mutable `baseURI` allows swapping NFT artwork post-mint. Owner calls `setBaseURI` to replace art with worthless images.
- **FP:** `baseURI` frozen after reveal. IPFS/Arweave permanent storage. On-chain metadata.

**139. Royalty Bypass**

- **D:** ERC-2981 royalties are informational only. Marketplaces can ignore them. Wrapper contracts bypass transfer hooks.
- **FP:** On-chain royalty enforcement via operator filter. Transfer restrictions verified.

**140. ERC721 Enumerable Reordering**

- **D:** `_removeTokenFromOwnerEnumeration` swaps last token into removed slot. Index-based lookups return wrong token after removal.
- **FP:** OZ ERC721Enumerable used unmodified. No external dependency on token ordering.

**141. ERC1155 Batch Callback Reentrancy**

- **D:** `safeBatchTransferFrom` triggers `onERC1155BatchReceived` callback. Reentrancy possible via batch operations.
- **FP:** State committed before batch transfer. `nonReentrant` applied. OZ ERC1155 unmodified.

**142. ERC721 `_safeMint` to Non-Receiver Contract**

- **D:** `_safeMint` calls `onERC721Received` which may revert. Intended recipient contract doesn't implement receiver interface. Mint permanently blocked.
- **FP:** `_mint` used (no callback). Recipient verified to implement IERC721Receiver.

**143. NFT Enumeration Gas DoS**

- **D:** `tokenOfOwnerByIndex()` loops over all tokens. Large collections exceed gas limit for enumeration.
- **FP:** Off-chain indexing for enumeration. Bounded collection size. Pagination in enumeration.

**144. Missing `supportsInterface` for ERC-165**

- **D:** Contract claims ERC-721/1155 compliance but doesn't implement `supportsInterface`. Integrating contracts fail to detect standard.
- **FP:** ERC-165 implemented. OZ introspection base used.

**145. ERC1155 URI Missing `{id}` Substitution**

- **D:** `uri(uint256 id)` returns fully resolved URL instead of template with `{id}` placeholder. Client-side substitution broken.
- **FP:** Returns string containing literal `{id}`. Per-ID on-chain URI documented.

---

**146. Blacklistable Token in Critical Payment Path**

- **D:** Push-model `token.transfer(recipient, amount)` with USDC/USDT. Blacklisted recipient reverts entire function.
- **FP:** Pull pattern. try/catch on transfers. Token whitelist excludes blacklistable tokens.

**147. Insecure Randomness via `block.timestamp` / `blockhash`**

- **D:** Using `block.timestamp`, `block.number`, or `blockhash` for randomness in games, lotteries, or critical selection.
- **FP:** Chainlink VRF used. Commit-reveal scheme. Randomness not security-critical.

**148. `blockhash` Only Available for Last 256 Blocks**

- **D:** `blockhash(block.number - n)` returns 0 for n > 256. Randomness or validation based on old block hash silently fails.
- **FP:** Block age checked before `blockhash` call. VRF used instead.

**149. Incorrect Inheritance Order (C3 Linearization)**

- **D:** Solidity uses C3 linearization for multiple inheritance. Wrong inheritance order causes wrong function to execute.
- **FP:** Inheritance order verified. Single inheritance chain. No conflicting function names.

**150. Shadowed State Variable**

- **D:** Child contract declares state variable with same name as parent. Parent's variable becomes inaccessible. Reads/writes hit wrong slot.
- **FP:** Compiler warning addressed. No variable shadowing. Unique naming convention.

---

**226. Governance Delegation Chain Exploit**

- **D:** Circular or deep delegation chains break vote counting or create exploitable states. Pattern: A delegates to B, B delegates to A — votes counted twice, not at all, or gas DoS on vote counting due to infinite loop. Also: delegation depth exceeding gas limits causes `getPastVotes()` to revert, blocking proposals that depend on that voter's participation. Flash loan → delegate → vote → undelegate → return in single block.
- **FP:** Circular delegation prevented: `require(delegatee != msg.sender)` with chain traversal. Maximum delegation depth enforced. Delegation snapshot at prior block prevents same-block manipulation.

**227. Proposal Execution Payload Injection**

- **D:** Governance proposal contains arbitrary calldata for execution. Proposer embeds malicious operations alongside legitimate ones — voters approve the visible title/description but miss the embedded exploit in the raw calldata. Pattern: proposal titled "Upgrade oracle" includes `approve(attacker, MAX_UINT)` as an additional call in the batch. Also: proposal with `delegatecall` to attacker contract that steals treasury.
- **FP:** All proposal actions displayed to voters (UI shows decoded calldata). Timelock allows guardian veto. Proposal actions limited to approved function selectors. No arbitrary `delegatecall` in executor.

**228. L2 Sequencer Grace Period Exploitation**

- **D:** After L2 sequencer comes back online, positions opened/modified during downtime get favorable treatment because oracle prices haven't updated yet. Grace period is too short or non-existent. Pattern: sequencer goes down → oracle price stale at $2000/ETH → sequencer restarts → ETH is actually $1800 → attacker borrows at stale $2000 price → profit on $200/ETH difference before oracle updates. Also: forced transactions via L1 during sequencer downtime bypass protocol protections.
- **FP:** `sequencerUptimeFeed` checked with adequate grace period (>= 1 hour). All operations paused during sequencer downtime. Oracle freshness checked independently of sequencer.

**229. Cross-Chain Message Value Mismatch**

- **D:** Cross-chain message carries a value/amount field that doesn't match the actual tokens locked on the source chain. Destination chain mints/releases based on the message amount, not the actual lock. Pattern: bridge `send(100 ETH)` but only locks 1 ETH on source — message says 100 ETH — destination releases 100 ETH. Also: decimal conversion errors between chains (18 decimal chain to 6 decimal chain), message replay with inflated amounts, or race condition between lock and message send.
- **FP:** Message amount derived from actual locked amount (event-based verification). Merkle proof of lock transaction required. Rate limits cap per-message amount. Decimal normalization verified in tests.

**230. Time-Weighted Balance Manipulation**

- **D:** Protocol uses time-weighted average balance (TWAB) for rewards, governance power, or fee calculations. Attacker maintains large balance briefly before snapshot/checkpoint and small balance otherwise, gaming the time-weighted calculation with minimal capital lockup. Pattern: deposit large amount 1 block before checkpoint, receive disproportionate time-weighted rewards, withdraw immediately after. Also: manipulating TWAB by stacking deposits at end of period and withdrawing at start.
- **FP:** TWAB uses per-second granularity (not per-block/per-checkpoint). Minimum observation period longer than manipulation window. Rewards proportional to actual time-weighted balance with sufficient history. Deposits locked through observation period.


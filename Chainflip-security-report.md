# Title

**Critical: `non_native_signed_call` permits forged signed-origin execution for EVM/Solana-backed accounts because `pre_dispatch` omits signature verification**

# Description

`pallet_cf_environment::non_native_signed_call` is designed to let EVM and Solana wallets authorize a runtime call by embedding a foreign-chain signature inside an **unsigned** extrinsic. The security invariant is that the wrapped runtime call must only execute as `Origin::signed(signer_account)` if the embedded EVM/Solana signature is valid for the exact `(call, nonce, expiry, network, spec_version)` payload.

That invariant is not enforced on the inclusion path.

The public extrinsic `non_native_signed_call` decodes the account directly from attacker-controlled `signature_data` and dispatches the wrapped call as `Origin::signed(signer_account)`, but it does **not** verify the signature itself:

- `state-chain/pallets/cf-environment/src/lib.rs:677-723`
  - signer is derived from `signature_data.signer_account()` at `685-686`
  - the inner call is dispatched as a signed origin at `705-706`
  - there is no call to `is_valid_signature(...)` anywhere in this function

Signature verification exists only in `validate_unsigned`:

- `state-chain/pallets/cf-environment/src/lib.rs:763-801`
  - `is_valid_signature(...)` is called at `791-800`

However, the inclusion-time hook `pre_dispatch` explicitly assumes the signature was already checked and performs only signer decoding, metadata validation, and nonce increment:

- `state-chain/pallets/cf-environment/src/lib.rs:807-821`
  - signer is decoded from untrusted `signature_data` at `814`
  - comment says signature validity was already checked at `818`
  - `validate_metadata(...)` is called at `819`
  - nonce is incremented at `820`
  - no signature verification occurs in this path

Because `non_native_signed_call` itself also lacks signature verification, any inclusion path that reaches `pre_dispatch` without relying on the transaction pool’s `validate_unsigned` decision can execute an arbitrary wrapped call as the forged EVM/Solana-backed account.

Additional relevant code:

- `SignatureData::signer_account()` simply maps the claimed EVM/Solana address into an on-chain account ID: `state-chain/pallets/cf-environment/src/submit_runtime_call.rs:111-122`
- `is_valid_signature(...)` is the intended authentication routine for the payload: `state-chain/pallets/cf-environment/src/submit_runtime_call.rs:244-279`

# Attack Path

1. The attacker selects a victim EVM-backed or Solana-backed account with on-chain funds.
2. The attacker constructs a `non_native_signed_call` whose `signature_data` claims to be from the victim, but contains an invalid or unrelated signature.
3. The attacker chooses any wrapped runtime call that is dangerous when executed as the victim. A concrete theft path is `Funding::redeem` with an attacker-controlled redemption address:
   - `state-chain/pallets/cf-funding/src/lib.rs:647-724`
4. If the forged extrinsic is evaluated by the transaction pool, `validate_unsigned` rejects it with `BadProof` because that path does call `is_valid_signature(...)`:
   - `state-chain/pallets/cf-environment/src/lib.rs:791-800`
5. If a malicious or compromised block author bypasses pool admission and includes the extrinsic through the runtime inclusion path, `pre_dispatch` succeeds because it does not verify the signature:
   - `state-chain/pallets/cf-environment/src/lib.rs:807-821`
6. The call body then executes and dispatches the wrapped call as `Origin::signed(victim_account)`:
   - `state-chain/pallets/cf-environment/src/lib.rs:685-706`
7. In the theft variant, `Funding::redeem` accepts the forged signed origin, creates a pending redemption for the victim, and points it to the attacker’s Ethereum address:
   - signed origin check: `state-chain/pallets/cf-funding/src/lib.rs:647-655`
   - pending redemption written with attacker-chosen `redeem_address`: `state-chain/pallets/cf-funding/src/lib.rs:705-712`
   - event emitted: `state-chain/pallets/cf-funding/src/lib.rs:714-719`
8. The victim’s liquid FLIP is moved into the pending-redemption reserve via `try_initiate_redemption(...)`:
   - call site: `state-chain/pallets/cf-funding/src/lib.rs:691-693`
   - reserve transfer: `state-chain/pallets/cf-flip/src/lib.rs:632-638`
   - reserve storage definition: `state-chain/pallets/cf-flip/src/lib.rs:141-144`

The exploit does not require the encoding RPC, but the system also exposes helpers for producing off-chain signed payloads:

- public RPC entrypoint: `state-chain/custom-rpc/src/lib.rs:2912-2958`
- runtime API helper: `state-chain/runtime/src/runtime_apis/impl_api.rs:1954-1986`

# Impact

This bug allows **forged signed-origin execution** for EVM/Solana-backed accounts on any inclusion path that relies on `pre_dispatch` without separately re-running signature verification.

The real-world consequence is unauthorized execution of any wrapped runtime call that the forged account is permitted to make. The attached proof-of-code demonstrates a direct theft path in which a forged call executes `Funding::redeem` as the victim and redirects the redemption to an attacker-controlled Ethereum address.

Observed theft effect in the demonstrated path:

- victim-origin redemption is accepted: `state-chain/pallets/cf-funding/src/lib.rs:647-724`
- victim’s FLIP is removed from liquid balance and placed into pending redemption reserve: `state-chain/pallets/cf-flip/src/lib.rs:632-638`
- the pending redemption is bound to the attacker’s address: `state-chain/pallets/cf-funding/src/lib.rs:705-712`

In practice, this means a malicious or compromised block author/validator can convert an invalid foreign-chain signature into an authorized on-chain action for any funded EVM/Solana-backed account.

# Proof of Code

A drop-in runtime test is attached as:

- `non_native_signed_call_theft_test.rs`
- patch form: `non_native_signed_call_theft_full.patch`

Key proof steps in the test:

- test entry: `non_native_signed_call_theft_test.rs:48-137`
- a forged `SignatureData::Ethereum` is created for the victim with a bogus signature: `82-87`
- the wrapped call is `RuntimeCall::Funding::redeem` with the attacker’s redemption address: `70-80`
- `validate_unsigned(...)` correctly rejects the forged transaction with `BadProof`: `90-100`
- `pre_dispatch(...)` still accepts the exact same forged transaction and increments the victim nonce: `102-106`
- the forged call is dispatched and succeeds: `108`
- storage proves theft:
  - victim now has a `PendingRedemptions` entry: `110-113`
  - `redeem_address == attacker_redemption_address`: `113`
  - victim funds moved into `PendingRedemptionsReserve`: `114-118`
  - victim liquid balance decreased: `119-122`

This reproduces the vulnerability end-to-end: an invalid foreign signature is rejected by pool validation but still accepted by the inclusion path, and the resulting forged signed-origin call causes a theft-relevant state transition.

# Mitigation

The fix should make signature verification part of the **inclusion-time** security boundary rather than only the transaction-pool boundary.

Recommended remediation:

1. **Re-run full signature verification in `pre_dispatch`.**
   - `pre_dispatch` should call the same `is_valid_signature(...)` logic currently used in `validate_unsigned`, using the same `(inner_call, network, transaction_metadata, signature_data, spec_version)` tuple.
   - Reject with `InvalidTransaction::BadProof` if verification fails.

2. **Do not rely on `validate_unsigned` as the only authentication check.**
   - The current comment at `state-chain/pallets/cf-environment/src/lib.rs:818` is unsafe in this context.
   - The runtime must assume the extrinsic may arrive via an inclusion path that bypasses pool admission.

3. **Optionally add a defensive assertion inside `non_native_signed_call` itself.**
   - Even after fixing `pre_dispatch`, a belt-and-suspenders check inside the extrinsic body would reduce the blast radius of future refactors.
   - If performance is a concern, at minimum document and test that `pre_dispatch` is the mandatory authentication boundary.

4. **Add regression tests covering both pool-validation and inclusion-time behavior.**
   - One test should assert that invalid signatures fail `validate_unsigned`.
   - Another should assert that the same invalid signatures fail `pre_dispatch`.
   - A high-value regression test should preserve the attached theft path and assert it can no longer move victim funds or create a pending redemption.

A safe implementation target is: **the exact same forged call that currently fails `validate_unsigned` must also fail `pre_dispatch`, and must never reach the inner dispatch as a forged `Origin::signed(victim_account)`**.

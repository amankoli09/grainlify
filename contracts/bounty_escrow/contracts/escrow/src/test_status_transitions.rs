use super::*;
use soroban_sdk::testutils::Ledger;
use soroban_sdk::{
    testutils::{Address as _, LedgerInfo},
    token, Address, Env,
};

fn create_token_contract<'a>(
    e: &Env,
    admin: &Address,
) -> (token::Client<'a>, token::StellarAssetClient<'a>) {
    let contract = e.register_stellar_asset_contract_v2(admin.clone());
    let contract_address = contract.address();
    (
        token::Client::new(e, &contract_address),
        token::StellarAssetClient::new(e, &contract_address),
    )
}

fn create_escrow_contract<'a>(e: &Env) -> BountyEscrowContractClient<'a> {
    let contract_id = e.register_contract(None, BountyEscrowContract);
    BountyEscrowContractClient::new(e, &contract_id)
}

struct TestSetup<'a> {
    env: Env,
    #[allow(dead_code)]
    admin: Address,
    depositor: Address,
    contributor: Address,
    #[allow(dead_code)]
    token: token::Client<'a>,
    #[allow(dead_code)]
    token_admin: token::StellarAssetClient<'a>,
    escrow: BountyEscrowContractClient<'a>,
}

impl<'a> TestSetup<'a> {
    fn new() -> Self {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let depositor = Address::generate(&env);
        let contributor = Address::generate(&env);

        let (token, token_admin) = create_token_contract(&env, &admin);
        let escrow = create_escrow_contract(&env);

        escrow.init(&admin, &token.address);
        token_admin.mint(&depositor, &1_000_000);

        Self {
            env,
            admin,
            depositor,
            contributor,
            token,
            token_admin,
            escrow,
        }
    }
}

#[test]
fn test_refund_eligibility_ineligible_before_deadline_without_approval() {
    let setup = TestSetup::new();
    let bounty_id = 99;
    let amount = 1_000;
    let deadline = setup.env.ledger().timestamp() + 500;

    setup
        .escrow
        .lock_funds(&setup.depositor, &bounty_id, &amount, &deadline);

    let view = setup.escrow.get_refund_eligibility_view(&bounty_id);
    assert!(!view.eligible);
    assert_eq!(
        view.code,
        RefundEligibilityCode::IneligibleDeadlineNotPassed
    );
    assert_eq!(view.amount, 0);
    assert!(!view.approval_present);
}

#[test]
fn test_refund_eligibility_eligible_after_deadline() {
    let setup = TestSetup::new();
    let bounty_id = 100;
    let amount = 1_200;
    let deadline = setup.env.ledger().timestamp() + 100;

    setup
        .escrow
        .lock_funds(&setup.depositor, &bounty_id, &amount, &deadline);
    setup.env.ledger().set_timestamp(deadline + 1);

    let view = setup.escrow.get_refund_eligibility_view(&bounty_id);
    assert!(view.eligible);
    assert_eq!(view.code, RefundEligibilityCode::EligibleDeadlinePassed);
    assert_eq!(view.amount, amount);
    assert_eq!(view.recipient, Some(setup.depositor.clone()));
    assert!(!view.approval_present);
}

#[test]
fn test_refund_eligibility_eligible_with_admin_approval_before_deadline() {
    let setup = TestSetup::new();
    let bounty_id = 101;
    let amount = 2_000;
    let deadline = setup.env.ledger().timestamp() + 1_000;
    let custom_recipient = Address::generate(&setup.env);

    setup
        .escrow
        .lock_funds(&setup.depositor, &bounty_id, &amount, &deadline);
    setup.escrow.approve_refund(
        &bounty_id,
        &500,
        &custom_recipient,
        &RefundMode::Partial,
    );

    let view = setup.escrow.get_refund_eligibility_view(&bounty_id);
    assert!(view.eligible);
    assert_eq!(view.code, RefundEligibilityCode::EligibleAdminApproval);
    assert_eq!(view.amount, 500);
    assert_eq!(view.recipient, Some(custom_recipient));
    assert!(view.approval_present);
}

// Valid transitions: Locked → Released
#[test]
fn test_locked_to_released() {
    let setup = TestSetup::new();
    let bounty_id = 1;
    let amount = 1000;
    let deadline = setup.env.ledger().timestamp() + 1000;

    setup
        .escrow
        .lock_funds(&setup.depositor, &bounty_id, &amount, &deadline);
    assert_eq!(
        setup.escrow.get_escrow_info(&bounty_id).status,
        EscrowStatus::Locked
    );

    setup.escrow.release_funds(&bounty_id, &setup.contributor);
    assert_eq!(
        setup.escrow.get_escrow_info(&bounty_id).status,
        EscrowStatus::Released
    );
}

// Valid transitions: Locked → Refunded
#[test]
fn test_locked_to_refunded() {
    let setup = TestSetup::new();
    let bounty_id = 1;
    let amount = 1000;
    let deadline = setup.env.ledger().timestamp() + 100;

    setup
        .escrow
        .lock_funds(&setup.depositor, &bounty_id, &amount, &deadline);
    assert_eq!(
        setup.escrow.get_escrow_info(&bounty_id).status,
        EscrowStatus::Locked
    );

    setup.env.ledger().set_timestamp(deadline + 1);
    setup.escrow.refund(&bounty_id);
    assert_eq!(
        setup.escrow.get_escrow_info(&bounty_id).status,
        EscrowStatus::Refunded
    );
}

// Valid transitions: Locked → PartiallyRefunded
#[test]
fn test_locked_to_partially_refunded() {
    let setup = TestSetup::new();
    let bounty_id = 1;
    let amount = 1000;
    let deadline = setup.env.ledger().timestamp() + 100;

    setup
        .escrow
        .lock_funds(&setup.depositor, &bounty_id, &amount, &deadline);
    assert_eq!(
        setup.escrow.get_escrow_info(&bounty_id).status,
        EscrowStatus::Locked
    );

    // Approve partial refund before deadline
    setup
        .escrow
        .approve_refund(&bounty_id, &500, &setup.depositor, &RefundMode::Partial);
    setup.escrow.refund(&bounty_id);
    assert_eq!(
        setup.escrow.get_escrow_info(&bounty_id).status,
        EscrowStatus::PartiallyRefunded
    );
}

// Valid transitions: PartiallyRefunded → Refunded
#[test]
fn test_partially_refunded_to_refunded() {
    let setup = TestSetup::new();
    let bounty_id = 1;
    let amount = 1000;
    let deadline = setup.env.ledger().timestamp() + 100;

    setup
        .escrow
        .lock_funds(&setup.depositor, &bounty_id, &amount, &deadline);

    // First partial refund
    setup
        .escrow
        .approve_refund(&bounty_id, &500, &setup.depositor, &RefundMode::Partial);
    setup.escrow.refund(&bounty_id);
    assert_eq!(
        setup.escrow.get_escrow_info(&bounty_id).status,
        EscrowStatus::PartiallyRefunded
    );

    // Second refund completes it
    setup.env.ledger().set_timestamp(deadline + 1);
    setup.escrow.refund(&bounty_id);
    assert_eq!(
        setup.escrow.get_escrow_info(&bounty_id).status,
        EscrowStatus::Refunded
    );
}

// Invalid transition: Released → Locked
#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn test_released_to_locked_fails() {
    let setup = TestSetup::new();
    let bounty_id = 1;
    let amount = 1000;
    let deadline = setup.env.ledger().timestamp() + 1000;

    setup
        .escrow
        .lock_funds(&setup.depositor, &bounty_id, &amount, &deadline);
    setup.escrow.release_funds(&bounty_id, &setup.contributor);

    setup
        .escrow
        .lock_funds(&setup.depositor, &bounty_id, &amount, &deadline);
}

// Invalid transition: Released → Released
#[test]
#[should_panic(expected = "Error(Contract, #5)")]
fn test_released_to_released_fails() {
    let setup = TestSetup::new();
    let bounty_id = 1;
    let amount = 1000;
    let deadline = setup.env.ledger().timestamp() + 1000;

    setup
        .escrow
        .lock_funds(&setup.depositor, &bounty_id, &amount, &deadline);
    setup.escrow.release_funds(&bounty_id, &setup.contributor);

    setup.escrow.release_funds(&bounty_id, &setup.contributor);
}

// Invalid transition: Released → Refunded
#[test]
#[should_panic(expected = "Error(Contract, #5)")]
fn test_released_to_refunded_fails() {
    let setup = TestSetup::new();
    let bounty_id = 1;
    let amount = 1000;
    let deadline = setup.env.ledger().timestamp() + 100;

    setup
        .escrow
        .lock_funds(&setup.depositor, &bounty_id, &amount, &deadline);
    setup.escrow.release_funds(&bounty_id, &setup.contributor);

    setup.env.ledger().set_timestamp(deadline + 1);
    setup.escrow.refund(&bounty_id);
}

// Invalid transition: Released → PartiallyRefunded
#[test]
#[should_panic(expected = "Error(Contract, #5)")]
fn test_released_to_partially_refunded_fails() {
    let setup = TestSetup::new();
    let bounty_id = 1;
    let amount = 1000;
    let deadline = setup.env.ledger().timestamp() + 100;

    setup
        .escrow
        .lock_funds(&setup.depositor, &bounty_id, &amount, &deadline);
    setup.escrow.release_funds(&bounty_id, &setup.contributor);

    setup.env.ledger().set_timestamp(deadline + 1);
    setup
        .escrow
        .partial_release(&bounty_id, &setup.contributor, &500);
}

// Invalid transition: Refunded → Locked
#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn test_refunded_to_locked_fails() {
    let setup = TestSetup::new();
    let bounty_id = 1;
    let amount = 1000;
    let deadline = setup.env.ledger().timestamp() + 100;

    setup
        .escrow
        .lock_funds(&setup.depositor, &bounty_id, &amount, &deadline);
    setup.env.ledger().set(LedgerInfo {
        timestamp: deadline + 1,
        protocol_version: 20,
        sequence_number: 0,
        network_id: Default::default(),
        base_reserve: 0,
        min_temp_entry_ttl: 0,
        min_persistent_entry_ttl: 0,
        max_entry_ttl: 0,
    });
    setup.escrow.refund(&bounty_id);

    setup
        .escrow
        .lock_funds(&setup.depositor, &bounty_id, &amount, &deadline);
}

// Invalid transition: Refunded → Released
#[test]
#[should_panic(expected = "Error(Contract, #5)")]
fn test_refunded_to_released_fails() {
    let setup = TestSetup::new();
    let bounty_id = 1;
    let amount = 1000;
    let deadline = setup.env.ledger().timestamp() + 100;

    setup
        .escrow
        .lock_funds(&setup.depositor, &bounty_id, &amount, &deadline);
    setup.env.ledger().set(LedgerInfo {
        timestamp: deadline + 1,
        protocol_version: 20,
        sequence_number: 0,
        network_id: Default::default(),
        base_reserve: 0,
        min_temp_entry_ttl: 0,
        min_persistent_entry_ttl: 0,
        max_entry_ttl: 0,
    });
    setup.escrow.refund(&bounty_id);

    setup.escrow.release_funds(&bounty_id, &setup.contributor);
}

// Invalid transition: Refunded → Refunded
#[test]
#[should_panic(expected = "Error(Contract, #5)")]
fn test_refunded_to_refunded_fails() {
    let setup = TestSetup::new();
    let bounty_id = 1;
    let amount = 1000;
    let deadline = setup.env.ledger().timestamp() + 100;

    setup
        .escrow
        .lock_funds(&setup.depositor, &bounty_id, &amount, &deadline);
    setup.env.ledger().set(LedgerInfo {
        timestamp: deadline + 1,
        protocol_version: 20,
        sequence_number: 0,
        network_id: Default::default(),
        base_reserve: 0,
        min_temp_entry_ttl: 0,
        min_persistent_entry_ttl: 0,
        max_entry_ttl: 0,
    });
    setup.escrow.refund(&bounty_id);

    setup.escrow.refund(&bounty_id);
}

// Invalid transition: Refunded → PartiallyRefunded
#[test]
#[should_panic(expected = "Error(Contract, #5)")]
fn test_refunded_to_partially_refunded_fails() {
    let setup = TestSetup::new();
    let bounty_id = 1;
    let amount = 1000;
    let deadline = setup.env.ledger().timestamp() + 100;

    setup
        .escrow
        .lock_funds(&setup.depositor, &bounty_id, &amount, &deadline);
    setup.env.ledger().set(LedgerInfo {
        timestamp: deadline + 1,
        protocol_version: 20,
        sequence_number: 0,
        network_id: Default::default(),
        base_reserve: 0,
        min_temp_entry_ttl: 0,
        min_persistent_entry_ttl: 0,
        max_entry_ttl: 0,
    });
    setup.escrow.refund(&bounty_id);

    setup
        .escrow
        .partial_release(&bounty_id, &setup.contributor, &100);
}

// Invalid transition: PartiallyRefunded → Locked
#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn test_partially_refunded_to_locked_fails() {
    let setup = TestSetup::new();
    let bounty_id = 1;
    let amount = 1000;
    let deadline = setup.env.ledger().timestamp() + 100;

    setup
        .escrow
        .lock_funds(&setup.depositor, &bounty_id, &amount, &deadline);
    setup
        .escrow
        .approve_refund(&bounty_id, &500, &setup.depositor, &RefundMode::Partial);
    setup.escrow.refund(&bounty_id);

    setup
        .escrow
        .lock_funds(&setup.depositor, &bounty_id, &amount, &deadline);
}

// Invalid transition: PartiallyRefunded → Released
#[test]
#[should_panic(expected = "Error(Contract, #5)")]
fn test_partially_refunded_to_released_fails() {
    let setup = TestSetup::new();
    let bounty_id = 1;
    let amount = 1000;
    let deadline = setup.env.ledger().timestamp() + 100;

    setup
        .escrow
        .lock_funds(&setup.depositor, &bounty_id, &amount, &deadline);
    setup
        .escrow
        .approve_refund(&bounty_id, &500, &setup.depositor, &RefundMode::Partial);
    setup.escrow.refund(&bounty_id);

    setup.escrow.release_funds(&bounty_id, &setup.contributor);
}

// ============================================================================
// FEE ROUTING INVARIANT TESTS
// ============================================================================
//
// These tests verify the core fee routing invariant:
//   fee_distributed_total == fee_amount
//
// Every stroop collected as a fee must be routed to exactly one recipient.
// No dust must be lost or double-counted.

/// Helper: build a setup with fee routing enabled and a treasury + partner split.
fn make_fee_routing_setup<'a>(
    env: &'a Env,
    treasury_weight: u32,
    partner_weight: u32,
    lock_fee_bps: i128,
    release_fee_bps: i128,
) -> (
    BountyEscrowContractClient<'a>,
    token::Client<'a>,
    token::StellarAssetClient<'a>,
    Address, // treasury
    Address, // partner
    Address, // depositor
    Address, // contributor
) {
    let admin = Address::generate(env);
    let (token, token_admin) = {
        let sac = env.register_stellar_asset_contract_v2(admin.clone());
        let addr = sac.address();
        (
            token::Client::new(env, &addr),
            token::StellarAssetClient::new(env, &addr),
        )
    };
    let escrow = {
        let id = env.register_contract(None, BountyEscrowContract);
        BountyEscrowContractClient::new(env, &id)
    };
    let treasury = Address::generate(env);
    let partner = Address::generate(env);
    let depositor = Address::generate(env);
    let contributor = Address::generate(env);

    escrow.init(&admin, &token.address);
    token_admin.mint(&depositor, &1_000_000);

    escrow.update_fee_config(
        &Some(lock_fee_bps),
        &Some(release_fee_bps),
        &Some(0),
        &Some(0),
        &Some(treasury.clone()),
        &Some(true),
    );

    let destinations = soroban_sdk::vec![
        env,
        TreasuryDestination {
            address: treasury.clone(),
            weight: treasury_weight,
            region: soroban_sdk::String::from_str(env, "Main"),
        },
        TreasuryDestination {
            address: partner.clone(),
            weight: partner_weight,
            region: soroban_sdk::String::from_str(env, "Partner"),
        },
    ];
    escrow.set_treasury_distributions(&destinations, &true);

    (escrow, token, token_admin, treasury, partner, depositor, contributor)
}

/// INV-FEE-1: fee + net == gross for a simple 50/50 lock fee split.
#[test]
fn test_fee_routing_invariant_50_50_lock_fee() {
    let env = Env::default();
    env.mock_all_auths();

    let (escrow, token, _token_admin, treasury, partner, depositor, _contributor) =
        make_fee_routing_setup(&env, 50, 50, 1000, 0); // 10% lock fee

    let gross = 1_000i128;
    let bounty_id = 10u64;
    let deadline = env.ledger().timestamp() + 1_000;

    escrow.lock_funds(&depositor, &bounty_id, &gross, &deadline);

    // fee = 10% of 1000 = 100; split 50/50 => 50 each
    let expected_fee = 100i128;
    let expected_net = gross - expected_fee;

    assert_eq!(token.balance(&treasury), 50, "treasury share must be 50");
    assert_eq!(token.balance(&partner), 50, "partner share must be 50");
    assert_eq!(
        token.balance(&treasury) + token.balance(&partner),
        expected_fee,
        "INV-FEE-1: distributed_total must equal fee_amount"
    );

    // Verify escrow stores net amount
    let stored = escrow.get_escrow_info(&bounty_id);
    assert_eq!(stored.amount, expected_net, "escrow stores net amount");
}

/// INV-FEE-2: remainder goes to last destination (no dust lost) for odd splits.
#[test]
fn test_fee_routing_invariant_remainder_to_last_destination() {
    let env = Env::default();
    env.mock_all_auths();

    // 70/30 split on a fee that doesn't divide evenly
    let (escrow, token, _token_admin, treasury, partner, depositor, _contributor) =
        make_fee_routing_setup(&env, 70, 30, 333, 0); // 3.33% lock fee

    let gross = 1_000i128;
    let bounty_id = 11u64;
    let deadline = env.ledger().timestamp() + 1_000;

    escrow.lock_funds(&depositor, &bounty_id, &gross, &deadline);

    // fee = floor(1000 * 333 / 10000) = 33
    let expected_fee = 33i128;
    let treasury_share = token.balance(&treasury);
    let partner_share = token.balance(&partner);

    // Invariant: every stroop of the fee is distributed
    assert_eq!(
        treasury_share + partner_share,
        expected_fee,
        "INV-FEE-2: no dust lost — distributed_total == fee_amount"
    );
    // Remainder goes to last destination (partner)
    let expected_treasury = expected_fee * 70 / 100; // floor
    assert_eq!(treasury_share, expected_treasury, "treasury gets floor share");
    assert_eq!(
        partner_share,
        expected_fee - expected_treasury,
        "partner absorbs remainder"
    );
}

/// INV-FEE-3: release fee routing invariant holds.
#[test]
fn test_fee_routing_invariant_release_fee() {
    let env = Env::default();
    env.mock_all_auths();

    let (escrow, token, _token_admin, treasury, partner, depositor, contributor) =
        make_fee_routing_setup(&env, 60, 40, 0, 500); // 5% release fee

    let gross = 2_000i128;
    let bounty_id = 12u64;
    let deadline = env.ledger().timestamp() + 1_000;

    escrow.lock_funds(&depositor, &bounty_id, &gross, &deadline);
    escrow.release_funds(&bounty_id, &contributor);

    // release fee = floor(2000 * 500 / 10000) = 100; split 60/40 => 60, 40
    let expected_fee = 100i128;
    assert_eq!(
        token.balance(&treasury) + token.balance(&partner),
        expected_fee,
        "INV-FEE-3: release fee distributed_total == fee_amount"
    );
    assert_eq!(token.balance(&treasury), 60);
    assert_eq!(token.balance(&partner), 40);
    assert_eq!(token.balance(&contributor), gross - expected_fee);
}

/// INV-FEE-4: when distribution is disabled, full fee goes to single recipient.
#[test]
fn test_fee_routing_invariant_single_recipient_fallback() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let (token, token_admin) = {
        let sac = env.register_stellar_asset_contract_v2(admin.clone());
        let addr = sac.address();
        (
            token::Client::new(&env, &addr),
            token::StellarAssetClient::new(&env, &addr),
        )
    };
    let escrow = {
        let id = env.register_contract(None, BountyEscrowContract);
        BountyEscrowContractClient::new(&env, &id)
    };
    let treasury = Address::generate(&env);
    let depositor = Address::generate(&env);
    let contributor = Address::generate(&env);

    escrow.init(&admin, &token.address);
    token_admin.mint(&depositor, &10_000);

    escrow.update_fee_config(
        &Some(1000), // 10% lock fee
        &Some(0),
        &Some(0),
        &Some(0),
        &Some(treasury.clone()),
        &Some(true),
    );
    // Disable distribution — fallback to single recipient
    escrow.set_treasury_distributions(&soroban_sdk::vec![&env], &false);

    let gross = 1_000i128;
    let bounty_id = 13u64;
    escrow.lock_funds(&depositor, &bounty_id, &gross, &(env.ledger().timestamp() + 1_000));

    let expected_fee = 100i128;
    assert_eq!(
        token.balance(&treasury),
        expected_fee,
        "INV-FEE-4: single recipient gets full fee"
    );
    let stored = escrow.get_escrow_info(&bounty_id);
    assert_eq!(stored.amount, gross - expected_fee);
    // Verify contract holds no residual fee balance
    let contract_id = escrow.address.clone();
    assert_eq!(
        token.balance(&contract_id),
        gross - expected_fee,
        "contract holds only escrowed net amount"
    );
    escrow.release_funds(&bounty_id, &contributor);
    assert_eq!(token.balance(&contract_id), 0, "contract drained after release");
}

/// INV-FEE-5: zero fee rate produces no fee transfer and invariant holds trivially.
#[test]
fn test_fee_routing_invariant_zero_fee_rate() {
    let env = Env::default();
    env.mock_all_auths();

    let (escrow, token, _token_admin, treasury, partner, depositor, contributor) =
        make_fee_routing_setup(&env, 50, 50, 0, 0); // no fees

    let gross = 500i128;
    let bounty_id = 14u64;
    let deadline = env.ledger().timestamp() + 1_000;

    escrow.lock_funds(&depositor, &bounty_id, &gross, &deadline);
    escrow.release_funds(&bounty_id, &contributor);

    // No fee collected
    assert_eq!(token.balance(&treasury), 0, "no fee to treasury");
    assert_eq!(token.balance(&partner), 0, "no fee to partner");
    assert_eq!(token.balance(&contributor), gross, "contributor gets full gross");
}

/// INV-FEE-6: combined lock + release fees — both invariants hold independently.
#[test]
fn test_fee_routing_invariant_combined_lock_and_release_fees() {
    let env = Env::default();
    env.mock_all_auths();

    let (escrow, token, _token_admin, treasury, partner, depositor, contributor) =
        make_fee_routing_setup(&env, 50, 50, 200, 300); // 2% lock, 3% release

    let gross = 10_000i128;
    let bounty_id = 15u64;
    let deadline = env.ledger().timestamp() + 1_000;

    escrow.lock_funds(&depositor, &bounty_id, &gross, &deadline);

    // lock fee = floor(10000 * 200 / 10000) = 200; split 50/50 => 100 each
    let lock_fee = 200i128;
    let net_escrowed = gross - lock_fee;

    assert_eq!(
        token.balance(&treasury) + token.balance(&partner),
        lock_fee,
        "INV-FEE-6a: lock fee invariant"
    );

    escrow.release_funds(&bounty_id, &contributor);

    // release fee = floor(net_escrowed * 300 / 10000) = floor(9800 * 300 / 10000) = 294
    let release_fee = net_escrowed * 300 / 10_000;
    let total_fee = lock_fee + release_fee;

    assert_eq!(
        token.balance(&treasury) + token.balance(&partner),
        total_fee,
        "INV-FEE-6b: combined fee invariant"
    );
    assert_eq!(
        token.balance(&contributor),
        net_escrowed - release_fee,
        "contributor receives net after release fee"
    );
}

/// INV-FEE-7: upgrade-safe storage — FeeRoutingSchemaVersion is written on init.
#[test]
fn test_fee_routing_schema_version_written_on_init() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let (token, _token_admin) = {
        let sac = env.register_stellar_asset_contract_v2(admin.clone());
        let addr = sac.address();
        (
            token::Client::new(&env, &addr),
            token::StellarAssetClient::new(&env, &addr),
        )
    };
    let contract_id = env.register_contract(None, BountyEscrowContract);
    let escrow = BountyEscrowContractClient::new(&env, &contract_id);

    escrow.init(&admin, &token.address);

    // The schema version key must be present after init
    let schema_version: u32 = env.as_contract(&contract_id, || {
        env.storage()
            .instance()
            .get(&DataKey::FeeRoutingSchemaVersion)
            .expect("FeeRoutingSchemaVersion must be set after init")
    });
    assert_eq!(schema_version, 1u32, "schema version must be v1 after init");
}

/// INV-FEE-8: no double-fee on release retry (idempotency guard).
#[test]
fn test_fee_routing_no_double_fee_on_release_retry() {
    let env = Env::default();
    env.mock_all_auths();

    let (escrow, token, _token_admin, treasury, partner, depositor, contributor) =
        make_fee_routing_setup(&env, 50, 50, 0, 1000); // 10% release fee

    let gross = 1_000i128;
    let bounty_id = 16u64;
    let deadline = env.ledger().timestamp() + 1_000;

    escrow.lock_funds(&depositor, &bounty_id, &gross, &deadline);
    escrow.release_funds(&bounty_id, &contributor);

    let fee_after_first = token.balance(&treasury) + token.balance(&partner);

    // Second release attempt must fail (FundsNotLocked)
    let result = escrow.try_release_funds(&bounty_id, &contributor);
    assert!(result.is_err(), "second release must fail");

    // Fee must not have been collected twice
    assert_eq!(
        token.balance(&treasury) + token.balance(&partner),
        fee_after_first,
        "INV-FEE-8: fee must not be double-collected"
    );
}

/// INV-FEE-9: multi-destination weight sum overflow is rejected gracefully.
#[test]
fn test_fee_routing_rejects_zero_weight_destination() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let (token, _token_admin) = {
        let sac = env.register_stellar_asset_contract_v2(admin.clone());
        let addr = sac.address();
        (
            token::Client::new(&env, &addr),
            token::StellarAssetClient::new(&env, &addr),
        )
    };
    let escrow = {
        let id = env.register_contract(None, BountyEscrowContract);
        BountyEscrowContractClient::new(&env, &id)
    };
    let treasury = Address::generate(&env);
    let partner = Address::generate(&env);

    escrow.init(&admin, &token.address);
    escrow.update_fee_config(
        &Some(1000),
        &Some(0),
        &Some(0),
        &Some(0),
        &Some(treasury.clone()),
        &Some(true),
    );

    // Zero weight must be rejected
    let bad_destinations = soroban_sdk::vec![
        &env,
        TreasuryDestination {
            address: treasury.clone(),
            weight: 0, // invalid
            region: soroban_sdk::String::from_str(&env, "Main"),
        },
        TreasuryDestination {
            address: partner.clone(),
            weight: 100,
            region: soroban_sdk::String::from_str(&env, "Partner"),
        },
    ];
    let result = escrow.try_set_treasury_distributions(&bad_destinations, &true);
    assert!(result.is_err(), "zero-weight destination must be rejected");
}

/// INV-FEE-10: fee routing invariant holds for a single-destination split (edge case).
#[test]
fn test_fee_routing_invariant_single_destination() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let (token, token_admin) = {
        let sac = env.register_stellar_asset_contract_v2(admin.clone());
        let addr = sac.address();
        (
            token::Client::new(&env, &addr),
            token::StellarAssetClient::new(&env, &addr),
        )
    };
    let escrow = {
        let id = env.register_contract(None, BountyEscrowContract);
        BountyEscrowContractClient::new(&env, &id)
    };
    let treasury = Address::generate(&env);
    let depositor = Address::generate(&env);
    let contributor = Address::generate(&env);

    escrow.init(&admin, &token.address);
    token_admin.mint(&depositor, &5_000);

    escrow.update_fee_config(
        &Some(500), // 5% lock fee
        &Some(0),
        &Some(0),
        &Some(0),
        &Some(treasury.clone()),
        &Some(true),
    );
    let destinations = soroban_sdk::vec![
        &env,
        TreasuryDestination {
            address: treasury.clone(),
            weight: 100,
            region: soroban_sdk::String::from_str(&env, "Main"),
        },
    ];
    escrow.set_treasury_distributions(&destinations, &true);

    let gross = 2_000i128;
    let bounty_id = 17u64;
    escrow.lock_funds(&depositor, &bounty_id, &gross, &(env.ledger().timestamp() + 1_000));

    let expected_fee = gross * 500 / 10_000; // 100
    assert_eq!(
        token.balance(&treasury),
        expected_fee,
        "INV-FEE-10: single destination receives full fee"
    );
    let stored = escrow.get_escrow_info(&bounty_id);
    assert_eq!(stored.amount, gross - expected_fee);
    escrow.release_funds(&bounty_id, &contributor);
    assert_eq!(token.balance(&contributor), gross - expected_fee);
}

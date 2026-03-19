/* tslint:disable */
/* eslint-disable */

export class ForeignFutureCompleteRustBuffer {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    call(_ctx: ForeignFutureCompleteF32, callback_data: bigint, result: any): void;
    call(_ctx: ForeignFutureCompleteF64, callback_data: bigint, result: any): void;
    call(_ctx: ForeignFutureCompleteI16, callback_data: bigint, result: any): void;
    call(_ctx: ForeignFutureCompleteI32, callback_data: bigint, result: any): void;
    call(_ctx: ForeignFutureCompleteI64, callback_data: bigint, result: any): void;
    call(_ctx: ForeignFutureCompleteI8, callback_data: bigint, result: any): void;
    call(_ctx: ForeignFutureCompletePointer, callback_data: bigint, result: any): void;
    call(_ctx: ForeignFutureCompleteRustBuffer, callback_data: bigint, result: any): void;
    call(_ctx: ForeignFutureCompleteU16, callback_data: bigint, result: any): void;
    call(_ctx: ForeignFutureCompleteU32, callback_data: bigint, result: any): void;
    call(_ctx: ForeignFutureCompleteU64, callback_data: bigint, result: any): void;
    call(_ctx: ForeignFutureCompleteU8, callback_data: bigint, result: any): void;
    call(_ctx: ForeignFutureCompleteVoid, callback_data: bigint, result: any): void;
}

export class RustCallStatus {
    free(): void;
    [Symbol.dispose](): void;
    constructor();
    code: number;
    get errorBuf(): Uint8Array | undefined;
    set errorBuf(value: Uint8Array | null | undefined);
}

export function ubrn_ffi_iota_sdk_ffi_rust_future_cancel_f32(handle: bigint): void;

export function ubrn_ffi_iota_sdk_ffi_rust_future_cancel_f64(handle: bigint): void;

export function ubrn_ffi_iota_sdk_ffi_rust_future_cancel_i16(handle: bigint): void;

export function ubrn_ffi_iota_sdk_ffi_rust_future_cancel_i32(handle: bigint): void;

export function ubrn_ffi_iota_sdk_ffi_rust_future_cancel_i64(handle: bigint): void;

export function ubrn_ffi_iota_sdk_ffi_rust_future_cancel_i8(handle: bigint): void;

export function ubrn_ffi_iota_sdk_ffi_rust_future_cancel_pointer(handle: bigint): void;

export function ubrn_ffi_iota_sdk_ffi_rust_future_cancel_rust_buffer(handle: bigint): void;

export function ubrn_ffi_iota_sdk_ffi_rust_future_cancel_u16(handle: bigint): void;

export function ubrn_ffi_iota_sdk_ffi_rust_future_cancel_u32(handle: bigint): void;

export function ubrn_ffi_iota_sdk_ffi_rust_future_cancel_u64(handle: bigint): void;

export function ubrn_ffi_iota_sdk_ffi_rust_future_cancel_u8(handle: bigint): void;

export function ubrn_ffi_iota_sdk_ffi_rust_future_cancel_void(handle: bigint): void;

export function ubrn_ffi_iota_sdk_ffi_rust_future_complete_f32(handle: bigint, f_status_: RustCallStatus): number;

export function ubrn_ffi_iota_sdk_ffi_rust_future_complete_f64(handle: bigint, f_status_: RustCallStatus): number;

export function ubrn_ffi_iota_sdk_ffi_rust_future_complete_i16(handle: bigint, f_status_: RustCallStatus): number;

export function ubrn_ffi_iota_sdk_ffi_rust_future_complete_i32(handle: bigint, f_status_: RustCallStatus): number;

export function ubrn_ffi_iota_sdk_ffi_rust_future_complete_i64(handle: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_ffi_iota_sdk_ffi_rust_future_complete_i8(handle: bigint, f_status_: RustCallStatus): number;

export function ubrn_ffi_iota_sdk_ffi_rust_future_complete_pointer(handle: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_ffi_iota_sdk_ffi_rust_future_complete_rust_buffer(handle: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_ffi_iota_sdk_ffi_rust_future_complete_u16(handle: bigint, f_status_: RustCallStatus): number;

export function ubrn_ffi_iota_sdk_ffi_rust_future_complete_u32(handle: bigint, f_status_: RustCallStatus): number;

export function ubrn_ffi_iota_sdk_ffi_rust_future_complete_u64(handle: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_ffi_iota_sdk_ffi_rust_future_complete_u8(handle: bigint, f_status_: RustCallStatus): number;

export function ubrn_ffi_iota_sdk_ffi_rust_future_complete_void(handle: bigint, f_status_: RustCallStatus): void;

export function ubrn_ffi_iota_sdk_ffi_rust_future_free_f32(handle: bigint): void;

export function ubrn_ffi_iota_sdk_ffi_rust_future_free_f64(handle: bigint): void;

export function ubrn_ffi_iota_sdk_ffi_rust_future_free_i16(handle: bigint): void;

export function ubrn_ffi_iota_sdk_ffi_rust_future_free_i32(handle: bigint): void;

export function ubrn_ffi_iota_sdk_ffi_rust_future_free_i64(handle: bigint): void;

export function ubrn_ffi_iota_sdk_ffi_rust_future_free_i8(handle: bigint): void;

export function ubrn_ffi_iota_sdk_ffi_rust_future_free_pointer(handle: bigint): void;

export function ubrn_ffi_iota_sdk_ffi_rust_future_free_rust_buffer(handle: bigint): void;

export function ubrn_ffi_iota_sdk_ffi_rust_future_free_u16(handle: bigint): void;

export function ubrn_ffi_iota_sdk_ffi_rust_future_free_u32(handle: bigint): void;

export function ubrn_ffi_iota_sdk_ffi_rust_future_free_u64(handle: bigint): void;

export function ubrn_ffi_iota_sdk_ffi_rust_future_free_u8(handle: bigint): void;

export function ubrn_ffi_iota_sdk_ffi_rust_future_free_void(handle: bigint): void;

export function ubrn_ffi_iota_sdk_ffi_rust_future_poll_f32(handle: bigint, callback: any, callback_data: bigint): void;

export function ubrn_ffi_iota_sdk_ffi_rust_future_poll_f64(handle: bigint, callback: any, callback_data: bigint): void;

export function ubrn_ffi_iota_sdk_ffi_rust_future_poll_i16(handle: bigint, callback: any, callback_data: bigint): void;

export function ubrn_ffi_iota_sdk_ffi_rust_future_poll_i32(handle: bigint, callback: any, callback_data: bigint): void;

export function ubrn_ffi_iota_sdk_ffi_rust_future_poll_i64(handle: bigint, callback: any, callback_data: bigint): void;

export function ubrn_ffi_iota_sdk_ffi_rust_future_poll_i8(handle: bigint, callback: any, callback_data: bigint): void;

export function ubrn_ffi_iota_sdk_ffi_rust_future_poll_pointer(handle: bigint, callback: any, callback_data: bigint): void;

export function ubrn_ffi_iota_sdk_ffi_rust_future_poll_rust_buffer(handle: bigint, callback: any, callback_data: bigint): void;

export function ubrn_ffi_iota_sdk_ffi_rust_future_poll_u16(handle: bigint, callback: any, callback_data: bigint): void;

export function ubrn_ffi_iota_sdk_ffi_rust_future_poll_u32(handle: bigint, callback: any, callback_data: bigint): void;

export function ubrn_ffi_iota_sdk_ffi_rust_future_poll_u64(handle: bigint, callback: any, callback_data: bigint): void;

export function ubrn_ffi_iota_sdk_ffi_rust_future_poll_u8(handle: bigint, callback: any, callback_data: bigint): void;

export function ubrn_ffi_iota_sdk_ffi_rust_future_poll_void(handle: bigint, callback: any, callback_data: bigint): void;

export function ubrn_ffi_iota_sdk_ffi_uniffi_contract_version(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_address_framework(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_address_from_bytes(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_address_from_hex(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_address_generate(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_address_std(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_address_system(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_address_zero(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_argument_new_gas(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_argument_new_input(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_argument_new_nested_result(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_argument_new_result(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_bls12381privatekey_generate(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_bls12381privatekey_new(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_bls12381publickey_from_bytes(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_bls12381publickey_from_str(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_bls12381publickey_generate(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_bls12381signature_from_bytes(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_bls12381signature_from_str(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_bls12381signature_generate(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_bls12381verifyingkey_new(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_bn254fieldelement_from_bytes(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_bn254fieldelement_from_str(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_bn254fieldelement_from_str_radix_10(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_cancelledtransaction_new(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_changeepoch_new(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_changeepochv2_new(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_changeepochv3_new(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_changeepochv4_new(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_checkpointcontents_new(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_checkpointsummary_new(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_checkpointtransactioninfo_new(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_circomg1_new(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_circomg2_new(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_coin_try_from_object(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_command_new_make_move_vector(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_command_new_merge_coins(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_command_new_move_call(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_command_new_publish(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_command_new_split_coins(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_command_new_transfer_objects(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_command_new_upgrade(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_consensuscommitprologuev1_new(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_consensusdeterminedversionassignments_new_cancelled_transactions(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_digest_from_base58(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_digest_from_bytes(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_digest_generate(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_ed25519privatekey_from_bech32(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_ed25519privatekey_from_der(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_ed25519privatekey_from_mnemonic(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_ed25519privatekey_from_mnemonic_with_path(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_ed25519privatekey_from_pem(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_ed25519privatekey_generate(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_ed25519privatekey_new(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_ed25519publickey_from_bytes(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_ed25519publickey_from_str(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_ed25519publickey_generate(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_ed25519signature_from_bytes(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_ed25519signature_from_str(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_ed25519signature_generate(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_ed25519verifier_new(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_ed25519verifyingkey_from_der(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_ed25519verifyingkey_from_pem(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_ed25519verifyingkey_new(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_endofepochtransactionkind_new_authenticator_state_create(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_endofepochtransactionkind_new_authenticator_state_expire(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_endofepochtransactionkind_new_change_epoch(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_endofepochtransactionkind_new_change_epoch_v2(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_endofepochtransactionkind_new_change_epoch_v3(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_endofepochtransactionkind_new_change_epoch_v4(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_executiontimeobservation_new(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_executiontimeobservationkey_new_make_move_vec(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_executiontimeobservationkey_new_merge_coins(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_executiontimeobservationkey_new_move_entry_point(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_executiontimeobservationkey_new_publish(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_executiontimeobservationkey_new_split_coins(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_executiontimeobservationkey_new_transfer_objects(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_executiontimeobservationkey_new_upgrade(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_executiontimeobservations_new_v1(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_faucetclient_new(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_faucetclient_new_devnet(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_faucetclient_new_localnet(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_faucetclient_new_testnet(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_genesisobject_new(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_genesistransaction_new(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_graphqlclient_new(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_graphqlclient_new_devnet(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_graphqlclient_new_localnet(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_graphqlclient_new_mainnet(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_graphqlclient_new_testnet(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_identifier_new(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_input_new_immutable_or_owned(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_input_new_pure(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_input_new_receiving(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_input_new_shared(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_intent_from_bytes(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_intent_from_hex(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_intent_new(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_intent_new_consensus_app(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_intent_new_iota_app(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_intent_new_iota_transaction(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_intent_new_personal_message(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_makemovevector_new(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_mergecoins_new(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_movearg_address(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_movearg_address_from_hex(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_movearg_address_vec(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_movearg_address_vec_from_hex(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_movearg_bool(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_movearg_bool_vec(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_movearg_digest(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_movearg_digest_from_base58(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_movearg_digest_vec(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_movearg_digest_vec_from_base58(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_movearg_option(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_movearg_string(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_movearg_string_vec(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_movearg_u128(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_movearg_u128_vec(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_movearg_u16(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_movearg_u16_vec(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_movearg_u256(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_movearg_u256_vec(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_movearg_u32(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_movearg_u32_vec(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_movearg_u64(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_movearg_u64_vec(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_movearg_u8(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_movearg_u8_vec(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_moveauthenticator_new_immutable(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_moveauthenticator_new_shared(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_moveauthenticatorbuilder_new(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_movecall_new(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_movepackage_new(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_movepackagedata_from_base64(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_movepackagedata_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_movepackagedata_new(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_moveviewarg_address(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_moveviewarg_bool(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_moveviewarg_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_moveviewarg_null(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_moveviewarg_object_id(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_moveviewarg_option(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_moveviewarg_string(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_moveviewarg_string_vec(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_moveviewarg_u128(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_moveviewarg_u16(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_moveviewarg_u32(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_moveviewarg_u64(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_moveviewarg_u8(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_moveviewarg_u8_vec(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_multisigaggregatedsignature_new(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_multisigaggregator_new_with_message(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_multisigaggregator_new_with_transaction(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_multisigcommittee_new(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_multisigmember_new(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_multisigverifier_new(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_name_from_str(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_nameregistration_new(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_object_new(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_objectdata_new_move_package(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_objectdata_new_move_struct(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_objectid_clock(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_objectid_derive_id(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_objectid_from_bytes(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_objectid_from_hex(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_objectid_system(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_objectid_zero(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_objecttype_new_package(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_objecttype_new_struct(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_owner_new_address(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_owner_new_immutable(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_owner_new_object(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_owner_new_shared(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_passkeypublickey_new(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_passkeyverifier_new(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_personalmessage_new(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_programmabletransaction_new(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_ptbargument_address(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_ptbargument_address_from_hex(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_ptbargument_address_vec(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_ptbargument_address_vec_from_hex(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_ptbargument_assigned(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_ptbargument_bool(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_ptbargument_bool_vec(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_ptbargument_digest(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_ptbargument_digest_from_base58(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_ptbargument_digest_vec(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_ptbargument_digest_vec_from_base58(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_ptbargument_gas(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_ptbargument_move_arg(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_ptbargument_object_id(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_ptbargument_object_id_from_hex(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_ptbargument_object_ref(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_ptbargument_option(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_ptbargument_receiving(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_ptbargument_receiving_from_hex(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_ptbargument_shared(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_ptbargument_shared_from_hex(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_ptbargument_shared_mut(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_ptbargument_shared_mut_from_hex(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_ptbargument_string(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_ptbargument_u128(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_ptbargument_u128_vec(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_ptbargument_u16(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_ptbargument_u16_vec(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_ptbargument_u256(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_ptbargument_u256_vec(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_ptbargument_u32(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_ptbargument_u32_vec(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_ptbargument_u64(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_ptbargument_u64_vec(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_ptbargument_u8(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_ptbargument_u8_vec(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_publish_new(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_secp256k1privatekey_from_bech32(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_secp256k1privatekey_from_der(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_secp256k1privatekey_from_mnemonic(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_secp256k1privatekey_from_mnemonic_with_path(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_secp256k1privatekey_from_pem(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_secp256k1privatekey_generate(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_secp256k1privatekey_new(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_secp256k1publickey_from_bytes(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_secp256k1publickey_from_str(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_secp256k1publickey_generate(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_secp256k1signature_from_bytes(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_secp256k1signature_from_str(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_secp256k1signature_generate(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_secp256k1verifier_new(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_secp256k1verifyingkey_from_der(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_secp256k1verifyingkey_from_pem(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_secp256k1verifyingkey_new(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_secp256r1privatekey_from_bech32(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_secp256r1privatekey_from_der(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_secp256r1privatekey_from_mnemonic(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_secp256r1privatekey_from_mnemonic_with_path(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_secp256r1privatekey_from_pem(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_secp256r1privatekey_generate(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_secp256r1privatekey_new(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_secp256r1publickey_from_bytes(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_secp256r1publickey_from_str(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_secp256r1publickey_generate(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_secp256r1signature_from_bytes(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_secp256r1signature_from_str(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_secp256r1signature_generate(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_secp256r1verifier_new(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_secp256r1verifyingkey_from_der(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_secp256r1verifyingkey_from_pem(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_secp256r1verifyingkey_new(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_simplekeypair_from_bech32(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_simplekeypair_from_bytes(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_simplekeypair_from_der(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_simplekeypair_from_ed25519(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_simplekeypair_from_pem(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_simplekeypair_from_secp256k1(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_simplekeypair_from_secp256r1(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_simplesignature_new_ed25519(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_simplesignature_new_secp256k1(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_simplesignature_new_secp256r1(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_simpleverifier_new(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_simpleverifyingkey_from_der(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_simpleverifyingkey_from_pem(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_splitcoins_new(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_structtag_new(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_structtag_new_ascii_string(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_structtag_new_balance(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_structtag_new_clock(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_structtag_new_coin(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_structtag_new_coin_manager(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_structtag_new_coin_metadata(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_structtag_new_config(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_structtag_new_config_setting(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_structtag_new_deny_list_address_key(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_structtag_new_deny_list_config_key(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_structtag_new_deny_list_global_pause_key(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_structtag_new_display_created(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_structtag_new_dynamic_object_field_wrapper(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_structtag_new_field(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_structtag_new_gas_coin(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_structtag_new_id(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_structtag_new_iota_coin_type(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_structtag_new_iota_system_admin_cap(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_structtag_new_iota_system_state(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_structtag_new_iota_treasury_cap(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_structtag_new_name(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_structtag_new_staked_iota(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_structtag_new_string(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_structtag_new_system_epoch_info_event(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_structtag_new_time_lock(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_structtag_new_timelocked_staked_iota(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_structtag_new_transfer_receiving(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_structtag_new_treasury_cap(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_structtag_new_uid(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_structtag_new_upgrade_cap(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_structtag_new_upgrade_receipt(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_structtag_new_upgrade_ticket(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_structtag_new_version_updated(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_systempackage_new(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_transaction_from_base64(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_transaction_new_v1(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_transactionbuilder_new(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_transactioneffects_new_v1(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_transactionevents_new(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_transactionkind_new_authenticator_state_update_v1(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_transactionkind_new_consensus_commit_prologue_v1(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_transactionkind_new_end_of_epoch(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_transactionkind_new_genesis(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_transactionkind_new_programmable_transaction(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_transactionkind_new_randomness_state_update(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_transactionsigner_from_ed25519(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_transactionsigner_from_keypair(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_transactionsigner_from_move_authenticator(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_transactionsigner_from_secp256k1(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_transactionsigner_from_secp256r1(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_transactionsigner_new(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_transactionv1_from_base64(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_transactionv1_new(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_transferobjects_new(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_typetag_new_address(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_typetag_new_bool(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_typetag_new_signer(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_typetag_new_struct(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_typetag_new_u128(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_typetag_new_u16(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_typetag_new_u256(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_typetag_new_u32(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_typetag_new_u64(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_typetag_new_u8(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_typetag_new_vector(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_upgrade_new(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_upgradepolicy_additive(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_upgradepolicy_compatible(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_upgradepolicy_dep_only(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_usersignature_from_base64(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_usersignature_from_bytes(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_usersignature_new_move_authenticator(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_usersignature_new_multisig(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_usersignature_new_passkey_authenticator(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_usersignature_new_simple(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_usersignature_new_zklogin_authenticator(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_usersignatureverifier_new(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_validatoraggregatedsignature_new(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_validatorcommitteesignatureaggregator_new_checkpoint_summary(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_validatorcommitteesignatureverifier_new(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_validatorexecutiontimeobservation_new(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_validatorsignature_new(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_versionassignment_new(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_zkloginauthenticator_new(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_zklogininputs_new(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_zkloginproof_new(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_zkloginpublicidentifier_new(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_zkloginverifier_new_dev(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_constructor_zkloginverifier_new_mainnet(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_active_jwk_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_active_jwk_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_active_jwk_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_active_jwk_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_address_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_address_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_address_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_address_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_argument_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_argument_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_argument_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_argument_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_authenticator_state_expire_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_authenticator_state_expire_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_authenticator_state_expire_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_authenticator_state_expire_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_authenticator_state_update_v1_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_authenticator_state_update_v1_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_authenticator_state_update_v1_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_authenticator_state_update_v1_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_base64_decode(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_base64_encode(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_bls12381_public_key_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_bls12381_public_key_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_bls12381_public_key_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_bls12381_public_key_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_bls12381_signature_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_bls12381_signature_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_bls12381_signature_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_bls12381_signature_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_bn254_field_element_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_bn254_field_element_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_bn254_field_element_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_bn254_field_element_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_bool_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_bool_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_bool_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_bool_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_cancelled_transaction_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_cancelled_transaction_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_cancelled_transaction_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_cancelled_transaction_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_change_epoch_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_change_epoch_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_change_epoch_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_change_epoch_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_change_epoch_v2_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_change_epoch_v2_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_change_epoch_v2_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_change_epoch_v2_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_changed_object_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_changed_object_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_changed_object_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_changed_object_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_checkpoint_commitment_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_checkpoint_commitment_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_checkpoint_commitment_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_checkpoint_commitment_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_checkpoint_contents_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_checkpoint_contents_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_checkpoint_contents_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_checkpoint_contents_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_checkpoint_summary_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_checkpoint_summary_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_checkpoint_summary_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_checkpoint_summary_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_checkpoint_transaction_info_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_checkpoint_transaction_info_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_checkpoint_transaction_info_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_checkpoint_transaction_info_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_circom_g1_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_circom_g1_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_circom_g1_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_circom_g1_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_circom_g2_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_circom_g2_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_circom_g2_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_circom_g2_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_command_argument_error_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_command_argument_error_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_command_argument_error_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_command_argument_error_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_command_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_command_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_command_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_command_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_consensus_commit_prologue_v1_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_consensus_commit_prologue_v1_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_consensus_commit_prologue_v1_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_consensus_commit_prologue_v1_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_consensus_determined_version_assignments_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_consensus_determined_version_assignments_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_consensus_determined_version_assignments_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_consensus_determined_version_assignments_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_digest_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_digest_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_digest_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_digest_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_ed25519_public_key_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_ed25519_public_key_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_ed25519_public_key_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_ed25519_public_key_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_ed25519_signature_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_ed25519_signature_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_ed25519_signature_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_ed25519_signature_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_end_of_epoch_data_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_end_of_epoch_data_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_end_of_epoch_data_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_end_of_epoch_data_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_event_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_event_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_event_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_event_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_execution_error_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_execution_error_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_execution_error_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_execution_error_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_execution_status_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_execution_status_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_execution_status_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_execution_status_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_execution_time_observation_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_execution_time_observation_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_execution_time_observation_key_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_execution_time_observation_key_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_execution_time_observation_key_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_execution_time_observation_key_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_execution_time_observation_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_execution_time_observation_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_execution_time_observations_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_execution_time_observations_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_execution_time_observations_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_execution_time_observations_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_gas_cost_summary_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_gas_cost_summary_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_gas_cost_summary_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_gas_cost_summary_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_gas_payment_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_gas_payment_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_gas_payment_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_gas_payment_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_generate_mnemonic(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_genesis_object_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_genesis_object_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_genesis_object_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_genesis_object_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_genesis_transaction_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_genesis_transaction_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_genesis_transaction_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_genesis_transaction_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_hex_decode(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_hex_encode(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_i16_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_i16_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_i16_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_i16_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_i32_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_i32_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_i32_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_i32_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_i64_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_i64_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_i64_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_i64_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_i8_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_i8_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_i8_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_i8_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_id_operation_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_id_operation_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_id_operation_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_id_operation_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_identifier_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_identifier_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_identifier_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_identifier_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_input_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_input_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_input_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_input_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_jwk_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_jwk_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_jwk_id_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_jwk_id_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_jwk_id_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_jwk_id_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_jwk_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_jwk_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_make_move_vector_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_make_move_vector_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_make_move_vector_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_make_move_vector_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_merge_coins_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_merge_coins_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_merge_coins_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_merge_coins_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_move_call_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_move_call_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_move_call_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_move_call_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_move_location_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_move_location_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_move_location_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_move_location_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_move_package_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_move_package_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_move_package_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_move_package_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_move_struct_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_move_struct_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_move_struct_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_move_struct_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_multisig_aggregated_signature_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_multisig_aggregated_signature_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_multisig_aggregated_signature_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_multisig_aggregated_signature_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_multisig_committee_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_multisig_committee_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_multisig_committee_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_multisig_committee_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_multisig_member_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_multisig_member_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_multisig_member_public_key_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_multisig_member_public_key_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_multisig_member_public_key_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_multisig_member_public_key_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_multisig_member_signature_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_multisig_member_signature_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_multisig_member_signature_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_multisig_member_signature_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_multisig_member_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_multisig_member_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_object_data_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_object_data_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_object_data_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_object_data_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_object_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_object_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_object_id_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_object_id_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_object_id_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_object_id_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_object_in_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_object_in_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_object_in_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_object_in_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_object_out_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_object_out_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_object_out_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_object_out_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_object_reference_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_object_reference_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_object_reference_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_object_reference_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_object_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_object_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_owner_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_owner_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_owner_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_owner_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_package_upgrade_error_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_package_upgrade_error_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_package_upgrade_error_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_package_upgrade_error_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_passkey_authenticator_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_passkey_authenticator_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_passkey_authenticator_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_passkey_authenticator_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_programmable_transaction_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_programmable_transaction_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_programmable_transaction_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_programmable_transaction_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_publish_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_publish_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_publish_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_publish_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_randomness_state_update_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_randomness_state_update_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_randomness_state_update_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_randomness_state_update_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_secp256k1_public_key_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_secp256k1_public_key_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_secp256k1_public_key_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_secp256k1_public_key_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_secp256k1_signature_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_secp256k1_signature_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_secp256k1_signature_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_secp256k1_signature_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_secp256r1_public_key_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_secp256r1_public_key_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_secp256r1_public_key_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_secp256r1_public_key_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_secp256r1_signature_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_secp256r1_signature_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_secp256r1_signature_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_secp256r1_signature_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_signed_transaction_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_signed_transaction_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_signed_transaction_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_signed_transaction_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_simple_signature_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_simple_signature_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_simple_signature_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_simple_signature_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_split_coins_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_split_coins_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_split_coins_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_split_coins_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_string_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_string_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_string_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_string_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_struct_tag_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_struct_tag_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_struct_tag_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_struct_tag_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_system_package_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_system_package_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_system_package_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_system_package_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_transaction_effects_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_transaction_effects_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_transaction_effects_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_transaction_effects_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_transaction_effects_v1_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_transaction_effects_v1_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_transaction_effects_v1_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_transaction_effects_v1_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_transaction_events_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_transaction_events_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_transaction_events_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_transaction_events_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_transaction_expiration_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_transaction_expiration_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_transaction_expiration_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_transaction_expiration_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_transaction_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_transaction_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_transaction_kind_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_transaction_kind_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_transaction_kind_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_transaction_kind_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_transaction_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_transaction_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_transaction_v1_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_transaction_v1_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_transaction_v1_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_transaction_v1_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_transfer_objects_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_transfer_objects_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_transfer_objects_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_transfer_objects_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_type_argument_error_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_type_argument_error_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_type_argument_error_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_type_argument_error_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_type_origin_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_type_origin_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_type_origin_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_type_origin_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_type_tag_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_type_tag_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_type_tag_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_type_tag_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_u16_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_u16_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_u16_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_u16_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_u32_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_u32_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_u32_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_u32_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_u64_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_u64_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_u64_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_u64_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_u8_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_u8_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_u8_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_u8_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_unchanged_shared_kind_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_unchanged_shared_kind_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_unchanged_shared_kind_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_unchanged_shared_kind_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_unchanged_shared_object_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_unchanged_shared_object_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_unchanged_shared_object_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_unchanged_shared_object_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_upgrade_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_upgrade_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_upgrade_info_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_upgrade_info_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_upgrade_info_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_upgrade_info_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_upgrade_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_upgrade_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_user_signature_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_user_signature_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_user_signature_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_user_signature_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_validator_aggregated_signature_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_validator_aggregated_signature_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_validator_aggregated_signature_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_validator_aggregated_signature_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_validator_committee_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_validator_committee_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_validator_committee_member_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_validator_committee_member_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_validator_committee_member_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_validator_committee_member_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_validator_committee_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_validator_committee_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_validator_execution_time_observation_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_validator_execution_time_observation_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_validator_execution_time_observation_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_validator_execution_time_observation_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_validator_signature_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_validator_signature_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_validator_signature_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_validator_signature_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_version_assignment_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_version_assignment_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_version_assignment_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_version_assignment_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_zk_login_authenticator_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_zk_login_authenticator_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_zk_login_authenticator_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_zk_login_authenticator_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_zk_login_claim_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_zk_login_claim_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_zk_login_claim_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_zk_login_claim_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_zk_login_proof_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_zk_login_proof_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_zk_login_proof_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_zk_login_proof_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_zk_login_public_identifier_from_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_zk_login_public_identifier_from_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_zk_login_public_identifier_to_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_func_zk_login_public_identifier_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_address_to_bytes(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_address_to_canonical_string(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_address_to_hex(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_address_to_short_string(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_argument_get_nested_result(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_bls12381privatekey_public_key(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_bls12381privatekey_scheme(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_bls12381privatekey_sign_checkpoint_summary(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_bls12381privatekey_try_sign(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_bls12381privatekey_verifying_key(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_bls12381publickey_to_bytes(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_bls12381signature_to_bytes(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_bls12381verifyingkey_public_key(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_bls12381verifyingkey_verify(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_bn254fieldelement_padded(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_bn254fieldelement_unpadded(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_cancelledtransaction_digest(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_cancelledtransaction_version_assignments(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_changeepoch_computation_charge(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_changeepoch_epoch(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_changeepoch_epoch_start_timestamp_ms(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_changeepoch_non_refundable_storage_fee(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_changeepoch_protocol_version(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_changeepoch_storage_charge(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_changeepoch_storage_rebate(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_changeepoch_system_packages(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_changeepochv2_computation_charge(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_changeepochv2_computation_charge_burned(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_changeepochv2_epoch(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_changeepochv2_epoch_start_timestamp_ms(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_changeepochv2_non_refundable_storage_fee(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_changeepochv2_protocol_version(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_changeepochv2_storage_charge(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_changeepochv2_storage_rebate(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_changeepochv2_system_packages(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_changeepochv3_computation_charge(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_changeepochv3_computation_charge_burned(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_changeepochv3_eligible_active_validators(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_changeepochv3_epoch(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_changeepochv3_epoch_start_timestamp_ms(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_changeepochv3_non_refundable_storage_fee(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_changeepochv3_protocol_version(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_changeepochv3_storage_charge(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_changeepochv3_storage_rebate(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_changeepochv3_system_packages(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_changeepochv4_adjust_rewards_by_score(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_changeepochv4_computation_charge(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_changeepochv4_computation_charge_burned(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_changeepochv4_eligible_active_validators(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_changeepochv4_epoch(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_changeepochv4_epoch_start_timestamp_ms(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_changeepochv4_non_refundable_storage_fee(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_changeepochv4_protocol_version(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_changeepochv4_scores(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_changeepochv4_storage_charge(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_changeepochv4_storage_rebate(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_changeepochv4_system_packages(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_checkpointcommitment_as_ecmh_live_object_set_digest(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_checkpointcommitment_is_ecmh_live_object_set(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_checkpointcontents_digest(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_checkpointcontents_transaction_info(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_checkpointsummary_checkpoint_commitments(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_checkpointsummary_content_digest(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_checkpointsummary_digest(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_checkpointsummary_end_of_epoch_data(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_checkpointsummary_epoch(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_checkpointsummary_epoch_rolling_gas_cost_summary(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_checkpointsummary_network_total_transactions(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_checkpointsummary_previous_digest(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_checkpointsummary_sequence_number(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_checkpointsummary_signing_message(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_checkpointsummary_signing_message_hex(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_checkpointsummary_timestamp_ms(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_checkpointsummary_version_specific_data(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_checkpointtransactioninfo_effects(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_checkpointtransactioninfo_signatures(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_checkpointtransactioninfo_transaction(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_clienttransactionbuilder_dry_run(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_clienttransactionbuilder_execute(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_clienttransactionbuilder_execute_with_sponsor(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_clienttransactionbuilder_expiration(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_clienttransactionbuilder_finish(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_clienttransactionbuilder_gas(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_clienttransactionbuilder_gas_budget(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_clienttransactionbuilder_gas_price(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_clienttransactionbuilder_gas_station_sponsor(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_clienttransactionbuilder_make_move_vec(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_clienttransactionbuilder_merge_coins(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_clienttransactionbuilder_move_call(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_clienttransactionbuilder_publish(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_clienttransactionbuilder_send_coins(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_clienttransactionbuilder_send_iota(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_clienttransactionbuilder_set_sender(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_clienttransactionbuilder_split_coins(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_clienttransactionbuilder_sponsor(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_clienttransactionbuilder_stake(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_clienttransactionbuilder_transfer_objects(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_clienttransactionbuilder_unstake(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_clienttransactionbuilder_upgrade(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_coin_balance(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_coin_coin_type(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_coin_id(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_consensuscommitprologuev1_commit_timestamp_ms(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_consensuscommitprologuev1_consensus_commit_digest(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_consensuscommitprologuev1_consensus_determined_version_assignments(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_consensuscommitprologuev1_epoch(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_consensuscommitprologuev1_round(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_consensuscommitprologuev1_sub_dag_index(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_consensusdeterminedversionassignments_as_cancelled_transactions(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_consensusdeterminedversionassignments_is_cancelled_transactions(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_digest_next_lexicographical(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_digest_to_base58(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_digest_to_bytes(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_ed25519privatekey_public_key(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_ed25519privatekey_scheme(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_ed25519privatekey_sign_personal_message(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_ed25519privatekey_sign_transaction(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_ed25519privatekey_to_bech32(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_ed25519privatekey_to_bytes(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_ed25519privatekey_to_der(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_ed25519privatekey_to_pem(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_ed25519privatekey_try_sign(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_ed25519privatekey_try_sign_simple(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_ed25519privatekey_try_sign_user(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_ed25519privatekey_verifying_key(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_ed25519publickey_derive_address(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_ed25519publickey_scheme(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_ed25519publickey_to_bytes(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_ed25519publickey_to_flagged_bytes(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_ed25519signature_to_bytes(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_ed25519verifier_verify_simple(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_ed25519verifier_verify_user(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_ed25519verifyingkey_public_key(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_ed25519verifyingkey_to_der(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_ed25519verifyingkey_to_pem(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_ed25519verifyingkey_verify(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_ed25519verifyingkey_verify_simple(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_ed25519verifyingkey_verify_user(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_executiontimeobservation_key(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_executiontimeobservation_observations(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_faucetclient_request(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_faucetclient_request_and_wait(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_faucetclient_request_and_wait_for_finalized(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_faucetclient_request_status(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_genesisobject_data(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_genesisobject_object_id(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_genesisobject_object_type(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_genesisobject_owner(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_genesisobject_version(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_genesistransaction_events(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_genesistransaction_objects(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_graphqlclient_active_validators(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_graphqlclient_balance(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_graphqlclient_chain_id(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_graphqlclient_checkpoint(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_graphqlclient_checkpoints(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_graphqlclient_clear_inspector(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_graphqlclient_coin_metadata(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_graphqlclient_coins(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_graphqlclient_dry_run_tx(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_graphqlclient_dry_run_tx_kind(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_graphqlclient_dynamic_field(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_graphqlclient_dynamic_fields(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_graphqlclient_dynamic_object_field(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_graphqlclient_epoch(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_graphqlclient_epoch_total_checkpoints(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_graphqlclient_epoch_total_transaction_blocks(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_graphqlclient_events(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_graphqlclient_execute_tx(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_graphqlclient_gas_coins(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_graphqlclient_iota_names_default_name(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_graphqlclient_iota_names_lookup(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_graphqlclient_iota_names_registrations(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_graphqlclient_is_tx_finalized(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_graphqlclient_is_tx_indexed_on_node(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_graphqlclient_latest_checkpoint_sequence_number(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_graphqlclient_max_page_size(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_graphqlclient_move_object_contents(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_graphqlclient_move_object_contents_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_graphqlclient_move_view_call(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_graphqlclient_move_view_call_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_graphqlclient_normalized_move_function(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_graphqlclient_normalized_move_module(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_graphqlclient_object(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_graphqlclient_object_bcs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_graphqlclient_objects(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_graphqlclient_package(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_graphqlclient_package_latest(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_graphqlclient_package_versions(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_graphqlclient_packages(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_graphqlclient_protocol_config(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_graphqlclient_reference_gas_price(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_graphqlclient_run_query(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_graphqlclient_service_config(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_graphqlclient_set_inspector(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_graphqlclient_set_rpc_server(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_graphqlclient_total_supply(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_graphqlclient_total_transaction_blocks(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_graphqlclient_total_transaction_blocks_by_digest(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_graphqlclient_total_transaction_blocks_by_seq_num(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_graphqlclient_transaction(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_graphqlclient_transaction_data_effects(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_graphqlclient_transaction_effects(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_graphqlclient_transactions(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_graphqlclient_transactions_data_effects(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_graphqlclient_transactions_effects(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_graphqlclient_wait_for_tx(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_graphqlrequestinspectorfn_on_request_complete(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_identifier_as_str(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_intent_app_id(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_intent_scope(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_intent_to_bytes(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_intent_version(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_makemovevector_elements(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_makemovevector_type_tag(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_mergecoins_coin(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_mergecoins_coins_to_merge(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_moveauthenticator_address(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_moveauthenticator_call_args(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_moveauthenticator_object_to_authenticate(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_moveauthenticator_type_args(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_moveauthenticatorbuilder_finish(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_movecall_arguments(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_movecall_function(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_movecall_module(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_movecall_package(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_movecall_type_arguments(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_movefunction_is_entry(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_movefunction_name(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_movefunction_parameters(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_movefunction_return_type(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_movefunction_type_parameters(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_movefunction_visibility(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_movepackage_id(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_movepackage_linkage_table(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_movepackage_modules(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_movepackage_type_origin_table(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_movepackage_version(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_movepackagedata_dependencies(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_movepackagedata_digest(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_movepackagedata_modules(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_movepackagedata_to_base64(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_movepackagedata_to_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_multisigaggregatedsignature_bitmap(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_multisigaggregatedsignature_committee(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_multisigaggregatedsignature_signatures(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_multisigaggregator_finish(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_multisigaggregator_verifier(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_multisigaggregator_with_signature(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_multisigaggregator_with_verifier(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_multisigcommittee_derive_address(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_multisigcommittee_is_valid(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_multisigcommittee_members(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_multisigcommittee_scheme(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_multisigcommittee_threshold(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_multisigmember_public_key(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_multisigmember_weight(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_multisigmemberpublickey_as_ed25519(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_multisigmemberpublickey_as_ed25519_opt(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_multisigmemberpublickey_as_secp256k1(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_multisigmemberpublickey_as_secp256k1_opt(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_multisigmemberpublickey_as_secp256r1(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_multisigmemberpublickey_as_secp256r1_opt(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_multisigmemberpublickey_as_zklogin(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_multisigmemberpublickey_as_zklogin_opt(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_multisigmemberpublickey_is_ed25519(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_multisigmemberpublickey_is_secp256k1(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_multisigmemberpublickey_is_secp256r1(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_multisigmemberpublickey_is_zklogin(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_multisigmemberpublickey_scheme(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_multisigmembersignature_as_ed25519(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_multisigmembersignature_as_ed25519_opt(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_multisigmembersignature_as_secp256k1(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_multisigmembersignature_as_secp256k1_opt(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_multisigmembersignature_as_secp256r1(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_multisigmembersignature_as_secp256r1_opt(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_multisigmembersignature_as_zklogin(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_multisigmembersignature_as_zklogin_opt(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_multisigmembersignature_is_ed25519(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_multisigmembersignature_is_secp256k1(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_multisigmembersignature_is_secp256r1(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_multisigmembersignature_is_zklogin(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_multisigverifier_verify(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_multisigverifier_with_zklogin_verifier(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_multisigverifier_zklogin_verifier(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_name_format(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_name_is_sln(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_name_is_subname(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_name_label(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_name_labels(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_name_num_labels(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_name_parent(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_nameregistration_expiration_timestamp_ms(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_nameregistration_id(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_nameregistration_name(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_nameregistration_name_str(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_object_as_package(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_object_as_package_opt(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_object_as_struct(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_object_as_struct_opt(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_object_data(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_object_digest(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_object_object_id(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_object_object_ref(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_object_object_type(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_object_owner(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_object_previous_transaction(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_object_storage_rebate(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_object_version(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_objectdata_as_package_opt(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_objectdata_as_struct_opt(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_objectdata_is_package(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_objectdata_is_struct(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_objectid_derive_dynamic_child_id(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_objectid_to_address(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_objectid_to_bytes(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_objectid_to_canonical_string(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_objectid_to_hex(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_objectid_to_short_string(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_objecttype_as_struct(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_objecttype_as_struct_opt(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_objecttype_is_package(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_objecttype_is_struct(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_owner_as_address(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_owner_as_address_opt(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_owner_as_object(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_owner_as_object_opt(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_owner_as_shared(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_owner_as_shared_opt(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_owner_is_address(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_owner_is_immutable(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_owner_is_object(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_owner_is_shared(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_passkeyauthenticator_authenticator_data(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_passkeyauthenticator_challenge(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_passkeyauthenticator_client_data_json(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_passkeyauthenticator_public_key(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_passkeyauthenticator_signature(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_passkeypublickey_derive_address(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_passkeypublickey_inner(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_passkeyverifier_verify(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_personalmessage_message_bytes(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_personalmessage_signing_digest(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_personalmessage_signing_digest_hex(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_programmabletransaction_commands(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_programmabletransaction_inputs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_publish_dependencies(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_publish_modules(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_secp256k1privatekey_public_key(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_secp256k1privatekey_scheme(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_secp256k1privatekey_sign_personal_message(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_secp256k1privatekey_sign_transaction(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_secp256k1privatekey_to_bech32(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_secp256k1privatekey_to_bytes(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_secp256k1privatekey_to_der(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_secp256k1privatekey_to_pem(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_secp256k1privatekey_try_sign(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_secp256k1privatekey_try_sign_simple(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_secp256k1privatekey_try_sign_user(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_secp256k1privatekey_verifying_key(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_secp256k1publickey_derive_address(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_secp256k1publickey_scheme(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_secp256k1publickey_to_bytes(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_secp256k1publickey_to_flagged_bytes(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_secp256k1signature_to_bytes(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_secp256k1verifier_verify_simple(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_secp256k1verifier_verify_user(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_secp256k1verifyingkey_public_key(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_secp256k1verifyingkey_to_der(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_secp256k1verifyingkey_to_pem(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_secp256k1verifyingkey_verify(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_secp256k1verifyingkey_verify_simple(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_secp256k1verifyingkey_verify_user(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_secp256r1privatekey_public_key(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_secp256r1privatekey_scheme(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_secp256r1privatekey_sign_personal_message(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_secp256r1privatekey_sign_transaction(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_secp256r1privatekey_to_bech32(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_secp256r1privatekey_to_bytes(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_secp256r1privatekey_to_der(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_secp256r1privatekey_to_pem(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_secp256r1privatekey_try_sign(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_secp256r1privatekey_try_sign_simple(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_secp256r1privatekey_try_sign_user(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_secp256r1privatekey_verifying_key(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_secp256r1publickey_derive_address(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_secp256r1publickey_scheme(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_secp256r1publickey_to_bytes(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_secp256r1publickey_to_flagged_bytes(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_secp256r1signature_to_bytes(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_secp256r1verifier_verify_simple(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_secp256r1verifier_verify_user(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_secp256r1verifyingkey_public_key(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_secp256r1verifyingkey_to_der(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_secp256r1verifyingkey_to_pem(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_secp256r1verifyingkey_verify(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_secp256r1verifyingkey_verify_simple(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_secp256r1verifyingkey_verify_user(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_simplekeypair_public_key(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_simplekeypair_scheme(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_simplekeypair_sign_personal_message(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_simplekeypair_sign_transaction(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_simplekeypair_to_bech32(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_simplekeypair_to_bytes(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_simplekeypair_to_der(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_simplekeypair_to_pem(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_simplekeypair_try_sign(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_simplekeypair_try_sign_user(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_simplekeypair_verifying_key(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_simplesignature_ed25519_pub_key(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_simplesignature_ed25519_pub_key_opt(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_simplesignature_ed25519_sig(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_simplesignature_ed25519_sig_opt(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_simplesignature_is_ed25519(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_simplesignature_is_secp256k1(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_simplesignature_is_secp256r1(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_simplesignature_scheme(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_simplesignature_secp256k1_pub_key(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_simplesignature_secp256k1_pub_key_opt(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_simplesignature_secp256k1_sig(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_simplesignature_secp256k1_sig_opt(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_simplesignature_secp256r1_pub_key(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_simplesignature_secp256r1_pub_key_opt(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_simplesignature_secp256r1_sig(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_simplesignature_secp256r1_sig_opt(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_simplesignature_to_bytes(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_simpleverifier_verify(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_simpleverifyingkey_public_key(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_simpleverifyingkey_scheme(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_simpleverifyingkey_to_der(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_simpleverifyingkey_to_pem(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_simpleverifyingkey_verify(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_splitcoins_amounts(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_splitcoins_coin(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_structtag_address(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_structtag_coin_type(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_structtag_coin_type_opt(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_structtag_module(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_structtag_name(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_structtag_to_canonical_string(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_structtag_type_args(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_systempackage_dependencies(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_systempackage_modules(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_systempackage_version(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_transaction_as_v1(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_transaction_digest(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_transaction_expiration(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_transaction_gas_payment(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_transaction_kind(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_transaction_sender(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_transaction_signing_digest(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_transaction_signing_digest_hex(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_transaction_to_base64(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_transactionbuilder_execute_with_gas_station(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_transactionbuilder_expiration(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_transactionbuilder_finish(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_transactionbuilder_gas(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_transactionbuilder_gas_budget(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_transactionbuilder_gas_price(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_transactionbuilder_gas_station_sponsor(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_transactionbuilder_make_move_vec(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_transactionbuilder_merge_coins(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_transactionbuilder_move_call(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_transactionbuilder_publish(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_transactionbuilder_send_coins(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_transactionbuilder_send_iota(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_transactionbuilder_set_sender(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_transactionbuilder_split_coins(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_transactionbuilder_sponsor(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_transactionbuilder_stake(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_transactionbuilder_transfer_objects(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_transactionbuilder_unstake(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_transactionbuilder_upgrade(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_transactionbuilder_with_client(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_transactioneffects_as_v1(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_transactioneffects_digest(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_transactioneffects_is_v1(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_transactionevents_digest(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_transactionevents_events(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_transactionsigner_sign(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_transactionsignerfn_sign(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_transactionv1_digest(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_transactionv1_expiration(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_transactionv1_gas_payment(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_transactionv1_kind(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_transactionv1_sender(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_transactionv1_signing_digest(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_transactionv1_signing_digest_hex(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_transactionv1_to_base64(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_transferobjects_address(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_transferobjects_objects(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_typetag_as_struct_tag(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_typetag_as_struct_tag_opt(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_typetag_as_vector_type_tag(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_typetag_as_vector_type_tag_opt(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_typetag_is_address(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_typetag_is_bool(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_typetag_is_signer(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_typetag_is_struct(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_typetag_is_u128(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_typetag_is_u16(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_typetag_is_u256(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_typetag_is_u32(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_typetag_is_u64(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_typetag_is_u8(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_typetag_is_vector(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_typetag_to_canonical_string(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_upgrade_dependencies(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_upgrade_modules(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_upgrade_package(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_upgrade_ticket(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_upgradepolicy_as_u8(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_usersignature_as_move_authenticator(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_usersignature_as_move_authenticator_opt(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_usersignature_as_multisig(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_usersignature_as_multisig_opt(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_usersignature_as_passkey_authenticator(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_usersignature_as_passkey_authenticator_opt(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_usersignature_as_simple(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_usersignature_as_simple_opt(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_usersignature_as_zklogin_authenticator(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_usersignature_as_zklogin_authenticator_opt(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_usersignature_is_move_authenticator(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_usersignature_is_multisig(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_usersignature_is_passkey_authenticator(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_usersignature_is_simple(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_usersignature_is_zklogin_authenticator(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_usersignature_scheme(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_usersignature_to_base64(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_usersignature_to_bytes(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_usersignatureverifier_verify(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_usersignatureverifier_with_zklogin_verifier(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_usersignatureverifier_zklogin_verifier(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_validatoraggregatedsignature_bitmap_bytes(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_validatoraggregatedsignature_epoch(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_validatoraggregatedsignature_signature(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_validatorcommitteesignatureaggregator_add_signature(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_validatorcommitteesignatureaggregator_committee(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_validatorcommitteesignatureaggregator_finish(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_validatorcommitteesignatureverifier_committee(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_validatorcommitteesignatureverifier_verify(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_validatorcommitteesignatureverifier_verify_aggregated(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_validatorcommitteesignatureverifier_verify_checkpoint_summary(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_validatorexecutiontimeobservation_duration(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_validatorexecutiontimeobservation_validator(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_validatorsignature_epoch(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_validatorsignature_public_key(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_validatorsignature_signature(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_versionassignment_object_id(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_versionassignment_version(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_zkloginauthenticator_inputs(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_zkloginauthenticator_max_epoch(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_zkloginauthenticator_signature(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_zklogininputs_address_seed(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_zklogininputs_header_base64(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_zklogininputs_iss(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_zklogininputs_iss_base64_details(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_zklogininputs_jwk_id(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_zklogininputs_proof_points(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_zklogininputs_public_identifier(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_zkloginproof_a(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_zkloginproof_b(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_zkloginproof_c(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_zkloginpublicidentifier_address_seed(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_zkloginpublicidentifier_derive_address(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_zkloginpublicidentifier_derive_address_padded(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_zkloginpublicidentifier_derive_address_unpadded(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_zkloginpublicidentifier_iss(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_zkloginverifier_jwks(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_zkloginverifier_verify(): number;

export function ubrn_uniffi_iota_sdk_ffi_checksum_method_zkloginverifier_with_jwks(): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_address(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_argument(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_bls12381privatekey(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_bls12381publickey(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_bls12381signature(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_bls12381verifyingkey(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_bn254fieldelement(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_cancelledtransaction(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_changeepoch(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_changeepochv2(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_changeepochv3(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_changeepochv4(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_checkpointcommitment(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_checkpointcontents(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_checkpointsummary(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_checkpointtransactioninfo(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_circomg1(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_circomg2(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_clienttransactionbuilder(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_coin(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_command(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_consensuscommitprologuev1(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_consensusdeterminedversionassignments(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_digest(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_ed25519privatekey(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_ed25519publickey(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_ed25519signature(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_ed25519verifier(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_ed25519verifyingkey(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_endofepochtransactionkind(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_executiontimeobservation(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_executiontimeobservationkey(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_executiontimeobservations(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_faucetclient(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_genesisobject(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_genesistransaction(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_graphqlclient(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_graphqlrequestinspectorfn(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_identifier(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_input(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_intent(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_makemovevector(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_mergecoins(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_movearg(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_moveauthenticator(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_moveauthenticatorbuilder(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_movecall(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_movefunction(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_movepackage(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_movepackagedata(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_moveviewarg(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_multisigaggregatedsignature(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_multisigaggregator(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_multisigcommittee(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_multisigmember(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_multisigmemberpublickey(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_multisigmembersignature(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_multisigverifier(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_name(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_nameregistration(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_object(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_objectdata(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_objectid(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_objecttype(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_owner(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_passkeyauthenticator(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_passkeypublickey(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_passkeyverifier(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_personalmessage(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_programmabletransaction(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_ptbargument(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_publish(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_secp256k1privatekey(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_secp256k1publickey(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_secp256k1signature(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_secp256k1verifier(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_secp256k1verifyingkey(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_secp256r1privatekey(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_secp256r1publickey(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_secp256r1signature(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_secp256r1verifier(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_secp256r1verifyingkey(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_simplekeypair(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_simplesignature(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_simpleverifier(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_simpleverifyingkey(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_splitcoins(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_structtag(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_systempackage(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_transaction(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_transactionbuilder(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_transactioneffects(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_transactionevents(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_transactionkind(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_transactionsigner(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_transactionsignerfn(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_transactionv1(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_transferobjects(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_typetag(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_upgrade(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_upgradepolicy(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_usersignature(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_usersignatureverifier(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_validatoraggregatedsignature(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_validatorcommitteesignatureaggregator(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_validatorcommitteesignatureverifier(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_validatorexecutiontimeobservation(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_validatorsignature(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_versionassignment(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_zkloginauthenticator(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_zklogininputs(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_zkloginproof(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_zkloginpublicidentifier(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_clone_zkloginverifier(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_address_framework(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_address_from_bytes(bytes: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_address_from_hex(hex: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_address_generate(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_address_std(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_address_system(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_address_zero(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_argument_new_gas(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_argument_new_input(input: number, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_argument_new_nested_result(command_index: number, subresult_index: number, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_argument_new_result(result: number, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_bls12381privatekey_generate(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_bls12381privatekey_new(bytes: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_bls12381publickey_from_bytes(bytes: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_bls12381publickey_from_str(s: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_bls12381publickey_generate(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_bls12381signature_from_bytes(bytes: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_bls12381signature_from_str(s: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_bls12381signature_generate(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_bls12381verifyingkey_new(public_key: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_bn254fieldelement_from_bytes(bytes: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_bn254fieldelement_from_str(s: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_bn254fieldelement_from_str_radix_10(s: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_cancelledtransaction_new(digest: bigint, version_assignments: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_changeepoch_new(epoch: bigint, protocol_version: bigint, storage_charge: bigint, computation_charge: bigint, storage_rebate: bigint, non_refundable_storage_fee: bigint, epoch_start_timestamp_ms: bigint, system_packages: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_changeepochv2_new(epoch: bigint, protocol_version: bigint, storage_charge: bigint, computation_charge: bigint, computation_charge_burned: bigint, storage_rebate: bigint, non_refundable_storage_fee: bigint, epoch_start_timestamp_ms: bigint, system_packages: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_changeepochv3_new(epoch: bigint, protocol_version: bigint, storage_charge: bigint, computation_charge: bigint, computation_charge_burned: bigint, storage_rebate: bigint, non_refundable_storage_fee: bigint, epoch_start_timestamp_ms: bigint, system_packages: Uint8Array, eligible_active_validators: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_changeepochv4_new(epoch: bigint, protocol_version: bigint, storage_charge: bigint, computation_charge: bigint, computation_charge_burned: bigint, storage_rebate: bigint, non_refundable_storage_fee: bigint, epoch_start_timestamp_ms: bigint, system_packages: Uint8Array, eligible_active_validators: Uint8Array, scores: Uint8Array, adjust_rewards_by_score: number, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_checkpointcontents_new(transaction_info: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_checkpointsummary_new(epoch: bigint, sequence_number: bigint, network_total_transactions: bigint, content_digest: bigint, previous_digest: Uint8Array, epoch_rolling_gas_cost_summary: Uint8Array, timestamp_ms: bigint, checkpoint_commitments: Uint8Array, end_of_epoch_data: Uint8Array, version_specific_data: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_checkpointtransactioninfo_new(transaction: bigint, effects: bigint, signatures: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_circomg1_new(el_0: bigint, el_1: bigint, el_2: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_circomg2_new(el_0_0: bigint, el_0_1: bigint, el_1_0: bigint, el_1_1: bigint, el_2_0: bigint, el_2_1: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_coin_try_from_object(object: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_command_new_make_move_vector(make_move_vector: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_command_new_merge_coins(merge_coins: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_command_new_move_call(move_call: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_command_new_publish(publish: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_command_new_split_coins(split_coins: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_command_new_transfer_objects(transfer_objects: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_command_new_upgrade(upgrade: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_consensuscommitprologuev1_new(epoch: bigint, round: bigint, sub_dag_index: Uint8Array, commit_timestamp_ms: bigint, consensus_commit_digest: bigint, consensus_determined_version_assignments: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_consensusdeterminedversionassignments_new_cancelled_transactions(cancelled_transactions: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_digest_from_base58(base58: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_digest_from_bytes(bytes: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_digest_generate(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_ed25519privatekey_from_bech32(value: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_ed25519privatekey_from_der(bytes: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_ed25519privatekey_from_mnemonic(phrase: Uint8Array, account_index: bigint, password: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_ed25519privatekey_from_mnemonic_with_path(phrase: Uint8Array, path: Uint8Array, password: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_ed25519privatekey_from_pem(s: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_ed25519privatekey_generate(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_ed25519privatekey_new(bytes: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_ed25519publickey_from_bytes(bytes: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_ed25519publickey_from_str(s: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_ed25519publickey_generate(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_ed25519signature_from_bytes(bytes: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_ed25519signature_from_str(s: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_ed25519signature_generate(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_ed25519verifier_new(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_ed25519verifyingkey_from_der(bytes: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_ed25519verifyingkey_from_pem(s: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_ed25519verifyingkey_new(public_key: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_endofepochtransactionkind_new_authenticator_state_create(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_endofepochtransactionkind_new_authenticator_state_expire(tx: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_endofepochtransactionkind_new_change_epoch(tx: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_endofepochtransactionkind_new_change_epoch_v2(tx: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_endofepochtransactionkind_new_change_epoch_v3(tx: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_endofepochtransactionkind_new_change_epoch_v4(tx: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_executiontimeobservation_new(key: bigint, observations: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_executiontimeobservationkey_new_make_move_vec(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_executiontimeobservationkey_new_merge_coins(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_executiontimeobservationkey_new_move_entry_point(_package: bigint, module: Uint8Array, _function: Uint8Array, type_arguments: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_executiontimeobservationkey_new_publish(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_executiontimeobservationkey_new_split_coins(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_executiontimeobservationkey_new_transfer_objects(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_executiontimeobservationkey_new_upgrade(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_executiontimeobservations_new_v1(execution_time_observations: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_faucetclient_new(faucet_url: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_faucetclient_new_devnet(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_faucetclient_new_localnet(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_faucetclient_new_testnet(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_genesisobject_new(data: bigint, owner: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_genesistransaction_new(objects: Uint8Array, events: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_graphqlclient_new(server: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_graphqlclient_new_devnet(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_graphqlclient_new_localnet(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_graphqlclient_new_mainnet(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_graphqlclient_new_testnet(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_identifier_new(identifier: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_input_new_immutable_or_owned(object_ref: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_input_new_pure(value: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_input_new_receiving(object_ref: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_input_new_shared(object_id: bigint, initial_shared_version: bigint, mutable: number, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_intent_from_bytes(bytes: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_intent_from_hex(hex: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_intent_new(scope: Uint8Array, version: Uint8Array, app_id: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_intent_new_consensus_app(scope: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_intent_new_iota_app(scope: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_intent_new_iota_transaction(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_intent_new_personal_message(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_makemovevector_new(type_tag: Uint8Array, elements: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_mergecoins_new(coin: bigint, coins_to_merge: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_movearg_address(address: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_movearg_address_from_hex(hex: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_movearg_address_vec(addresses: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_movearg_address_vec_from_hex(addresses: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_movearg_bool(value: number, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_movearg_bool_vec(values: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_movearg_digest(digest: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_movearg_digest_from_base58(base58: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_movearg_digest_vec(digests: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_movearg_digest_vec_from_base58(digests: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_movearg_option(value: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_movearg_string(string: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_movearg_string_vec(addresses: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_movearg_u128(value: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_movearg_u128_vec(values: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_movearg_u16(value: number, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_movearg_u16_vec(values: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_movearg_u256(value: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_movearg_u256_vec(values: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_movearg_u32(value: number, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_movearg_u32_vec(values: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_movearg_u64(value: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_movearg_u64_vec(values: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_movearg_u8(value: number, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_movearg_u8_vec(values: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_moveauthenticator_new_immutable(call_args: Uint8Array, type_args: Uint8Array, object_to_authenticate: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_moveauthenticator_new_shared(call_args: Uint8Array, type_args: Uint8Array, object_to_authenticate: bigint, initial_shared_version: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_moveauthenticatorbuilder_new(account_id: bigint, call_args: Uint8Array, type_args: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_movecall_new(_package: bigint, module: bigint, _function: bigint, type_arguments: Uint8Array, _arguments: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_movepackage_new(id: bigint, version: bigint, modules: Uint8Array, type_origin_table: Uint8Array, linkage_table: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_movepackagedata_from_base64(base64: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_movepackagedata_from_json(json: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_movepackagedata_new(modules: Uint8Array, dependencies: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_moveviewarg_address(value: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_moveviewarg_bool(value: number, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_moveviewarg_json(value: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_moveviewarg_null(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_moveviewarg_object_id(value: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_moveviewarg_option(value: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_moveviewarg_string(value: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_moveviewarg_string_vec(values: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_moveviewarg_u128(value: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_moveviewarg_u16(value: number, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_moveviewarg_u32(value: number, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_moveviewarg_u64(value: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_moveviewarg_u8(value: number, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_moveviewarg_u8_vec(values: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_multisigaggregatedsignature_new(committee: bigint, signatures: Uint8Array, bitmap: number, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_multisigaggregator_new_with_message(committee: bigint, message: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_multisigaggregator_new_with_transaction(committee: bigint, transaction: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_multisigcommittee_new(members: Uint8Array, threshold: number, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_multisigmember_new(public_key: bigint, weight: number, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_multisigverifier_new(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_name_from_str(s: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_nameregistration_new(id: bigint, name: bigint, name_str: Uint8Array, expiration_timestamp_ms: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_object_new(data: bigint, owner: bigint, previous_transaction: bigint, storage_rebate: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_objectdata_new_move_package(move_package: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_objectdata_new_move_struct(move_struct: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_objectid_clock(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_objectid_derive_id(digest: bigint, count: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_objectid_from_bytes(bytes: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_objectid_from_hex(hex: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_objectid_system(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_objectid_zero(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_objecttype_new_package(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_objecttype_new_struct(struct_tag: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_owner_new_address(address: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_owner_new_immutable(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_owner_new_object(id: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_owner_new_shared(version: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_passkeypublickey_new(public_key: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_passkeyverifier_new(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_personalmessage_new(message_bytes: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_programmabletransaction_new(inputs: Uint8Array, commands: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_ptbargument_address(address: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_ptbargument_address_from_hex(hex: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_ptbargument_address_vec(addresses: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_ptbargument_address_vec_from_hex(addresses: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_ptbargument_assigned(name: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_ptbargument_bool(value: number, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_ptbargument_bool_vec(values: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_ptbargument_digest(digest: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_ptbargument_digest_from_base58(base58: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_ptbargument_digest_vec(digests: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_ptbargument_digest_vec_from_base58(digests: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_ptbargument_gas(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_ptbargument_move_arg(arg: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_ptbargument_object_id(id: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_ptbargument_object_id_from_hex(hex: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_ptbargument_object_ref(id: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_ptbargument_option(value: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_ptbargument_receiving(id: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_ptbargument_receiving_from_hex(hex: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_ptbargument_shared(id: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_ptbargument_shared_from_hex(hex: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_ptbargument_shared_mut(id: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_ptbargument_shared_mut_from_hex(hex: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_ptbargument_string(string: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_ptbargument_u128(value: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_ptbargument_u128_vec(values: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_ptbargument_u16(value: number, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_ptbargument_u16_vec(values: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_ptbargument_u256(value: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_ptbargument_u256_vec(values: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_ptbargument_u32(value: number, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_ptbargument_u32_vec(values: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_ptbargument_u64(value: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_ptbargument_u64_vec(values: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_ptbargument_u8(value: number, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_ptbargument_u8_vec(values: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_publish_new(modules: Uint8Array, dependencies: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_secp256k1privatekey_from_bech32(value: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_secp256k1privatekey_from_der(bytes: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_secp256k1privatekey_from_mnemonic(phrase: Uint8Array, account_index: bigint, password: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_secp256k1privatekey_from_mnemonic_with_path(phrase: Uint8Array, path: Uint8Array, password: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_secp256k1privatekey_from_pem(s: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_secp256k1privatekey_generate(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_secp256k1privatekey_new(bytes: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_secp256k1publickey_from_bytes(bytes: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_secp256k1publickey_from_str(s: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_secp256k1publickey_generate(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_secp256k1signature_from_bytes(bytes: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_secp256k1signature_from_str(s: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_secp256k1signature_generate(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_secp256k1verifier_new(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_secp256k1verifyingkey_from_der(bytes: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_secp256k1verifyingkey_from_pem(s: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_secp256k1verifyingkey_new(public_key: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_secp256r1privatekey_from_bech32(value: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_secp256r1privatekey_from_der(bytes: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_secp256r1privatekey_from_mnemonic(phrase: Uint8Array, account_index: bigint, password: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_secp256r1privatekey_from_mnemonic_with_path(phrase: Uint8Array, path: Uint8Array, password: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_secp256r1privatekey_from_pem(s: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_secp256r1privatekey_generate(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_secp256r1privatekey_new(bytes: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_secp256r1publickey_from_bytes(bytes: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_secp256r1publickey_from_str(s: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_secp256r1publickey_generate(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_secp256r1signature_from_bytes(bytes: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_secp256r1signature_from_str(s: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_secp256r1signature_generate(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_secp256r1verifier_new(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_secp256r1verifyingkey_from_der(bytes: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_secp256r1verifyingkey_from_pem(s: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_secp256r1verifyingkey_new(public_key: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_simplekeypair_from_bech32(value: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_simplekeypair_from_bytes(bytes: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_simplekeypair_from_der(bytes: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_simplekeypair_from_ed25519(keypair: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_simplekeypair_from_pem(s: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_simplekeypair_from_secp256k1(keypair: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_simplekeypair_from_secp256r1(keypair: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_simplesignature_new_ed25519(signature: bigint, public_key: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_simplesignature_new_secp256k1(signature: bigint, public_key: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_simplesignature_new_secp256r1(signature: bigint, public_key: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_simpleverifier_new(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_simpleverifyingkey_from_der(bytes: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_simpleverifyingkey_from_pem(s: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_splitcoins_new(coin: bigint, amounts: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_structtag_new(address: bigint, module: bigint, name: bigint, type_params: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_structtag_new_ascii_string(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_structtag_new_balance(type_tag: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_structtag_new_clock(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_structtag_new_coin(type_tag: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_structtag_new_coin_manager(struct_tag: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_structtag_new_coin_metadata(struct_tag: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_structtag_new_config(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_structtag_new_config_setting(type_tag: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_structtag_new_deny_list_address_key(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_structtag_new_deny_list_config_key(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_structtag_new_deny_list_global_pause_key(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_structtag_new_display_created(struct_tag: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_structtag_new_dynamic_object_field_wrapper(type_tag: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_structtag_new_field(key: bigint, value: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_structtag_new_gas_coin(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_structtag_new_id(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_structtag_new_iota_coin_type(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_structtag_new_iota_system_admin_cap(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_structtag_new_iota_system_state(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_structtag_new_iota_treasury_cap(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_structtag_new_name(address: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_structtag_new_staked_iota(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_structtag_new_string(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_structtag_new_system_epoch_info_event(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_structtag_new_time_lock(type_tag: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_structtag_new_timelocked_staked_iota(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_structtag_new_transfer_receiving(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_structtag_new_treasury_cap(struct_tag: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_structtag_new_uid(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_structtag_new_upgrade_cap(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_structtag_new_upgrade_receipt(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_structtag_new_upgrade_ticket(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_structtag_new_version_updated(struct_tag: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_systempackage_new(version: bigint, modules: Uint8Array, dependencies: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_transaction_from_base64(base64: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_transaction_new_v1(transaction_v1: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_transactionbuilder_new(sender: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_transactioneffects_new_v1(effects: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_transactionevents_new(events: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_transactionkind_new_authenticator_state_update_v1(tx: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_transactionkind_new_consensus_commit_prologue_v1(tx: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_transactionkind_new_end_of_epoch(tx: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_transactionkind_new_genesis(tx: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_transactionkind_new_programmable_transaction(tx: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_transactionkind_new_randomness_state_update(tx: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_transactionsigner_from_ed25519(key: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_transactionsigner_from_keypair(key: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_transactionsigner_from_move_authenticator(auth: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_transactionsigner_from_secp256k1(key: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_transactionsigner_from_secp256r1(key: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_transactionsigner_new(signer_fn: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_transactionv1_from_base64(bytes: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_transactionv1_new(kind: bigint, sender: bigint, gas_payment: Uint8Array, expiration: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_transferobjects_new(objects: Uint8Array, address: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_typetag_new_address(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_typetag_new_bool(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_typetag_new_signer(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_typetag_new_struct(struct_tag: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_typetag_new_u128(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_typetag_new_u16(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_typetag_new_u256(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_typetag_new_u32(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_typetag_new_u64(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_typetag_new_u8(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_typetag_new_vector(type_tag: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_upgrade_new(modules: Uint8Array, dependencies: Uint8Array, _package: bigint, ticket: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_upgradepolicy_additive(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_upgradepolicy_compatible(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_upgradepolicy_dep_only(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_usersignature_from_base64(base64: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_usersignature_from_bytes(bytes: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_usersignature_new_move_authenticator(authenticator: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_usersignature_new_multisig(signature: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_usersignature_new_passkey_authenticator(authenticator: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_usersignature_new_simple(signature: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_usersignature_new_zklogin_authenticator(authenticator: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_usersignatureverifier_new(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_validatoraggregatedsignature_new(epoch: bigint, signature: bigint, bitmap_bytes: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_validatorcommitteesignatureaggregator_new_checkpoint_summary(committee: Uint8Array, summary: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_validatorcommitteesignatureverifier_new(committee: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_validatorexecutiontimeobservation_new(validator: bigint, duration: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_validatorsignature_new(epoch: bigint, public_key: bigint, signature: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_versionassignment_new(object_id: bigint, version: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_zkloginauthenticator_new(inputs: bigint, max_epoch: bigint, signature: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_zklogininputs_new(proof_points: bigint, iss_base64_details: Uint8Array, header_base64: Uint8Array, address_seed: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_zkloginproof_new(a: bigint, b: bigint, c: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_zkloginpublicidentifier_new(iss: Uint8Array, address_seed: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_zkloginverifier_new_dev(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_constructor_zkloginverifier_new_mainnet(f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_address(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_argument(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_bls12381privatekey(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_bls12381publickey(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_bls12381signature(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_bls12381verifyingkey(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_bn254fieldelement(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_cancelledtransaction(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_changeepoch(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_changeepochv2(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_changeepochv3(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_changeepochv4(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_checkpointcommitment(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_checkpointcontents(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_checkpointsummary(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_checkpointtransactioninfo(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_circomg1(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_circomg2(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_clienttransactionbuilder(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_coin(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_command(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_consensuscommitprologuev1(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_consensusdeterminedversionassignments(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_digest(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_ed25519privatekey(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_ed25519publickey(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_ed25519signature(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_ed25519verifier(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_ed25519verifyingkey(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_endofepochtransactionkind(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_executiontimeobservation(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_executiontimeobservationkey(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_executiontimeobservations(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_faucetclient(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_genesisobject(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_genesistransaction(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_graphqlclient(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_graphqlrequestinspectorfn(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_identifier(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_input(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_intent(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_makemovevector(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_mergecoins(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_movearg(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_moveauthenticator(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_moveauthenticatorbuilder(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_movecall(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_movefunction(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_movepackage(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_movepackagedata(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_moveviewarg(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_multisigaggregatedsignature(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_multisigaggregator(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_multisigcommittee(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_multisigmember(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_multisigmemberpublickey(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_multisigmembersignature(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_multisigverifier(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_name(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_nameregistration(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_object(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_objectdata(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_objectid(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_objecttype(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_owner(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_passkeyauthenticator(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_passkeypublickey(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_passkeyverifier(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_personalmessage(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_programmabletransaction(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_ptbargument(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_publish(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_secp256k1privatekey(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_secp256k1publickey(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_secp256k1signature(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_secp256k1verifier(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_secp256k1verifyingkey(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_secp256r1privatekey(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_secp256r1publickey(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_secp256r1signature(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_secp256r1verifier(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_secp256r1verifyingkey(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_simplekeypair(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_simplesignature(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_simpleverifier(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_simpleverifyingkey(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_splitcoins(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_structtag(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_systempackage(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_transaction(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_transactionbuilder(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_transactioneffects(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_transactionevents(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_transactionkind(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_transactionsigner(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_transactionsignerfn(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_transactionv1(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_transferobjects(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_typetag(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_upgrade(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_upgradepolicy(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_usersignature(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_usersignatureverifier(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_validatoraggregatedsignature(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_validatorcommitteesignatureaggregator(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_validatorcommitteesignatureverifier(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_validatorexecutiontimeobservation(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_validatorsignature(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_versionassignment(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_zkloginauthenticator(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_zklogininputs(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_zkloginproof(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_zkloginpublicidentifier(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_free_zkloginverifier(ptr: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_active_jwk_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_active_jwk_from_json(json: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_active_jwk_to_bcs(data: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_active_jwk_to_json(data: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_address_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_address_from_json(json: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_address_to_bcs(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_address_to_json(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_argument_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_argument_from_json(json: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_argument_to_bcs(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_argument_to_json(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_authenticator_state_expire_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_authenticator_state_expire_from_json(json: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_authenticator_state_expire_to_bcs(data: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_authenticator_state_expire_to_json(data: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_authenticator_state_update_v1_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_authenticator_state_update_v1_from_json(json: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_authenticator_state_update_v1_to_bcs(data: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_authenticator_state_update_v1_to_json(data: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_base64_decode(input: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_base64_encode(input: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_bls12381_public_key_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_bls12381_public_key_from_json(json: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_bls12381_public_key_to_bcs(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_bls12381_public_key_to_json(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_bls12381_signature_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_bls12381_signature_from_json(json: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_bls12381_signature_to_bcs(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_bls12381_signature_to_json(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_bn254_field_element_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_bn254_field_element_from_json(json: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_bn254_field_element_to_bcs(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_bn254_field_element_to_json(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_bool_from_bcs(input: Uint8Array, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_bool_from_json(input: Uint8Array, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_bool_to_bcs(input: number, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_bool_to_json(input: number, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_cancelled_transaction_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_cancelled_transaction_from_json(json: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_cancelled_transaction_to_bcs(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_cancelled_transaction_to_json(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_change_epoch_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_change_epoch_from_json(json: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_change_epoch_to_bcs(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_change_epoch_to_json(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_change_epoch_v2_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_change_epoch_v2_from_json(json: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_change_epoch_v2_to_bcs(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_change_epoch_v2_to_json(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_changed_object_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_changed_object_from_json(json: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_changed_object_to_bcs(data: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_changed_object_to_json(data: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_checkpoint_commitment_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_checkpoint_commitment_from_json(json: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_checkpoint_commitment_to_bcs(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_checkpoint_commitment_to_json(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_checkpoint_contents_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_checkpoint_contents_from_json(json: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_checkpoint_contents_to_bcs(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_checkpoint_contents_to_json(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_checkpoint_summary_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_checkpoint_summary_from_json(json: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_checkpoint_summary_to_bcs(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_checkpoint_summary_to_json(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_checkpoint_transaction_info_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_checkpoint_transaction_info_from_json(json: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_checkpoint_transaction_info_to_bcs(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_checkpoint_transaction_info_to_json(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_circom_g1_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_circom_g1_from_json(json: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_circom_g1_to_bcs(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_circom_g1_to_json(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_circom_g2_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_circom_g2_from_json(json: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_circom_g2_to_bcs(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_circom_g2_to_json(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_command_argument_error_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_command_argument_error_from_json(json: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_command_argument_error_to_bcs(data: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_command_argument_error_to_json(data: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_command_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_command_from_json(json: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_command_to_bcs(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_command_to_json(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_consensus_commit_prologue_v1_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_consensus_commit_prologue_v1_from_json(json: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_consensus_commit_prologue_v1_to_bcs(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_consensus_commit_prologue_v1_to_json(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_consensus_determined_version_assignments_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_consensus_determined_version_assignments_from_json(json: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_consensus_determined_version_assignments_to_bcs(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_consensus_determined_version_assignments_to_json(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_digest_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_digest_from_json(json: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_digest_to_bcs(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_digest_to_json(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_ed25519_public_key_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_ed25519_public_key_from_json(json: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_ed25519_public_key_to_bcs(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_ed25519_public_key_to_json(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_ed25519_signature_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_ed25519_signature_from_json(json: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_ed25519_signature_to_bcs(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_ed25519_signature_to_json(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_end_of_epoch_data_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_end_of_epoch_data_from_json(json: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_end_of_epoch_data_to_bcs(data: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_end_of_epoch_data_to_json(data: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_event_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_event_from_json(json: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_event_to_bcs(data: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_event_to_json(data: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_execution_error_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_execution_error_from_json(json: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_execution_error_to_bcs(data: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_execution_error_to_json(data: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_execution_status_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_execution_status_from_json(json: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_execution_status_to_bcs(data: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_execution_status_to_json(data: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_execution_time_observation_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_execution_time_observation_from_json(json: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_execution_time_observation_key_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_execution_time_observation_key_from_json(json: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_execution_time_observation_key_to_bcs(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_execution_time_observation_key_to_json(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_execution_time_observation_to_bcs(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_execution_time_observation_to_json(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_execution_time_observations_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_execution_time_observations_from_json(json: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_execution_time_observations_to_bcs(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_execution_time_observations_to_json(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_gas_cost_summary_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_gas_cost_summary_from_json(json: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_gas_cost_summary_to_bcs(data: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_gas_cost_summary_to_json(data: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_gas_payment_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_gas_payment_from_json(json: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_gas_payment_to_bcs(data: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_gas_payment_to_json(data: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_generate_mnemonic(word_count: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_genesis_object_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_genesis_object_from_json(json: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_genesis_object_to_bcs(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_genesis_object_to_json(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_genesis_transaction_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_genesis_transaction_from_json(json: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_genesis_transaction_to_bcs(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_genesis_transaction_to_json(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_hex_decode(input: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_hex_encode(input: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_i16_from_bcs(input: Uint8Array, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_i16_from_json(input: Uint8Array, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_i16_to_bcs(input: number, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_i16_to_json(input: number, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_i32_from_bcs(input: Uint8Array, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_i32_from_json(input: Uint8Array, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_i32_to_bcs(input: number, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_i32_to_json(input: number, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_i64_from_bcs(input: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_i64_from_json(input: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_i64_to_bcs(input: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_i64_to_json(input: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_i8_from_bcs(input: Uint8Array, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_i8_from_json(input: Uint8Array, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_i8_to_bcs(input: number, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_i8_to_json(input: number, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_id_operation_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_id_operation_from_json(json: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_id_operation_to_bcs(data: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_id_operation_to_json(data: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_identifier_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_identifier_from_json(json: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_identifier_to_bcs(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_identifier_to_json(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_input_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_input_from_json(json: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_input_to_bcs(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_input_to_json(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_jwk_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_jwk_from_json(json: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_jwk_id_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_jwk_id_from_json(json: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_jwk_id_to_bcs(data: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_jwk_id_to_json(data: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_jwk_to_bcs(data: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_jwk_to_json(data: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_make_move_vector_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_make_move_vector_from_json(json: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_make_move_vector_to_bcs(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_make_move_vector_to_json(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_merge_coins_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_merge_coins_from_json(json: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_merge_coins_to_bcs(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_merge_coins_to_json(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_move_call_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_move_call_from_json(json: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_move_call_to_bcs(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_move_call_to_json(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_move_location_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_move_location_from_json(json: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_move_location_to_bcs(data: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_move_location_to_json(data: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_move_package_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_move_package_from_json(json: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_move_package_to_bcs(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_move_package_to_json(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_move_struct_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_move_struct_from_json(json: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_move_struct_to_bcs(data: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_move_struct_to_json(data: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_multisig_aggregated_signature_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_multisig_aggregated_signature_from_json(json: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_multisig_aggregated_signature_to_bcs(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_multisig_aggregated_signature_to_json(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_multisig_committee_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_multisig_committee_from_json(json: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_multisig_committee_to_bcs(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_multisig_committee_to_json(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_multisig_member_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_multisig_member_from_json(json: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_multisig_member_public_key_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_multisig_member_public_key_from_json(json: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_multisig_member_public_key_to_bcs(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_multisig_member_public_key_to_json(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_multisig_member_signature_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_multisig_member_signature_from_json(json: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_multisig_member_signature_to_bcs(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_multisig_member_signature_to_json(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_multisig_member_to_bcs(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_multisig_member_to_json(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_object_data_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_object_data_from_json(json: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_object_data_to_bcs(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_object_data_to_json(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_object_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_object_from_json(json: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_object_id_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_object_id_from_json(json: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_object_id_to_bcs(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_object_id_to_json(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_object_in_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_object_in_from_json(json: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_object_in_to_bcs(data: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_object_in_to_json(data: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_object_out_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_object_out_from_json(json: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_object_out_to_bcs(data: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_object_out_to_json(data: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_object_reference_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_object_reference_from_json(json: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_object_reference_to_bcs(data: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_object_reference_to_json(data: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_object_to_bcs(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_object_to_json(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_owner_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_owner_from_json(json: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_owner_to_bcs(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_owner_to_json(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_package_upgrade_error_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_package_upgrade_error_from_json(json: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_package_upgrade_error_to_bcs(data: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_package_upgrade_error_to_json(data: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_passkey_authenticator_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_passkey_authenticator_from_json(json: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_passkey_authenticator_to_bcs(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_passkey_authenticator_to_json(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_programmable_transaction_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_programmable_transaction_from_json(json: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_programmable_transaction_to_bcs(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_programmable_transaction_to_json(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_publish_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_publish_from_json(json: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_publish_to_bcs(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_publish_to_json(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_randomness_state_update_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_randomness_state_update_from_json(json: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_randomness_state_update_to_bcs(data: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_randomness_state_update_to_json(data: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_secp256k1_public_key_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_secp256k1_public_key_from_json(json: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_secp256k1_public_key_to_bcs(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_secp256k1_public_key_to_json(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_secp256k1_signature_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_secp256k1_signature_from_json(json: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_secp256k1_signature_to_bcs(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_secp256k1_signature_to_json(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_secp256r1_public_key_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_secp256r1_public_key_from_json(json: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_secp256r1_public_key_to_bcs(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_secp256r1_public_key_to_json(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_secp256r1_signature_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_secp256r1_signature_from_json(json: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_secp256r1_signature_to_bcs(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_secp256r1_signature_to_json(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_signed_transaction_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_signed_transaction_from_json(json: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_signed_transaction_to_bcs(data: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_signed_transaction_to_json(data: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_simple_signature_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_simple_signature_from_json(json: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_simple_signature_to_bcs(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_simple_signature_to_json(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_split_coins_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_split_coins_from_json(json: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_split_coins_to_bcs(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_split_coins_to_json(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_string_from_bcs(input: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_string_from_json(input: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_string_to_bcs(input: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_string_to_json(input: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_struct_tag_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_struct_tag_from_json(json: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_struct_tag_to_bcs(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_struct_tag_to_json(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_system_package_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_system_package_from_json(json: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_system_package_to_bcs(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_system_package_to_json(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_transaction_effects_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_transaction_effects_from_json(json: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_transaction_effects_to_bcs(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_transaction_effects_to_json(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_transaction_effects_v1_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_transaction_effects_v1_from_json(json: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_transaction_effects_v1_to_bcs(data: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_transaction_effects_v1_to_json(data: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_transaction_events_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_transaction_events_from_json(json: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_transaction_events_to_bcs(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_transaction_events_to_json(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_transaction_expiration_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_transaction_expiration_from_json(json: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_transaction_expiration_to_bcs(data: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_transaction_expiration_to_json(data: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_transaction_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_transaction_from_json(json: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_transaction_kind_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_transaction_kind_from_json(json: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_transaction_kind_to_bcs(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_transaction_kind_to_json(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_transaction_to_bcs(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_transaction_to_json(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_transaction_v1_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_transaction_v1_from_json(json: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_transaction_v1_to_bcs(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_transaction_v1_to_json(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_transfer_objects_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_transfer_objects_from_json(json: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_transfer_objects_to_bcs(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_transfer_objects_to_json(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_type_argument_error_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_type_argument_error_from_json(json: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_type_argument_error_to_bcs(data: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_type_argument_error_to_json(data: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_type_origin_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_type_origin_from_json(json: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_type_origin_to_bcs(data: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_type_origin_to_json(data: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_type_tag_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_type_tag_from_json(json: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_type_tag_to_bcs(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_type_tag_to_json(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_u16_from_bcs(input: Uint8Array, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_u16_from_json(input: Uint8Array, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_u16_to_bcs(input: number, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_u16_to_json(input: number, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_u32_from_bcs(input: Uint8Array, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_u32_from_json(input: Uint8Array, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_u32_to_bcs(input: number, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_u32_to_json(input: number, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_u64_from_bcs(input: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_u64_from_json(input: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_u64_to_bcs(input: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_u64_to_json(input: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_u8_from_bcs(input: Uint8Array, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_u8_from_json(input: Uint8Array, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_u8_to_bcs(input: number, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_u8_to_json(input: number, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_unchanged_shared_kind_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_unchanged_shared_kind_from_json(json: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_unchanged_shared_kind_to_bcs(data: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_unchanged_shared_kind_to_json(data: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_unchanged_shared_object_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_unchanged_shared_object_from_json(json: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_unchanged_shared_object_to_bcs(data: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_unchanged_shared_object_to_json(data: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_upgrade_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_upgrade_from_json(json: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_upgrade_info_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_upgrade_info_from_json(json: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_upgrade_info_to_bcs(data: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_upgrade_info_to_json(data: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_upgrade_to_bcs(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_upgrade_to_json(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_user_signature_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_user_signature_from_json(json: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_user_signature_to_bcs(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_user_signature_to_json(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_validator_aggregated_signature_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_validator_aggregated_signature_from_json(json: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_validator_aggregated_signature_to_bcs(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_validator_aggregated_signature_to_json(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_validator_committee_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_validator_committee_from_json(json: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_validator_committee_member_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_validator_committee_member_from_json(json: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_validator_committee_member_to_bcs(data: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_validator_committee_member_to_json(data: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_validator_committee_to_bcs(data: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_validator_committee_to_json(data: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_validator_execution_time_observation_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_validator_execution_time_observation_from_json(json: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_validator_execution_time_observation_to_bcs(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_validator_execution_time_observation_to_json(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_validator_signature_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_validator_signature_from_json(json: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_validator_signature_to_bcs(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_validator_signature_to_json(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_version_assignment_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_version_assignment_from_json(json: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_version_assignment_to_bcs(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_version_assignment_to_json(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_zk_login_authenticator_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_zk_login_authenticator_from_json(json: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_zk_login_authenticator_to_bcs(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_zk_login_authenticator_to_json(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_zk_login_claim_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_zk_login_claim_from_json(json: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_zk_login_claim_to_bcs(data: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_zk_login_claim_to_json(data: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_zk_login_proof_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_zk_login_proof_from_json(json: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_zk_login_proof_to_bcs(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_zk_login_proof_to_json(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_zk_login_public_identifier_from_bcs(bcs: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_zk_login_public_identifier_from_json(json: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_zk_login_public_identifier_to_bcs(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_func_zk_login_public_identifier_to_json(data: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_init_callback_vtable_graphqlrequestinspectorfn(vtable: any): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_init_callback_vtable_transactionsignerfn(vtable: any): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_address_to_bytes(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_address_to_canonical_string(ptr: bigint, with_prefix: number, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_address_to_hex(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_address_to_short_string(ptr: bigint, with_prefix: number, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_address_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_address_uniffi_trait_display(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_address_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_address_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_address_uniffi_trait_hash(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_argument_get_nested_result(ptr: bigint, ix: number, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_argument_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_argument_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_argument_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_bls12381privatekey_public_key(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_bls12381privatekey_scheme(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_bls12381privatekey_sign_checkpoint_summary(ptr: bigint, summary: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_bls12381privatekey_try_sign(ptr: bigint, message: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_bls12381privatekey_verifying_key(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_bls12381publickey_to_bytes(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_bls12381publickey_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_bls12381publickey_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_bls12381publickey_uniffi_trait_hash(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_bls12381signature_to_bytes(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_bls12381signature_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_bls12381signature_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_bls12381signature_uniffi_trait_hash(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_bls12381verifyingkey_public_key(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_bls12381verifyingkey_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_bls12381verifyingkey_verify(ptr: bigint, message: Uint8Array, signature: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_bn254fieldelement_padded(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_bn254fieldelement_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_bn254fieldelement_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_bn254fieldelement_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_bn254fieldelement_unpadded(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_cancelledtransaction_digest(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_cancelledtransaction_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_cancelledtransaction_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_cancelledtransaction_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_cancelledtransaction_version_assignments(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_changeepoch_computation_charge(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_changeepoch_epoch(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_changeepoch_epoch_start_timestamp_ms(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_changeepoch_non_refundable_storage_fee(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_changeepoch_protocol_version(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_changeepoch_storage_charge(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_changeepoch_storage_rebate(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_changeepoch_system_packages(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_changeepoch_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_changeepoch_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_changeepoch_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_changeepochv2_computation_charge(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_changeepochv2_computation_charge_burned(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_changeepochv2_epoch(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_changeepochv2_epoch_start_timestamp_ms(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_changeepochv2_non_refundable_storage_fee(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_changeepochv2_protocol_version(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_changeepochv2_storage_charge(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_changeepochv2_storage_rebate(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_changeepochv2_system_packages(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_changeepochv2_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_changeepochv2_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_changeepochv2_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_changeepochv3_computation_charge(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_changeepochv3_computation_charge_burned(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_changeepochv3_eligible_active_validators(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_changeepochv3_epoch(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_changeepochv3_epoch_start_timestamp_ms(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_changeepochv3_non_refundable_storage_fee(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_changeepochv3_protocol_version(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_changeepochv3_storage_charge(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_changeepochv3_storage_rebate(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_changeepochv3_system_packages(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_changeepochv3_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_changeepochv3_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_changeepochv3_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_changeepochv4_adjust_rewards_by_score(ptr: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_changeepochv4_computation_charge(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_changeepochv4_computation_charge_burned(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_changeepochv4_eligible_active_validators(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_changeepochv4_epoch(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_changeepochv4_epoch_start_timestamp_ms(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_changeepochv4_non_refundable_storage_fee(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_changeepochv4_protocol_version(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_changeepochv4_scores(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_changeepochv4_storage_charge(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_changeepochv4_storage_rebate(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_changeepochv4_system_packages(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_checkpointcommitment_as_ecmh_live_object_set_digest(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_checkpointcommitment_is_ecmh_live_object_set(ptr: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_checkpointcontents_digest(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_checkpointcontents_transaction_info(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_checkpointsummary_checkpoint_commitments(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_checkpointsummary_content_digest(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_checkpointsummary_digest(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_checkpointsummary_end_of_epoch_data(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_checkpointsummary_epoch(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_checkpointsummary_epoch_rolling_gas_cost_summary(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_checkpointsummary_network_total_transactions(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_checkpointsummary_previous_digest(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_checkpointsummary_sequence_number(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_checkpointsummary_signing_message(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_checkpointsummary_signing_message_hex(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_checkpointsummary_timestamp_ms(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_checkpointsummary_version_specific_data(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_checkpointtransactioninfo_effects(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_checkpointtransactioninfo_signatures(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_checkpointtransactioninfo_transaction(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_circomg1_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_circomg1_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_circomg1_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_circomg2_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_circomg2_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_circomg2_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_clienttransactionbuilder_dry_run(ptr: bigint, skip_checks: number): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_clienttransactionbuilder_execute(ptr: bigint, signer: bigint, wait_for: Uint8Array): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_clienttransactionbuilder_execute_with_sponsor(ptr: bigint, signer: bigint, sponsor_signer: bigint, wait_for: Uint8Array): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_clienttransactionbuilder_expiration(ptr: bigint, epoch: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_clienttransactionbuilder_finish(ptr: bigint): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_clienttransactionbuilder_gas(ptr: bigint, object_ids: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_clienttransactionbuilder_gas_budget(ptr: bigint, budget: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_clienttransactionbuilder_gas_price(ptr: bigint, price: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_clienttransactionbuilder_gas_station_sponsor(ptr: bigint, url: Uint8Array, duration: Uint8Array, headers: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_clienttransactionbuilder_make_move_vec(ptr: bigint, elements: Uint8Array, type_tag: bigint, name: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_clienttransactionbuilder_merge_coins(ptr: bigint, primary_coin: bigint, consumed_coins: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_clienttransactionbuilder_move_call(ptr: bigint, _package: bigint, module: bigint, _function: bigint, _arguments: Uint8Array, type_args: Uint8Array, names: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_clienttransactionbuilder_publish(ptr: bigint, package_data: bigint, upgrade_cap_name: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_clienttransactionbuilder_send_coins(ptr: bigint, coins: Uint8Array, recipient: bigint, amount: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_clienttransactionbuilder_send_iota(ptr: bigint, recipient: bigint, amount: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_clienttransactionbuilder_set_sender(ptr: bigint, sender: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_clienttransactionbuilder_split_coins(ptr: bigint, coin: bigint, amounts: Uint8Array, names: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_clienttransactionbuilder_sponsor(ptr: bigint, sponsor: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_clienttransactionbuilder_stake(ptr: bigint, stake: bigint, validator_address: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_clienttransactionbuilder_transfer_objects(ptr: bigint, recipient: bigint, objects: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_clienttransactionbuilder_unstake(ptr: bigint, staked_iota: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_clienttransactionbuilder_upgrade(ptr: bigint, package_id: bigint, package_data: bigint, upgrade_ticket: bigint, name: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_coin_balance(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_coin_coin_type(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_coin_id(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_coin_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_command_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_command_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_command_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_consensuscommitprologuev1_commit_timestamp_ms(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_consensuscommitprologuev1_consensus_commit_digest(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_consensuscommitprologuev1_consensus_determined_version_assignments(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_consensuscommitprologuev1_epoch(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_consensuscommitprologuev1_round(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_consensuscommitprologuev1_sub_dag_index(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_consensuscommitprologuev1_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_consensuscommitprologuev1_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_consensuscommitprologuev1_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_consensusdeterminedversionassignments_as_cancelled_transactions(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_consensusdeterminedversionassignments_is_cancelled_transactions(ptr: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_consensusdeterminedversionassignments_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_consensusdeterminedversionassignments_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_consensusdeterminedversionassignments_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_digest_next_lexicographical(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_digest_to_base58(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_digest_to_bytes(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_digest_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_digest_uniffi_trait_display(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_digest_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_digest_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_digest_uniffi_trait_hash(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_ed25519privatekey_public_key(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_ed25519privatekey_scheme(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_ed25519privatekey_sign_personal_message(ptr: bigint, message: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_ed25519privatekey_sign_transaction(ptr: bigint, transaction: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_ed25519privatekey_to_bech32(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_ed25519privatekey_to_bytes(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_ed25519privatekey_to_der(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_ed25519privatekey_to_pem(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_ed25519privatekey_try_sign(ptr: bigint, message: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_ed25519privatekey_try_sign_simple(ptr: bigint, message: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_ed25519privatekey_try_sign_user(ptr: bigint, message: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_ed25519privatekey_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_ed25519privatekey_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_ed25519privatekey_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_ed25519privatekey_verifying_key(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_ed25519publickey_derive_address(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_ed25519publickey_scheme(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_ed25519publickey_to_bytes(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_ed25519publickey_to_flagged_bytes(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_ed25519publickey_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_ed25519publickey_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_ed25519publickey_uniffi_trait_hash(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_ed25519signature_to_bytes(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_ed25519signature_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_ed25519signature_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_ed25519signature_uniffi_trait_hash(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_ed25519verifier_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_ed25519verifier_verify_simple(ptr: bigint, message: Uint8Array, signature: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_ed25519verifier_verify_user(ptr: bigint, message: Uint8Array, signature: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_ed25519verifyingkey_public_key(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_ed25519verifyingkey_to_der(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_ed25519verifyingkey_to_pem(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_ed25519verifyingkey_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_ed25519verifyingkey_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_ed25519verifyingkey_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_ed25519verifyingkey_verify(ptr: bigint, message: Uint8Array, signature: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_ed25519verifyingkey_verify_simple(ptr: bigint, message: Uint8Array, signature: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_ed25519verifyingkey_verify_user(ptr: bigint, message: Uint8Array, signature: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_endofepochtransactionkind_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_endofepochtransactionkind_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_endofepochtransactionkind_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_executiontimeobservation_key(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_executiontimeobservation_observations(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_executiontimeobservation_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_executiontimeobservation_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_executiontimeobservation_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_executiontimeobservation_uniffi_trait_hash(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_executiontimeobservationkey_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_executiontimeobservationkey_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_executiontimeobservationkey_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_executiontimeobservationkey_uniffi_trait_hash(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_executiontimeobservations_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_executiontimeobservations_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_executiontimeobservations_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_executiontimeobservations_uniffi_trait_hash(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_faucetclient_request(ptr: bigint, address: bigint): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_faucetclient_request_and_wait(ptr: bigint, address: bigint): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_faucetclient_request_and_wait_for_finalized(ptr: bigint, address: bigint, client: bigint): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_faucetclient_request_status(ptr: bigint, id: Uint8Array): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_genesisobject_data(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_genesisobject_object_id(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_genesisobject_object_type(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_genesisobject_owner(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_genesisobject_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_genesisobject_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_genesisobject_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_genesisobject_version(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_genesistransaction_events(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_genesistransaction_objects(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_genesistransaction_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_genesistransaction_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_genesistransaction_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_graphqlclient_active_validators(ptr: bigint, epoch: Uint8Array, pagination_filter: Uint8Array): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_graphqlclient_balance(ptr: bigint, address: bigint, coin_type: Uint8Array): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_graphqlclient_chain_id(ptr: bigint): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_graphqlclient_checkpoint(ptr: bigint, digest: Uint8Array, seq_num: Uint8Array): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_graphqlclient_checkpoints(ptr: bigint, pagination_filter: Uint8Array): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_graphqlclient_clear_inspector(ptr: bigint): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_graphqlclient_coin_metadata(ptr: bigint, coin_type: Uint8Array): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_graphqlclient_coins(ptr: bigint, owner: bigint, pagination_filter: Uint8Array, coin_type: Uint8Array): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_graphqlclient_dry_run_tx(ptr: bigint, tx: bigint, skip_checks: number): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_graphqlclient_dry_run_tx_kind(ptr: bigint, tx_kind: bigint, tx_meta: Uint8Array, skip_checks: number): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_graphqlclient_dynamic_field(ptr: bigint, address: bigint, type_tag: bigint, name: Uint8Array): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_graphqlclient_dynamic_fields(ptr: bigint, address: bigint, pagination_filter: Uint8Array): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_graphqlclient_dynamic_object_field(ptr: bigint, address: bigint, type_tag: bigint, name: Uint8Array): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_graphqlclient_epoch(ptr: bigint, epoch: Uint8Array): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_graphqlclient_epoch_total_checkpoints(ptr: bigint, epoch: Uint8Array): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_graphqlclient_epoch_total_transaction_blocks(ptr: bigint, epoch: Uint8Array): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_graphqlclient_events(ptr: bigint, filter: Uint8Array, pagination_filter: Uint8Array): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_graphqlclient_execute_tx(ptr: bigint, signatures: Uint8Array, tx: bigint, wait_for: Uint8Array): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_graphqlclient_gas_coins(ptr: bigint, owner: bigint, pagination_filter: Uint8Array): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_graphqlclient_iota_names_default_name(ptr: bigint, address: bigint, format: Uint8Array): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_graphqlclient_iota_names_lookup(ptr: bigint, name: Uint8Array): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_graphqlclient_iota_names_registrations(ptr: bigint, address: bigint, pagination_filter: Uint8Array): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_graphqlclient_is_tx_finalized(ptr: bigint, digest: bigint): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_graphqlclient_is_tx_indexed_on_node(ptr: bigint, digest: bigint): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_graphqlclient_latest_checkpoint_sequence_number(ptr: bigint): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_graphqlclient_max_page_size(ptr: bigint): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_graphqlclient_move_object_contents(ptr: bigint, object_id: bigint, version: Uint8Array): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_graphqlclient_move_object_contents_bcs(ptr: bigint, object_id: bigint, version: Uint8Array): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_graphqlclient_move_view_call(ptr: bigint, function_name: Uint8Array, type_arguments: Uint8Array, _arguments: Uint8Array): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_graphqlclient_move_view_call_json(ptr: bigint, function_name: Uint8Array, type_arguments: Uint8Array, _arguments: Uint8Array): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_graphqlclient_normalized_move_function(ptr: bigint, _package: bigint, module: Uint8Array, _function: Uint8Array, version: Uint8Array): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_graphqlclient_normalized_move_module(ptr: bigint, _package: bigint, module: Uint8Array, version: Uint8Array, pagination_filter_enums: Uint8Array, pagination_filter_friends: Uint8Array, pagination_filter_functions: Uint8Array, pagination_filter_structs: Uint8Array): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_graphqlclient_object(ptr: bigint, object_id: bigint, version: Uint8Array): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_graphqlclient_object_bcs(ptr: bigint, object_id: bigint): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_graphqlclient_objects(ptr: bigint, filter: Uint8Array, pagination_filter: Uint8Array): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_graphqlclient_package(ptr: bigint, address: bigint, version: Uint8Array): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_graphqlclient_package_latest(ptr: bigint, address: bigint): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_graphqlclient_package_versions(ptr: bigint, address: bigint, after_version: Uint8Array, before_version: Uint8Array, pagination_filter: Uint8Array): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_graphqlclient_packages(ptr: bigint, after_checkpoint: Uint8Array, before_checkpoint: Uint8Array, pagination_filter: Uint8Array): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_graphqlclient_protocol_config(ptr: bigint, version: Uint8Array): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_graphqlclient_reference_gas_price(ptr: bigint, epoch: Uint8Array): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_graphqlclient_run_query(ptr: bigint, query: Uint8Array): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_graphqlclient_service_config(ptr: bigint): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_graphqlclient_set_inspector(ptr: bigint, inspector: bigint): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_graphqlclient_set_rpc_server(ptr: bigint, server: Uint8Array): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_graphqlclient_total_supply(ptr: bigint, coin_type: Uint8Array): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_graphqlclient_total_transaction_blocks(ptr: bigint): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_graphqlclient_total_transaction_blocks_by_digest(ptr: bigint, digest: bigint): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_graphqlclient_total_transaction_blocks_by_seq_num(ptr: bigint, seq_num: bigint): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_graphqlclient_transaction(ptr: bigint, digest: bigint): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_graphqlclient_transaction_data_effects(ptr: bigint, digest: bigint): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_graphqlclient_transaction_effects(ptr: bigint, digest: bigint): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_graphqlclient_transactions(ptr: bigint, filter: Uint8Array, pagination_filter: Uint8Array): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_graphqlclient_transactions_data_effects(ptr: bigint, filter: Uint8Array, pagination_filter: Uint8Array): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_graphqlclient_transactions_effects(ptr: bigint, filter: Uint8Array, pagination_filter: Uint8Array): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_graphqlclient_wait_for_tx(ptr: bigint, digest: bigint, wait_for: Uint8Array, timeout: Uint8Array): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_graphqlrequestinspectorfn_on_request_complete(ptr: bigint, result: Uint8Array, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_identifier_as_str(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_identifier_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_identifier_uniffi_trait_display(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_identifier_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_identifier_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_identifier_uniffi_trait_hash(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_input_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_input_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_input_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_intent_app_id(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_intent_scope(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_intent_to_bytes(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_intent_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_intent_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_intent_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_intent_uniffi_trait_hash(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_intent_version(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_makemovevector_elements(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_makemovevector_type_tag(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_makemovevector_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_makemovevector_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_makemovevector_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_mergecoins_coin(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_mergecoins_coins_to_merge(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_mergecoins_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_mergecoins_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_mergecoins_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_moveauthenticator_address(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_moveauthenticator_call_args(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_moveauthenticator_object_to_authenticate(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_moveauthenticator_type_args(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_moveauthenticatorbuilder_finish(ptr: bigint, client: bigint): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_movecall_arguments(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_movecall_function(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_movecall_module(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_movecall_package(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_movecall_type_arguments(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_movecall_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_movecall_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_movecall_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_movefunction_is_entry(ptr: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_movefunction_name(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_movefunction_parameters(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_movefunction_return_type(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_movefunction_type_parameters(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_movefunction_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_movefunction_uniffi_trait_display(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_movefunction_visibility(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_movepackage_id(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_movepackage_linkage_table(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_movepackage_modules(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_movepackage_type_origin_table(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_movepackage_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_movepackage_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_movepackage_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_movepackage_uniffi_trait_hash(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_movepackage_version(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_movepackagedata_dependencies(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_movepackagedata_digest(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_movepackagedata_modules(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_movepackagedata_to_base64(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_movepackagedata_to_json(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_movepackagedata_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_multisigaggregatedsignature_bitmap(ptr: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_multisigaggregatedsignature_committee(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_multisigaggregatedsignature_signatures(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_multisigaggregatedsignature_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_multisigaggregatedsignature_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_multisigaggregatedsignature_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_multisigaggregator_finish(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_multisigaggregator_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_multisigaggregator_verifier(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_multisigaggregator_with_signature(ptr: bigint, signature: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_multisigaggregator_with_verifier(ptr: bigint, verifier: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_multisigcommittee_derive_address(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_multisigcommittee_is_valid(ptr: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_multisigcommittee_members(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_multisigcommittee_scheme(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_multisigcommittee_threshold(ptr: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_multisigcommittee_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_multisigcommittee_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_multisigcommittee_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_multisigmember_public_key(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_multisigmember_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_multisigmember_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_multisigmember_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_multisigmember_weight(ptr: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_multisigmemberpublickey_as_ed25519(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_multisigmemberpublickey_as_ed25519_opt(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_multisigmemberpublickey_as_secp256k1(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_multisigmemberpublickey_as_secp256k1_opt(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_multisigmemberpublickey_as_secp256r1(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_multisigmemberpublickey_as_secp256r1_opt(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_multisigmemberpublickey_as_zklogin(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_multisigmemberpublickey_as_zklogin_opt(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_multisigmemberpublickey_is_ed25519(ptr: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_multisigmemberpublickey_is_secp256k1(ptr: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_multisigmemberpublickey_is_secp256r1(ptr: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_multisigmemberpublickey_is_zklogin(ptr: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_multisigmemberpublickey_scheme(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_multisigmemberpublickey_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_multisigmemberpublickey_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_multisigmemberpublickey_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_multisigmembersignature_as_ed25519(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_multisigmembersignature_as_ed25519_opt(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_multisigmembersignature_as_secp256k1(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_multisigmembersignature_as_secp256k1_opt(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_multisigmembersignature_as_secp256r1(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_multisigmembersignature_as_secp256r1_opt(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_multisigmembersignature_as_zklogin(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_multisigmembersignature_as_zklogin_opt(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_multisigmembersignature_is_ed25519(ptr: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_multisigmembersignature_is_secp256k1(ptr: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_multisigmembersignature_is_secp256r1(ptr: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_multisigmembersignature_is_zklogin(ptr: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_multisigmembersignature_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_multisigmembersignature_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_multisigmembersignature_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_multisigverifier_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_multisigverifier_verify(ptr: bigint, message: Uint8Array, signature: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_multisigverifier_with_zklogin_verifier(ptr: bigint, zklogin_verifier: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_multisigverifier_zklogin_verifier(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_name_format(ptr: bigint, format: Uint8Array, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_name_is_sln(ptr: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_name_is_subname(ptr: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_name_label(ptr: bigint, index: number, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_name_labels(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_name_num_labels(ptr: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_name_parent(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_name_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_name_uniffi_trait_display(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_name_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_name_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_name_uniffi_trait_hash(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_nameregistration_expiration_timestamp_ms(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_nameregistration_id(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_nameregistration_name(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_nameregistration_name_str(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_nameregistration_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_nameregistration_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_nameregistration_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_object_as_package(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_object_as_package_opt(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_object_as_struct(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_object_as_struct_opt(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_object_data(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_object_digest(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_object_object_id(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_object_object_ref(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_object_object_type(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_object_owner(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_object_previous_transaction(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_object_storage_rebate(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_object_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_object_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_object_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_object_version(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_objectdata_as_package_opt(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_objectdata_as_struct_opt(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_objectdata_is_package(ptr: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_objectdata_is_struct(ptr: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_objectdata_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_objectdata_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_objectdata_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_objectdata_uniffi_trait_hash(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_objectid_derive_dynamic_child_id(ptr: bigint, key_type_tag: bigint, key_bytes: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_objectid_to_address(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_objectid_to_bytes(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_objectid_to_canonical_string(ptr: bigint, with_prefix: number, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_objectid_to_hex(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_objectid_to_short_string(ptr: bigint, with_prefix: number, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_objectid_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_objectid_uniffi_trait_display(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_objectid_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_objectid_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_objectid_uniffi_trait_hash(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_objecttype_as_struct(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_objecttype_as_struct_opt(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_objecttype_is_package(ptr: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_objecttype_is_struct(ptr: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_objecttype_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_objecttype_uniffi_trait_display(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_objecttype_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_objecttype_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_owner_as_address(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_owner_as_address_opt(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_owner_as_object(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_owner_as_object_opt(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_owner_as_shared(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_owner_as_shared_opt(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_owner_is_address(ptr: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_owner_is_immutable(ptr: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_owner_is_object(ptr: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_owner_is_shared(ptr: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_owner_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_owner_uniffi_trait_display(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_owner_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_owner_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_owner_uniffi_trait_hash(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_passkeyauthenticator_authenticator_data(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_passkeyauthenticator_challenge(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_passkeyauthenticator_client_data_json(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_passkeyauthenticator_public_key(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_passkeyauthenticator_signature(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_passkeyauthenticator_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_passkeyauthenticator_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_passkeyauthenticator_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_passkeypublickey_derive_address(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_passkeypublickey_inner(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_passkeypublickey_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_passkeypublickey_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_passkeypublickey_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_passkeyverifier_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_passkeyverifier_verify(ptr: bigint, message: Uint8Array, authenticator: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_personalmessage_message_bytes(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_personalmessage_signing_digest(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_personalmessage_signing_digest_hex(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_personalmessage_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_personalmessage_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_personalmessage_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_programmabletransaction_commands(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_programmabletransaction_inputs(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_programmabletransaction_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_programmabletransaction_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_programmabletransaction_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_publish_dependencies(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_publish_modules(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_publish_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_publish_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_publish_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256k1privatekey_public_key(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256k1privatekey_scheme(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256k1privatekey_sign_personal_message(ptr: bigint, message: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256k1privatekey_sign_transaction(ptr: bigint, transaction: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256k1privatekey_to_bech32(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256k1privatekey_to_bytes(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256k1privatekey_to_der(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256k1privatekey_to_pem(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256k1privatekey_try_sign(ptr: bigint, message: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256k1privatekey_try_sign_simple(ptr: bigint, message: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256k1privatekey_try_sign_user(ptr: bigint, message: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256k1privatekey_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256k1privatekey_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256k1privatekey_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256k1privatekey_verifying_key(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256k1publickey_derive_address(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256k1publickey_scheme(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256k1publickey_to_bytes(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256k1publickey_to_flagged_bytes(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256k1publickey_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256k1publickey_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256k1publickey_uniffi_trait_hash(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256k1signature_to_bytes(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256k1signature_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256k1signature_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256k1signature_uniffi_trait_hash(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256k1verifier_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256k1verifier_verify_simple(ptr: bigint, message: Uint8Array, signature: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256k1verifier_verify_user(ptr: bigint, message: Uint8Array, signature: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256k1verifyingkey_public_key(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256k1verifyingkey_to_der(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256k1verifyingkey_to_pem(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256k1verifyingkey_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256k1verifyingkey_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256k1verifyingkey_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256k1verifyingkey_verify(ptr: bigint, message: Uint8Array, signature: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256k1verifyingkey_verify_simple(ptr: bigint, message: Uint8Array, signature: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256k1verifyingkey_verify_user(ptr: bigint, message: Uint8Array, signature: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256r1privatekey_public_key(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256r1privatekey_scheme(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256r1privatekey_sign_personal_message(ptr: bigint, message: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256r1privatekey_sign_transaction(ptr: bigint, transaction: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256r1privatekey_to_bech32(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256r1privatekey_to_bytes(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256r1privatekey_to_der(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256r1privatekey_to_pem(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256r1privatekey_try_sign(ptr: bigint, message: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256r1privatekey_try_sign_simple(ptr: bigint, message: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256r1privatekey_try_sign_user(ptr: bigint, message: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256r1privatekey_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256r1privatekey_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256r1privatekey_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256r1privatekey_verifying_key(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256r1publickey_derive_address(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256r1publickey_scheme(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256r1publickey_to_bytes(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256r1publickey_to_flagged_bytes(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256r1publickey_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256r1publickey_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256r1publickey_uniffi_trait_hash(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256r1signature_to_bytes(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256r1signature_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256r1signature_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256r1signature_uniffi_trait_hash(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256r1verifier_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256r1verifier_verify_simple(ptr: bigint, message: Uint8Array, signature: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256r1verifier_verify_user(ptr: bigint, message: Uint8Array, signature: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256r1verifyingkey_public_key(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256r1verifyingkey_to_der(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256r1verifyingkey_to_pem(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256r1verifyingkey_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256r1verifyingkey_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256r1verifyingkey_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256r1verifyingkey_verify(ptr: bigint, message: Uint8Array, signature: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256r1verifyingkey_verify_simple(ptr: bigint, message: Uint8Array, signature: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_secp256r1verifyingkey_verify_user(ptr: bigint, message: Uint8Array, signature: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_simplekeypair_public_key(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_simplekeypair_scheme(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_simplekeypair_sign_personal_message(ptr: bigint, message: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_simplekeypair_sign_transaction(ptr: bigint, transaction: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_simplekeypair_to_bech32(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_simplekeypair_to_bytes(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_simplekeypair_to_der(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_simplekeypair_to_pem(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_simplekeypair_try_sign(ptr: bigint, message: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_simplekeypair_try_sign_user(ptr: bigint, message: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_simplekeypair_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_simplekeypair_verifying_key(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_simplesignature_ed25519_pub_key(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_simplesignature_ed25519_pub_key_opt(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_simplesignature_ed25519_sig(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_simplesignature_ed25519_sig_opt(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_simplesignature_is_ed25519(ptr: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_simplesignature_is_secp256k1(ptr: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_simplesignature_is_secp256r1(ptr: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_simplesignature_scheme(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_simplesignature_secp256k1_pub_key(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_simplesignature_secp256k1_pub_key_opt(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_simplesignature_secp256k1_sig(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_simplesignature_secp256k1_sig_opt(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_simplesignature_secp256r1_pub_key(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_simplesignature_secp256r1_pub_key_opt(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_simplesignature_secp256r1_sig(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_simplesignature_secp256r1_sig_opt(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_simplesignature_to_bytes(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_simplesignature_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_simplesignature_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_simplesignature_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_simplesignature_uniffi_trait_hash(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_simpleverifier_verify(ptr: bigint, message: Uint8Array, signature: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_simpleverifyingkey_public_key(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_simpleverifyingkey_scheme(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_simpleverifyingkey_to_der(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_simpleverifyingkey_to_pem(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_simpleverifyingkey_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_simpleverifyingkey_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_simpleverifyingkey_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_simpleverifyingkey_verify(ptr: bigint, message: Uint8Array, signature: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_splitcoins_amounts(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_splitcoins_coin(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_splitcoins_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_splitcoins_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_splitcoins_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_structtag_address(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_structtag_coin_type(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_structtag_coin_type_opt(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_structtag_module(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_structtag_name(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_structtag_to_canonical_string(ptr: bigint, with_prefix: number, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_structtag_type_args(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_structtag_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_structtag_uniffi_trait_display(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_structtag_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_structtag_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_structtag_uniffi_trait_hash(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_systempackage_dependencies(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_systempackage_modules(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_systempackage_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_systempackage_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_systempackage_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_systempackage_version(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_transaction_as_v1(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_transaction_digest(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_transaction_expiration(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_transaction_gas_payment(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_transaction_kind(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_transaction_sender(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_transaction_signing_digest(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_transaction_signing_digest_hex(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_transaction_to_base64(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_transaction_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_transaction_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_transaction_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_transactionbuilder_execute_with_gas_station(ptr: bigint, signer: bigint): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_transactionbuilder_expiration(ptr: bigint, epoch: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_transactionbuilder_finish(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_transactionbuilder_gas(ptr: bigint, object_refs: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_transactionbuilder_gas_budget(ptr: bigint, budget: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_transactionbuilder_gas_price(ptr: bigint, price: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_transactionbuilder_gas_station_sponsor(ptr: bigint, url: Uint8Array, duration: Uint8Array, headers: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_transactionbuilder_make_move_vec(ptr: bigint, elements: Uint8Array, type_tag: bigint, name: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_transactionbuilder_merge_coins(ptr: bigint, primary_coin: bigint, consumed_coins: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_transactionbuilder_move_call(ptr: bigint, _package: bigint, module: bigint, _function: bigint, _arguments: Uint8Array, type_args: Uint8Array, names: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_transactionbuilder_publish(ptr: bigint, package_data: bigint, upgrade_cap_name: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_transactionbuilder_send_coins(ptr: bigint, coins: Uint8Array, recipient: bigint, amount: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_transactionbuilder_send_iota(ptr: bigint, recipient: bigint, amount: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_transactionbuilder_set_sender(ptr: bigint, sender: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_transactionbuilder_split_coins(ptr: bigint, coin: bigint, amounts: Uint8Array, names: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_transactionbuilder_sponsor(ptr: bigint, sponsor: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_transactionbuilder_stake(ptr: bigint, stake: bigint, validator_address: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_transactionbuilder_transfer_objects(ptr: bigint, recipient: bigint, objects: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_transactionbuilder_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_transactionbuilder_unstake(ptr: bigint, staked_iota: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_transactionbuilder_upgrade(ptr: bigint, package_id: bigint, package_data: bigint, upgrade_ticket: bigint, name: Uint8Array, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_transactionbuilder_with_client(ptr: bigint, client: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_transactioneffects_as_v1(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_transactioneffects_digest(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_transactioneffects_is_v1(ptr: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_transactioneffects_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_transactioneffects_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_transactioneffects_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_transactionevents_digest(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_transactionevents_events(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_transactionkind_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_transactionkind_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_transactionkind_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_transactionsigner_sign(ptr: bigint, txn: bigint): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_transactionsignerfn_sign(ptr: bigint, transaction: bigint): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_transactionv1_digest(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_transactionv1_expiration(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_transactionv1_gas_payment(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_transactionv1_kind(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_transactionv1_sender(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_transactionv1_signing_digest(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_transactionv1_signing_digest_hex(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_transactionv1_to_base64(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_transactionv1_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_transactionv1_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_transactionv1_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_transferobjects_address(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_transferobjects_objects(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_transferobjects_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_transferobjects_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_transferobjects_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_typetag_as_struct_tag(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_typetag_as_struct_tag_opt(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_typetag_as_vector_type_tag(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_typetag_as_vector_type_tag_opt(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_typetag_is_address(ptr: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_typetag_is_bool(ptr: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_typetag_is_signer(ptr: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_typetag_is_struct(ptr: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_typetag_is_u128(ptr: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_typetag_is_u16(ptr: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_typetag_is_u256(ptr: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_typetag_is_u32(ptr: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_typetag_is_u64(ptr: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_typetag_is_u8(ptr: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_typetag_is_vector(ptr: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_typetag_to_canonical_string(ptr: bigint, with_prefix: number, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_typetag_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_typetag_uniffi_trait_display(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_typetag_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_typetag_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_typetag_uniffi_trait_hash(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_upgrade_dependencies(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_upgrade_modules(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_upgrade_package(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_upgrade_ticket(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_upgrade_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_upgrade_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_upgrade_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_upgradepolicy_as_u8(ptr: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_upgradepolicy_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_upgradepolicy_uniffi_trait_display(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_upgradepolicy_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_upgradepolicy_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_usersignature_as_move_authenticator(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_usersignature_as_move_authenticator_opt(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_usersignature_as_multisig(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_usersignature_as_multisig_opt(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_usersignature_as_passkey_authenticator(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_usersignature_as_passkey_authenticator_opt(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_usersignature_as_simple(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_usersignature_as_simple_opt(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_usersignature_as_zklogin_authenticator(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_usersignature_as_zklogin_authenticator_opt(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_usersignature_is_move_authenticator(ptr: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_usersignature_is_multisig(ptr: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_usersignature_is_passkey_authenticator(ptr: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_usersignature_is_simple(ptr: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_usersignature_is_zklogin_authenticator(ptr: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_usersignature_scheme(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_usersignature_to_base64(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_usersignature_to_bytes(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_usersignature_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_usersignature_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_usersignature_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_usersignatureverifier_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_usersignatureverifier_verify(ptr: bigint, message: Uint8Array, signature: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_usersignatureverifier_with_zklogin_verifier(ptr: bigint, zklogin_verifier: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_usersignatureverifier_zklogin_verifier(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_validatoraggregatedsignature_bitmap_bytes(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_validatoraggregatedsignature_epoch(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_validatoraggregatedsignature_signature(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_validatoraggregatedsignature_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_validatorcommitteesignatureaggregator_add_signature(ptr: bigint, signature: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_validatorcommitteesignatureaggregator_committee(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_validatorcommitteesignatureaggregator_finish(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_validatorcommitteesignatureaggregator_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_validatorcommitteesignatureverifier_committee(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_validatorcommitteesignatureverifier_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_validatorcommitteesignatureverifier_verify(ptr: bigint, message: Uint8Array, signature: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_validatorcommitteesignatureverifier_verify_aggregated(ptr: bigint, message: Uint8Array, signature: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_validatorcommitteesignatureverifier_verify_checkpoint_summary(ptr: bigint, summary: bigint, signature: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_validatorexecutiontimeobservation_duration(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_validatorexecutiontimeobservation_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_validatorexecutiontimeobservation_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_validatorexecutiontimeobservation_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_validatorexecutiontimeobservation_uniffi_trait_hash(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_validatorexecutiontimeobservation_validator(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_validatorsignature_epoch(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_validatorsignature_public_key(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_validatorsignature_signature(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_validatorsignature_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_validatorsignature_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_validatorsignature_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_versionassignment_object_id(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_versionassignment_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_versionassignment_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_versionassignment_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_versionassignment_version(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_zkloginauthenticator_inputs(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_zkloginauthenticator_max_epoch(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_zkloginauthenticator_signature(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_zkloginauthenticator_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_zkloginauthenticator_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_zkloginauthenticator_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_zklogininputs_address_seed(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_zklogininputs_header_base64(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_zklogininputs_iss(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_zklogininputs_iss_base64_details(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_zklogininputs_jwk_id(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_zklogininputs_proof_points(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_zklogininputs_public_identifier(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_zklogininputs_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_zklogininputs_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_zklogininputs_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_zkloginproof_a(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_zkloginproof_b(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_zkloginproof_c(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_zkloginproof_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_zkloginproof_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_zkloginproof_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_zkloginpublicidentifier_address_seed(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_zkloginpublicidentifier_derive_address(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_zkloginpublicidentifier_derive_address_padded(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_zkloginpublicidentifier_derive_address_unpadded(ptr: bigint, f_status_: RustCallStatus): bigint;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_zkloginpublicidentifier_iss(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_zkloginpublicidentifier_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_zkloginpublicidentifier_uniffi_trait_eq_eq(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_zkloginpublicidentifier_uniffi_trait_eq_ne(ptr: bigint, other: bigint, f_status_: RustCallStatus): number;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_zkloginverifier_jwks(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_zkloginverifier_uniffi_trait_debug(ptr: bigint, f_status_: RustCallStatus): Uint8Array;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_zkloginverifier_verify(ptr: bigint, message: Uint8Array, authenticator: bigint, f_status_: RustCallStatus): void;

export function ubrn_uniffi_iota_sdk_ffi_fn_method_zkloginverifier_with_jwks(ptr: bigint, jwks: Uint8Array, f_status_: RustCallStatus): bigint;

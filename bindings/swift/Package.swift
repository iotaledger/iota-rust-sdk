// swift-tools-version: 5.9

import PackageDescription

// All example files in the examples directory
let exampleNames = [
    "abstract_account",
    "address_from_mnemonic",
    "chain_id",
    "coin_balances",
    "custom_query",
    "dev_inspect",
    "dry_run_bytes",
    "dynamic_fields",
    "epoch",
    "faucet",
    "gas_sponsor",
    "gas_station",
    "generate_ed25519_address",
    "generate_mnemonic",
    "generic_move_function",
    "get_object",
    "get_transaction",
    "json_query",
    "json_roundtrip",
    "move_functions",
    "move_view_call",
    "objects_by_type",
    "owned_objects",
    "package_events",
    "pagination",
    "prepare_merge_coins",
    "prepare_send_coins",
    "prepare_send_iota",
    "prepare_send_iota_multi",
    "prepare_split_coins",
    "prepare_transfer_objects",
    "prepare_transfer_objects_offline",
    "publish_upgrade",
    "sign_send_iota",
    "stake",
    "transaction_signer_callback",
    "transactions_with_function",
    "transactions_with_shared",
    "tx_command_results",
    "unstake",
]

let package = Package(
    name: "IotaSDK",
    platforms: [
        .macOS(.v13),
        .iOS(.v16),
    ],
    products: [
        .library(
            name: "IotaSDK",
            targets: ["IotaSDK"]
        ),
    ],
    targets: [
        .systemLibrary(
            name: "IotaSDKFFI",
            path: "Sources/IotaSDKFFI"
        ),
        .target(
            name: "IotaSDK",
            dependencies: ["IotaSDKFFI"],
            path: "Sources/IotaSDK",
            // Link against the pre-built Rust FFI library for local development.
            // The published package at iota-sdk-swift uses a different Package.swift
            // that bundles the library via XCFramework instead.
            linkerSettings: [
                .unsafeFlags(["-L", "Sources/IotaSDKFFI", "-liota_sdk_ffi"]),
            ]
        ),
    ]
        + exampleNames.map { name in
            .executableTarget(
                name: name,
                dependencies: ["IotaSDK"],
                path: "examples",
                exclude: exampleNames.filter { $0 != name }.map { "\($0).swift" } + ["release"],
                sources: ["\(name).swift"]
            )
        }
)

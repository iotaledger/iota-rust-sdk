// swift-tools-version: 5.9

import PackageDescription
import Foundation

// Auto-discover example files from the examples directory
let exampleNames: [String] = {
    let examplesDir = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .appendingPathComponent("examples")
    guard let files = try? FileManager.default.contentsOfDirectory(atPath: examplesDir.path) else {
        return []
    }
    return files
        .filter { $0.hasSuffix(".swift") }
        .map { String($0.dropLast(6)) }
        .sorted()
}()

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

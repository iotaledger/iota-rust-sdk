// swift-tools-version: 5.9

import PackageDescription

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
        .binaryTarget(
            name: "CIotaSDK",
            path: "IotaSDK.xcframework"
        ),
        .target(
            name: "IotaSDK",
            dependencies: ["CIotaSDK"],
            path: "Sources/IotaSDK"
        ),
    ]
)

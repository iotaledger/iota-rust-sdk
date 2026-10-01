// swift-tools-version: 5.9

import PackageDescription

let package = Package(
  name: "IotaSDKExample",
  platforms: [
    .macOS(.v13)
  ],
  dependencies: [
    .package(url: "https://github.com/iotaledger/iota-sdk-swift.git", from: "1.0.0-beta.2")
  ],
  targets: [
    .executableTarget(
      name: "Example",
      dependencies: [
        .product(name: "IotaSDK", package: "iota-sdk-swift")
      ],
      path: "Sources"
    )
  ]
)

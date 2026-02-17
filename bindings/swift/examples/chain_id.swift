// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import Foundation
import IotaSDK

@main
struct ChainIdExample {
    static func main() async {
        do {
            let client = try GraphQlClient.newDevnet()
            let chainId = try await client.chainId()
            print("Chain ID: \(chainId)")
        } catch {
            print("Error: \(error)")
            exit(1)
        }
    }
}

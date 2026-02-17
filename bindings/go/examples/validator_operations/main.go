// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"

	"github.com/iotaledger/iota-rust-sdk/bindings/go/iota_sdk"
)

func main() {
	_ = iota_sdk.GraphQlClientNewDevnet()

	fmt.Println("=== Validator Operations Example ===\n")

	// Step 1: Query validators
	fmt.Println("1. Querying active validators...")
	fmt.Println("   Use client.ActiveValidators()\n")

	// Step 2: Display info
	fmt.Println("2. Validator Information:")
	fmt.Println("   - Name and address")
	fmt.Println("   - Voting power")
	fmt.Println("   - Staking APY")
	fmt.Println("   - Pending stake/withdraw\n")

	// Step 3: Selection criteria
	fmt.Println("3. Validator Selection Criteria:")
	fmt.Println("   - Commission rates")
	fmt.Println("   - Voting power distribution")
	fmt.Println("   - Uptime and performance")
	fmt.Println("   - Staking APY")
	fmt.Println("   - Community reputation\n")

	// Step 4: Staking workflow
	fmt.Println("4. Staking Workflow:")
	fmt.Println("   a. Choose validator")
	fmt.Println("   b. Prepare transaction")
	fmt.Println("   c. Sign and submit")
	fmt.Println("   d. Monitor rewards")
	fmt.Println("   e. Unstake when needed\n")

	fmt.Println("Validator operations example completed!")
}

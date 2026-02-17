// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import "fmt"

func main() {
	fmt.Println("=== Shared Object Operations Example ===\n")

	// Step 1: Overview
	fmt.Println("1. Shared Objects Overview:")
	fmt.Println("   - Accessible by anyone")
	fmt.Println("   - Concurrent multi-transaction use")
	fmt.Println("   - Special handling required")
	fmt.Println("   - Pools, registries, state\n")

	// Step 2: Comparison
	fmt.Println("2. Shared vs Owned Objects:")
	fmt.Println("   Owned: Single owner, simpler")
	fmt.Println("   Shared: Public access, complex\n")

	// Step 3: Querying
	fmt.Println("3. Querying Shared Objects:")
	fmt.Println("   - Fetch object details")
	fmt.Println("   - Check ownership type")
	fmt.Println("   - Examine structure\n")

	// Step 4: Patterns
	fmt.Println("4. Transaction Patterns:")
	fmt.Println("   - Move calls with shared objects")
	fmt.Println("   - Multiple shared objects")
	fmt.Println("   - Mixed transactions\n")

	// Step 5: Use cases
	fmt.Println("5. Common Use Cases:")
	fmt.Println("   - DEX pools")
	fmt.Println("   - Registries")
	fmt.Println("   - Governance")
	fmt.Println("   - Public state\n")

	// Step 6: Practices
	fmt.Println("6. Best Practices:")
	fmt.Println("   - Minimize usage")
	fmt.Println("   - Handle concurrency")
	fmt.Println("   - Manage gas costs\n")

	fmt.Println("Shared objects example completed!")
}

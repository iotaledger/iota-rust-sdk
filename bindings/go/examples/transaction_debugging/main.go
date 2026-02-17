// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

package main

import "fmt"

func main() {
	fmt.Println("=== Transaction Debugging Example ===\n")

	// Step 1: Common errors
	fmt.Println("1. Common Transaction Errors:")
	fmt.Println("   - Insufficient gas")
	fmt.Println("   - Object not found")
	fmt.Println("   - Invalid version")
	fmt.Println("   - Permission denied")
	fmt.Println("   - Move abort\n")

	// Step 2: Dry run
	fmt.Println("2. Using Dry Run:")
	fmt.Println("   - Test before submission")
	fmt.Println("   - Estimate gas costs")
	fmt.Println("   - Safe error checking\n")

	// Step 3: Error interpretation
	fmt.Println("3. Error Interpretation:")
	fmt.Println("   - Read messages")
	fmt.Println("   - Check abort codes")
	fmt.Println("   - Verify ownership")
	fmt.Println("   - Validate types\n")

	// Step 4: Debugging strategies
	fmt.Println("4. Debugging Strategies:")
	fmt.Println("   a. Start with dry run")
	fmt.Println("   b. Check object states")
	fmt.Println("   c. Verify sender")
	fmt.Println("   d. Inspect effects\n")

	// Step 5: Transaction inspection
	fmt.Println("5. Transaction Inspection:")
	fmt.Println("   - Use get_transaction()")
	fmt.Println("   - Check status")
	fmt.Println("   - Review effects\n")

	// Step 6: Best practices
	fmt.Println("6. Best Practices:")
	fmt.Println("   - Always dry run first")
	fmt.Println("   - Set gas budget")
	fmt.Println("   - Handle errors")
	fmt.Println("   - Test incrementally\n")

	fmt.Println("Transaction debugging example completed!")
}

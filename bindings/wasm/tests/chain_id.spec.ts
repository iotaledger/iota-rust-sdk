// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import { expect, test } from "@playwright/test";

test("chain_id example fetches and displays the testnet chain ID", async ({
  page,
}) => {
  await page.goto("/examples/chain_id.html");

  // Wait for the async WASM + network call to finish.
  // #status is set to "Done" on success or "Error – see console" on failure.
  const status = page.locator("#status");
  await expect(status).toHaveText("Done", { timeout: 30_000 });

  // The result element must contain a chain ID in IOTA hex format (0x…).
  const result = page.locator("#result");
  await expect(result).toContainText("Chain ID: 0x");
});

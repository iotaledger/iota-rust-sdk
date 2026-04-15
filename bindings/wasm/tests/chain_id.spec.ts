// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import { expect, test } from "@playwright/test";

// Stub chain ID value used in the mocked GraphQL response.
const MOCK_CHAIN_ID = "0x243f6a8885a308d3";

test("chain_id example fetches and displays the testnet chain ID", async ({
  page,
}) => {
  // Intercept every fetch to the testnet GraphQL endpoint and return a
  // deterministic mock response.  This prevents the test from depending on
  // live network access, making it reliable in offline / flaky-network CI.
  await page.route("**graphql.testnet.iota.cafe**", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        data: { chainIdentifier: MOCK_CHAIN_ID },
      }),
    });
  });

  await page.goto("/examples/chain_id.html");

  // Wait for the async WASM + network call to finish.
  // #status is set to "Done" on success or "Error – see console" on failure.
  const status = page.locator("#status");
  await expect(status).toHaveText("Done", { timeout: 20_000 });

  // The result element must contain the mocked chain ID.
  const result = page.locator("#result");
  await expect(result).toContainText("Chain ID: " + MOCK_CHAIN_ID);
});

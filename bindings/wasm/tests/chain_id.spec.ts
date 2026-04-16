// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import { expect, test } from "@playwright/test";

// Stub chain ID value used in the mocked GraphQL response.
const MOCK_CHAIN_ID = "0x243f6a8885a308d3";

// NOTE: This test requires shared WASM function tables between the two
// dynamically-linked WASM modules (index_bg.wasm and iota_sdk_ffi_bg.wasm).
// Until that is implemented, async Rust→JS callbacks (used by every uniffi
// async method, including chainId()) will fail with "function signature
// mismatch" because call_indirect cannot cross module boundaries.
test("chain_id example fetches and displays the testnet chain ID", async ({
  page,
}) => {
  // Intercept every fetch to the testnet GraphQL endpoint and return a
  // deterministic mock response.  This prevents the test from depending on
  // live network access, making it reliable in offline / flaky-network CI.
  //
  // The dev server sets COEP/COOP headers, so the browser performs a CORS
  // preflight OPTIONS request before the POST.  Both must carry CORS headers
  // or the browser will reject the preflight and the POST never fires.
  await page.route("**graphql.testnet.iota.cafe**", async (route) => {
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
      "Access-Control-Allow-Headers": "content-type, accept",
    };
    if (route.request().method() === "OPTIONS") {
      await route.fulfill({ status: 204, headers: corsHeaders });
    } else {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        headers: corsHeaders,
        body: JSON.stringify({
          data: { chainIdentifier: MOCK_CHAIN_ID },
        }),
      });
    }
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

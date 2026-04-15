// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./tests",
  // Network calls are mocked, so 30 s is plenty.
  timeout: 30_000,
  use: {
    baseURL: "http://localhost:5173",
  },
  webServer: {
    // `pnpm run serve` builds the bundle and starts the static dev server.
    // It requires `index_bg.wasm` to already exist in src/ts/wasm-bindgen/
    // (produced by `make wasm` / `ubrn build web` earlier in CI).
    command: "pnpm run serve",
    url: "http://localhost:5173",
    // Reuse a running server in local dev; always start fresh in CI.
    reuseExistingServer: !process.env.CI,
    // Give the build + server up to 120 s on first run.
    timeout: 120_000,
  },
});

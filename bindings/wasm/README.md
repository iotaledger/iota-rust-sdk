# IOTA SDK - WASM Bindings

TypeScript/WASM bindings for the IOTA SDK, generated from the [`iota-sdk-ffi`](../../crates/iota-sdk-ffi) crate using [UniFFI](https://github.com/mozilla/uniffi-rs) and [uniffi-bindgen-react-native](https://github.com/jhugman/uniffi-bindgen-react-native).

The pipeline has two steps:

1. **Generate TS + Rust bridge** – `uniffi-bindgen-react-native` reads the native `.so` and emits `src/ts/iota_sdk_ffi.ts` (TypeScript API) and `iota-sdk-wasm/src/iota_sdk_ffi_module.rs` (wasm-bindgen Rust bridge).
2. **Compile to WASM + generate JS glue** – `iota-sdk-wasm` statically links `iota-sdk-ffi` and compiles to `wasm32-unknown-unknown`, then `wasm-bindgen` emits the browser JS glue.

> **Why a separate `iota-sdk-wasm` crate?** The generated bridge uses `extern "C" { fn uniffi_iota_sdk_ffi_fn_*... }` to reference UniFFI symbols. These must come from an external crate; they cannot be placed inside `iota-sdk-ffi` itself.

## Prerequisites

```bash
# WASM target
rustup target add wasm32-unknown-unknown

# wasm-bindgen CLI, at the version pinned in wasm-cargo-patch.toml (run from the repository root)
make wasm-bindgen-cli
```

The binding generator (`uniffi-bindgen-react-native`) is installed as an npm dependency and invoked via `npx`.

## Build

From the workspace root, run:

```bash
make wasm
```

This single command performs all three stages (generate bindings, compile to WASM, bundle for browser) and works on both macOS and Linux without any manual changes. The output is `bindings/wasm/dist/iota-sdk.js` + `dist/index_bg.wasm`, along with TypeScript declarations under `dist/types/` (entry `dist/types/index.web.d.ts`).

<details>
<summary>What the build does (detailed steps)</summary>

### Step 1 – Generate TypeScript bindings and Rust bridge

Builds `iota-sdk-ffi` for the native target, then runs `uniffi-bindgen-react-native` to extract UniFFI metadata and emit:

- `bindings/wasm/src/ts/iota_sdk_ffi.ts` – full TypeScript API (~45 k lines)
- `iota-sdk-wasm/src/iota_sdk_ffi_module.rs` – wasm-bindgen bridge

### Step 2 – Compile to WASM and generate JS glue

Compiles `iota-sdk-wasm` to `wasm32-unknown-unknown` with the `wasm-release` profile, optionally runs `wasm-opt` (if installed via `binaryen`), then runs `wasm-bindgen` to emit the browser JS glue.

### Step 3 – Bundle for the browser

Runs the TypeScript fixer script, bundles everything into `dist/iota-sdk.js` via esbuild, copies the WASM binary alongside it, and emits TypeScript declarations to `dist/types/` (via `tsc -p tsconfig.types.json`).

</details>

## Run the examples

The scripts under [`examples/`](examples) are Node programs (`.mjs`) that import
the package exactly as an npm consumer would (resolved to this package via the
pnpm workspace). From the workspace root:

```bash
make wasm-example chain_id   # run a single example with Node
make wasm-examples           # run every example
```

Most examples expect a running localnet (see `run_localnet.sh` at the repo
root); `chain_id` and a few read-only examples run against the public testnet.

The standalone [`examples/release/`](examples/release) project instead consumes
the **published** `@iota/sdk-wasm` from npm (rather than the workspace-local
build), for a minimal smoke test of the released package:

```bash
make wasm-release-example
```

To open the browser (HTML) examples instead, start the dev server:

```bash
make wasm-serve              # serves http://localhost:5173/examples/chain_id.html
```

## Using the bindings

```javascript
import { initAsync, GraphQlClient } from "./dist/iota-sdk.js";

await initAsync();

const client = GraphQlClient.newTestnet();
const chainId = await client.chainId();
console.log("Chain ID:", chainId);
```

See [`examples/chain_id.html`](examples/chain_id.html) for a complete browser example.

## Ledger

`Ledger` connects to the IOTA app on a Ledger hardware wallet, and a `LedgerSigner` signs transactions and personal messages with the key at one derivation path.

WASM can open neither USB devices nor TCP sockets, so `Ledger.nativeHid` and the calls on a `Ledger.speculos` connection fail. The device is reached through a `LedgerTransport` implemented in JavaScript and passed to `Ledger.fromTransport`: its `exchange` method receives an APDU command and returns the device's answer, which ends with the two-byte status word, both as an `ArrayBuffer`.

### Browser

Ledger's WebHID and WebUSB transports exchange the same bytes, as a Node.js `Buffer`. With [`@ledgerhq/hw-transport-webhid`](https://www.npmjs.com/package/@ledgerhq/hw-transport-webhid), in a Chromium-based browser:

```javascript
import TransportWebHID from "@ledgerhq/hw-transport-webhid";

// Asks the user to select the device the first time, which the browser
// only allows in response to a user action such as a click
const device = await TransportWebHID.create();
const ledger = Ledger.fromTransport({
  async exchange(apdu) {
    const answer = await device.exchange(Buffer.from(apdu));
    return new Uint8Array(answer).buffer;
  },
});
const signer = await ledger.signer("m/44'/4218'/0'/0'/0'");

const builder = client.transactionBuilder(signer.address());
builder.sendIota(recipientAddress, PtbArgument.u64(1000n));
const effects = await builder.execute(
  TransactionSigner.fromLedger(signer),
  WaitForTransaction.Finalized,
);
```

- Install the IOTA app on the device with Ledger Live, unlock the device and open the app. `openApp` can open it instead, but that disconnects the device, so the transport's `exchange` then has to connect again.
- On Linux, install the udev rules from [LedgerHQ/udev-rules](https://github.com/LedgerHQ/udev-rules) so that the browser can open the device.

### Speculos

[Speculos](https://github.com/LedgerHQ/speculos) emulates a device running the IOTA app, for development without hardware. From the repository root, `make speculos-start` runs it in Docker and `make speculos-stop` stops it; [Using Speculos](../../crates/iota-sdk-ledger/README.md#using-speculos) describes running it yourself. Requests are approved in the emulator's web interface at <http://127.0.0.1:5001>.

Under Node, a transport over a TCP socket reaches the emulator's APDU port, as in the [`ledger_sign_send_iota`](examples/ledger_sign_send_iota.mjs) example. With a local network running, `make ledger-example lang=wasm` starts the emulator, runs the example on it and approves the transaction.

### Clear and blind signing

The IOTA app shows what a transaction does when it can work that out from the transaction and its input objects. The transaction builder passes them to a `TransactionSigner.fromLedger` signer; `LedgerSigner.signTransaction` sends none, and `signTransactionWithObjects` takes them as an argument. A transaction the app cannot interpret is only signed when blind signing is enabled in the app's settings. Otherwise the device tells the user so, and `LedgerSigner` then fails with `LedgerError.BlindSigningDisabled`.

## File layout

```
bindings/wasm/
  examples/
    chain_id.html          # browser example
    staking.html           # browser example
    *.mjs                  # Node examples (run via `make wasm-example NAME`)
    package.json           # pnpm workspace member that resolves `@iota/sdk-wasm`
    release/               # standalone project using the published @iota/sdk-wasm (npm)
  dist/                    # build output (gitignored)
    iota-sdk.js            # bundled ES module (browser / default entry)
    node.js                # Node entry (loads index_bg.wasm from disk)
    index_bg.wasm          # WASM binary
    types/                 # generated TypeScript declarations
  src/
    ts/
      iota_sdk_ffi.ts      # generated TypeScript API
      index.web.ts         # entrypoint (re-exports + initAsync)
      node-init.mjs        # Node entry source (copied to dist/node.js)
      wasm-bindgen/        # generated by wasm-bindgen CLI
        index.js
        index_bg.js
        index_bg.wasm
        index.d.ts
        index_bg.wasm.d.ts
  scripts/
    fix-generated-typescript.mjs  # normalizes generated TS (auto-run by build)
    serve.mjs                     # dev server for browser examples (make wasm-serve)
  iota-sdk-wasm/           # thin crate compiled to wasm32 (placeholder; ubrn regenerates it)
    Cargo.toml
    src/
      lib.rs
      iota_sdk_ffi_module.rs  # generated wasm-bindgen bridge
```

## Notes

- Async FFI exports use `#[uniffi::export(async_runtime = "tokio")]` only on native targets (via `cfg_attr`); on wasm32 they use a plain `#[uniffi::export]`. The tokio variant wraps every future in `async_compat::Compat`, which panics on wasm32 because it spawns a runtime thread — on wasm32 futures are driven by the JS event loop instead and need no tokio context.
- The `fix-generated-typescript.mjs` script fixes known issues in the generated TypeScript: wrong `async public` method order, a generated `Object` class that shadows the built-in, a reserved `arguments` parameter name, and redirecting `index.js` imports to `index_bg.js` (avoids WASM loader issues in esbuild).
- Async operations use Tokio's minimal `macros` + `rt` + `sync` feature set when compiled for WASM.
- `getrandom` is configured with the `wasm_js` feature for browser-compatible randomness.

# iota-sdk-ledger

[![iota-sdk-ledger on crates.io](https://img.shields.io/crates/v/iota-sdk-ledger)](https://crates.io/crates/iota-sdk-ledger)
[![Documentation (latest release)](https://img.shields.io/badge/docs-latest-brightgreen)](https://docs.rs/iota-sdk-ledger)

The `iota-sdk-ledger` crate communicates with the IOTA app on Ledger hardware
wallets, or on the Speculos emulator: it reads public keys and addresses,
shows addresses for verification, signs transactions and personal messages,
and opens or closes the app.

```rust,no_run
use iota_sdk_ledger::{Ledger, iota_crypto::DerivationPath};

async fn print_address() -> Result<(), Box<dyn std::error::Error>> {
    let mut ledger = Ledger::native_hid()?;
    ledger.ensure_app_is_open().await?;

    let path: DerivationPath = "m/44'/4218'/0'/0'/0'".parse()?;
    let key = ledger.get_public_key(&path).await?;
    println!("{}", key.derive_address());
    Ok(())
}
```

Calls are async so that transports backed by asynchronous host APIs, such as
WebHID, can be plugged in. The USB HID and Speculos transports block the thread
polling a call until the device answers; synchronous programs can run calls
with an executor such as `futures::executor::block_on`.

## Signing

`LedgerSigner` signs with the key at one derivation path and returns the
`UserSignature` to submit with a transaction. Passing the transaction's input
objects lets the device show what it does; without them the device only signs
when blind signing is enabled in the IOTA app's settings.

```rust,no_run
use iota_sdk_ledger::{Ledger, LedgerSigner, iota_types::{Object, Transaction}};

async fn sign(
    transaction: &Transaction,
    objects: &[Object],
) -> Result<(), Box<dyn std::error::Error>> {
    let ledger = Ledger::native_hid()?;
    let signer = LedgerSigner::new(ledger, "m/44'/4218'/0'/0'/0'".parse()?).await?;
    let signature = signer
        .sign_transaction_with_objects(transaction, objects)
        .await?;
    println!("{} signed: {signature:?}", signer.address());
    Ok(())
}
```

## Transports

- USB HID, through `Ledger::native_hid` for the first device found, or
  `Ledger::native_hid_device` for one listed by `Ledger::hid_devices`.
- TCP to the Speculos emulator, through `Ledger::speculos`; the emulator's
  APDU port is 9999 by default.
- Any other link, by implementing `Transport` and passing it to `Ledger::new`.

## Features

- `hid` (default): the USB HID transport, built on `hidapi`, which supports
  Linux, macOS, Windows and the BSDs; on Linux it links `libudev`, so building
  needs its development package (`libudev-dev` on Debian and Ubuntu). Disable
  it to build for other targets with a custom transport.
- `speculos`: the transport to the Speculos emulator, for development and
  testing without a device.

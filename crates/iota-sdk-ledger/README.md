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
    let mut ledger = Ledger::new_native_hid()?;
    ledger.open_app().await?;

    let path: DerivationPath = "m/44'/4218'/0'/0'/0'".parse()?;
    let key = ledger.get_public_key(&path).await?;
    println!("{}", key.derive_address());
    Ok(())
}
```

Calls are async so that transports backed by asynchronous host APIs, such as
WebHID, can be plugged in. The Speculos transport blocks the thread polling a
call until the emulator answers; synchronous programs can run calls with an
executor such as `futures::executor::block_on`.

## Signing

`LedgerSigner` signs with the key at one derivation path and returns the
`UserSignature` to submit with a transaction. Passing the transaction's input
objects lets the device show what it does; without them the device only signs
when blind signing is enabled in the IOTA app's settings.

```rust,no_run
use iota_sdk_ledger::{
    Ledger,
    iota_types::{Object, Transaction},
};

async fn sign(
    transaction: &Transaction,
    objects: &[Object],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut ledger = Ledger::new_native_hid()?;
    ledger.open_app().await?;

    let signer = ledger.into_signer("m/44'/4218'/0'/0'/0'".parse()?).await?;
    let signature = signer
        .sign_transaction_with_objects(transaction, objects)
        .await?;
    println!("{} signed: {signature:?}", signer.address());
    Ok(())
}
```

## Transports

- USB HID, through `Ledger::new_native_hid` for the first device found, or
  `Ledger::new_native_hid_device` for one listed by `Ledger::hid_devices`.
- TCP to the Speculos emulator, through `Ledger::new_speculos`; the emulator's
  APDU port is 9999 by default.
- Any other link, by implementing `Transport` and passing it to `Ledger::new`.

## Using a device

Install the IOTA app on the device with Ledger Live, unlock the device and
open the app, or call `Ledger::ensure_app_is_open` to open it.

On Linux, a regular user can only open the device once udev rules grant access
to Ledger's USB vendor ID; install the rules from
[LedgerHQ/udev-rules](https://github.com/LedgerHQ/udev-rules).

## Using Speculos

[Speculos](https://github.com/LedgerHQ/speculos) emulates a device running the
IOTA app, for development and testing without hardware. The app builds for
each device model are attached to the
[ledger-app-iota releases](https://github.com/iotaledger/ledger-app-iota/releases);
for a Nano S Plus, extract `nanosplus.tar.gz` and run:

```sh
docker run --rm -p 9999:9999 -p 5000:5000 -v "$PWD/nanosplus:/speculos/apps" \
  ghcr.io/ledgerhq/speculos --model nanosp --display headless \
  --apdu-port 9999 --api-port 5000 apps/iota
```

Connect with `Ledger::speculos("127.0.0.1", 9999)`, and approve requests in the
web interface at <http://127.0.0.1:5000> or through its REST API. The emulator
runs a single app and cannot switch apps, so `Ledger::ensure_app_is_open` does
nothing there.

## Clear and blind signing

The IOTA app shows what a transaction does when it receives the transaction's
input objects: pass them to `LedgerSigner::sign_transaction_with_objects`.
Without them, or for a transaction the app cannot interpret, it signs only when
blind signing is enabled in the app's settings, and fails with
`LedgerError::BlindSigningDisabled` otherwise. Personal messages are shown
too, unless they are too long for the app to display, which also needs blind
signing.

## Features

- `hid` (default): the USB HID transport, built on `hidapi`, which supports
  Linux, macOS, Windows and the BSDs; on Linux it links `libudev`, so building
  needs its development package (`libudev-dev` on Debian and Ubuntu). Disable
  it to build for other targets with a custom transport.
- `speculos`: the transport to the Speculos emulator, for development and
  testing without a device.

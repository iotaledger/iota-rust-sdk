# iota-sdk-ledger

[![iota-sdk-ledger on crates.io](https://img.shields.io/crates/v/iota-sdk-ledger)](https://crates.io/crates/iota-sdk-ledger)
[![Documentation (latest release)](https://img.shields.io/badge/docs-latest-brightgreen)](https://docs.rs/iota-sdk-ledger)

The `iota-sdk-ledger` crate communicates with the IOTA app on Ledger hardware
wallets, or on the Speculos emulator: it reads public keys and addresses,
shows addresses for verification, signs transactions and personal messages,
and opens or closes the app.

```rust,no_run
use iota_sdk_ledger::{Ledger, iota_crypto::DerivationPath};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let mut ledger = Ledger::native_hid()?;
ledger.ensure_app_is_open()?;

let path: DerivationPath = "m/44'/4218'/0'/0'/0'".parse()?;
let key = ledger.get_public_key(&path)?;
println!("{}", key.derive_address());
# Ok(())
# }
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

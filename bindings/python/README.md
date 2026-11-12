# IOTA SDK Library - Python Bindings

This document describes how to generate platform specific Python bindings for the IOTA SDK locally from the repository itself.

Instructions on how you can add the officially released Python bindings to your project via `pip` you can find [`here`](src/README.md).

## Prerequisites

Make sure to have those dependencies installed on your system:

- GNU Make
- Python3

Please follow the general install instructions for your platform.

Verify by running `make --version` and `python3 --version`.

## Generate Python bindings module `iota_sdk.py`

1. Build the bindings: `make python`
2. Test by running the following minimal example: `make python-example chain_id`

## Ledger

`Ledger` connects to the IOTA app on a Ledger hardware wallet, and a `LedgerSigner` signs transactions and personal messages with the key at one derivation path:

```python
ledger = Ledger.native_hid()
await ledger.open_app()
signer = await ledger.signer("m/44'/4218'/0'/0'/0'")

builder = client.transaction_builder(signer.address())
builder.send_iota(recipient_address, PtbArgument.u64(1000))
effects = await builder.execute(TransactionSigner.from_ledger(signer),
                                WaitForTransaction.FINALIZED)
```

The complete program is the [`ledger_sign_send_iota`](examples/ledger_sign_send_iota.py) example.

### USB

`Ledger.native_hid` connects to the first Ledger device attached over USB, on Linux, macOS and Windows.

- Install the IOTA app on the device with Ledger Live and unlock the device. `open_app` opens the app.
- On Linux, install the udev rules from [LedgerHQ/udev-rules](https://github.com/LedgerHQ/udev-rules) so that a regular user can open the device.
- The wheels released on PyPI are built without USB support, so `Ledger.native_hid` fails with them. The bindings built by `make python` have it; on Linux that build needs the `libudev` development package (`libudev-dev` on Debian and Ubuntu).

### Speculos

[Speculos](https://github.com/LedgerHQ/speculos) emulates a device running the IOTA app, for development without hardware. From the repository root, `make speculos-start` runs it in Docker and `make speculos-stop` stops it; [Using Speculos](../../crates/iota-sdk-ledger/README.md#using-speculos) describes running it yourself. Connect with `Ledger.speculos("127.0.0.1", 9999)` and approve requests in the emulator's web interface at <http://127.0.0.1:5001>.

With a local network running, `make ledger-example lang=python` starts the emulator, runs the example on it and approves the transaction.

### Host transport

To reach a device over a link the SDK does not provide, subclass `LedgerTransport` and pass it to `Ledger.from_transport`. Its `exchange` method receives an APDU command and returns the device's answer, which ends with the two-byte status word.

### Clear and blind signing

The IOTA app shows what a transaction does when it can work that out from the transaction and its input objects. The transaction builder passes them to a `TransactionSigner.from_ledger` signer; `LedgerSigner.sign_transaction` sends none, and `sign_transaction_with_objects` takes them as an argument. A transaction the app cannot interpret is only signed when blind signing is enabled in the app's settings. Otherwise the device tells the user so, and `LedgerSigner` then fails with `LedgerError.BlindSigningDisabled`.

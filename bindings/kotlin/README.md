# IOTA SDK - Kotlin Bindings

## Prerequisites

Make sure to have those dependencies installed on your system:

- GNU Make
- Gradle

It is recommended to install `Gradle` through:

```bash
curl -s "https://get.sdkman.io" | bash
source "$HOME/.sdkman/bin/sdkman-init.sh"
sdk install gradle
```

Verify by running `make --version` and `gradle --version`.

## Generate Kotlin bindings

```bash
make kotlin
```

## Run Kotlin example

```sh
make kotlin-example chain_id
```

## Android Support

The IOTA Kotlin SDK supports Android via [JNA](https://github.com/java-native-access/jna) (Java Native Access). JNA 5.13.0+ includes native Android support and automatically extracts `.so` files from JAR resources at runtime.

### Supported ABIs

| Android ABI | JNA Resource Prefix | Rust Target               |
| ----------- | ------------------- | ------------------------- |
| arm64-v8a   | `android-aarch64`   | `aarch64-linux-android`   |
| armeabi-v7a | `android-arm`       | `armv7-linux-androideabi` |
| x86_64      | `android-x86-64`    | `x86_64-linux-android`    |
| x86         | `android-x86`       | `i686-linux-android`      |

### Minimum API Level

The native libraries are built with a minimum API level of **21** (Android 5.0 Lollipop).

### Gradle Setup

Add the following dependencies to your Android app's `build.gradle.kts`:

```kotlin
dependencies {
    implementation("org.iota:iota-sdk:latest.release") {
        exclude(group = "net.java.dev.jna", module = "jna")
    }
    implementation("net.java.dev.jna:jna:5.13.0@aar")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
}
```

The `@aar` suffix is required for JNA on Android — it packages JNA's Android-specific native libraries. The `exclude` on `iota-sdk` prevents the JNA JAR (pulled as a transitive dependency) from conflicting with the JNA AAR.

### How Native Loading Works

1. Your app depends on `org.iota:iota-sdk` (JAR containing `.so` files at `android-aarch64/`, etc.)
2. Your app depends on `net.java.dev.jna:jna:5.13.0@aar` (JNA with Android support)
3. At runtime, `Native.load("iota_sdk_ffi", ...)` triggers JNA to detect Android and resolve `Platform.RESOURCE_PREFIX` (e.g., `android-aarch64`)
4. JNA extracts the `.so` from classpath resources to the app's private directory and loads it

### Alternative: Manual jniLibs Placement

For maximum compatibility, you can place `.so` files directly in your app module:

```
app/src/main/jniLibs/
├── arm64-v8a/libiota_sdk_ffi.so
├── armeabi-v7a/libiota_sdk_ffi.so
├── x86_64/libiota_sdk_ffi.so
└── x86/libiota_sdk_ffi.so
```

Android packages these into the APK's `lib/<abi>/` directory automatically.

### Building Native Libraries Locally

To build the Android native libraries locally, you need the Android NDK and `cargo-ndk`:

```bash
# Add Android Rust targets
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android

# Install cargo-ndk
cargo install cargo-ndk

# Set ANDROID_NDK_HOME if not already set (replace with your actual NDK path)
# Example: export ANDROID_NDK_HOME=/home/alice/Android/Sdk/ndk/26.1.10909125
export ANDROID_NDK_HOME=/path/to/your/Android/Sdk/ndk/<version>

# Build for all Android ABIs
make kotlin-android
```

This builds `.so` files for all 4 ABIs and copies them to `bindings/kotlin/lib/android-*/`.

### Demo App

See [`examples/android-demo/`](examples/android-demo/) for a minimal Android app using the IOTA Kotlin SDK.

## Ledger

`Ledger` connects to the IOTA app on a Ledger hardware wallet, and a `LedgerSigner` signs transactions and personal messages with the key at one derivation path:

```kotlin
val ledger = Ledger.nativeHid()
ledger.openApp()
val signer = ledger.signer("m/44'/4218'/0'/0'/0'")

val builder = client.transactionBuilder(signer.address())
builder.sendIota(recipientAddress, PtbArgument.u64(1000uL))
val effects =
    builder.execute(TransactionSigner.fromLedger(signer), WaitForTransaction.FINALIZED)
```

The complete program is the [`LedgerSignSendIota`](examples/LedgerSignSendIota.kt) example.

### USB

`Ledger.nativeHid` connects to the first Ledger device attached over USB, on Linux, macOS and Windows.

- Install the IOTA app on the device with Ledger Live and unlock the device. `openApp` opens the app.
- On Linux, install the udev rules from [LedgerHQ/udev-rules](https://github.com/LedgerHQ/udev-rules) so that a regular user can open the device.
- The native libraries of the released package are built without USB support, so `Ledger.nativeHid` fails with them. The library built by `make kotlin` has it; on Linux that build needs the `libudev` development package (`libudev-dev` on Debian and Ubuntu).

### Speculos

[Speculos](https://github.com/LedgerHQ/speculos) emulates a device running the IOTA app, for development without hardware. From the repository root, `make speculos-start` runs it in Docker and `make speculos-stop` stops it; [Using Speculos](../../crates/iota-sdk-ledger/README.md#using-speculos) describes running it yourself. Connect with `Ledger.speculos("127.0.0.1", 9999u)` and approve requests in the emulator's web interface at <http://127.0.0.1:5001>.

With a local network running, `make ledger-example lang=kotlin` starts the emulator, runs the example on it and approves the transaction.

### Host transport

The Android libraries cannot open USB devices. To reach a device there, or over any other link the SDK does not provide, implement `LedgerTransport` on top of that link, such as Bluetooth through Ledger's mobile SDKs, and pass it to `Ledger.fromTransport`:

```kotlin
class BluetoothTransport : LedgerTransport {
    override suspend fun exchange(apdu: ByteArray): ByteArray {
        // Send the APDU command to the device and return its answer, which
        // ends with the two-byte status word
    }
}

val ledger = Ledger.fromTransport(BluetoothTransport())
```

### Clear and blind signing

The IOTA app shows what a transaction does when it can work that out from the transaction and its input objects. The transaction builder passes them to a `TransactionSigner.fromLedger` signer; `LedgerSigner.signTransaction` sends none, and `signTransactionWithObjects` takes them as an argument. A transaction the app cannot interpret is only signed when blind signing is enabled in the app's settings. Otherwise the device tells the user so, and `LedgerSigner` then fails with `LedgerException.BlindSigningDisabled`.

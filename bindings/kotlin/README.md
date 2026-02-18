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
# Install cargo-ndk
cargo install cargo-ndk

# Build for all Android ABIs
make kotlin-android
```

This builds `.so` files for all 4 ABIs and copies them to `bindings/kotlin/lib/android-*/`.

### Demo App

See [`examples/android-demo/`](examples/android-demo/) for a minimal Android app using the IOTA Kotlin SDK.

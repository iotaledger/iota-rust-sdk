# IOTA SDK Android Demo

A minimal Android app demonstrating the IOTA Kotlin SDK. It fetches the chain ID from the IOTA devnet using `GraphQlClient`.

## Prerequisites

- Android Studio (or Android SDK command-line tools)
- Android SDK with API level 35
- JDK 17+

## Build & Run

### Using the published SDK (default)

The app is configured to use the latest published `org.iota:iota-sdk` from Maven Central:

```bash
cd bindings/kotlin/examples/android-demo
./gradlew :app:assembleDebug
```

The APK will be at `app/build/outputs/apk/debug/app-debug.apk`.

### Using locally built native libraries

If you want to test with locally built `.so` files:

1. Build the native libraries (requires [cargo-ndk](https://github.com/nickelc/cargo-ndk) and Android NDK):
   ```bash
   # From the repository root
   cargo install cargo-ndk
   make kotlin-android
   ```

2. Copy the libraries into the app's `jniLibs`:
   ```bash
   mkdir -p app/src/main/jniLibs/arm64-v8a
   mkdir -p app/src/main/jniLibs/armeabi-v7a
   mkdir -p app/src/main/jniLibs/x86_64
   mkdir -p app/src/main/jniLibs/x86
   cp ../../lib/android-aarch64/libiota_sdk_ffi.so app/src/main/jniLibs/arm64-v8a/
   cp ../../lib/android-arm/libiota_sdk_ffi.so app/src/main/jniLibs/armeabi-v7a/
   cp ../../lib/android-x86-64/libiota_sdk_ffi.so app/src/main/jniLibs/x86_64/
   cp ../../lib/android-x86/libiota_sdk_ffi.so app/src/main/jniLibs/x86/
   ```

3. Build and install:
   ```bash
   ./gradlew :app:installDebug
   ```

## What It Does

The app displays a button that, when pressed, calls `GraphQlClient.newDevnet().chainId()` and shows the result (or error) on screen.

### Expected Result

<p align="center">
  <img src="screenshot.png" alt="IOTA SDK Android Demo" width="300"/>
</p>

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

## Android support

The Kotlin SDK can be consumed by Android apps with the published Maven artifact.

### Gradle setup (Kotlin DSL)

```kotlin
dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
    }
}

dependencies {
    implementation("org.iota:iota-sdk:<version>")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
}
```

### Native libraries

`kotlin_publish.yml` now builds and packages Android Rust FFI libraries for:

- `arm64-v8a`
- `armeabi-v7a`
- `x86_64`

These are distributed as release artifacts and can be consumed by Android packaging flows.

### Android demo

A minimal Android demo is included at:

- `bindings/kotlin/examples/android-demo`

It performs one IOTA API call (`GraphQlClient.newDevnet().chainId()`) and displays the result in UI.

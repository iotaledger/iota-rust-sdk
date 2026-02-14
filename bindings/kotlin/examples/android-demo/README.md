# Android Demo (IOTA Kotlin SDK)

Minimal Android demo that uses the published Kotlin SDK and performs one API call:

- `GraphQlClient.newDevnet().chainId()`

## Build

```bash
./gradlew :app:assembleDebug
```

## Notes

- Requires Android SDK/NDK toolchain configured on host machine.
- Ensure network access from emulator/device to devnet endpoint.

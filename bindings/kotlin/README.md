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

## Publishing to Maven Central

### Publishing

For snapshot releases, set the version in `build.gradle.kts` to end with `-SNAPSHOT`.

#### Dry Run Testing

To test the publishing process without actually publishing to Maven Central:

1. Go to the Actions tab in GitHub
2. Select "Publish to Maven Central" workflow
3. Click "Run workflow"
4. Check "Dry run - publish to local Maven repo only"
5. Optionally specify a version
6. Run the workflow

This will build all artifacts, sign them, and publish to your local Maven repository (`~/.m2/repository`) for verification, without uploading to Maven Central.

**Note:** The dry run uses the same GPG signing secrets as real publishing, but skips the Sonatype upload step.

#### Local Testing

You can also test the publishing process locally (signing is optional):

**Complete local testing script:**

```bash
#!/bin/bash
cd bindings/kotlin

# Test publish to Maven Local (no GPG required)
./gradlew clean publishToMavenLocal --info

# Verify the results
echo "Published artifacts:"
find ~/.m2/repository/org/iota -name "*.jar" -o -name "*.pom" | head -5

echo "JAR contents check:"
jar -tf ~/.m2/repository/org/iota/iota-sdk-jvm/1.0-SNAPSHOT/iota-sdk-jvm-1.0-SNAPSHOT.jar | grep -E "(libiota_sdk_ffi|iota_sdk)" | wc -l
echo "files found (should be > 1)"
```

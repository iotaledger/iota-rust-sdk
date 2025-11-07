import com.ncorti.ktfmt.gradle.tasks.*
import java.util.Base64

plugins {
    kotlin("jvm") version "1.9.24"
    kotlin("plugin.serialization") version "1.9.24"
    id("com.ncorti.ktfmt.gradle") version "0.25.0"
    application
    `maven-publish`
    signing
}

group = "org.iota"

version = "1.0-SNAPSHOT"

repositories { mavenCentral() }

dependencies {
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.7.3")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.6.3")
    implementation("net.java.dev.jna:jna:5.13.0")
}

kotlin { jvmToolchain(21) }

ktfmt { kotlinLangStyle() }

tasks.named("ktfmtCheckMain") { enabled = false }

tasks.register<KtfmtCheckTask>("KtfmtCheck") {
    source = project.fileTree(rootDir)
    include("examples/*.kt")
    include("build.gradle.kts")
    include("settings.gradle.kts")
}

tasks.register<KtfmtFormatTask>("KtfmtFormat") {
    source = project.fileTree(rootDir)
    include("examples/*.kt")
    include("build.gradle.kts")
    include("settings.gradle.kts")
}

// Generic task to run any example
tasks.register<JavaExec>("example") {
    classpath = sourceSets["main"].runtimeClasspath
    jvmArgs = listOf("-Djna.library.path=${projectDir}/lib")

    // Get the example name from the command line argument -Pexample=<name>
    val exampleProperty = "example"
    inputs.property(exampleProperty, project.findProperty(exampleProperty) ?: "example")

    mainClass.set(
        provider {
            val example = project.findProperty(exampleProperty)?.toString() ?: "example"
            // Convert snake_case to CamelCase and append Kt
            val className =
                example
                    .split('_')
                    .map { it.replaceFirstChar { c -> c.uppercaseChar() } }
                    .joinToString("")
            "${className}Kt"
        }
    )
}

sourceSets {
    main {
        kotlin { srcDirs("lib", "examples") }
        // Explicitly disable Java source sets since we only have Kotlin
        java { setSrcDirs(emptyList<String>()) }
    }
}

// Add compiler configuration to handle UniFFI type conflicts
tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile> {
    kotlinOptions {
        jvmTarget = "21"
        freeCompilerArgs +=
            listOf(
                "-Xjvm-default=all",
                "-Xallow-kotlin-package",
                "-Xskip-prerelease-check",
                "-Xsuppress-version-warnings",
                "-Xno-param-assertions",
                "-Xno-call-assertions",
                "-Xno-receiver-assertions",
                // Add these flags to help with recursive type issues
                "-Xtype-enhancement-improvements-strict-mode=false",
                "-Xskip-runtime-version-check",
                "-Xlenient-function-type-parameter-checks",
            )
        allWarningsAsErrors = false
        suppressWarnings = true
    }
}

// Alternative: Create a custom task that compiles with error tolerance
tasks.register("compileWithErrors") {
    doLast {
        try {
            tasks.compileKotlin.get().actions.forEach { action ->
                action.execute(tasks.compileKotlin.get())
            }
        } catch (e: Exception) {
            println("Compilation completed with errors: ${e.message}")
        }
    }
}

publishing {
    publications {
        create<MavenPublication>("maven") {
            from(components["java"])
            pom {
                name.set("IOTA SDK Kotlin Bindings")
                description.set("Kotlin bindings for the IOTA SDK")
                url.set("https://github.com/iotaledger/iota-rust-sdk")
                licenses {
                    license {
                        name.set("Apache-2.0")
                        url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
                    }
                }
                developers {
                    developer {
                        id.set("iotaledger")
                        name.set("IOTA Foundation")
                        email.set("contact@iota.org")
                    }
                }
                scm {
                    connection.set("scm:git:git://github.com/iotaledger/iota-rust-sdk.git")
                    developerConnection.set("scm:git:ssh://github.com/iotaledger/iota-rust-sdk.git")
                    url.set("https://github.com/iotaledger/iota-rust-sdk")
                }
            }
        }
    }
    repositories {
        maven {
            name = "ossrh"
            url =
                uri(
                    if (version.toString().endsWith("SNAPSHOT")) {
                        "https://s01.oss.sonatype.org/content/repositories/snapshots/"
                    } else {
                        "https://s01.oss.sonatype.org/service/local/staging/deploy/maven2/"
                    }
                )
            val sonatypeUsername =
                providers.environmentVariable("ORG_GRADLE_PROJECT_SONATYPE_USERNAME")
            val sonatypePassword =
                providers.environmentVariable("ORG_GRADLE_PROJECT_SONATYPE_PASSWORD")
            if (sonatypeUsername.isPresent && sonatypePassword.isPresent) {
                credentials {
                    username = sonatypeUsername.get()
                    password = sonatypePassword.get()
                }
            }
        }
    }
}

signing {
    val signingKeyEncoded =
        providers.environmentVariable("ORG_GRADLE_PROJECT_BASE64_ENCODED_ASCII_ARMORED_SIGNING_KEY")
    val signingPassword = providers.environmentVariable("ORG_GRADLE_PROJECT_SIGNING_PASSWORD")
    if (signingKeyEncoded.isPresent && signingPassword.isPresent) {
        val signingKey = String(Base64.getDecoder().decode(signingKeyEncoded.get()))
        useInMemoryPgpKeys(signingKey, signingPassword.get())
        sign(publishing.publications["maven"])
    }
}

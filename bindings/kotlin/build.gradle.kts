import com.ncorti.ktfmt.gradle.tasks.*
import java.util.Base64
import org.gradle.api.tasks.bundling.Jar

plugins {
    kotlin("jvm") version "2.2.21"
    kotlin("plugin.serialization") version "2.2.21"
    id("com.ncorti.ktfmt.gradle") version "0.25.0"
    id("com.vanniktech.maven.publish") version "0.30.0"
    id("org.jetbrains.dokka") version "1.9.20"
    application
    signing
}

group = "org.iota"

version = "0.0.1-alpha.4"

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

// API reference generation (scripts/reference-docs/generate.sh): document
// only the generated bindings under lib/, not the examples.
tasks.withType<org.jetbrains.dokka.gradle.DokkaTask>().configureEach {
    dokkaSourceSets { named("main") { sourceRoots.setFrom(file("lib")) } }
}

sourceSets {
    main {
        kotlin {
            srcDirs("lib", "examples")
            exclude("android-demo/**")
        }
        resources {
            srcDir("lib")
            exclude("**/*.kt")
        }
        // Explicitly disable Java source sets since we only have Kotlin
        java { setSrcDirs(emptyList<String>()) }
    }
}

// Add compiler configuration to handle UniFFI type conflicts
tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile> {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_21)
        freeCompilerArgs.addAll(
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
            )
        )
        allWarningsAsErrors.set(false)
        suppressWarnings.set(true)
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

mavenPublishing {
    publishToMavenCentral(com.vanniktech.maven.publish.SonatypeHost.CENTRAL_PORTAL)
    signAllPublications()

    coordinates("org.iota", "iota-sdk", version.toString())

    pom {
        name.set("IOTA Kotlin SDK")
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
                email.set("info@iota.org")
            }
        }
        scm {
            connection.set("scm:git:git://github.com/iotaledger/iota-rust-sdk.git")
            developerConnection.set("scm:git:ssh://github.com/iotaledger/iota-rust-sdk.git")
            url.set("https://github.com/iotaledger/iota-rust-sdk")
        }
    }
}

signing {
    val signingKeyEncoded = providers.environmentVariable("ORG_GRADLE_PROJECT_signingInMemoryKey")
    val signingPassword =
        providers.environmentVariable("ORG_GRADLE_PROJECT_signingInMemoryKeyPassword")
    if (signingKeyEncoded.isPresent && signingPassword.isPresent) {
        val signingKey = String(Base64.getDecoder().decode(signingKeyEncoded.get()))
        useInMemoryPgpKeys(signingKey, signingPassword.get())
    }
}

tasks.whenTaskAdded {
    if (name == "sourcesJar") {
        (this as Jar).exclude("**/*.so", "**/*.dylib", "**/*.dll")
    }
}

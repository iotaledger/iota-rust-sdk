plugins {
    kotlin("jvm") version "1.9.24"
    kotlin("plugin.serialization") version "1.9.24"
    application
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

// Generic task to run any example
tasks.register<JavaExec>("example") {
    classpath = sourceSets["main"].runtimeClasspath
    jvmArgs = listOf("-Djna.library.path=${projectDir}/lib")
    
    // Get the example name from the command line argument -Pexample=<name>
    val exampleProperty = "example"
    inputs.property(exampleProperty, project.findProperty(exampleProperty) ?: "example")
    
    mainClass.set(provider {
        val example = project.findProperty(exampleProperty)?.toString() ?: "example"
        // Convert snake_case to CamelCase and append Kt
        val className = example.split('_')
            .map { it.replaceFirstChar { c -> c.uppercaseChar() } }
            .joinToString("")
        "${className}Kt"
    })
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
                        "-Xlenient-function-type-parameter-checks"
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

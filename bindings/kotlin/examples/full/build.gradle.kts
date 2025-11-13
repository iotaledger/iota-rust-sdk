plugins {
    kotlin("jvm") version "2.2.20"
    application
}

group = "com.example"

version = "1.0-SNAPSHOT"

repositories { mavenCentral() }

dependencies {
    implementation("org.iota:iota-sdk:0.0.1-alpha.2")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.9.0")
}

kotlin { jvmToolchain(21) }

application { mainClass.set("MainKt") }

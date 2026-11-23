// Google's mirror of Maven Central comes before mavenCentral() in both blocks:
// Gradle moves to the next repository on a 404 but fails the build on an
// HTTP 429, so a Maven Central rate limit would fail it if Central came
// first. Maven Central stays last as the fallback for anything the mirror
// lacks.
pluginManagement {
    repositories {
        google()
        maven { url = uri("https://maven-central.storage-download.googleapis.com/maven2/") }
        mavenCentral()
        gradlePluginPortal()
    }
}
plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        maven { url = uri("https://maven-central.storage-download.googleapis.com/maven2/") }
        mavenCentral()
    }
}

rootProject.name = "xKey"
include(":app")

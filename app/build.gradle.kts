import java.util.Properties
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    kotlin("kapt")
    jacoco
}

/**
 * Release signing credentials, from `keystore.properties` at the repository root
 * if it exists, otherwise from the environment so CI can supply them as secrets.
 * Both sources are absent from version control (see .gitignore).
 *
 * Returns null when the credentials are not fully configured; the release build
 * then has no signing config and fails rather than producing an unsigned APK.
 */
val releaseSigningCredentials: Map<String, String>? = run {
    val fromFile = rootProject.file("keystore.properties")
        .takeIf { it.exists() }
        ?.let { file -> Properties().apply { file.inputStream().use(::load) } }

    fun credential(key: String, environmentVariable: String): String? =
        fromFile?.getProperty(key)?.takeIf { it.isNotBlank() }
            ?: System.getenv(environmentVariable)?.takeIf { it.isNotBlank() }

    val storeFile = credential("storeFile", "XKEY_KEYSTORE_FILE")
    val storePassword = credential("storePassword", "XKEY_KEYSTORE_PASSWORD")
    val keyAlias = credential("keyAlias", "XKEY_KEY_ALIAS")
    val keyPassword = credential("keyPassword", "XKEY_KEY_PASSWORD")

    if (storeFile == null || storePassword == null || keyAlias == null || keyPassword == null) {
        null
    } else {
        mapOf(
            "storeFile" to storeFile,
            "storePassword" to storePassword,
            "keyAlias" to keyAlias,
            "keyPassword" to keyPassword
        )
    }
}

android {
    namespace = "com.automatethethings.xkey"
    compileSdk = 37

    defaultConfig {
        applicationId = "com.automatethethings.xkey"
        minSdk = 28  // Android 9 - Keystore StrongBox support
        targetSdk = 34
        versionCode = 1
        versionName = "1.0.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    signingConfigs {
        releaseSigningCredentials?.let { credentials ->
            create("release") {
                storeFile = rootProject.file(credentials.getValue("storeFile"))
                storePassword = credentials.getValue("storePassword")
                keyAlias = credentials.getValue("keyAlias")
                keyPassword = credentials.getValue("keyPassword")
            }
        }
    }

    buildTypes {
        release {
            // Null when no credentials are configured. An unsigned release APK
            // cannot be installed or distributed, so assembleRelease/bundleRelease
            // fail below rather than emitting one that looks like a build success.
            signingConfig = signingConfigs.findByName("release")
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
        debug {
            isDebuggable = true
            applicationIdSuffix = ".debug"
            versionNameSuffix = "-debug"
            // Instrument the debug variant so both JVM unit tests and
            // on-device instrumented tests emit coverage data.
            enableUnitTestCoverage = true
            enableAndroidTestCoverage = true
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        viewBinding = true
        buildConfig = true
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
            excludes += "/META-INF/versions/9/OSGI-INF/MANIFEST.MF"
            excludes += "/META-INF/{LICENSE.md,LICENSE-notice.md}"
        }
    }

    // AGP instruments the debug variant with this JaCoCo (its own default is
    // 0.8.14); the report tasks below read the data with jacoco.toolVersion.
    testCoverage {
        jacocoVersion = libs.versions.jacoco.get()
    }

    // Robolectric tests (activities on the JVM) read the merged resources.
    testOptions {
        unitTests.isIncludeAndroidResources = true
    }

    lint {
        abortOnError = true
        warningsAsErrors = false
        checkDependencies = true
    }
}

// Kotlin 2.4 makes the android { kotlinOptions } DSL an error; compilerOptions
// is its replacement.
kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
        freeCompilerArgs.addAll(
            "-opt-in=kotlin.RequiresOptIn",
            "-opt-in=kotlinx.coroutines.ExperimentalCoroutinesApi"
        )
    }
}

// Room schema export location for kapt
kapt {
    arguments {
        arg("room.schemaLocation", "$projectDir/schemas")
    }
}

dependencies {
    // AndroidX Core
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.androidx.activity.ktx)
    implementation(libs.androidx.fragment.ktx)

    // Lifecycle
    implementation(libs.bundles.lifecycle)

    // Security
    implementation(libs.androidx.security.crypto)
    implementation(libs.androidx.biometric)

    // DataStore
    implementation(libs.androidx.datastore.preferences)

    // Room Database
    implementation(libs.androidx.room.runtime)
    implementation(libs.androidx.room.ktx)
    kapt(libs.androidx.room.compiler)
    kapt(libs.kotlin.metadata.jvm)

    // Credentials (Android 14+ CredentialProvider)
    implementation(libs.androidx.credentials)

    // Material Design 3
    implementation(libs.material)

    // Networking
    implementation(libs.okhttp)

    // BouncyCastle (X.509 certificate generation)
    implementation(libs.bouncycastle.bcprov)
    implementation(libs.bouncycastle.bcpkix)

    // Argon2 (PIN hashing)
    implementation(libs.argon2)

    // ExifInterface
    implementation(libs.androidx.exifinterface)

    // QR Code (ZXing)
    implementation(libs.zxing.core)

    // ML Kit Barcode Scanning
    implementation(libs.mlkit.barcode)

    // CameraX
    implementation(libs.camerax.core)
    implementation(libs.camerax.camera2)
    implementation(libs.camerax.lifecycle)
    implementation(libs.camerax.view)

    // Media3 (ExoPlayer)
    implementation(libs.media3.exoplayer)
    implementation(libs.media3.ui)

    // Coroutines
    implementation(libs.bundles.coroutines)

    // Unit Testing
    testImplementation(libs.bundles.testing)

    // Android Instrumented Testing
    androidTestImplementation(libs.bundles.androidTesting)
    androidTestImplementation(libs.androidx.test.uiautomator)

    // Lint's classpath (androidLintTool, lint-gradle 32.5.1): bcprov-jdk18on
    // 1.80.2 (CVE-2026-8763, CVE-2026-13506), from sdk-common, raised with
    // bcpkix and bcutil 1.80.2, which Bouncy Castle releases with it. AGP adds
    // lint-gradle only when the configuration has no dependencies; constraints
    // are not dependencies. Its guava 33.4.0-jre (CVE-2026-102554), from lint
    // 32.5.1, is raised the same way.
    //
    // guava (CVE-2026-102554): 33.3.1-android reaches the APK from media3
    // 1.11.1 and CameraX 1.6.2, and kapt's 33.2.1-jre comes from Room's
    // compiler (auto-common 1.2.1).
    constraints {
        add("androidLintTool", libs.bouncycastle.bcprov)
        add("androidLintTool", libs.bouncycastle.bcpkix)
        add("androidLintTool", libs.bouncycastle.bcutil)
        add("androidLintTool", libs.guava.jre)
        implementation(libs.guava.android)
        kapt(libs.guava.jre)
    }
}

// KGP 2.4.21 adds kotlin-build-tools-impl to its ABI-validation classpath as
// strictly 2.4.0, which neither compilerVersion nor any property reaches
// (KotlinPluginWrapper.addKotlinCompilerConfiguration), so take the catalog's
// Kotlin there with a resolution override; useVersion replaces the strict pin.
configurations.named("kotlinAbiValidationCompatClasspath") {
    resolutionStrategy.eachDependency {
        if (requested.group == "org.jetbrains.kotlin" && requested.name == "kotlin-build-tools-impl") {
            useVersion(libs.versions.kotlin.get())
            because("KGP pins the ABI-validation build tools to 2.4.0")
        }
    }
}

// -----------------------------------------------------------------------------
// Coverage
//
// `coverageReport` merges JVM unit-test coverage with on-device instrumented
// coverage into one HTML/XML report, so the number reflects everything the
// suite actually exercises rather than one half of it.
//
// Usage:
//   ./gradlew coverageReport              (unit only, no device needed)
//   ./gradlew coverageReportWithDevice    (unit + instrumented; needs a device)
// -----------------------------------------------------------------------------

// AGP 9.5.1 resets jacoco.toolVersion to its own default (0.8.14) in its
// afterEvaluate (DependencyConfigurator.configureJacocoTransforms), so set it
// in an afterEvaluate registered after AGP's; jacocoAgent and jacocoAnt read
// it when they resolve.
afterEvaluate {
    jacoco {
        toolVersion = libs.versions.jacoco.get()
    }
}

/** Generated, framework, and DI classes carry no logic worth measuring. */
val coverageExclusions = listOf(
    "**/R.class", "**/R$*.class", "**/BuildConfig.*", "**/Manifest*.*",
    "**/*Test*.*", "android/**/*.*",
    "**/databinding/**", "**/*_Impl*.*",           // Room-generated DAOs
    "**/*\$\$serializer.*", "**/*\$Companion*.*",
    "**/*Kt\$*.*", "**/*\$WhenMappings*.*"
)

// Every coverage input names the exact file or directory its producer writes.
// A tree rooted at the whole build directory would make every task that writes
// under it an undeclared producer, which Gradle 9 rejects when the report runs
// in the same invocation as assembleDebug or lintDebug.

/** Where AGP writes the JVM unit-test execution data (UNIT_TEST_CODE_COVERAGE). */
val unitTestExecutionData = layout.buildDirectory.file(
    "outputs/unit_test_code_coverage/debugUnitTest/testDebugUnitTest.exec"
)

/** Where AGP writes the connected-test execution data (CODE_COVERAGE), one .ec per device. */
val instrumentedExecutionData = layout.buildDirectory.dir("outputs/code_coverage/debugAndroidTest")

fun JacocoReportBase.configureCoverageSources() {
    // The class trees are the compile tasks' outputs; order the report after
    // them. The test-running reports already depend on them through their tests.
    mustRunAfter("compileDebugKotlin", "compileDebugJavaWithJavac")
    val kotlinClasses = fileTree(layout.buildDirectory.dir("tmp/kotlin-classes/debug")) {
        exclude(coverageExclusions)
    }
    val javaClasses = fileTree(layout.buildDirectory.dir("intermediates/javac/debug")) {
        exclude(coverageExclusions)
    }
    classDirectories.setFrom(files(kotlinClasses, javaClasses))
    sourceDirectories.setFrom(files("$projectDir/src/main/kotlin", "$projectDir/src/main/java"))
}

tasks.register<JacocoReport>("coverageReport") {
    group = "verification"
    description = "JaCoCo coverage from JVM unit tests."
    dependsOn("testDebugUnitTest")

    configureCoverageSources()
    executionData.setFrom(unitTestExecutionData)
    reports {
        html.required.set(true)
        xml.required.set(true)
    }
}

/**
 * Builds a report from whatever coverage data is already on disk, without
 * running anything. Useful when a test failed but its coverage is still worth
 * reading, since a failing suite still exercised most of the code.
 */
tasks.register<JacocoReport>("coverageReportFromExisting") {
    group = "verification"
    description = "JaCoCo report from existing execution data (runs no tests)."

    configureCoverageSources()
    executionData.setFrom(
        unitTestExecutionData,
        fileTree(instrumentedExecutionData) { include("**/*.ec") }
    )
    reports {
        html.required.set(true)
        xml.required.set(true)
    }
}

tasks.register<JacocoReport>("coverageReportWithDevice") {
    group = "verification"
    description = "JaCoCo coverage from JVM unit tests plus on-device instrumented tests."
    dependsOn("testDebugUnitTest", "connectedDebugAndroidTest")

    configureCoverageSources()
    // Instrumented coverage lands under outputs/code_coverage as .ec files;
    // unit coverage is a .exec. Both feed the same report.
    executionData.setFrom(
        unitTestExecutionData,
        fileTree(instrumentedExecutionData) { include("**/*.ec") }
    )
    reports {
        html.required.set(true)
        xml.required.set(true)
    }
}

// Refuse to produce an unsigned release artifact. Without this the release tasks
// succeed and emit an -unsigned.apk, which cannot be installed and is easy to
// mistake for a shippable build.
tasks.matching { it.name == "assembleRelease" || it.name == "bundleRelease" }.configureEach {
    // Resolved here, at configuration time, so the execution-time closure captures
    // a plain Boolean. Referencing the script property directly from doFirst makes
    // the task unserializable for the configuration cache.
    val signingConfigured = releaseSigningCredentials != null
    doFirst {
        check(signingConfigured) {
            "Release signing is not configured. Create keystore.properties at the repository " +
                "root with storeFile/storePassword/keyAlias/keyPassword, or set XKEY_KEYSTORE_FILE, " +
                "XKEY_KEYSTORE_PASSWORD, XKEY_KEY_ALIAS and XKEY_KEY_PASSWORD in the environment. " +
                "Both are excluded from version control."
        }
    }
}

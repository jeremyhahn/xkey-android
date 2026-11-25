/*
 * Copyright (c) 2025 Jeremy Hahn
 * Copyright (c) 2025 Automate The Things, LLC
 *
 * This file is part of xKey.
 *
 * xKey is dual-licensed:
 *
 * 1. GNU Affero General Public License v3.0 (AGPL-3.0)
 *    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
 *
 * 2. Commercial License
 *    Contact licensing@automatethethings.com for commercial licensing options.
 */
package com.automatethethings.xkey.crypto

import android.app.Application
import android.os.Build
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_WEAK
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.biometric.BiometricPrompt
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.util.ReflectionHelpers
import java.io.File

/**
 * A prompt that accepts the screen lock (the audit log's deletion
 * confirmation) must build on every supported API level. PromptInfo refuses
 * BIOMETRIC_STRONG | DEVICE_CREDENTIAL on Android 9 and 10, so the helper
 * picks a combination each level accepts, in one place.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = Application::class)
class BiometricPromptAuthenticatorsTest {

    private val originalSdkInt = Build.VERSION.SDK_INT

    @After
    fun restoreSdkInt() {
        ReflectionHelpers.setStaticField(Build.VERSION::class.java, "SDK_INT", originalSdkInt)
    }

    @Test
    fun `Android 9 and 10 accept the screen lock through BIOMETRIC_WEAK`() {
        for (sdk in listOf(Build.VERSION_CODES.P, Build.VERSION_CODES.Q)) {
            val authenticators = BiometricHelper.promptAuthenticators(true, sdk)
            assertEquals("API $sdk", BIOMETRIC_WEAK or DEVICE_CREDENTIAL, authenticators)
            ReflectionHelpers.setStaticField(Build.VERSION::class.java, "SDK_INT", sdk)
            // Throws IllegalArgumentException when the combination is unsupported.
            BiometricPrompt.PromptInfo.Builder()
                .setTitle("t")
                .setAllowedAuthenticators(authenticators)
                .build()
        }
    }

    @Test
    fun `the harness reaches the library check on Android 9`() {
        ReflectionHelpers.setStaticField(Build.VERSION::class.java, "SDK_INT", Build.VERSION_CODES.P)
        try {
            BiometricPrompt.PromptInfo.Builder()
                .setTitle("t")
                .setAllowedAuthenticators(BIOMETRIC_STRONG or DEVICE_CREDENTIAL)
                .build()
            fail("BIOMETRIC_STRONG | DEVICE_CREDENTIAL built on API 28")
        } catch (expected: IllegalArgumentException) {
            // The library refuses the combination, as on a real Android 9 phone.
        }
    }

    @Test
    fun `Android 11 and later keep BIOMETRIC_STRONG with the screen lock`() {
        for (sdk in listOf(Build.VERSION_CODES.R, Build.VERSION_CODES.UPSIDE_DOWN_CAKE)) {
            assertEquals(
                "API $sdk",
                BIOMETRIC_STRONG or DEVICE_CREDENTIAL,
                BiometricHelper.promptAuthenticators(true, sdk)
            )
        }
    }

    @Test
    fun `without the screen lock the prompt is BIOMETRIC_STRONG only`() {
        for (sdk in listOf(Build.VERSION_CODES.P, Build.VERSION_CODES.UPSIDE_DOWN_CAKE)) {
            assertEquals("API $sdk", BIOMETRIC_STRONG, BiometricHelper.promptAuthenticators(false, sdk))
        }
    }

    @Test
    fun `every prompt in the helper takes its authenticators from promptAuthenticators`() {
        val rel = "src/main/kotlin/com/automatethethings/xkey/crypto/BiometricHelper.kt"
        val source = listOf(File(rel), File("app/$rel")).first { it.isFile }
        val text = source.readLines()
            .filterNot { it.trimStart().startsWith("//") || it.trimStart().startsWith("*") }
            .joinToString("\n")
        val calls = Regex("""setAllowedAuthenticators\(\s*([A-Za-z_]+)""").findAll(text).toList()
        assertTrue("no setAllowedAuthenticators call found", calls.isNotEmpty())
        for (call in calls) {
            assertEquals(
                "setAllowedAuthenticators takes a literal combination: ${call.value}",
                "promptAuthenticators",
                call.groupValues[1]
            )
        }
    }
}

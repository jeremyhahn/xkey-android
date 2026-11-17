/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
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

package com.automatethethings.xkey.ble.fido

import android.content.Context
import android.content.Intent
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import com.automatethethings.xkey.auth.BiometricActivityLauncher
import com.automatethethings.xkey.crypto.UserCancelledException
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.slot
import io.mockk.unmockkAll
import io.mockk.verify
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * getInfo's `uv` comes from [BiometricFidoUserPrompt.available], so it may
 * only claim the verification the prompt can perform. The prompt
 * (TransparentBiometricActivity) accepts a strong biometric only.
 */
class BiometricFidoUserPromptTest {

    private val context = mockk<Context>(relaxed = true)
    private val launcher = mockk<BiometricActivityLauncher>(relaxed = true)

    /** A phone on which only [enrolled] authenticators can verify the user. */
    private fun enrol(enrolled: Int) {
        val manager = mockk<BiometricManager>()
        every { manager.canAuthenticate(any()) } answers {
            // As the framework answers: success when any requested
            // authenticator is enrolled.
            if (firstArg<Int>() and enrolled != 0) BiometricManager.BIOMETRIC_SUCCESS
            else BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED
        }
        mockkStatic(BiometricManager::class)
        every { BiometricManager.from(any()) } returns manager
    }

    @After
    fun tearDown() = unmockkAll()

    @Test
    fun `a strong biometric makes user verification available`() {
        enrol(BIOMETRIC_STRONG)

        assertTrue(BiometricFidoUserPrompt(context) { launcher }.available)
    }

    @Test
    fun `a device credential alone does not advertise user verification the prompt cannot accept`() {
        enrol(DEVICE_CREDENTIAL)

        assertFalse(BiometricFidoUserPrompt(context) { launcher }.available)
    }

    @Test
    fun `no launcher means no user verification`() {
        enrol(BIOMETRIC_STRONG)

        assertFalse(BiometricFidoUserPrompt(context) { null }.available)
    }

    /** A lock screen that records what the prompt posts on it. */
    private class FakeLockScreen(override var locked: Boolean) : FidoLockScreen {
        val posted = mutableListOf<Pair<String, Intent>>()
        val cancelled = mutableListOf<String>()
        var expire: (() -> Unit)? = null
        override fun post(operationType: String, rpId: String, key: String, prompt: Intent, onTimeout: () -> Unit) {
            posted += key to prompt
            expire = onTimeout
        }
        override fun cancel(key: String) {
            cancelled += key
        }
    }

    private val promptIntent = mockk<Intent>()

    @Test
    fun `on a locked phone the BLE user check shows over the lock screen and posts its own prompt`() = runTest {
        val lockScreen = FakeLockScreen(locked = true)
        val overLockScreen = slot<Boolean>()
        coEvery {
            launcher.requestAuthentication(any(), any(), any(), capture(overLockScreen), any())
        } coAnswers {
            arg<(String, Intent) -> Unit>(4)("approval-1", promptIntent)
        }

        val check = BiometricFidoUserPrompt(context, lockScreen) { launcher }.verify("example.com", false)

        assertEquals(UserCheck.VERIFIED, check)
        assertTrue(overLockScreen.captured)
        assertEquals(listOf("approval-1" to promptIntent), lockScreen.posted)
        assertEquals("taken down once answered", listOf("approval-1"), lockScreen.cancelled)
        lockScreen.expire!!()
        verify { launcher.expireUnshown("approval-1") }
    }

    @Test
    fun `on a locked phone the key-bound prompt shows over the lock screen and posts its own prompt`() = runTest {
        val lockScreen = FakeLockScreen(locked = true)
        val overLockScreen = slot<Boolean>()
        coEvery {
            launcher.requestCryptoSignature(any(), any(), any(), any(), capture(overLockScreen), any(), any())
        } coAnswers {
            arg<(String, Intent) -> Unit>(6)("signature-1", promptIntent)
            byteArrayOf(0x30)
        }

        val signature = BiometricFidoUserPrompt(context, lockScreen) { launcher }
            .signWithKey("key", byteArrayOf(1), "example.com")

        assertArrayEquals(byteArrayOf(0x30), signature)
        assertTrue(overLockScreen.captured)
        assertEquals(listOf("signature-1" to promptIntent), lockScreen.posted)
        assertEquals(listOf("signature-1"), lockScreen.cancelled)
    }

    @Test
    fun `an unlocked phone posts nothing on the lock screen`() = runTest {
        val lockScreen = FakeLockScreen(locked = false)
        val overLockScreen = slot<Boolean>()
        coEvery {
            launcher.requestAuthentication(any(), any(), any(), capture(overLockScreen), any())
        } coAnswers {
            arg<(String, Intent) -> Unit>(4)("approval-2", promptIntent)
        }

        BiometricFidoUserPrompt(context, lockScreen) { launcher }.verify("example.com", true)

        assertFalse(overLockScreen.captured)
        assertTrue(lockScreen.posted.isEmpty())
    }

    @Test
    fun `a declined prompt still takes its lock-screen notification down`() = runTest {
        val lockScreen = FakeLockScreen(locked = true)
        coEvery { launcher.requestAuthentication(any(), any(), any(), any(), any()) } coAnswers {
            arg<(String, Intent) -> Unit>(4)("approval-3", promptIntent)
            throw UserCancelledException()
        }

        val check = BiometricFidoUserPrompt(context, lockScreen) { launcher }.verify("example.com", false)

        assertEquals(UserCheck.DECLINED, check)
        assertEquals(listOf("approval-3"), lockScreen.cancelled)
    }
}

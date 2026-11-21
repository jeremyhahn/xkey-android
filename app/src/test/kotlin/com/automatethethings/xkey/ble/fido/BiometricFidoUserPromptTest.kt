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
import androidx.biometric.BiometricPrompt
import com.automatethethings.xkey.auth.BiometricActivityLauncher
import com.automatethethings.xkey.crypto.BiometricException
import com.automatethethings.xkey.crypto.UserCancelledException
import com.automatethethings.xkey.testing.ReleaseMocks
import io.mockk.coEvery
import io.mockk.coVerify
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
import org.junit.Rule
import org.junit.Test

/**
 * getInfo's `uv` comes from [BiometricFidoUserPrompt.available], so it may
 * only claim the verification the prompt can perform. The prompt
 * (TransparentBiometricActivity) accepts a strong biometric only.
 */
class BiometricFidoUserPromptTest {

    /** Drops what MockK recorded here, so it does not outlive the test. */
    @get:Rule
    val releaseMocks = ReleaseMocks()

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
            launcher.requestCryptoSignatureOnTurn(any(), any(), any(), any(), capture(overLockScreen), any(), any(), any())
        } coAnswers {
            arg<(String, Intent) -> Unit>(6)("signature-1", promptIntent)
            byteArrayOf(0x30)
        }

        val signature = BiometricFidoUserPrompt(context, lockScreen) { launcher }
            .signWithKey("key", "xkey_credential_key", "example.com") { byteArrayOf(1) }

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

    /** The account list answers [index]; records the accounts it was shown. */
    private fun choose(index: Int?): MutableList<List<String>> {
        val shown = mutableListOf<List<String>>()
        coEvery { launcher.requestAccountChoice(any(), any(), any(), any(), any()) } coAnswers {
            shown += thirdArg<List<String>>()
            arg<(String, Intent) -> Unit>(4)("approval-4", promptIntent)
            index
        }
        return shown
    }

    @Test
    fun `the account chooser is one list screen and answers the account picked`() = runTest {
        val lockScreen = FakeLockScreen(locked = true)
        val shown = choose(2)
        val accounts = listOf("Alice (alice)", "Bob (bob)", "Carol (carol)")

        val chosen = BiometricFidoUserPrompt(context, lockScreen) { launcher }.chooseAccount("example.com", accounts)

        assertEquals(2, chosen)
        assertEquals("one list, every account in order", listOf(accounts), shown)
        coVerify(exactly = 1) { launcher.requestAccountChoice(any(), "example.com", accounts, true, any()) }
        coVerify(exactly = 0) { launcher.requestAuthentication(any(), any(), any(), any(), any()) }
        assertEquals(listOf("approval-4" to promptIntent), lockScreen.posted)
        assertEquals("taken down once answered", listOf("approval-4"), lockScreen.cancelled)
    }

    @Test
    fun `declining the list declines the choice`() = runTest {
        choose(null)

        val chosen = BiometricFidoUserPrompt(context, FakeLockScreen(locked = false)) { launcher }
            .chooseAccount("example.com", listOf("alice", "bob"))

        assertEquals(null, chosen)
    }

    @Test
    fun `an index outside the list declines the choice`() = runTest {
        val prompt = BiometricFidoUserPrompt(context, FakeLockScreen(locked = false)) { launcher }

        choose(3)
        assertEquals(null, prompt.chooseAccount("example.com", listOf("alice", "bob", "carol")))
        choose(-1)
        assertEquals(null, prompt.chooseAccount("example.com", listOf("alice", "bob", "carol")))
    }

    @Test
    fun `no launcher means no account choice`() = runTest {
        val chosen = BiometricFidoUserPrompt(context, FakeLockScreen(locked = false)) { null }
            .chooseAccount("example.com", listOf("alice", "bob"))

        assertEquals(null, chosen)
    }

    @Test
    fun `a failed or unregistered list declines the choice`() = runTest {
        val prompt = BiometricFidoUserPrompt(context, FakeLockScreen(locked = false)) { launcher }

        coEvery { launcher.requestAccountChoice(any(), any(), any(), any(), any()) } throws
            BiometricException(BiometricPrompt.ERROR_TIMEOUT, "timed out")
        assertEquals(null, prompt.chooseAccount("example.com", listOf("alice", "bob")))
        coEvery { launcher.requestAccountChoice(any(), any(), any(), any(), any()) } throws
            IllegalStateException("not registered")
        assertEquals(null, prompt.chooseAccount("example.com", listOf("alice", "bob")))
    }

    @Test
    fun `a cancelled user check or account choice propagates the cancellation, not a refusal`() = runTest {
        coEvery { launcher.requestAuthentication(any(), any(), any(), any(), any()) } throws
            kotlinx.coroutines.CancellationException("the client went away")
        coEvery { launcher.requestAccountChoice(any(), any(), any(), any(), any()) } throws
            kotlinx.coroutines.CancellationException("the client went away")
        val prompt = BiometricFidoUserPrompt(context, FakeLockScreen(locked = false)) { launcher }

        val verified = runCatching { prompt.verify("example.com", false) }.exceptionOrNull()
        val chosen = runCatching { prompt.chooseAccount("example.com", listOf("alice", "bob")) }.exceptionOrNull()

        assertTrue("verify got $verified", verified is kotlinx.coroutines.CancellationException)
        assertTrue("chooseAccount got $chosen", chosen is kotlinx.coroutines.CancellationException)
    }
}

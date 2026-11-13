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

package com.automatethethings.xkey.protocol

import android.app.KeyguardManager
import android.app.NotificationManager
import android.content.Context
import android.os.Looper
import android.util.Log
import com.automatethethings.xkey.auth.BiometricActivityLauncher
import com.automatethethings.xkey.auth.SessionAuthManager
import com.automatethethings.xkey.crypto.BiometricRequiredException
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.crypto.UserCancelledException
import com.automatethethings.xkey.settings.BiometricAuthMode
import com.automatethethings.xkey.settings.BiometricSettingsData
import com.automatethethings.xkey.settings.UserVerificationPolicy
import com.automatethethings.xkey.storage.XKeyDatabase
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import java.util.Base64
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.async
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import kotlinx.coroutines.withContext
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test

/**
 * A PER_SESSION approval belongs to the connection it was given on (#134).
 *
 * Each transport assigns a connection its id at connect and routes every
 * request on it with that id, so a detach and reattach gives USB a new one,
 * and BLE, TCP and USB never share one. The Keystore's own
 * auth window (300 s) may still be open then, so a `signWithoutBiometric`
 * would succeed: the handler must prompt anyway, because the new session has
 * not been approved.
 *
 * This drives the real [RequestHandler] through `sign`; only its Android edges
 * are mocked, and the biometric launcher's `requestAuthentication` is the
 * prompt.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class PerSessionApprovalReattachTest {

    private lateinit var keystore: KeystoreManager
    private lateinit var biometricLauncher: BiometricActivityLauncher
    private lateinit var handler: RequestHandler
    private var keystoreWindowOpen = false

    @Before
    fun setUp() {
        mockkStatic(Log::class)
        every { Log.v(any(), any<String>()) } returns 0
        every { Log.d(any(), any<String>()) } returns 0
        every { Log.i(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>()) } returns 0
        every { Log.e(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>(), any()) } returns 0
        every { Log.e(any(), any<String>(), any()) } returns 0

        mockkStatic(Looper::class)
        every { Looper.getMainLooper() } returns mockk(relaxed = true)
        mockkObject(XKeyDatabase.Companion)
        every { XKeyDatabase.getInstance(any()) } returns mockk(relaxed = true)
        Dispatchers.setMain(UnconfinedTestDispatcher())

        val context = mockk<Context>(relaxed = true)
        every { context.getSystemService(Context.KEYGUARD_SERVICE) } returns
            mockk<KeyguardManager>(relaxed = true)
        every { context.getSystemService(NotificationManager::class.java) } returns
            mockk<NotificationManager>(relaxed = true)

        // The Keystore signs without a prompt only inside its auth window,
        // which a successful prompt opens.
        keystore = mockk(relaxed = true)
        every { keystore.keyExists(any()) } returns true
        coEvery { keystore.signWithoutBiometric(any(), any()) } answers {
            if (!keystoreWindowOpen) throw BiometricRequiredException()
            ByteArray(64) { 7 }
        }
        // After a prompt the approved key signs under the alias it was read at.
        every { keystore.resolveKeystoreAlias(any()) } answers { "xkey_credential_${firstArg<String>()}" }
        every { keystore.publicKeyDERAt(any()) } returns ByteArray(91) { 3 }
        coEvery { keystore.signApproved(any(), any(), any(), any()) } answers {
            if (!keystoreWindowOpen) throw BiometricRequiredException()
            ByteArray(64) { 7 }
        }
        biometricLauncher = mockk(relaxed = true)
        coEvery { biometricLauncher.requestAuthentication(any(), any(), any(), any(), any()) } answers {
            keystoreWindowOpen = true
            Unit
        }

        handler = RequestHandler(
            context = context,
            keystoreManager = keystore,
            biometricLauncher = biometricLauncher,
            sessionAuthManager = SessionAuthManager(clock = { 0L }),
        )
        handler.updateSettings(
            BiometricSettingsData(
                uvPolicy = UserVerificationPolicy.REQUIRED,
                authMode = BiometricAuthMode.PER_SESSION,
            )
        )
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
        unmockkAll()
    }

    @Test
    fun `a reattach inside the Keystore window still prompts for the new session`() = runTest {
        attachUsb(USB_FIRST)
        sign(USB_FIRST)
        assertPrompts(1)
        sign(USB_FIRST)
        assertPrompts(1)

        // Detach, then reattach while the Keystore window is still open.
        attachUsb(USB_SECOND)
        sign(USB_SECOND)

        assertPrompts(2)
    }

    @Test
    fun `a prompt pending on another transport during a reattach approves only its own connection`() = runTest {
        val bleApproval = CompletableDeferred<Unit>()
        coEvery { biometricLauncher.requestAuthentication(any(), any(), any(), any(), any()) } coAnswers {
            bleApproval.await()
            keystoreWindowOpen = true
            Unit
        }
        attachUsb(USB_FIRST)

        // A BLE or TCP sign arrives and its prompt stays open...
        val pending = async { sign(BLE) }
        runCurrent()
        assertPrompts(1)

        // ...while USB detaches and reattaches with a new session.
        attachUsb(USB_SECOND)
        bleApproval.complete(Unit)
        pending.await()

        // The new USB session's first protected sign still prompts.
        sign(USB_SECOND)
        assertPrompts(2)
    }

    @Test
    fun `a BLE sign approved after a reattach does not approve the new USB session`() = runTest {
        attachUsb(USB_FIRST)
        sign(USB_FIRST)
        attachUsb(USB_SECOND)

        // BLE's sign starts after the reattach and before USB's first sign.
        sign(BLE)
        assertPrompts(2)

        sign(USB_SECOND)
        assertPrompts(3)
    }

    @Test
    fun `a TCP sign approved after a reattach does not approve the new USB session`() = runTest {
        attachUsb(USB_FIRST)
        sign(USB_FIRST)
        attachUsb(USB_SECOND)

        sign(TCP)
        assertPrompts(2)

        sign(USB_SECOND)
        assertPrompts(3)
    }

    @Test
    fun `a USB approval never authenticates a BLE or TCP request`() = runTest {
        attachUsb(USB_FIRST)
        sign(USB_FIRST)
        assertPrompts(1)

        sign(BLE)
        assertPrompts(2)

        sign(TCP)
        assertPrompts(3)
    }

    @Test
    fun `an approved BLE request between two USB requests keeps the USB approval`() = runTest {
        attachUsb(USB_FIRST)
        sign(USB_FIRST)
        sign(BLE)
        assertPrompts(2)

        // The USB connection is unchanged, so its approval still stands.
        sign(USB_FIRST)
        assertPrompts(2)

        // A new connection id is a new session and prompts.
        attachUsb(USB_SECOND)
        sign(USB_SECOND)
        assertPrompts(3)
    }

    @Test
    fun `a cancelled BLE prompt between two USB requests keeps the USB approval`() = runTest {
        var cancel = false
        coEvery { biometricLauncher.requestAuthentication(any(), any(), any(), any(), any()) } answers {
            if (cancel) throw UserCancelledException()
            keystoreWindowOpen = true
            Unit
        }
        attachUsb(USB_FIRST)
        sign(USB_FIRST)

        cancel = true
        sign(BLE, expectSuccess = false)
        cancel = false
        assertPrompts(2)

        sign(USB_FIRST)
        assertPrompts(2)
    }

    @Test
    fun `two requests on one connection share one approval`() = runTest {
        attachUsb(USB_FIRST)
        sign(BLE)
        sign(BLE)
        assertPrompts(1)

        sign(TCP)
        sign(TCP)
        assertPrompts(2)
    }

    /**
     * Opens a USB connection named [connectionId]. The handler-wide session
     * id is announced as the USB server once did, so a request on another
     * transport would pick it up if approval still read handler-wide state.
     */
    private fun attachUsb(connectionId: String) {
        handler.setSessionId(connectionId)
    }

    /** Signs on the connection [connectionId], as its transport routes a request. */
    private suspend fun sign(connectionId: String, expectSuccess: Boolean = true) {
        val params = JSONObject()
            .put("credentialId", "credential-1")
            .put("dataHash", Base64.getEncoder().encodeToString(ByteArray(32) { 1 }))
            .put("userVerificationRequired", true)
        val raw = withContext(
            RequestHandler.servedConnection(SessionBindingProvider { null }, null, connectionId)
        ) {
            handler.handleRawRequest(Request(id = 1, method = MethodNames.SIGN, params = params).toJson())
        }
        val response = Response.fromJson(raw)
        if (expectSuccess) {
            assertNull("sign failed: ${response.error?.message}", response.error)
        } else {
            assertNotNull("a cancelled sign succeeded", response.error)
        }
    }

    private companion object {
        const val USB_FIRST = "usb:first"
        const val USB_SECOND = "usb:second"
        const val BLE = "ble:peer"
        const val TCP = "tcp:peer"
    }

    private fun assertPrompts(expected: Int) {
        coVerify(exactly = expected) {
            biometricLauncher.requestAuthentication(any(), any(), any(), any(), any())
        }
    }
}

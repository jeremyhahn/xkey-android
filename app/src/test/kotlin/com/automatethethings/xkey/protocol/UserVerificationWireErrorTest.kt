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
import com.automatethethings.xkey.credential.UserVerificationCompliance
import com.automatethethings.xkey.credential.UserVerificationRequiredException
import com.automatethethings.xkey.credential.UvRequirement
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.dao.KeyDao
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test

/**
 * Pins the wire error a FIDO2 request answers with when the peer required
 * user verification that did not happen (#135).
 *
 * Both wire FIDO2 methods go through the real [RequestHandler.handleRequest],
 * so the test exercises the catch in `RequestHandler.dispatch`. The refusal
 * is the real one from [UserVerificationCompliance.enforce]; the [KeyDao]
 * call each handler makes first throws it, since that is the dependency both
 * methods share. Without the catch, dispatch answers INTERNAL_ERROR and the
 * test fails. The Android edges are mocked as in [VerifyUserHandlerTest].
 */
@OptIn(ExperimentalCoroutinesApi::class)
class UserVerificationWireErrorTest {

    private lateinit var keyDao: KeyDao
    private lateinit var handler: RequestHandler

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

        keyDao = mockk(relaxed = true)
        val database = mockk<XKeyDatabase>(relaxed = true)
        // No key has a pending deletion.
        every { database.keyPolicyDao() } returns mockk<com.automatethethings.xkey.storage.dao.KeyPolicyDao>(relaxed = true) { io.mockk.coEvery { deletion(any()) } returns null }
        every { database.keyDao() } returns keyDao
        mockkObject(XKeyDatabase.Companion)
        every { XKeyDatabase.getInstance(any()) } returns database

        Dispatchers.setMain(UnconfinedTestDispatcher())

        val context = mockk<Context>(relaxed = true)
        every { context.getSystemService(Context.KEYGUARD_SERVICE) } returns
            mockk<KeyguardManager>(relaxed = true)
        every { context.getSystemService(NotificationManager::class.java) } returns
            mockk<NotificationManager>(relaxed = true)

        handler = RequestHandler(
            context = context,
            keystoreManager = mockk<KeystoreManager>(relaxed = true),
            biometricLauncher = null,
            sessionAuthManager = null
        )
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
        unmockkAll()
    }

    private fun refusal(): UserVerificationRequiredException =
        assertThrows(UserVerificationRequiredException::class.java) {
            UserVerificationCompliance.enforce(
                requirement = UvRequirement.REQUIRED,
                verificationPerformed = false,
                strict = true,
                ceremony = "Passkey assertion for example.com"
            )
        }

    private fun assertBiometricFailed(request: Request, error: UserVerificationRequiredException) = runTest {
        val response = handler.handleRequest(request)

        assertEquals(request.method, request.id, response.id)
        assertNull(request.method, response.result)
        assertEquals(request.method, ErrorCodes.BIOMETRIC_FAILED, response.error?.code)
        assertEquals(request.method, -32003, response.error?.code)
        assertEquals(request.method, error.message, response.error?.message)
    }

    @Test
    fun `listFido2Credentials answers missing user verification with BIOMETRIC_FAILED`() {
        val error = refusal()
        coEvery { keyDao.getFido2ByRpId(any()) } throws error

        assertBiometricFailed(
            Request(
                id = 41L,
                method = MethodNames.LOCAL_LIST_FIDO2_CREDENTIALS,
                params = JSONObject().put("rpId", "example.com")
            ),
            error
        )
    }

    @Test
    fun `signFido2Assertion answers missing user verification with BIOMETRIC_FAILED`() {
        val error = refusal()
        coEvery { keyDao.getByKeyId(any()) } throws error

        assertBiometricFailed(
            Request(
                id = 42L,
                method = MethodNames.LOCAL_SIGN_FIDO2_ASSERTION,
                params = JSONObject()
                    .put("credentialId", "Y3JlZA==")
                    .put("clientDataHash", "aGFzaA==")
                    .put("rpId", "example.com")
                    .put("userVerificationRequired", true)
            ),
            error
        )
    }

    @Test
    fun `mapping constant is BIOMETRIC_FAILED`() {
        assertEquals(ErrorCodes.BIOMETRIC_FAILED, UserVerificationWireError.CODE)
    }
}

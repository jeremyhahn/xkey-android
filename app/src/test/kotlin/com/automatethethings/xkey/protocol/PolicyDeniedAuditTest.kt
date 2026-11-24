/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
 *
 * This file is part of xkey-android.
 *
 * xkey-android is dual-licensed:
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
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.entity.KeyEntity
import com.automatethethings.xkey.storage.entity.SharingPolicyType
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import java.util.Base64
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test

/**
 * A request refused with OPERATION_DENIED leaves one POLICY_DENIED audit row,
 * written where every refusal passes (the dispatcher), naming the peer and
 * the operation; a request that succeeds or fails for another reason leaves
 * none.
 *
 * The assertion runs through the real [RequestHandler.handleRawRequest] over
 * a faked [KeyDao], built as in [Fido2WireEncodingTest].
 */
@OptIn(ExperimentalCoroutinesApi::class)
class PolicyDeniedAuditTest {

    private data class Denial(val deviceId: String?, val operation: String?, val reason: String)

    private val denials = mutableListOf<Denial>()
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

        mockkStatic(android.util.Base64::class)
        every { android.util.Base64.encodeToString(any(), any()) } answers {
            Base64.getUrlEncoder().withoutPadding().encodeToString(firstArg<ByteArray>())
        }

        mockkStatic(Looper::class)
        every { Looper.getMainLooper() } returns mockk(relaxed = true)
        Dispatchers.setMain(UnconfinedTestDispatcher())

        mockkObject(AuditLogger)
        every {
            AuditLogger.logFido2Authentication(any(), any(), any(), any(), any(), any(), any(), any())
        } returns Unit
        every { AuditLogger.logPolicyDenied(any(), any(), any(), any(), any(), any()) } answers {
            denials += Denial(arg(2), arg(5), arg(4))
        }

        val keyDao = mockk<KeyDao>(relaxed = true)
        coEvery { keyDao.getByKeyId(any()) } returns null
        coEvery { keyDao.getFido2ByRpId(any()) } returns emptyList()
        coEvery { keyDao.getFido2ByRpId(RP_ID) } returns listOf(passkey(PRIVATE_ID, SharingPolicyType.PRIVATE))

        val database = mockk<XKeyDatabase>(relaxed = true)
        every { database.keyDao() } returns keyDao
        mockkObject(XKeyDatabase.Companion)
        every { XKeyDatabase.getInstance(any()) } returns database

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
        handler.setConnectedDevicePublicKeyHex(PEER)
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
        unmockkAll()
    }

    @Test
    fun `an assertion for a credential not shared with the peer writes one POLICY_DENIED row`() = runTest {
        val response = sign(PRIVATE_ID)

        assertNotNull("the assertion must be refused", response.error)
        assertEquals(ErrorCodes.OPERATION_DENIED, response.error!!.code)
        val denial = denials.single()
        assertEquals(PEER, denial.deviceId)
        assertEquals(MethodNames.LOCAL_SIGN_FIDO2_ASSERTION, denial.operation)
        assertFalse("the row must not carry the client data", denial.reason.contains(CLIENT_DATA_B64))
    }

    @Test
    fun `a request refused for another reason writes no POLICY_DENIED row`() = runTest {
        val response = sign("no-such-credential")

        assertEquals(ErrorCodes.KEY_NOT_FOUND, response.error!!.code)
        assertEquals(emptyList<Denial>(), denials)
    }

    @Test
    fun `an unknown method writes no POLICY_DENIED row`() = runTest {
        val request = Request(id = 3, method = "local.noSuchMethod", params = JSONObject())
        val response = Response.fromJson(handler.handleRawRequest(request.toJson()))

        assertNull(response.result)
        assertEquals(emptyList<Denial>(), denials)
    }

    private suspend fun sign(credentialId: String): Response {
        val params = JSONObject()
            .put("credentialId", Fido2WireIds.encode(credentialId))
            .put("clientDataHash", CLIENT_DATA_B64)
            .put("rpId", RP_ID)
            .put("userVerificationRequired", false)
        val request = Request(id = 2, method = MethodNames.LOCAL_SIGN_FIDO2_ASSERTION, params = params)
        return Response.fromJson(handler.handleRawRequest(request.toJson()))
    }

    private fun passkey(stored: String, policy: SharingPolicyType): KeyEntity = mockk(relaxed = true) {
        every { keyId } returns stored
        every { keyType } returns "fido2"
        every { rpId } returns RP_ID
        every { rpName } returns "passkey"
        every { userId } returns null
        every { sharingPolicy } returns policy
        every { biometricRequired } returns false
        every { signCount } returns 0L
    }

    private companion object {
        const val RP_ID = "example.com"
        const val PRIVATE_ID = "private-passkey-1"
        const val PEER = "0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9"
        val CLIENT_DATA_B64: String = Base64.getEncoder().encodeToString(ByteArray(32) { 0x21 })
    }
}

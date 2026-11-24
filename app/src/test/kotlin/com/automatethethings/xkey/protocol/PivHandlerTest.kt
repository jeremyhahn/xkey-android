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
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.piv.FakePivKeystore
import com.automatethethings.xkey.piv.PivKeyManager
import com.automatethethings.xkey.piv.PivSlotDao
import com.automatethethings.xkey.piv.PivTestCertificates
import com.automatethethings.xkey.storage.XKeyDatabase
import io.mockk.coEvery
import io.mockk.coVerify
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
import org.junit.Assert.assertFalse
import org.junit.Before
import org.junit.Test
import java.util.Base64

/**
 * Unit tests for PIV and PIN protocol method names and error codes defined in
 * [MethodNames] and [ErrorCodes].
 *
 * These tests verify the protocol contract between the Android authenticator
 * and desktop clients. They pin the wire values of the PIV and PIN method
 * names and error codes; uniqueness and range of every error code are checked
 * in [ProtocolConstantsTest]. `local.pivImportCert` is driven through the
 * [RequestHandler] dispatch over a real [PivKeyManager] and a mocked
 * [PivSlotDao] (#173), with only the handler's Android edges mocked, as in
 * [PinOathHandlerErrorsTest].
 */
@OptIn(ExperimentalCoroutinesApi::class)
class PivHandlerTest {

    private lateinit var pivSlotDao: PivSlotDao
    private lateinit var handler: RequestHandler
    private val slotKey = PivTestCertificates.ecKeyPair()

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

        pivSlotDao = mockk(relaxed = true)
        // The slot key lives in the Keystore; the row only caches it.
        FakePivKeystore(slotKey).install()
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
        unmockkAll()
    }

    // -------------------------------------------------------------------------
    // local.pivImportCert checks the certificate against the slot key
    // -------------------------------------------------------------------------

    @Test
    fun `pivImportCert stores a certificate for the slot key`() = runTest {
        coEvery { pivSlotDao.getBySlotId("9A") } returns PivTestCertificates.slotRow(slotKey.public.encoded)
        val cert = PivTestCertificates.selfSigned(slotKey)

        val response = importCert(Base64.getEncoder().encodeToString(cert))

        assertFalse(response.toString(), response.has("error"))
        assertEquals(true, response.getJSONObject("result").getBoolean("success"))
        coVerify { pivSlotDao.upsert(match { it.certificateDer.contentEquals(cert) }) }
    }

    @Test
    fun `pivImportCert of a certificate for another key is INVALID_PARAMS and keeps the earlier one`() = runTest {
        val earlier = PivTestCertificates.selfSigned(slotKey)
        coEvery { pivSlotDao.getBySlotId("9A") } returns PivTestCertificates.slotRow(slotKey.public.encoded, earlier)
        val other = PivTestCertificates.selfSigned(PivTestCertificates.ecKeyPair())

        val response = importCert(Base64.getEncoder().encodeToString(other))

        assertEquals(ErrorCodes.INVALID_PARAMS, errorCode(response))
        coVerify(exactly = 0) { pivSlotDao.upsert(any()) }
    }

    @Test
    fun `pivImportCert of bytes that are not a certificate is INVALID_PARAMS`() = runTest {
        coEvery { pivSlotDao.getBySlotId("9A") } returns PivTestCertificates.slotRow(slotKey.public.encoded)

        val response = importCert(Base64.getEncoder().encodeToString("not a certificate".toByteArray()))

        assertEquals(ErrorCodes.INVALID_PARAMS, errorCode(response))
        coVerify(exactly = 0) { pivSlotDao.upsert(any()) }
    }

    @Test
    fun `pivImportCert of a certificate that is not base64 is INVALID_PARAMS`() = runTest {
        coEvery { pivSlotDao.getBySlotId("9A") } returns PivTestCertificates.slotRow(slotKey.public.encoded)

        val response = importCert("not base64 !!")

        assertEquals(ErrorCodes.INVALID_PARAMS, errorCode(response))
        coVerify(exactly = 0) { pivSlotDao.upsert(any()) }
    }

    @Test
    fun `pivImportCert into a slot with no key is PIV_SLOT_NOT_FOUND`() = runTest {
        coEvery { pivSlotDao.getBySlotId("9A") } returns null

        val response = importCert(Base64.getEncoder().encodeToString(PivTestCertificates.selfSigned(slotKey)))

        assertEquals(ErrorCodes.PIV_SLOT_NOT_FOUND, errorCode(response))
        coVerify(exactly = 0) { pivSlotDao.upsert(any()) }
    }

    // -------------------------------------------------------------------------
    // PIV method names
    // -------------------------------------------------------------------------

    @Test
    fun `PIV local method names have expected values`() {
        assertEquals("local.pivGenerateKey", MethodNames.LOCAL_PIV_GENERATE_KEY)
        assertEquals("local.pivImportCert", MethodNames.LOCAL_PIV_IMPORT_CERT)
        assertEquals("local.pivListSlots", MethodNames.LOCAL_PIV_LIST_SLOTS)
        assertEquals("local.pivSign", MethodNames.LOCAL_PIV_SIGN)
        assertEquals("local.pivGetCert", MethodNames.LOCAL_PIV_GET_CERT)
    }

    @Test
    fun `PIV remote method names have expected values`() {
        assertEquals("remote.pivListSlots", MethodNames.REMOTE_PIV_LIST_SLOTS)
        assertEquals("remote.pivSign", MethodNames.REMOTE_PIV_SIGN)
        assertEquals("remote.pivGetCert", MethodNames.REMOTE_PIV_GET_CERT)
    }

    // -------------------------------------------------------------------------
    // PIV error codes
    // -------------------------------------------------------------------------

    @Test
    fun `PIV error codes have expected values`() {
        assertEquals(-32026, ErrorCodes.PIV_SLOT_NOT_FOUND)
        assertEquals(-32027, ErrorCodes.PIV_SLOT_OCCUPIED)
        assertEquals(-32028, ErrorCodes.PIV_SIGN_FAILED)
        assertEquals(-32029, ErrorCodes.PIV_INVALID_SLOT)
    }

    // -------------------------------------------------------------------------
    // PIN method names
    // -------------------------------------------------------------------------

    @Test
    fun `PIN method names have expected values`() {
        assertEquals("local.pinVerify", MethodNames.LOCAL_PIN_VERIFY)
        assertEquals("local.pinStatus", MethodNames.LOCAL_PIN_STATUS)
        assertEquals("local.pinSet", MethodNames.LOCAL_PIN_SET)
        assertEquals("local.pinChange", MethodNames.LOCAL_PIN_CHANGE)
        assertEquals("local.pinResetLockout", MethodNames.LOCAL_PIN_RESET_LOCKOUT)
    }

    // -------------------------------------------------------------------------
    // PIN error codes
    // -------------------------------------------------------------------------

    @Test
    fun `PIN error codes have expected values`() {
        assertEquals(-32032, ErrorCodes.PIN_REQUIRED)
        assertEquals(-32033, ErrorCodes.PIN_INCORRECT)
        assertEquals(-32034, ErrorCodes.PIN_LOCKED)
    }

    // -------------------------------------------------------------------------
    // JSON-RPC standard error codes sanity check
    // -------------------------------------------------------------------------

    @Test
    fun `standard JSON-RPC error codes are in specification range`() {
        assertEquals(-32700, ErrorCodes.PARSE_ERROR)
        assertEquals(-32600, ErrorCodes.INVALID_REQUEST)
        assertEquals(-32601, ErrorCodes.METHOD_NOT_FOUND)
        assertEquals(-32602, ErrorCodes.INVALID_PARAMS)
        assertEquals(-32603, ErrorCodes.INTERNAL_ERROR)
    }

    /**
     * Sends `local.pivImportCert` for slot 9A. The handler is built per call so
     * that a [PivKeyManager] which cannot be built on the JVM fails only the
     * import tests.
     */
    private suspend fun importCert(certificateBase64: String): JSONObject {
        val context = mockk<Context>(relaxed = true)
        every { context.getSystemService(Context.KEYGUARD_SERVICE) } returns
            mockk<KeyguardManager>(relaxed = true)
        every { context.getSystemService(NotificationManager::class.java) } returns
            mockk<NotificationManager>(relaxed = true)
        handler = RequestHandler(
            context = context,
            keystoreManager = mockk<KeystoreManager>(relaxed = true),
            biometricLauncher = null,
            sessionAuthManager = null,
            pivKeyManager = PivKeyManager(pivSlotDao)
        )
        val params = JSONObject().put("slot", "9A").put("certificate_der", certificateBase64)
        val request = JSONObject().put("id", 1).put("method", MethodNames.LOCAL_PIV_IMPORT_CERT).put("params", params)
        return JSONObject(String(handler.handleRawRequest(request.toString().toByteArray(Charsets.UTF_8)), Charsets.UTF_8))
    }

    private fun errorCode(response: JSONObject): Int = response.getJSONObject("error").getInt("code")
}

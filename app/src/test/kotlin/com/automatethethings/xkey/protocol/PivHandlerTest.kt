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
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.crypto.KeySecurityLevel
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.piv.FakePivKeystore
import com.automatethethings.xkey.piv.PivAlgorithm
import com.automatethethings.xkey.piv.PivKeyManager
import com.automatethethings.xkey.piv.PivPublicKeyEncoding
import com.automatethethings.xkey.piv.PivSlotDao
import com.automatethethings.xkey.piv.PivTestCertificates
import com.automatethethings.xkey.piv.SUPPORTED_TEST_SDK
import com.automatethethings.xkey.piv.testPivKeyManager
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
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.security.KeyPair
import java.security.Signature
import java.util.Base64

/**
 * Unit tests for PIV and PIN protocol method names and error codes defined in
 * [MethodNames] and [ErrorCodes].
 *
 * These tests verify the protocol contract between the Android authenticator
 * and desktop clients. They pin the wire values of the PIV and PIN method
 * names and error codes; uniqueness and range of every error code are checked
 * in [ProtocolConstantsTest]. The PIV methods are driven through the
 * [RequestHandler] dispatch over a real [PivKeyManager] and a mocked
 * [PivSlotDao] (#173), with only the handler's Android edges mocked, as in
 * [PinOathHandlerErrorsTest]. Ed25519 and X25519 slot keys come from the
 * manager's `generateKeyPair` seam, on an injected platform level and key
 * security level.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class PivHandlerTest {

    private lateinit var pivSlotDao: PivSlotDao
    private lateinit var handler: RequestHandler
    private lateinit var keystore: FakePivKeystore
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
        keystore = FakePivKeystore(slotKey).also { it.install() }
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
    // Ed25519 and X25519 slot keys
    // -------------------------------------------------------------------------

    @Test
    fun `pivGenerateKey Ed25519 answers the PIV algorithm id and the raw public key`() = runTest {
        stubAudit()

        val response = send(
            MethodNames.LOCAL_PIV_GENERATE_KEY,
            JSONObject().put("slot", "9A").put("algorithm", "Ed25519")
        )

        assertFalse(response.toString(), response.has("error"))
        val result = response.getJSONObject("result")
        assertEquals(0xE0, result.getInt("algorithm_id"))
        val der = Base64.getDecoder().decode(result.getString("public_key_der"))
        val raw = Base64.getDecoder().decode(result.getString("public_key_raw"))
        assertEquals(32, raw.size)
        assertArrayEquals(PivPublicKeyEncoding.pivPublicKeyValue(der), raw)
    }

    @Test
    fun `pivGenerateKey ES256 answers its PIV algorithm id and no raw key`() = runTest {
        stubAudit()

        val response = send(MethodNames.LOCAL_PIV_GENERATE_KEY, JSONObject().put("slot", "9A").put("algorithm", "ES256"))

        val result = response.getJSONObject("result")
        assertEquals(0x11, result.getInt("algorithm_id"))
        assertFalse(result.toString(), result.has("public_key_raw"))
    }

    @Test
    fun `pivGenerateKey accepts every curve 25519 and PIV id spelling`() = runTest {
        stubAudit()
        val spellings = mapOf(
            "ED25519" to 0xE0, "Ed25519" to 0xE0, "ed25519" to 0xE0, "EDDSA" to 0xE0, "0xE0" to 0xE0,
            "X25519" to 0xE1, "x25519" to 0xE1, "0xE1" to 0xE1,
            "0x11" to 0x11, "0x14" to 0x14, "0x07" to 0x07,
        )

        spellings.forEach { (spelling, id) ->
            val response = send(MethodNames.LOCAL_PIV_GENERATE_KEY, JSONObject().put("slot", "9A").put("algorithm", spelling))
            assertFalse("$spelling: $response", response.has("error"))
            assertEquals(spelling, id, response.getJSONObject("result").getInt("algorithm_id"))
        }
    }

    @Test
    fun `pivGenerateKey Ed25519 below Android 13 is FEATURE_UNAVAILABLE and keeps the slot key`() = runTest {
        stubAudit()

        val response = send(
            MethodNames.LOCAL_PIV_GENERATE_KEY,
            JSONObject().put("slot", "9A").put("algorithm", "Ed25519"),
            sdkInt = 32
        )

        assertEquals(ErrorCodes.FEATURE_UNAVAILABLE, errorCode(response))
        assertTrue(response.toString(), errorMessage(response).contains("Android 13 secure hardware"))
        assertTrue(keystore.live === slotKey)
        coVerify(exactly = 0) { pivSlotDao.upsert(any()) }
    }

    @Test
    fun `pivGenerateKey X25519 in a software Keystore is FEATURE_UNAVAILABLE`() = runTest {
        stubAudit()

        val response = send(
            MethodNames.LOCAL_PIV_GENERATE_KEY,
            JSONObject().put("slot", "9A").put("algorithm", "X25519"),
            level = KeySecurityLevel.SOFTWARE
        )

        assertEquals(ErrorCodes.FEATURE_UNAVAILABLE, errorCode(response))
        coVerify(exactly = 0) { pivSlotDao.upsert(any()) }
    }

    @Test
    fun `pivSign without an algorithm signs with the slot's Ed25519 key`() = runTest {
        stubAudit()
        val edKey = PivTestCertificates.ed25519KeyPair()
        keystore.live = edKey
        coEvery { pivSlotDao.getBySlotId("9A") } returns
            PivTestCertificates.slotRow(edKey.public.encoded, algorithm = PivAlgorithm.ED25519)
        val message = "piv handler message".toByteArray()

        val response = send(
            MethodNames.LOCAL_PIV_SIGN,
            JSONObject().put("slot", "9A").put("data", Base64.getEncoder().encodeToString(message))
        )

        assertFalse(response.toString(), response.has("error"))
        val signature = Base64.getDecoder().decode(response.getJSONObject("result").getString("signature"))
        val verifier = Signature.getInstance("Ed25519").apply {
            initVerify(edKey.public)
            update(message)
        }
        assertTrue(verifier.verify(signature))
    }

    @Test
    fun `pivSign on an X25519 slot is INVALID_ALGORITHM`() = runTest {
        stubAudit()
        val xKey = PivTestCertificates.x25519KeyPair()
        keystore.live = xKey
        coEvery { pivSlotDao.getBySlotId("9A") } returns
            PivTestCertificates.slotRow(xKey.public.encoded, algorithm = PivAlgorithm.X25519)

        val response = send(
            MethodNames.LOCAL_PIV_SIGN,
            JSONObject().put("slot", "9A").put("data", Base64.getEncoder().encodeToString(byteArrayOf(1, 2, 3)))
        )

        assertEquals(ErrorCodes.INVALID_ALGORITHM, errorCode(response))
        assertEquals("X25519 keys cannot sign", errorMessage(response))
    }

    @Test
    fun `pivListSlots reports a curve 25519 slot's PIV id and raw key`() = runTest {
        val xKey = PivTestCertificates.x25519KeyPair()
        keystore.live = xKey
        val row = PivTestCertificates.slotRow(xKey.public.encoded, algorithm = PivAlgorithm.X25519)
        coEvery { pivSlotDao.getAll() } returns listOf(row)
        coEvery { pivSlotDao.getBySlotId("9A") } returns row

        val response = send(MethodNames.LOCAL_PIV_LIST_SLOTS, JSONObject())

        assertFalse(response.toString(), response.has("error"))
        val slot = response.getJSONObject("result").getJSONArray("slots").getJSONObject(0)
        assertEquals(0xE1, slot.getInt("algorithm_id"))
        assertArrayEquals(
            PivPublicKeyEncoding.pivPublicKeyValue(xKey.public.encoded),
            Base64.getDecoder().decode(slot.getString("public_key_raw"))
        )
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
        assertEquals(-32052, ErrorCodes.PIN_REQUIRED)
        assertEquals(-32053, ErrorCodes.PIN_INCORRECT)
        assertEquals(-32054, ErrorCodes.PIN_LOCKED)
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
    private suspend fun importCert(certificateBase64: String): JSONObject =
        send(
            MethodNames.LOCAL_PIV_IMPORT_CERT,
            JSONObject().put("slot", "9A").put("certificate_der", certificateBase64),
            manager = testPivKeyManager(pivSlotDao)
        )

    /**
     * Sends [method] with [params] to a handler over a [PivKeyManager] whose
     * generator makes a JDK key of the requested algorithm, on platform level
     * [sdkInt], every key reading as [level].
     */
    private suspend fun send(
        method: String,
        params: JSONObject,
        sdkInt: Int = SUPPORTED_TEST_SDK,
        level: KeySecurityLevel? = KeySecurityLevel.TEE,
        manager: PivKeyManager = testPivKeyManager(
            pivSlotDao,
            generateKeyPair = { _, algorithm -> keyFor(algorithm).also { keystore.live = it } },
            sdkInt = sdkInt,
            securityLevelOf = { level },
            // A classical generate drops any software ML-DSA record under the slot's alias.
            pqcStore = mockk(relaxed = true)
        )
    ): JSONObject {
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
            pivKeyManager = manager
        )
        val request = JSONObject().put("id", 1).put("method", method).put("params", params)
        return JSONObject(String(handler.handleRawRequest(request.toString().toByteArray(Charsets.UTF_8)), Charsets.UTF_8))
    }

    private fun keyFor(algorithm: PivAlgorithm): KeyPair = when (algorithm) {
        PivAlgorithm.ED25519 -> PivTestCertificates.ed25519KeyPair()
        PivAlgorithm.X25519 -> PivTestCertificates.x25519KeyPair()
        else -> PivTestCertificates.ecKeyPair()
    }

    private fun stubAudit() {
        mockkObject(AuditLogger)
        every { AuditLogger.logKeyCreated(any(), any(), any(), any()) } returns Unit
        every { AuditLogger.logKeyDeleted(any(), any(), any()) } returns Unit
        every {
            AuditLogger.logSigningRequest(any(), any(), any(), any(), any(), any(), any(), any(), any())
        } returns Unit
        every { AuditLogger.logKeyUsed(any(), any(), any(), any(), any(), any(), any()) } returns Unit
    }

    private fun errorCode(response: JSONObject): Int = response.getJSONObject("error").getInt("code")

    private fun errorMessage(response: JSONObject): String = response.getJSONObject("error").getString("message")
}

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
import java.io.File
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64
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
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * The byte fields of `local.listFido2Credentials` and
 * `local.signFido2Assertion` as the desktop reads them.
 *
 * The desktop decodes both results with Go's `encoding/json`, which reads a
 * `[]byte` field only from standard-alphabet, padded base64 and fails the
 * whole result on anything else, and it sends `credentialId` back in the
 * same form. The phone stores passkey ids and user ids as URL-safe, unpadded
 * base64, so each byte field here is checked with the strict standard
 * decoder ([Base64.getDecoder]), never a lenient one.
 *
 * Both methods run through the real [RequestHandler.handleRawRequest] over a
 * faked [KeyDao] and signer, built as in [UserVerificationWireErrorTest].
 */
@OptIn(ExperimentalCoroutinesApi::class)
class Fido2WireEncodingTest {

    /** Every input the faked signer was asked to sign. */
    private val signed = mutableListOf<ByteArray>()

    private lateinit var keyDao: KeyDao
    private lateinit var keystoreManager: KeystoreManager
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

        val passkey = passkey(STORED_ID, STORED_USER_ID)
        val plain = passkey(PLAIN_ID, null)
        keyDao = mockk(relaxed = true)
        coEvery { keyDao.getByKeyId(any()) } returns null
        coEvery { keyDao.getByKeyId(STORED_ID) } returns passkey
        coEvery { keyDao.getByKeyId(PLAIN_ID) } returns plain
        coEvery { keyDao.getFido2ByRpId(any()) } returns emptyList()
        coEvery { keyDao.getFido2ByRpId(RP_ID) } returns listOf(passkey, plain)

        val database = mockk<XKeyDatabase>(relaxed = true)
        every { database.keyDao() } returns keyDao
        mockkObject(XKeyDatabase.Companion)
        every { XKeyDatabase.getInstance(any()) } returns database

        val context = mockk<Context>(relaxed = true)
        every { context.getSystemService(Context.KEYGUARD_SERVICE) } returns
            mockk<KeyguardManager>(relaxed = true)
        every { context.getSystemService(NotificationManager::class.java) } returns
            mockk<NotificationManager>(relaxed = true)

        keystoreManager = mockk(relaxed = true)
        every { keystoreManager.resolveKeystoreAlias(any()) } returns null
        for (stored in listOf(STORED_ID, PLAIN_ID)) {
            val alias = "xkey_credential_$stored"
            every { keystoreManager.resolveKeystoreAlias(stored) } returns alias
            every { keystoreManager.publicKeyDERAt(alias) } returns APPROVED_DER
            coEvery { keystoreManager.signApproved(alias, APPROVED_DER, any(), any()) } answers {
                signed += thirdArg<ByteArray>()
                SIGNATURE
            }
        }

        handler = RequestHandler(
            context = context,
            keystoreManager = keystoreManager,
            biometricLauncher = null,
            sessionAuthManager = null
        )
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
        unmockkAll()
    }

    @Test
    fun `the seeded passkey ids are URL-safe and unpadded`() {
        assertTrue(
            "the stored id must use the URL-safe alphabet: $STORED_ID",
            STORED_ID.any { it == '-' || it == '_' }
        )
        assertTrue("the stored user id must use the URL-safe alphabet", STORED_USER_ID.any { it == '-' || it == '_' })
        assertTrue(STORED_ID.none { it == '=' })
    }

    @Test
    fun `every listed credentialId and userId decodes as standard padded base64`() = runTest {
        val credentials = list()

        assertEquals(2, credentials.size)
        val passkey = credentials.single { it.optString("rpName") == "passkey" }
        assertArrayEquals(ID_BYTES, strict(passkey.getString("credentialId")))
        assertArrayEquals(USER_BYTES, strict(passkey.getString("userId")))
    }

    @Test
    fun `a stored id that is not base64 is listed as its UTF-8 bytes`() = runTest {
        val plain = list().single { it.optString("rpName") == "plain" }

        assertArrayEquals(PLAIN_ID.toByteArray(Charsets.UTF_8), strict(plain.getString("credentialId")))
    }

    @Test
    fun `the listed credentialId signs and its userHandle decodes as standard base64`() = runTest {
        val listed = list().single { it.optString("rpName") == "passkey" }.getString("credentialId")

        val response = sign(listed)

        assertNull("no error expected: ${response.error?.message}", response.error)
        assertEquals(1, signed.size)
        assertArrayEquals(USER_BYTES, strict(response.result!!.getString("userHandle")))
        assertEquals(37, strict(response.result!!.getString("authenticatorData")).size)
        assertArrayEquals(SIGNATURE, strict(response.result!!.getString("signature")))
    }

    /**
     * A relying party verifies the assertion signature over
     * `authenticatorData || clientDataHash` with SHA256withECDSA, so the
     * signer must get those bytes unhashed: a pre-hash here would make the
     * signature cover SHA-256 of SHA-256 of them.
     */
    @Test
    fun `the assertion signature verifies over authenticatorData and clientDataHash with the passkey's real key`() = runTest {
        val pair = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()
        coEvery {
            keystoreManager.signApproved("xkey_credential_$STORED_ID", APPROVED_DER, any(), any())
        } answers {
            signed += thirdArg<ByteArray>()
            Signature.getInstance(arg<String>(3)).apply {
                initSign(pair.private)
                update(arg<ByteArray>(2))
            }.sign()
        }
        val listed = list().single { it.optString("rpName") == "passkey" }.getString("credentialId")

        val response = sign(listed)

        assertNull("no error expected: ${response.error?.message}", response.error)
        val authenticatorData = strict(response.result!!.getString("authenticatorData"))
        val signature = strict(response.result!!.getString("signature"))
        assertArrayEquals(
            "the signer must get authenticatorData || clientDataHash unhashed",
            authenticatorData + CLIENT_DATA_HASH,
            signed.last()
        )
        val verifier = Signature.getInstance("SHA256withECDSA").apply {
            initVerify(pair.public)
            update(authenticatorData + CLIENT_DATA_HASH)
        }
        assertTrue(
            "the signature must verify over authenticatorData || clientDataHash",
            verifier.verify(signature)
        )
    }

    @Test
    fun `a listed id of a non-base64 stored id signs that passkey`() = runTest {
        val listed = list().single { it.optString("rpName") == "plain" }.getString("credentialId")

        val response = sign(listed)

        assertNull("no error expected: ${response.error?.message}", response.error)
        assertEquals(1, signed.size)
    }

    @Test
    fun `a credentialId that is not standard padded base64 answers INVALID_PARAMS`() = runTest {
        val unpadded = Base64.getEncoder().withoutPadding().encodeToString(ByteArray(16) { 7 })

        val response = sign(unpadded)

        assertEquals(ErrorCodes.INVALID_PARAMS, response.error?.code)
        assertTrue(signed.isEmpty())
    }

    @Test
    fun `an unknown credentialId answers KEY_NOT_FOUND`() = runTest {
        val response = sign(Base64.getEncoder().encodeToString(ByteArray(32) { 9 }))

        assertEquals(ErrorCodes.KEY_NOT_FOUND, response.error?.code)
        assertTrue(signed.isEmpty())
    }

    @Test
    fun `the raw stored URL-safe id does not sign`() = runTest {
        val response = sign(STORED_ID)

        assertNotNull("the stored form is not the wire form", response.error)
        assertTrue("the raw stored id signed", signed.isEmpty())
    }

    @Test
    fun `two passkeys with the same bytes sign neither`() = runTest {
        val twin = passkey(Base64.getEncoder().encodeToString(ID_BYTES), STORED_USER_ID)
        coEvery { keyDao.getFido2ByRpId(RP_ID) } returns listOf(passkey(STORED_ID, STORED_USER_ID), twin)

        val response = sign(Base64.getEncoder().encodeToString(ID_BYTES))

        assertNotNull("an id naming two passkeys must be refused", response.error)
        assertTrue(signed.isEmpty())
    }

    @Test
    fun `a passkey of another relying party answers KEY_NOT_FOUND`() = runTest {
        // The DAO offers the RP_ID passkey for the other relying party too, so
        // the refusal comes from the lookup's own rpId check, not an empty answer.
        coEvery { keyDao.getFido2ByRpId(OTHER_RP_ID) } returns listOf(passkey(STORED_ID, STORED_USER_ID))
        val listed = list().single { it.optString("rpName") == "passkey" }.getString("credentialId")

        val response = sign(listed, forRpId = OTHER_RP_ID)

        assertEquals(ErrorCodes.KEY_NOT_FOUND, response.error?.code)
        assertTrue(response.error!!.message.contains("Credential not found"))
        assertTrue(signed.isEmpty())
    }

    @Test
    fun `a non-FIDO2 key with the same bytes answers KEY_NOT_FOUND`() = runTest {
        val general = passkey(STORED_ID, STORED_USER_ID)
        every { general.keyType } returns KeyTypes.SIGNING
        coEvery { keyDao.getFido2ByRpId(RP_ID) } returns listOf(general)

        val response = sign(Fido2WireIds.encode(STORED_ID))

        assertEquals(ErrorCodes.KEY_NOT_FOUND, response.error?.code)
        assertTrue(response.error!!.message.contains("Credential not found"))
        assertTrue(signed.isEmpty())
    }

    /**
     * The device tests compare listed credentials only through their two
     * wire-ID helpers, which encode the stored ID; a test that reads a listed
     * `credentialId` itself could compare it with a raw stored ID and pass
     * vacuously on a negative assertion.
     */
    @Test
    fun `the device tests read listed credential ids only through their wire-id helpers`() {
        val file = File(DEVICE_TEST_PATH)
        assertTrue(
            "device test not found at ${file.absolutePath}; unit tests must run from the app module",
            file.isFile
        )
        val source = file.readText()
        val helpers = bodyRange(source, "private fun listsCredential(", "private fun listedEntry(")
        val listingRefusal = bodyRange(source, "fun listFido2CredentialsRequiresAnRpId()", null)

        for (index in occurrences(source, "getString(\"credentialId\")")) {
            assertTrue(
                "a listed credentialId is read outside listsCredential/listedEntry at offset $index",
                index in helpers
            )
        }
        for (index in occurrences(source, "\"local.listFido2Credentials\"")) {
            assertTrue(
                "local.listFido2Credentials is called outside the wire-id helpers at offset $index",
                index in helpers || index in listingRefusal
            )
        }
    }

    /**
     * From the line that holds [start] to the end of the function that
     * begins at [last] (or at [start] when null), by the four-space closing brace.
     */
    private fun bodyRange(source: String, start: String, last: String?): IntRange {
        val from = source.indexOf(start)
        assertTrue("$start not found in the device test", from >= 0)
        val lastFrom = if (last == null) from else source.indexOf(last, from)
        assertTrue("$last not found after $start in the device test", lastFrom >= 0)
        val end = source.indexOf("\n    }\n", lastFrom)
        assertTrue("no end of the function at $lastFrom", end >= 0)
        return from until end
    }

    private fun occurrences(source: String, needle: String): List<Int> =
        generateSequence(source.indexOf(needle).takeIf { it >= 0 }) { previous ->
            source.indexOf(needle, previous + 1).takeIf { it >= 0 }
        }.toList()

    private suspend fun list(): List<JSONObject> {
        val request = Request(
            id = 1,
            method = MethodNames.LOCAL_LIST_FIDO2_CREDENTIALS,
            params = JSONObject().put("rpId", RP_ID)
        )
        val response = Response.fromJson(handler.handleRawRequest(request.toJson()))
        assertNull("no error expected: ${response.error?.message}", response.error)
        val credentials = response.result!!.getJSONArray("credentials")
        return (0 until credentials.length()).map { credentials.getJSONObject(it) }
    }

    private suspend fun sign(credentialId: String, forRpId: String = RP_ID): Response {
        val params = JSONObject()
            .put("credentialId", credentialId)
            .put("clientDataHash", Base64.getEncoder().encodeToString(CLIENT_DATA_HASH))
            .put("rpId", forRpId)
            .put("userVerificationRequired", false)
        val request = Request(id = 2, method = MethodNames.LOCAL_SIGN_FIDO2_ASSERTION, params = params)
        return Response.fromJson(handler.handleRawRequest(request.toJson()))
    }

    /** Go's `encoding/json` []byte rule: standard alphabet, padded, nothing else. */
    private fun strict(text: String): ByteArray {
        // java.util.Base64 tolerates missing padding; Go does not.
        assertEquals("not padded: $text", 0, text.length % 4)
        return Base64.getDecoder().decode(text)
    }

    private fun passkey(stored: String, user: String?): KeyEntity = mockk(relaxed = true) {
        every { keyId } returns stored
        every { keyType } returns "fido2"
        every { rpId } returns RP_ID
        every { rpName } returns if (stored == PLAIN_ID) "plain" else "passkey"
        every { userId } returns user
        every { sharingPolicy } returns SharingPolicyType.ALL_PEERS
        every { biometricRequired } returns false
        every { signCount } returns 0L
    }

    private companion object {
        const val RP_ID = "example.com"
        const val OTHER_RP_ID = "other.example"
        const val DEVICE_TEST_PATH =
            "src/androidTest/kotlin/com/automatethethings/xkey/protocol/RequestHandlerFido2AndCosignTest.kt"

        /** 0xfb and 0xff put '-' and '_' into the URL-safe form. */
        val ID_BYTES = ByteArray(32) { (0xF0 + it % 16).toByte() }
        val USER_BYTES = ByteArray(16) { (0xFF - it).toByte() }
        val STORED_ID: String = Base64.getUrlEncoder().withoutPadding().encodeToString(ID_BYTES)
        val STORED_USER_ID: String = Base64.getUrlEncoder().withoutPadding().encodeToString(USER_BYTES)

        /** A stored id that is not base64 in either alphabet (13 characters). */
        const val PLAIN_ID = "list-shared-1"

        /** The clientDataHash every assertion request sends. */
        val CLIENT_DATA_HASH = ByteArray(32) { 0x21 }

        val SIGNATURE = byteArrayOf(0x30, 0x00)
        val APPROVED_DER = ByteArray(91) { 3 }
    }
}

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
import android.net.Uri
import android.os.Looper
import android.util.Log
import com.automatethethings.xkey.audit.AuditLogEntity
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.audit.AuditOperationType
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.oath.OathCredentialDao
import com.automatethethings.xkey.oath.OathCredentialEntity
import com.automatethethings.xkey.oath.OathEngine
import com.automatethethings.xkey.oath.OathRepository
import com.automatethethings.xkey.oath.OathSecretManager
import com.automatethethings.xkey.pin.PinManager
import com.automatethethings.xkey.settings.DeviceLookup
import com.automatethethings.xkey.settings.PairedDeviceData
import com.automatethethings.xkey.settings.PairedDeviceRepository
import com.automatethethings.xkey.storage.XKeyDatabase
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import java.net.URI
import java.net.URLDecoder
import java.security.KeyStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import kotlinx.coroutines.withContext
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * The four OATH methods a paired desktop calls (local.oathList,
 * local.oathGenerate, local.oathAdd, local.oathRemove), driven through
 * [RequestHandler.handleRawRequest] on a served connection.
 *
 * The real `OathRepository` and `OathEngine` run over an in-memory
 * [OathCredentialDao] fake ([rows]); the secret manager passes the secret
 * through (so a stored secret is the RFC test secret) and records every
 * plaintext it hands back ([decrypted]); `Uri.parse` is backed by [URI];
 * the audit log records its entries ([audit]).
 *
 * TOTP codes at a fixed time: the repository asks the engine for the code
 * at the current time. While [totpAtSeconds] is set, the engine answers
 * with the HOTP code for the RFC 6238 time step `T / period`, the value
 * RFC 6238 defines the TOTP code as, so the RFC 6238 vectors are asserted
 * with the secret, algorithm, digits and period the handler passed.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class OathHandlerWireTest {

    private lateinit var handler: RequestHandler
    private lateinit var dao: OathCredentialDao
    private lateinit var pairedDevices: PairedDeviceRepository

    /** The credential store, by oath id. */
    private val rows = linkedMapOf<String, OathCredentialEntity>()
    private val inserted = mutableListOf<OathCredentialEntity>()
    private val deleted = mutableListOf<String>()
    private val decrypted = mutableListOf<ByteArray>()
    private val audit = mutableListOf<AuditLogEntity>()

    /** The Unix time, in seconds, the TOTP code is computed at; null: the real clock. */
    private var totpAtSeconds: Long? = null

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

        mockkObject(AuditLogger)
        every { AuditLogger["log"](any<AuditLogEntity>()) } answers {
            audit += firstArg<AuditLogEntity>()
            Unit
        }

        dao = mockk()
        coEvery { dao.getAll() } answers { rows.values.toList() }
        coEvery { dao.getByOathId(any()) } answers { rows[firstArg()] }
        coEvery { dao.insert(any()) } answers {
            val entity = firstArg<OathCredentialEntity>()
            inserted += entity
            rows[entity.oathId] = entity
            1L
        }
        coEvery { dao.claimCounter(any(), any()) } answers {
            val id = firstArg<String>()
            val expected = secondArg<Long>()
            val row = rows[id]
            if (row != null && row.counter == expected && expected < OathRepository.HOTP_COUNTER_MAX) {
                rows[id] = row.copy(counter = expected + 1)
                1
            } else {
                0
            }
        }
        coEvery { dao.recordUsage(any(), any()) } returns Unit
        coEvery { dao.deleteAndRecordDeletion(any(), any()) } answers {
            val id = firstArg<String>()
            deleted += id
            rows.remove(id)
            Unit
        }
        val database = mockk<XKeyDatabase>(relaxed = true)
        every { database.oathCredentialDao() } returns dao
        mockkObject(XKeyDatabase.Companion)
        every { XKeyDatabase.getInstance(any()) } returns database

        // OathSecretManager opens the AndroidKeyStore when it is built.
        mockkStatic(KeyStore::class)
        every { KeyStore.getInstance(any<String>()) } returns mockk(relaxed = true)
        mockkConstructor(OathSecretManager::class)
        every { anyConstructed<OathSecretManager>().encryptSecret(any()) } answers { firstArg<ByteArray>().copyOf() }
        every { anyConstructed<OathSecretManager>().decryptSecret(any()) } answers {
            firstArg<ByteArray>().copyOf().also { decrypted += it }
        }

        mockkObject(OathEngine)
        every { OathEngine.generateTotpCode(any(), any(), any(), any(), any()) } answers {
            val at = totpAtSeconds
            if (at == null) {
                callOriginal()
            } else {
                OathEngine.generateHotpCode(
                    secret = firstArg(),
                    counter = at / arg<Int>(3),
                    algorithm = secondArg(),
                    digits = thirdArg()
                )
            }
        }

        mockkStatic(Uri::class)
        every { Uri.parse(any()) } answers { jvmUri(firstArg()) }

        pairedDevices = mockk(relaxed = true)
        every { pairedDevices.lookupDevice(any()) } returns
            DeviceLookup.Paired(PairedDeviceData(PEER, PEER_NAME, 0L))

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
            sessionAuthManager = null,
            pairedDeviceRepository = pairedDevices,
            pinManager = mockk<PinManager>(relaxed = true)
        )
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
        unmockkAll()
    }

    // -------------------------------------------------------------------------
    // local.oathList
    // -------------------------------------------------------------------------

    @Test
    fun `oathList returns every stored credential with an empty secret`() = runTest {
        store(totp(ID_TOTP, issuer = "Acme", account = "alice", algorithm = "SHA256", digits = 8, period = 60))
        store(hotp(ID_HOTP, issuer = null, account = "bob", counter = 7))

        val credentials = result(call(MethodNames.LOCAL_OATH_LIST)).getJSONArray("credentials")

        assertEquals(2, credentials.length())
        val first = credentials.getJSONObject(0)
        assertEquals(ID_TOTP, first.getString("name"))
        assertEquals("Acme", first.getString("issuer"))
        assertEquals("alice", first.getString("account_name"))
        assertEquals("totp", first.getString("type"))
        assertEquals("SHA256", first.getString("algorithm"))
        assertEquals(8, first.getInt("digits"))
        assertEquals(60, first.getInt("period"))
        val second = credentials.getJSONObject(1)
        assertEquals(ID_HOTP, second.getString("name"))
        assertTrue(second.isNull("issuer"))
        assertEquals("bob", second.getString("account_name"))
        assertEquals("hotp", second.getString("type"))
        assertEquals(7L, second.getLong("counter"))
        for (i in 0 until credentials.length()) {
            assertEquals("no secret in a listing", "", credentials.getJSONObject(i).getString("secret"))
        }
        assertTrue("a listing decrypts no secret", decrypted.isEmpty())
    }

    @Test
    fun `oathList with no credentials returns an empty list`() = runTest {
        val credentials = result(call(MethodNames.LOCAL_OATH_LIST)).getJSONArray("credentials")

        assertEquals(0, credentials.length())
    }

    @Test
    fun `oathList answers INTERNAL_ERROR when the store fails`() = runTest {
        coEvery { dao.getAll() } throws IllegalStateException("database is closed")

        assertEquals(ErrorCodes.INTERNAL_ERROR, errorCode(call(MethodNames.LOCAL_OATH_LIST)))
    }

    // -------------------------------------------------------------------------
    // local.oathGenerate
    // -------------------------------------------------------------------------

    @Test
    fun `oathGenerate gives the RFC 4226 HOTP codes for counters 0 to 9`() = runTest {
        store(hotp(ID_HOTP, counter = 0))

        val codes = (0 until 10).map {
            val result = result(generate(ID_HOTP))
            assertEquals("HOTP has no expiry", 0, result.getInt("expires_in"))
            result.getString("code")
        }

        assertEquals(RFC4226_CODES, codes)
        for (counter in 0L until 10L) {
            coVerify(exactly = 1) { dao.claimCounter(ID_HOTP, counter) }
        }
        assertEquals(10L, rows.getValue(ID_HOTP).counter)
    }

    @Test
    fun `oathGenerate gives the RFC 6238 TOTP codes at the vector times`() = runTest {
        store(totp("sha1", secret = RFC6238_SHA1_SECRET, algorithm = "SHA1", digits = 8))
        store(totp("sha256", secret = RFC6238_SHA256_SECRET, algorithm = "SHA256", digits = 8))
        store(totp("sha512", secret = RFC6238_SHA512_SECRET, algorithm = "SHA512", digits = 8))

        for ((time, sha1, sha256, sha512) in RFC6238_VECTORS) {
            totpAtSeconds = time
            assertEquals("SHA1 at $time", sha1, code(generate("sha1")))
            assertEquals("SHA256 at $time", sha256, code(generate("sha256")))
            assertEquals("SHA512 at $time", sha512, code(generate("sha512")))
        }
        coVerify(exactly = 0) { dao.claimCounter(any(), any()) }
    }

    @Test
    fun `oathGenerate gives 6, 7 and 8 digit TOTP codes`() = runTest {
        totpAtSeconds = 59L
        store(totp("d6", secret = RFC6238_SHA1_SECRET, digits = 6))
        store(totp("d7", secret = RFC6238_SHA1_SECRET, digits = 7))
        store(totp("d8", secret = RFC6238_SHA1_SECRET, digits = 8))

        assertEquals("287082", code(generate("d6")))
        assertEquals("4287082", code(generate("d7")))
        assertEquals("94287082", code(generate("d8")))
    }

    @Test
    fun `oathGenerate expires_in is within the period`() = runTest {
        store(totp("p30", period = 30))
        store(totp("p60", period = 60))

        val in30 = result(generate("p30")).getInt("expires_in")
        val in60 = result(generate("p60")).getInt("expires_in")

        assertTrue("expires_in $in30", in30 in 1..30)
        assertTrue("expires_in $in60", in60 in 1..60)
    }

    @Test
    fun `oathGenerate with an unknown credential_id answers INVALID_PARAMS`() = runTest {
        val response = generate("no-such-credential")

        assertEquals(ErrorCodes.INVALID_PARAMS, errorCode(response))
        assertFalse(errorMessage(response), errorMessage(response).contains("No OATH credential found"))
        assertTrue(decrypted.isEmpty())
    }

    @Test
    fun `oathGenerate without a credential_id answers INVALID_PARAMS`() = runTest {
        store(hotp(ID_HOTP))

        assertEquals(ErrorCodes.INVALID_PARAMS, errorCode(call(MethodNames.LOCAL_OATH_GENERATE, JSONObject())))
        assertEquals(
            ErrorCodes.INVALID_PARAMS,
            errorCode(call(MethodNames.LOCAL_OATH_GENERATE, JSONObject().put("credential_id", "")))
        )
        assertEquals(ErrorCodes.INVALID_PARAMS, errorCode(call(MethodNames.LOCAL_OATH_GENERATE, null)))
        coVerify(exactly = 0) { dao.claimCounter(any(), any()) }
    }


    @Test
    fun `oathGenerate at HOTP_COUNTER_MAX answers OPERATION_DENIED without the exception text`() = runTest {
        store(hotp(ID_HOTP, counter = OathRepository.HOTP_COUNTER_MAX))

        val response = generate(ID_HOTP)

        assertEquals(ErrorCodes.OPERATION_DENIED, errorCode(response))
        assertFalse(errorMessage(response), errorMessage(response).contains("for OATH credential"))
        coVerify(exactly = 0) { dao.claimCounter(any(), any()) }
        assertEquals(OathRepository.HOTP_COUNTER_MAX, rows.getValue(ID_HOTP).counter)
        assertTrue("no code, no audit entry: $audit", audit.isEmpty())
    }

    @Test
    fun `oathGenerate for a stored period of 0 answers INTERNAL_ERROR without the exception text`() = runTest {
        // A synced row can carry period 0; the real engine refuses it.
        store(totp(ID_TOTP, period = 0))

        val response = generate(ID_TOTP)

        assertEquals(ErrorCodes.INTERNAL_ERROR, errorCode(response))
        assertFalse(errorMessage(response), errorMessage(response).contains("Period"))
        assertFalse(errorMessage(response), errorMessage(response).contains("Exception"))
        assertTrue("no code, no audit entry: $audit", audit.isEmpty())
    }

    @Test
    fun `oathGenerate reports the credential it generated for, when it is removed right after`() = runTest {
        store(totp(ID_TOTP, issuer = "Acme", account = "alice", period = 30))
        // A removal lands after the code is computed and before the answer.
        coEvery { dao.recordUsage(ID_TOTP, any()) } answers { rows.remove(ID_TOTP); Unit }

        val result = result(generate(ID_TOTP))

        val expiresIn = result.getInt("expires_in")
        assertTrue("expires_in $expiresIn", expiresIn in 1..30)
        val entry = audit.single { it.operationType == AuditOperationType.OATH_CODE_GENERATED }
        assertEquals(ID_TOTP, entry.keyId)
        assertEquals("Acme:alice", entry.keyLabel)
    }

    // -------------------------------------------------------------------------
    // Harness
    // -------------------------------------------------------------------------

    /** An android [Uri] answering what the importer reads, from [URI]. */
    private fun jvmUri(uriString: String): Uri {
        val uri = URI(uriString)
        val params = uri.rawQuery.orEmpty().split("&").filter { it.isNotEmpty() }
            .map { it.split("=", limit = 2) }
            .associate { it[0] to URLDecoder.decode(it.getOrElse(1) { "" }, Charsets.UTF_8.name()) }
        return mockk {
            every { scheme } returns uri.scheme
            every { host } returns uri.host
            every { encodedPath } returns uri.rawPath
            every { getQueryParameter(any()) } answers { params[firstArg()] }
        }
    }

    private fun store(entity: OathCredentialEntity) {
        rows[entity.oathId] = entity
    }

    private fun totp(
        id: String,
        issuer: String? = "Acme",
        account: String = "alice",
        secret: ByteArray = RFC6238_SHA1_SECRET,
        algorithm: String = "SHA1",
        digits: Int = 6,
        period: Int = 30
    ) = OathCredentialEntity(
        oathId = id,
        oathType = "TOTP",
        algorithm = algorithm,
        digits = digits,
        periodSeconds = period,
        issuer = issuer,
        accountName = account,
        secretEncrypted = secret,
        createdAt = 0L
    )

    private fun hotp(
        id: String,
        issuer: String? = "Acme",
        account: String = "alice",
        counter: Long = 0L
    ) = OathCredentialEntity(
        oathId = id,
        oathType = "HOTP",
        algorithm = "SHA1",
        digits = 6,
        counter = counter,
        issuer = issuer,
        accountName = account,
        secretEncrypted = RFC6238_SHA1_SECRET,
        createdAt = 0L
    )

    private suspend fun generate(credentialId: String): JSONObject =
        call(MethodNames.LOCAL_OATH_GENERATE, JSONObject().put("credential_id", credentialId))

    /** [method] with [params] on a connection served for [peer]. */
    private suspend fun call(method: String, params: JSONObject? = JSONObject(), peer: String? = PEER): JSONObject {
        val request = JSONObject().put("id", 1).put("method", method)
        if (params != null) request.put("params", params)
        val bytes = request.toString().toByteArray(Charsets.UTF_8)
        val answer = withContext(RequestHandler.servedConnection(SessionBindingProvider { null }, peer, "test:connection")) {
            handler.handleRawRequest(bytes)
        }
        return JSONObject(String(answer, Charsets.UTF_8))
    }

    private fun result(response: JSONObject): JSONObject {
        assertTrue(response.toString(), response.has("result"))
        return response.getJSONObject("result")
    }

    private fun code(response: JSONObject): String = result(response).getString("code")

    private fun errorCode(response: JSONObject): Int {
        assertTrue(response.toString(), response.has("error"))
        return response.getJSONObject("error").getInt("code")
    }

    private fun errorMessage(response: JSONObject): String =
        response.getJSONObject("error").getString("message")

    private data class TotpVector(val time: Long, val sha1: String, val sha256: String, val sha512: String)

    private companion object {
        const val PEER = "0a1b2c3d4e5f"
        const val PEER_NAME = "Test desktop"
        const val ID_TOTP = "totp-credential"
        const val ID_HOTP = "hotp-credential"

        /** RFC 4226 appendix D: secret "12345678901234567890", counters 0 to 9. */
        val RFC4226_CODES = listOf(
            "755224", "287082", "359152", "969429", "338314",
            "254676", "287922", "162583", "399871", "520489"
        )

        /** RFC 6238 appendix B seeds. */
        val RFC6238_SHA1_SECRET = "12345678901234567890".toByteArray(Charsets.US_ASCII)
        val RFC6238_SHA256_SECRET = "12345678901234567890123456789012".toByteArray(Charsets.US_ASCII)
        val RFC6238_SHA512_SECRET =
            "1234567890123456789012345678901234567890123456789012345678901234".toByteArray(Charsets.US_ASCII)

        /** RFC 6238 appendix B: 8 digits, period 30. */
        val RFC6238_VECTORS = listOf(
            TotpVector(59L, "94287082", "46119246", "90693936"),
            TotpVector(1111111109L, "07081804", "68084774", "25091201"),
            TotpVector(1111111111L, "14050471", "67062674", "99943326"),
            TotpVector(1234567890L, "89005924", "91819424", "93441116"),
            TotpVector(2000000000L, "69279037", "90698825", "38618901"),
            TotpVector(20000000000L, "65353130", "77737706", "47863826")
        )
    }
}

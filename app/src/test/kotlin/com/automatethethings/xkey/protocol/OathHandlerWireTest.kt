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

        val response = call(MethodNames.LOCAL_OATH_LIST)

        assertEquals(ErrorCodes.INTERNAL_ERROR, errorCode(response))
        assertFalse(errorMessage(response), errorMessage(response).contains("database is closed"))
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
    // local.oathAdd
    // -------------------------------------------------------------------------

    @Test
    fun `oathAdd stores a valid credential and a generate gives its RFC code`() = runTest {
        totpAtSeconds = 59L
        val response = add(credential(secret = RFC6238_SHA1_BASE32).put("digits", 8))

        val id = result(response).getString("credential_id")
        val stored = inserted.single()
        assertEquals(id, stored.oathId)
        assertEquals("TOTP", stored.oathType)
        assertTrue(stored.secretEncrypted.contentEquals(RFC6238_SHA1_SECRET))
        assertEquals("94287082", code(generate(id)))
    }

    @Test
    fun `oathAdd without a credential or its fields answers INVALID_PARAMS`() = runTest {
        assertEquals(ErrorCodes.INVALID_PARAMS, errorCode(call(MethodNames.LOCAL_OATH_ADD, null)))
        assertEquals(ErrorCodes.INVALID_PARAMS, errorCode(call(MethodNames.LOCAL_OATH_ADD, JSONObject())))
        assertEquals(ErrorCodes.INVALID_PARAMS, errorCode(add(credential().put("secret", ""))))
        assertEquals(ErrorCodes.INVALID_PARAMS, errorCode(add(credential().put("account_name", ""))))
        assertTrue(inserted.isEmpty())
    }


    @Test
    fun `oathAdd refuses an invalid credential with INVALID_PARAMS and stores nothing`() = runTest {
        val invalid = mapOf(
            "unknown type" to credential().put("type", "motp"),
            "blank secret" to credential(secret = "   "),
            "secret shorter than 10 bytes" to credential(secret = "JBSWY3DP"),
            "invalid base32" to credential(secret = "JBSWY3DPEHPK3PX1"),
            "unsupported algorithm" to credential().put("algorithm", "MD5"),
            "digits 5" to credential().put("digits", 5),
            "digits 9" to credential().put("digits", 9),
            "TOTP period 0" to credential().put("type", "totp").put("period", 0)
        )

        for ((case, credential) in invalid) {
            val response = add(credential)
            assertEquals("$case: $response", ErrorCodes.INVALID_PARAMS, errorCode(response))
            assertFalse("$case: $response", errorMessage(response).contains(credential.getString("secret").trim().ifEmpty { "\u0000" }))
        }
        assertTrue("nothing stored: $inserted", inserted.isEmpty())
        assertTrue("nothing audited: $audit", audit.isEmpty())
    }

    @Test
    fun `oathAdd audits the id the credential was stored under`() = runTest {
        val id = result(add(credential())).getString("credential_id")

        val entry = audit.single { it.operationType == AuditOperationType.OATH_CREDENTIAL_CREATED }
        assertEquals(id, entry.keyId)
        assertEquals("Acme:alice", entry.keyLabel)
    }

    // -------------------------------------------------------------------------
    // local.oathRemove
    // -------------------------------------------------------------------------

    @Test
    fun `oathRemove removes only the requested credential and audits its id`() = runTest {
        store(totp(ID_TOTP, issuer = "Acme", account = "alice"))
        store(hotp(ID_HOTP, issuer = "Other", account = "bob"))

        val result = result(remove(ID_TOTP))

        assertTrue(result.getBoolean("deleted"))
        assertEquals(listOf(ID_TOTP), deleted)
        coVerify(exactly = 1) { dao.deleteAndRecordDeletion(ID_TOTP, any()) }
        assertEquals(listOf(ID_HOTP), rows.keys.toList())
        val entry = audit.single { it.operationType == AuditOperationType.OATH_CREDENTIAL_DELETED }
        assertEquals(ID_TOTP, entry.keyId)
        assertEquals("Acme:alice", entry.keyLabel)
    }

    @Test
    fun `oathRemove of an unknown or missing credential_id deletes nothing`() = runTest {
        store(hotp(ID_HOTP))

        assertFalse(result(remove("no-such-credential")).getBoolean("deleted"))
        assertEquals(ErrorCodes.INVALID_PARAMS, errorCode(call(MethodNames.LOCAL_OATH_REMOVE, JSONObject())))
        assertEquals(ErrorCodes.INVALID_PARAMS, errorCode(call(MethodNames.LOCAL_OATH_REMOVE, null)))

        coVerify(exactly = 0) { dao.deleteAndRecordDeletion(any(), any()) }
        assertEquals(listOf(ID_HOTP), rows.keys.toList())
        assertTrue(audit.isEmpty())
    }

    @Test
    fun `oathRemove answers INTERNAL_ERROR when the store fails`() = runTest {
        store(hotp(ID_HOTP))
        coEvery { dao.deleteAndRecordDeletion(any(), any()) } throws IllegalStateException("disk I/O error")

        val response = remove(ID_HOTP)

        assertEquals(ErrorCodes.INTERNAL_ERROR, errorCode(response))
        assertFalse(errorMessage(response), errorMessage(response).contains("disk I/O error"))
        assertTrue(audit.isEmpty())
    }


    // -------------------------------------------------------------------------
    // Audit and secret handling
    // -------------------------------------------------------------------------

    @Test
    fun `one audit entry per created, generated and deleted credential names its id`() = runTest {
        val id = result(add(credential())).getString("credential_id")
        code(generate(id))
        assertTrue(result(remove(id)).getBoolean("deleted"))

        val oath = audit.filter { it.operationType in OATH_ENTRIES }
        assertEquals(OATH_ENTRIES, oath.map { it.operationType })
        oath.forEach { assertEquals("entry names the credential: $it", id, it.keyId) }
    }

    @Test
    fun `every OATH audit entry names the requesting desktop`() = runTest {
        val id = result(add(credential())).getString("credential_id")
        code(generate(id))
        result(remove(id))

        val oath = audit.filter { it.operationType in OATH_ENTRIES }
        assertEquals(OATH_ENTRIES, oath.map { it.operationType })
        oath.forEach {
            assertEquals("entry names the desktop: $it", PEER, it.deviceId)
            assertEquals("entry names the desktop: $it", PEER_NAME, it.deviceName)
        }
    }

    @Test
    fun `oathGenerate zeroes the decrypted secret after the code`() = runTest {
        totpAtSeconds = 59L
        store(hotp(ID_HOTP))
        store(totp(ID_TOTP))

        code(generate(ID_HOTP))
        code(generate(ID_TOTP))

        assertEquals(2, decrypted.size)
        decrypted.forEach { secret ->
            assertTrue("secret left in memory", secret.all { it == 0.toByte() })
        }
    }

    @Test
    fun `a HOTP code whose counter was claimed is not lost to a later failure`() = runTest {
        store(hotp(ID_HOTP, counter = 0))
        coEvery { dao.recordUsage(any(), any()) } throws IllegalStateException("disk I/O error")

        val response = generate(ID_HOTP)

        assertEquals(RFC4226_CODES[0], code(response))
        assertEquals("the claimed counter is spent once", 1L, rows.getValue(ID_HOTP).counter)
    }


    // -------------------------------------------------------------------------
    // Device attestation gate
    // -------------------------------------------------------------------------

    @Test
    fun `a desktop whose required attestation is stale is refused every OATH method`() = runTest {
        every { pairedDevices.lookupDevice(PEER) } returns DeviceLookup.Paired(
            attestedDesktop(lastAttestationTime = System.currentTimeMillis() - 60 * 60 * 1000L)
        )

        assertEveryOathMethodRefused()
    }

    @Test
    fun `a desktop that never attested, where attestation is required, is refused every OATH method`() = runTest {
        every { pairedDevices.lookupDevice(PEER) } returns DeviceLookup.Paired(attestedDesktop(lastAttestationTime = null))

        assertEveryOathMethodRefused()
    }

    @Test
    fun `an unreadable paired-device store refuses every OATH method`() = runTest {
        every { pairedDevices.lookupDevice(any()) } returns
            DeviceLookup.Unreadable(SecurityException("keystore unavailable"))

        assertEveryOathMethodRefused()
    }

    @Test
    fun `a desktop with a current attestation is served every OATH method`() = runTest {
        every { pairedDevices.lookupDevice(PEER) } returns DeviceLookup.Paired(
            attestedDesktop(lastAttestationTime = System.currentTimeMillis())
        )
        store(hotp(ID_HOTP))

        assertEquals(1, result(call(MethodNames.LOCAL_OATH_LIST)).getJSONArray("credentials").length())
        assertEquals(RFC4226_CODES[0], code(generate(ID_HOTP)))
        result(add(credential()))
        assertTrue(result(remove(ID_HOTP)).getBoolean("deleted"))
    }

    private fun attestedDesktop(lastAttestationTime: Long?) = PairedDeviceData(
        publicKeyHex = PEER,
        deviceName = PEER_NAME,
        pairedAt = 0L,
        lastAttestationTime = lastAttestationTime,
        requireAttestationForKeyUse = true,
        attestationGracePeriodMinutes = 5
    )

    /** Each method answers DEVICE_ATTESTATION_REQUIRED and nothing is read, written or audited. */
    private suspend fun assertEveryOathMethodRefused() {
        store(hotp(ID_HOTP, counter = 0))

        val answers = mapOf(
            MethodNames.LOCAL_OATH_LIST to call(MethodNames.LOCAL_OATH_LIST),
            MethodNames.LOCAL_OATH_GENERATE to generate(ID_HOTP),
            MethodNames.LOCAL_OATH_ADD to add(credential()),
            MethodNames.LOCAL_OATH_REMOVE to remove(ID_HOTP)
        )

        for ((method, response) in answers) {
            assertEquals("$method: $response", ErrorCodes.DEVICE_ATTESTATION_REQUIRED, errorCode(response))
        }
        coVerify(exactly = 0) { dao.getAll() }
        coVerify(exactly = 0) { dao.claimCounter(any(), any()) }
        assertEquals(0L, rows.getValue(ID_HOTP).counter)
        assertTrue("no secret decrypted", decrypted.isEmpty())
        assertTrue("nothing stored: $inserted", inserted.isEmpty())
        assertTrue("nothing deleted: $deleted", deleted.isEmpty())
        assertTrue("nothing audited: $audit", audit.none { it.operationType in OATH_ENTRIES })
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


    private suspend fun remove(credentialId: String): JSONObject =
        call(MethodNames.LOCAL_OATH_REMOVE, JSONObject().put("credential_id", credentialId))

    private suspend fun add(credential: JSONObject): JSONObject =
        call(MethodNames.LOCAL_OATH_ADD, JSONObject().put("credential", credential))

    /** A local.oathAdd credential, valid unless a test changes a field. */
    private fun credential(secret: String = BASE32_SECRET): JSONObject =
        JSONObject()
            .put("name", CALLER_NAME)
            .put("issuer", "Acme")
            .put("account_name", "alice")
            .put("secret", secret)

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
        const val CALLER_NAME = "caller-chosen-name"

        val OATH_ENTRIES = listOf(
            AuditOperationType.OATH_CREDENTIAL_CREATED,
            AuditOperationType.OATH_CODE_GENERATED,
            AuditOperationType.OATH_CREDENTIAL_DELETED
        )

        /** A 10-byte secret, the shortest the importer accepts. */
        const val BASE32_SECRET = "JBSWY3DPEHPK3PXP"

        /** Base32 of the RFC 6238 SHA1 seed. */
        const val RFC6238_SHA1_BASE32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

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

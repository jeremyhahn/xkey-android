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
import com.automatethethings.xkey.audit.AuditLogDao
import com.automatethethings.xkey.audit.AuditLogEntity
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.audit.AuditOperationType
import com.automatethethings.xkey.crypto.DecryptResult
import com.automatethethings.xkey.crypto.HmacResult
import com.automatethethings.xkey.crypto.KeyNotFoundException
import com.automatethethings.xkey.crypto.KeystoreCapabilities
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.crypto.SoftwareKey
import com.automatethethings.xkey.crypto.SoftwareKeyStore
import com.automatethethings.xkey.settings.DeviceLookup
import com.automatethethings.xkey.settings.PairedDeviceData
import com.automatethethings.xkey.settings.PairedDeviceRepository
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.entity.KeyEntity
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import java.security.KeyStore
import java.util.Base64
import java.util.concurrent.atomic.AtomicReference
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import kotlinx.coroutines.withContext
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * The handlers that use a stored key for a desktop: local.decrypt,
 * local.symmetricEncrypt, local.symmetricDecrypt, local.hmac, local.ecdh and
 * local.getPublicKey, driven through handleRawRequest for Keystore-backed
 * keys (a mocked KeystoreManager) and software keys (real material run by
 * javax.crypto): their results, parameter errors, the attestation gate, the
 * audit entries and the zeroing of software key material.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class KeyUseHandlerTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private lateinit var handler: RequestHandler
    private lateinit var keystore: KeystoreManager
    private val inserted = mutableListOf<AuditLogEntity>()

    /** Every material array the mocked SoftwareKeyStore.get handed out. */
    private val handedMaterial = mutableListOf<ByteArray>()

    private val aesMaterial = ByteArray(32) { (it * 7 + 1).toByte() }

    /** Software keys by id: (stored algorithm, stored type, material). */
    private val softwareKeys = mapOf(
        SW_AES to Triple("AES-256-GCM", "symmetric", aesMaterial),
        SW_HMAC_256 to Triple("HMAC-SHA256", "symmetric", RFC4231_KEY),
        SW_HMAC_384 to Triple("HMAC-SHA384", "symmetric", RFC4231_KEY),
        SW_HMAC_512 to Triple("HMAC-SHA512", "symmetric", RFC4231_KEY)
    )

    private val hwCiphertext = ByteArray(44) { 0x41 }
    private val hwPlaintext = ByteArray(16) { 0x42 }
    private val hwMac = ByteArray(32) { 0x43 }
    private val sharedSecret = ByteArray(32) { 0x44 }
    private val publicDer = ByteArray(91) { 0x45 }
    private val publicCose = ByteArray(77) { 0x46 }
    private val publicPem = "-----BEGIN PUBLIC KEY-----\nRUVF\n-----END PUBLIC KEY-----\n"
    private val publicSsh = "ecdsa-sha2-nistp256 AAAAE2VjZHNh"
    private val peerKey = b64(ByteArray(91) { (it + 7).toByte() })
    private val data = b64("payload".toByteArray())

    @Suppress("UNCHECKED_CAST")
    private fun <T> holder(name: String): AtomicReference<T?> =
        AuditLogger::class.java.getDeclaredField(name)
            .apply { isAccessible = true }
            .get(AuditLogger) as AtomicReference<T?>

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

        val keyDao = mockk<KeyDao>(relaxed = true)
        coEvery { keyDao.getByKeyId(any()) } returns null
        listOf(
            KeyEntity(keyId = HW_AES, keyType = "secret", algorithm = "AES-256-GCM", label = "aes", keySizeBits = 256, source = "local"),
            KeyEntity(keyId = HW_HMAC, keyType = "secret", algorithm = "HMAC-SHA256", label = "hmac", keySizeBits = 256, source = "local"),
            KeyEntity(keyId = HW_EC, keyType = "signing", algorithm = "ES256", label = "ec", keySizeBits = 256, source = "local"),
            KeyEntity(keyId = HW_RSA, keyType = "encryption", algorithm = "RSA-OAEP", label = "rsa", keySizeBits = 2048, source = "local")
        ).forEach { entity -> coEvery { keyDao.getByKeyId(entity.keyId) } returns entity }
        val database = mockk<XKeyDatabase>(relaxed = true)
        every { database.keyDao() } returns keyDao
        mockkObject(XKeyDatabase.Companion)
        every { XKeyDatabase.getInstance(any()) } returns database

        // local.ecdh runs only from API 31; SDK_INT reads 0 on the JVM.
        mockkObject(KeystoreCapabilities)
        every { KeystoreCapabilities.supportsEcdh(any()) } returns true

        Dispatchers.setMain(UnconfinedTestDispatcher())

        inserted.clear()
        val dao = mockk<AuditLogDao>(relaxed = true)
        coEvery { dao.insert(any()) } answers {
            inserted += firstArg<AuditLogEntity>()
            inserted.size.toLong()
        }
        holder<AuditLogDao>("daoRef").set(dao)
        holder<CoroutineScope>("scopeRef").set(CoroutineScope(Dispatchers.Unconfined))

        // SoftwareKeyStore's default cipher opens AndroidKeyStore on construction.
        mockkStatic(KeyStore::class)
        every { KeyStore.getInstance("AndroidKeyStore") } returns mockk(relaxed = true)
        mockkConstructor(SoftwareKeyStore::class)
        handedMaterial.clear()
        // Each get decrypts a fresh copy of the material, as the real store does.
        every { anyConstructed<SoftwareKeyStore>().get(any()) } answers {
            val id = firstArg<String>()
            softwareKeys[id]?.let { (algorithm, type, material) ->
                val copy = material.copyOf().also { handedMaterial += it }
                SoftwareKey(
                    keyId = id, algorithm = algorithm, keyType = type, keySize = copy.size * 8,
                    exportable = true, shareable = true, material = copy
                )
            }
        }

        val context = mockk<Context>(relaxed = true)
        every { context.filesDir } returns tmp.root
        every { context.applicationContext } returns context
        every { context.getSystemService(Context.KEYGUARD_SERVICE) } returns
            mockk<KeyguardManager>(relaxed = true)
        every { context.getSystemService(NotificationManager::class.java) } returns
            mockk<NotificationManager>(relaxed = true)

        val pairedDevices = mockk<PairedDeviceRepository>()
        every { pairedDevices.lookupDevice(any()) } returns DeviceLookup.NotPaired
        every { pairedDevices.lookupDevice(PEER_OK) } returns
            DeviceLookup.Paired(device("Desktop A", requireAttestation = false, lastAttested = null))
        // Requires attestation for key use; last attested an hour ago, 5 minutes of grace.
        every { pairedDevices.lookupDevice(PEER_STALE) } returns DeviceLookup.Paired(
            device("Desktop S", requireAttestation = true, lastAttested = System.currentTimeMillis() - 3_600_000L)
        )
        every { pairedDevices.lookupDevice(PEER_UNREADABLE) } returns
            DeviceLookup.Unreadable(IllegalStateException("store locked"))

        // The Keystore answers KeyNotFoundException for a key it does not
        // hold, or one of another type (KeystoreManager casts the entry to
        // the key class the operation needs).
        keystore = mockk(relaxed = true)
        coEvery { keystore.rsaDecryptWithAlgorithm(any(), any()) } answers { throw KeyNotFoundException(firstArg()) }
        coEvery { keystore.symmetricEncrypt(any(), any(), any()) } answers { throw KeyNotFoundException(firstArg()) }
        coEvery { keystore.symmetricDecrypt(any(), any(), any()) } answers { throw KeyNotFoundException(firstArg()) }
        coEvery { keystore.computeHMACWithAlgorithm(any(), any()) } answers { throw KeyNotFoundException(firstArg()) }
        coEvery { keystore.performECDH(any(), any()) } answers { throw KeyNotFoundException(firstArg()) }
        every { keystore.getPublicKeyDER(any()) } returns null
        every { keystore.getPublicKeyPEM(any()) } returns null
        every { keystore.getPublicKeySSH(any()) } returns null
        every { keystore.getCOSEPublicKey(any()) } returns null

        coEvery { keystore.rsaDecryptWithAlgorithm(HW_RSA, any()) } returns
            DecryptResult(hwPlaintext, "RSA-OAEP-SHA-256-MGF1-SHA-1")
        coEvery { keystore.symmetricEncrypt(HW_AES, any(), any()) } returns hwCiphertext
        coEvery { keystore.symmetricDecrypt(HW_AES, any(), any()) } returns hwPlaintext
        coEvery { keystore.computeHMACWithAlgorithm(HW_HMAC, any()) } returns HmacResult(hwMac, "HMAC-SHA256")
        coEvery { keystore.performECDH(HW_EC, any()) } returns sharedSecret
        every { keystore.getPublicKeyDER(HW_EC) } returns publicDer
        every { keystore.getPublicKeyPEM(HW_EC) } returns publicPem
        every { keystore.getPublicKeySSH(HW_EC) } returns publicSsh
        every { keystore.getCOSEPublicKey(HW_EC) } returns publicCose

        handler = RequestHandler(
            context = context,
            keystoreManager = keystore,
            biometricLauncher = null,
            sessionAuthManager = null,
            pairedDeviceRepository = pairedDevices,
            pinManager = mockk(relaxed = true)
        )
    }

    @After
    fun tearDown() {
        holder<AuditLogDao>("daoRef").set(null)
        holder<CoroutineScope>("scopeRef").set(null)
        Dispatchers.resetMain()
        unmockkAll()
    }

    // ---------------------------------------------------------------------
    // Results
    // ---------------------------------------------------------------------

    @Test
    fun `software symmetric encrypt then decrypt round-trips without aad`() = runTest {
        val plaintext = "software round trip".toByteArray()
        val encrypted = result(call(MethodNames.LOCAL_SYMMETRIC_ENCRYPT, """{"keyId":"$SW_AES","plaintext":"${b64(plaintext)}"}"""))
        val ciphertext = encrypted.getString("ciphertext")
        assertEquals("the older peer's field carries the same bytes", ciphertext, encrypted.getString("data"))
        // iv(12) || ciphertext || tag(16), under the key's own material.
        val raw = unb64(ciphertext)
        assertEquals(12 + plaintext.size + 16, raw.size)
        assertArrayEquals(plaintext, javaxGcmDecrypt(aesMaterial, raw, null))

        val decrypted = result(call(MethodNames.LOCAL_SYMMETRIC_DECRYPT, """{"keyId":"$SW_AES","ciphertext":"$ciphertext"}"""))
        assertArrayEquals(plaintext, unb64(decrypted.getString("plaintext")))
        assertEquals(decrypted.getString("plaintext"), decrypted.getString("data"))
    }

    @Test
    fun `software symmetric encrypt then decrypt round-trips with aad`() = runTest {
        val plaintext = "bound to a context".toByteArray()
        val aad = b64("context-1".toByteArray())
        val ciphertext = result(
            call(MethodNames.LOCAL_SYMMETRIC_ENCRYPT, """{"keyId":"$SW_AES","plaintext":"${b64(plaintext)}","aad":"$aad"}""")
        ).getString("ciphertext")
        assertArrayEquals(plaintext, javaxGcmDecrypt(aesMaterial, unb64(ciphertext), unb64(aad)))

        val decrypted = result(
            call(MethodNames.LOCAL_SYMMETRIC_DECRYPT, """{"keyId":"$SW_AES","ciphertext":"$ciphertext","aad":"$aad"}""")
        )
        assertArrayEquals(plaintext, unb64(decrypted.getString("plaintext")))
    }

    @Test
    fun `software symmetric encrypt uses a fresh iv each call`() = runTest {
        val request = """{"keyId":"$SW_AES","plaintext":"$data"}"""
        val first = result(call(MethodNames.LOCAL_SYMMETRIC_ENCRYPT, request)).getString("ciphertext")
        val second = result(call(MethodNames.LOCAL_SYMMETRIC_ENCRYPT, request)).getString("ciphertext")
        assertNotEquals(first, second)
    }

    @Test
    fun `software symmetric decrypt fails on a flipped ciphertext byte`() = runTest {
        val ciphertext = result(
            call(MethodNames.LOCAL_SYMMETRIC_ENCRYPT, """{"keyId":"$SW_AES","plaintext":"$data"}""")
        ).getString("ciphertext")
        val raw = unb64(ciphertext)
        listOf(0, 12, raw.size - 1).forEach { index ->
            val flipped = raw.copyOf().also { it[index] = (it[index].toInt() xor 0x01).toByte() }
            val response = call(MethodNames.LOCAL_SYMMETRIC_DECRYPT, """{"keyId":"$SW_AES","ciphertext":"${b64(flipped)}"}""")
            assertTrue("byte $index: $response", response.has("error"))
            assertFalse(response.has("result"))
        }
    }

    @Test
    fun `software symmetric decrypt fails on a wrong or missing aad`() = runTest {
        val ciphertext = result(
            call(
                MethodNames.LOCAL_SYMMETRIC_ENCRYPT,
                """{"keyId":"$SW_AES","plaintext":"$data","aad":"${b64("context-1".toByteArray())}"}"""
            )
        ).getString("ciphertext")
        val wrong = call(
            MethodNames.LOCAL_SYMMETRIC_DECRYPT,
            """{"keyId":"$SW_AES","ciphertext":"$ciphertext","aad":"${b64("context-2".toByteArray())}"}"""
        )
        val missing = call(MethodNames.LOCAL_SYMMETRIC_DECRYPT, """{"keyId":"$SW_AES","ciphertext":"$ciphertext"}""")
        assertTrue(wrong.toString(), wrong.has("error"))
        assertTrue(missing.toString(), missing.has("error"))
    }

    @Test
    fun `software symmetric decrypt reads a ciphertext javax produced`() = runTest {
        val iv = ByteArray(12) { 9 }
        val plaintext = "made elsewhere".toByteArray()
        val ct = Cipher.getInstance("AES/GCM/NoPadding").run {
            init(Cipher.ENCRYPT_MODE, SecretKeySpec(aesMaterial, "AES"), GCMParameterSpec(128, iv))
            iv + doFinal(plaintext)
        }
        val decrypted = result(call(MethodNames.LOCAL_SYMMETRIC_DECRYPT, """{"keyId":"$SW_AES","ciphertext":"${b64(ct)}"}"""))
        assertArrayEquals(plaintext, unb64(decrypted.getString("plaintext")))
    }

    @Test
    fun `keystore symmetric encrypt and decrypt return the keystore bytes`() = runTest {
        val aad = b64("context".toByteArray())
        val encrypted = result(
            call(MethodNames.LOCAL_SYMMETRIC_ENCRYPT, """{"keyId":"$HW_AES","plaintext":"$data","aad":"$aad"}""")
        )
        assertEquals(b64(hwCiphertext), encrypted.getString("ciphertext"))
        val decrypted = result(
            call(MethodNames.LOCAL_SYMMETRIC_DECRYPT, """{"keyId":"$HW_AES","ciphertext":"${b64(hwCiphertext)}","aad":"$aad"}""")
        )
        assertEquals(b64(hwPlaintext), decrypted.getString("plaintext"))
        io.mockk.coVerify {
            keystore.symmetricEncrypt(HW_AES, match { it.contentEquals(unb64(data)) }, match { it.contentEquals(unb64(aad)) })
            keystore.symmetricDecrypt(HW_AES, match { it.contentEquals(hwCiphertext) }, match { it.contentEquals(unb64(aad)) })
        }
    }

    @Test
    fun `software hmac matches the RFC 4231 vector for each algorithm`() = runTest {
        val message = b64(RFC4231_DATA)
        mapOf(
            SW_HMAC_256 to RFC4231_SHA256,
            SW_HMAC_384 to RFC4231_SHA384,
            SW_HMAC_512 to RFC4231_SHA512
        ).forEach { (keyId, expected) ->
            val mac = result(call(MethodNames.LOCAL_HMAC, """{"keyId":"$keyId","data":"$message"}""")).getString("mac")
            assertEquals(keyId, expected, unb64(mac).joinToString("") { "%02x".format(it) })
        }
    }

    @Test
    fun `keystore hmac returns the keystore mac`() = runTest {
        val mac = result(call(MethodNames.LOCAL_HMAC, """{"keyId":"$HW_HMAC","data":"$data"}""")).getString("mac")
        assertEquals(b64(hwMac), mac)
    }

    @Test
    fun `ecdh returns the keystore shared secret`() = runTest {
        val secret = result(call(MethodNames.LOCAL_ECDH, """{"keyId":"$HW_EC","peerPublicKey":"$peerKey"}"""))
            .getString("sharedSecret")
        assertEquals(b64(sharedSecret), secret)
        io.mockk.coVerify { keystore.performECDH(HW_EC, match { it.contentEquals(unb64(peerKey)) }) }
    }

    @Test
    fun `getPublicKey answers each format`() = runTest {
        val expected = mapOf(
            ExportFormats.DER to b64(publicDer),
            ExportFormats.PEM to publicPem,
            ExportFormats.SSH to publicSsh,
            ExportFormats.COSE to b64(publicCose)
        )
        expected.forEach { (format, publicKey) ->
            val answer = result(call(MethodNames.LOCAL_GET_PUBLIC_KEY, """{"keyId":"$HW_EC","format":"$format"}"""))
            assertEquals(format, publicKey, answer.getString("publicKey"))
            assertEquals(format, answer.getString("format"))
            assertEquals("the stored key's algorithm", "ES256", answer.getString("algorithm"))
        }
        // No format: DER.
        val default = result(call(MethodNames.LOCAL_GET_PUBLIC_KEY, """{"keyId":"$HW_EC"}"""))
        assertEquals(b64(publicDer), default.getString("publicKey"))
        assertEquals(ExportFormats.DER, default.getString("format"))
    }

    @Test
    fun `getPublicKey refuses an unknown format`() = runTest {
        val response = call(MethodNames.LOCAL_GET_PUBLIC_KEY, """{"keyId":"$HW_EC","format":"jwk"}""")
        assertEquals(ErrorCodes.UNSUPPORTED_FORMAT, errorCode(response))
    }

    @Test
    fun `getPublicKey answers EXPORT_FAILED when the keystore has no public key`() = runTest {
        every { keystore.getPublicKeyDER(HW_EC) } returns null
        val response = call(MethodNames.LOCAL_GET_PUBLIC_KEY, """{"keyId":"$HW_EC","format":"der"}""")
        assertEquals(ErrorCodes.EXPORT_FAILED, errorCode(response))
    }

    @Test
    fun `decrypt returns the keystore plaintext for each OAEP result`() = runTest {
        listOf(
            "RSA-OAEP-SHA-256-MGF1-SHA-1",
            "RSA-OAEP-SHA-256-MGF1-SHA-256",
            "RSA-OAEP-SHA-1-MGF1-SHA-1"
        ).forEachIndexed { i, algorithm ->
            val plaintext = ByteArray(16 + i) { (i + 1).toByte() }
            coEvery { keystore.rsaDecryptWithAlgorithm(HW_RSA, any()) } returns DecryptResult(plaintext, algorithm)
            val ciphertext = b64(ByteArray(256) { 5 })
            val answer = result(call(MethodNames.LOCAL_DECRYPT, """{"keyId":"$HW_RSA","ciphertext":"$ciphertext"}"""))
            assertEquals(algorithm, b64(plaintext), answer.getString("plaintext"))
        }
    }

    // ---------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------

    private fun b64(bytes: ByteArray): String = Base64.getEncoder().encodeToString(bytes)

    private fun unb64(text: String): ByteArray = Base64.getDecoder().decode(text)

    private fun javaxGcmDecrypt(key: ByteArray, ivAndCiphertext: ByteArray, aad: ByteArray?): ByteArray =
        Cipher.getInstance("AES/GCM/NoPadding").run {
            init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, ivAndCiphertext.copyOfRange(0, 12)))
            aad?.let { updateAAD(it) }
            doFinal(ivAndCiphertext.copyOfRange(12, ivAndCiphertext.size))
        }

    private fun result(response: JSONObject): JSONObject {
        assertFalse(response.toString(), response.has("error"))
        return response.getJSONObject("result")
    }

    private fun errorCode(response: JSONObject): Int {
        assertTrue(response.toString(), response.has("error"))
        return response.getJSONObject("error").getInt("code")
    }

    private fun errorMessage(response: JSONObject): String =
        response.getJSONObject("error").getString("message")

    private fun algorithmOf(entry: AuditLogEntity): String? =
        entry.details?.let { JSONObject(it).optString("algorithm", "").ifEmpty { null } }

    private suspend fun <T> servedBy(peer: String, block: suspend () -> T): T =
        withContext(RequestHandler.servedConnection(binding, peer, "test:connection")) { block() }

    private fun device(name: String, requireAttestation: Boolean, lastAttested: Long?): PairedDeviceData =
        mockk(relaxed = true) {
            every { deviceName } returns name
            every { requireAttestationForKeyUse } returns requireAttestation
            every { lastAttestationTime } returns lastAttested
            every { attestationGracePeriodMinutes } returns 5
        }

    private suspend fun call(method: String, params: String): JSONObject {
        val request = """{"id":1,"method":"$method","params":$params}"""
        return JSONObject(String(handler.handleRawRequest(request.toByteArray(Charsets.UTF_8)), Charsets.UTF_8))
    }

    private companion object {
        const val SW_AES = "sw-aes"
        const val SW_HMAC_256 = "sw-hmac-256"
        const val SW_HMAC_384 = "sw-hmac-384"
        const val SW_HMAC_512 = "sw-hmac-512"
        const val HW_AES = "hw-aes"
        const val HW_HMAC = "hw-hmac"
        const val HW_EC = "hw-ec"
        const val HW_RSA = "hw-rsa"

        const val PEER_OK = "aa01"
        const val PEER_STALE = "cc03"
        const val PEER_UNREADABLE = "dd04"
        const val PEER_UNPAIRED = "ee05"

        // RFC 4231 test case 2.
        val RFC4231_KEY = "Jefe".toByteArray(Charsets.US_ASCII)
        val RFC4231_DATA = "what do ya want for nothing?".toByteArray(Charsets.US_ASCII)
        const val RFC4231_SHA256 = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        const val RFC4231_SHA384 =
            "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649"
        const val RFC4231_SHA512 =
            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"

        val binding = SessionBindingProvider {
            SessionBinding(ByteArray(32) { 3 }, ByteArray(32) { 4 }, ByteArray(0))
        }
    }
}

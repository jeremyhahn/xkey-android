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
        SW_HMAC_512 to Triple("HMAC-SHA512", "symmetric", RFC4231_KEY),
        SW_ODD_AES to Triple("AES-XTS", "symmetric", aesMaterial),
        SW_ODD_HMAC to Triple("HMAC-SHA224", "symmetric", RFC4231_KEY),
        SW_ODD_NAME to Triple("XYZ", "symmetric", aesMaterial),
        SW_SHORT_AES to Triple("AES-256-GCM", "symmetric", ByteArray(5) { 1 })
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
        // No key here is deleted or carries a stored policy.
        every { database.keyPolicyDao() } returns mockk<com.automatethethings.xkey.storage.dao.KeyPolicyDao>(relaxed = true) {
            coEvery { deletion(any()) } returns null
            coEvery { policyRow(any()) } returns null
        }
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
        // Every key here is a general key, never a credential.
        every { keystore.exportKind(any()) } returns com.automatethethings.xkey.crypto.UserKeyKind.GENERAL
        every { keystore.rowKeyKind(any(), any(), any(), any()) } returns com.automatethethings.xkey.crypto.UserKeyKind.GENERAL
        coEvery { keystore.rsaDecryptWithAlgorithm(any(), any()) } answers { throw KeyNotFoundException(firstArg()) }
        coEvery { keystore.symmetricEncrypt(any(), any(), any()) } answers { throw KeyNotFoundException(firstArg()) }
        coEvery { keystore.symmetricDecrypt(any(), any(), any()) } answers { throw KeyNotFoundException(firstArg()) }
        coEvery { keystore.computeHMACWithAlgorithm(any(), any()) } answers { throw KeyNotFoundException(firstArg()) }
        coEvery { keystore.performECDH(any(), any()) } answers { throw KeyNotFoundException(firstArg()) }
        every { keystore.getPublicKeyDER(any(), any()) } returns null
        every { keystore.getPublicKeyPEM(any(), any()) } returns null
        every { keystore.getPublicKeySSH(any(), any()) } returns null
        every { keystore.getCOSEPublicKey(any(), any()) } returns null

        coEvery { keystore.rsaDecryptWithAlgorithm(HW_RSA, any()) } returns
            DecryptResult(hwPlaintext, "RSA-OAEP-SHA-256-MGF1-SHA-1")
        coEvery { keystore.symmetricEncrypt(HW_AES, any(), any()) } returns hwCiphertext
        coEvery { keystore.symmetricDecrypt(HW_AES, any(), any()) } returns hwPlaintext
        coEvery { keystore.computeHMACWithAlgorithm(HW_HMAC, any()) } returns HmacResult(hwMac, "HMAC-SHA256")
        coEvery { keystore.performECDH(HW_EC, any()) } returns sharedSecret
        every { keystore.getPublicKeyDER(HW_EC, any()) } returns publicDer
        every { keystore.getPublicKeyPEM(HW_EC, any()) } returns publicPem
        every { keystore.getPublicKeySSH(HW_EC, any()) } returns publicSsh
        every { keystore.getCOSEPublicKey(HW_EC, any()) } returns publicCose

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
        every { keystore.getPublicKeyDER(HW_EC, any()) } returns null
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
    // Parameter errors
    // ---------------------------------------------------------------------

    @Test
    fun `an unknown key id answers KEY_NOT_FOUND for each method`() = runTest {
        allRequests().forEach { (method, params) ->
            val response = call(method, withField(params, "keyId", "no-such-key"))
            assertCleanError(method, ErrorCodes.KEY_NOT_FOUND, response)
        }
    }

    @Test
    fun `an empty key id answers KEY_NOT_FOUND for each method`() = runTest {
        allRequests().forEach { (method, params) ->
            val response = call(method, withField(params, "keyId", ""))
            assertCleanError(method, ErrorCodes.KEY_NOT_FOUND, response)
        }
    }

    @Test
    fun `a keystore key of the wrong type is refused for each method`() = runTest {
        // The Keystore holds each key under its own class: an AES key is no
        // private key and an EC key no secret key.
        listOf(
            MethodNames.LOCAL_DECRYPT to """{"keyId":"$HW_AES","ciphertext":"${b64(ByteArray(256) { 5 })}"}""",
            MethodNames.LOCAL_SYMMETRIC_ENCRYPT to """{"keyId":"$HW_EC","plaintext":"$data"}""",
            MethodNames.LOCAL_SYMMETRIC_DECRYPT to """{"keyId":"$HW_RSA","ciphertext":"${b64(hwCiphertext)}"}""",
            MethodNames.LOCAL_HMAC to """{"keyId":"$HW_AES","data":"$data"}""",
            MethodNames.LOCAL_ECDH to """{"keyId":"$HW_AES","peerPublicKey":"$peerKey"}"""
        ).forEach { (method, params) ->
            assertCleanError(method, ErrorCodes.KEY_NOT_FOUND, call(method, params))
        }
        // A secret key has no public key to export.
        val export = call(MethodNames.LOCAL_GET_PUBLIC_KEY, """{"keyId":"$HW_AES","format":"der"}""")
        assertCleanError(MethodNames.LOCAL_GET_PUBLIC_KEY, ErrorCodes.EXPORT_FAILED, export)
    }

    @Test
    fun `a software key of the wrong type is refused as a keystore key is`() = runTest {
        // An HMAC key's material is no AES key, and an AES key's no MAC key:
        // refused with the code a Keystore key of the wrong type answers.
        listOf(
            MethodNames.LOCAL_SYMMETRIC_ENCRYPT to """{"keyId":"$SW_HMAC_256","plaintext":"$data"}""",
            MethodNames.LOCAL_SYMMETRIC_DECRYPT to """{"keyId":"$SW_HMAC_256","ciphertext":"${b64(swCiphertext(unb64(data)))}"}""",
            MethodNames.LOCAL_HMAC to """{"keyId":"$SW_AES","data":"$data"}"""
        ).forEach { (method, params) ->
            assertCleanError(method, ErrorCodes.KEY_NOT_FOUND, call(method, params))
        }
        assertTrue("no key-use entry: $inserted", inserted.none { it.success && it.keyId != null })
    }

    @Test
    fun `a missing field answers INVALID_PARAMS for each method`() = runTest {
        allRequests().forEach { (method, params) ->
            JSONObject(params).keys().asSequence().toList()
                // aad is optional, and format defaults to DER.
                .filter { it != "aad" && it != "format" }
                .forEach { field ->
                    val response = call(method, JSONObject(params).apply { remove(field) }.toString())
                    assertCleanError("$method without $field", ErrorCodes.INVALID_PARAMS, response)
                }
        }
    }

    @Test
    fun `a request with no params answers INVALID_PARAMS for each method`() = runTest {
        allRequests().forEach { (method, _) ->
            val request = """{"id":1,"method":"$method"}"""
            val response = servedBy(PEER_OK) {
                JSONObject(String(handler.handleRawRequest(request.toByteArray(Charsets.UTF_8)), Charsets.UTF_8))
            }
            assertCleanError(method, ErrorCodes.INVALID_PARAMS, response)
        }
    }

    @Test
    fun `malformed base64 in each byte field answers INVALID_PARAMS before any key operation`() = runTest {
        gatedRequests().forEach { (method, params) ->
            JSONObject(params).keys().asSequence().toList()
                .filter { it != "keyId" }
                .forEach { field ->
                    val response = call(method, withField(params, field, "not*base64!"))
                    assertCleanError("$method $field", ErrorCodes.INVALID_PARAMS, response)
                    assertTrue(
                        "$method $field: the message names the field: ${errorMessage(response)}",
                        errorMessage(response).contains(field)
                    )
                }
        }
        assertNoKeyOperation()
    }

    @Test
    fun `a software key decrypt that fails answers DECRYPTION_FAILED`() = runTest {
        val good = swCiphertext(unb64(data))
        val flipped = good.copyOf().also { it[it.size - 1] = (it[it.size - 1].toInt() xor 0x01).toByte() }
        mapOf(
            "a flipped tag byte" to """{"keyId":"$SW_AES","ciphertext":"${b64(flipped)}","aad":"$data"}""",
            "a wrong aad" to """{"keyId":"$SW_AES","ciphertext":"${b64(good)}","aad":"${b64("other".toByteArray())}"}""",
            "a missing aad" to """{"keyId":"$SW_AES","ciphertext":"${b64(good)}"}""",
            "a ciphertext shorter than the iv" to """{"keyId":"$SW_AES","ciphertext":"${b64(ByteArray(5))}"}""",
            "an empty ciphertext" to """{"keyId":"$SW_AES","ciphertext":""}"""
        ).forEach { (case, params) ->
            assertCleanError(case, ErrorCodes.DECRYPTION_FAILED, call(MethodNames.LOCAL_SYMMETRIC_DECRYPT, params))
        }
    }

    @Test
    fun `a software AES key with bad material answers ENCRYPTION_FAILED`() = runTest {
        val params = """{"keyId":"$SW_SHORT_AES","plaintext":"$data"}"""
        assertCleanError("5-byte AES material", ErrorCodes.ENCRYPTION_FAILED, call(MethodNames.LOCAL_SYMMETRIC_ENCRYPT, params))
        assertTrue("no key-use entry: $inserted", inserted.none { it.success && it.keyId != null })
    }

    @Test
    fun `symmetricDecrypt refuses a payload sent as plaintext`() = runTest {
        val ciphertext = b64(swCiphertext(unb64(data)))
        listOf(SW_AES, HW_AES).forEach { keyId ->
            val response = call(MethodNames.LOCAL_SYMMETRIC_DECRYPT, """{"keyId":"$keyId","plaintext":"$ciphertext"}""")
            assertCleanError(keyId, ErrorCodes.INVALID_PARAMS, response)
            assertTrue(errorMessage(response), errorMessage(response).contains("plaintext"))
        }
        assertNoKeyOperation()
    }

    @Test
    fun `symmetricEncrypt refuses a payload sent as ciphertext`() = runTest {
        listOf(SW_AES, HW_AES).forEach { keyId ->
            val response = call(MethodNames.LOCAL_SYMMETRIC_ENCRYPT, """{"keyId":"$keyId","ciphertext":"$data"}""")
            assertCleanError(keyId, ErrorCodes.INVALID_PARAMS, response)
            assertTrue(errorMessage(response), errorMessage(response).contains("ciphertext"))
        }
        assertNoKeyOperation()
    }

    @Test
    fun `symmetric requests still take the older data field`() = runTest {
        val encrypted = result(call(MethodNames.LOCAL_SYMMETRIC_ENCRYPT, """{"keyId":"$SW_AES","data":"$data"}"""))
        val decrypted = result(
            call(MethodNames.LOCAL_SYMMETRIC_DECRYPT, """{"keyId":"$SW_AES","data":"${encrypted.getString("ciphertext")}"}""")
        )
        assertEquals(data, decrypted.getString("plaintext"))
    }

    // ---------------------------------------------------------------------
    // Attestation gate
    // ---------------------------------------------------------------------

    @Test
    fun `a paired desktop with stale attestation is refused before any key operation`() = runTest {
        allRequests().forEach { (method, params) ->
            val response = servedBy(PEER_STALE) { call(method, params) }
            assertCleanError(method, ErrorCodes.DEVICE_ATTESTATION_REQUIRED, response)
        }
        assertNoKeyOperation()
    }

    @Test
    fun `an unreadable paired-device store is refused before any key operation`() = runTest {
        allRequests().forEach { (method, params) ->
            val response = servedBy(PEER_UNREADABLE) { call(method, params) }
            assertCleanError(method, ErrorCodes.DEVICE_ATTESTATION_REQUIRED, response)
        }
        assertNoKeyOperation()
    }

    @Test
    fun `a paired desktop with current attestation is served`() = runTest {
        allRequests().forEach { (method, params) ->
            servedBy(PEER_OK) { result(call(method, params)) }
        }
    }

    @Test
    fun `an unpaired peer is refused before any key operation`() = runTest {
        allRequests().forEach { (method, params) ->
            val response = servedBy(PEER_UNPAIRED) { call(method, params) }
            assertCleanError(method, ErrorCodes.DEVICE_ATTESTATION_REQUIRED, response)
        }
        assertNoKeyOperation()
    }

    @Test
    fun `a served connection with no authenticated peer is refused before any key operation`() = runTest {
        allRequests().forEach { (method, params) ->
            val response = withContext(RequestHandler.servedConnection(binding, null, "test:anonymous")) {
                rawCall(method, params)
            }
            assertCleanError(method, ErrorCodes.DEVICE_ATTESTATION_REQUIRED, response)
        }
        assertNoKeyOperation()
    }

    @Test
    fun `a request outside any session with no connected desktop is refused before any key operation`() = runTest {
        allRequests().forEach { (method, params) ->
            assertCleanError(method, ErrorCodes.DEVICE_ATTESTATION_REQUIRED, rawCall(method, params))
        }
        assertNoKeyOperation()
    }

    // ---------------------------------------------------------------------
    // Audit entries and key material
    // ---------------------------------------------------------------------

    @Test
    fun `each keystore key use writes one entry naming the key and the desktop`() = runTest {
        gatedRequests().filter { (_, params) -> JSONObject(params).getString("keyId").startsWith("hw-") }
            .forEach { (method, params) -> assertOneKeyUseEntry(method, params) }
    }

    @Test
    fun `a software hmac writes one entry naming the key and the desktop`() = runTest {
        assertOneKeyUseEntry(MethodNames.LOCAL_HMAC, """{"keyId":"$SW_HMAC_256","data":"$data"}""")
    }

    @Test
    fun `a software symmetric encrypt and decrypt each write one entry naming the key and the desktop`() = runTest {
        gatedRequests().filter { (method, params) ->
            method != MethodNames.LOCAL_HMAC && JSONObject(params).getString("keyId") == SW_AES
        }.also { assertEquals(2, it.size) }
            .forEach { (method, params) ->
                assertOneKeyUseEntry(method, params)
                assertEquals(method, "symmetric", inserted.single { it.success && it.keyId != null }.keyType)
            }
    }

    @Test
    fun `software key material is zeroed after each AES-GCM use`() = runTest {
        val flipped = swCiphertext(unb64(data)).also { it[it.size - 1] = (it[it.size - 1].toInt() xor 0x01).toByte() }
        val requests = gatedRequests().filter { (method, params) ->
            method != MethodNames.LOCAL_HMAC && JSONObject(params).getString("keyId").startsWith("sw-")
        } + listOf(
            // A failed decrypt and a key refused for its type.
            MethodNames.LOCAL_SYMMETRIC_DECRYPT to """{"keyId":"$SW_AES","ciphertext":"${b64(flipped)}","aad":"$data"}""",
            MethodNames.LOCAL_SYMMETRIC_ENCRYPT to """{"keyId":"$SW_HMAC_256","plaintext":"$data"}"""
        )
        requests.forEach { (method, params) ->
            handedMaterial.clear()
            call(method, params)
            assertTrue("$method $params: the store handed out material", handedMaterial.isNotEmpty())
            handedMaterial.forEach { material ->
                assertTrue("$method $params: the key material is zeroed", material.all { it == 0.toByte() })
            }
        }
    }

    @Test
    fun `software key material is zeroed after each HMAC use`() = runTest {
        val requests = listOf(SW_HMAC_256, SW_HMAC_384, SW_HMAC_512).map { keyId ->
            MethodNames.LOCAL_HMAC to """{"keyId":"$keyId","data":"$data"}"""
        } + listOf(
            // A key refused for its type.
            MethodNames.LOCAL_HMAC to """{"keyId":"$SW_AES","data":"$data"}"""
        )
        requests.forEach { (method, params) ->
            handedMaterial.clear()
            call(method, params)
            assertTrue("$method $params: the store handed out material", handedMaterial.isNotEmpty())
            handedMaterial.forEach { material ->
                assertTrue("$method $params: the key material is zeroed", material.all { it == 0.toByte() })
            }
        }
    }

    @Test
    fun `a software key with an unrecognised algorithm is refused for AES and HMAC`() = runTest {
        val ciphertext = b64(swCiphertext(unb64(data)))
        fun aes(keyId: String) = listOf(
            MethodNames.LOCAL_SYMMETRIC_ENCRYPT to """{"keyId":"$keyId","plaintext":"$data"}""",
            MethodNames.LOCAL_SYMMETRIC_DECRYPT to """{"keyId":"$keyId","ciphertext":"$ciphertext"}"""
        )
        fun hmac(keyId: String) = listOf(MethodNames.LOCAL_HMAC to """{"keyId":"$keyId","data":"$data"}""")
        val requests = aes(SW_ODD_AES) + hmac(SW_ODD_HMAC) + aes(SW_ODD_NAME) + hmac(SW_ODD_NAME)
        requests.forEach { (method, params) ->
            handedMaterial.clear()
            assertCleanError("$method $params", ErrorCodes.INVALID_PARAMS, call(method, params))
            handedMaterial.forEach { material ->
                assertTrue("$method $params: the key material is zeroed", material.all { it == 0.toByte() })
            }
        }
        io.mockk.coVerify(exactly = 0) { keystore.symmetricEncrypt(any(), any(), any()) }
        io.mockk.coVerify(exactly = 0) { keystore.symmetricDecrypt(any(), any(), any()) }
        io.mockk.coVerify(exactly = 0) { keystore.computeHMACWithAlgorithm(any(), any()) }
        assertTrue("no key-use entry: $inserted", inserted.none { it.success && it.keyId != null })
    }

    @Test
    fun `getPublicKey writes one entry naming the key, the format and the desktop`() = runTest {
        listOf("der", "pem", "ssh", "cose").forEach { format ->
            assertOneKeyUseEntry(MethodNames.LOCAL_GET_PUBLIC_KEY, """{"keyId":"$HW_EC","format":"$format"}""")
            val entry = inserted.single { it.success && it.keyId != null }
            assertEquals(format, "signing", entry.keyType)
            assertTrue("$format: ${entry.details}", entry.details.orEmpty().contains(format))
        }
    }

    // ---------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------

    /** The audit operation each key-use method records. */
    private fun operationOf(method: String): AuditOperationType = when (method) {
        MethodNames.LOCAL_DECRYPT, MethodNames.LOCAL_SYMMETRIC_DECRYPT -> AuditOperationType.DECRYPTION_REQUEST
        MethodNames.LOCAL_SYMMETRIC_ENCRYPT -> AuditOperationType.ENCRYPTION_REQUEST
        MethodNames.LOCAL_HMAC -> AuditOperationType.HMAC_REQUEST
        MethodNames.LOCAL_ECDH -> AuditOperationType.KEY_DERIVATION_REQUEST
        MethodNames.LOCAL_GET_PUBLIC_KEY -> AuditOperationType.KEY_EXPORTED
        else -> error("no key-use operation for $method")
    }

    /** [method] served for desktop A succeeds and leaves exactly one success entry for its key. */
    private suspend fun assertOneKeyUseEntry(method: String, params: String) {
        inserted.clear()
        val keyId = JSONObject(params).getString("keyId")
        servedBy(PEER_OK) { result(call(method, params)) }
        val entries = inserted.filter { it.success && it.keyId != null }
        assertEquals("$method $keyId: $inserted", 1, entries.size)
        val entry = entries.single()
        assertEquals("$method $keyId", operationOf(method), entry.operationType)
        assertEquals("$method $keyId", keyId, entry.keyId)
        assertEquals("$method $keyId", PEER_OK, entry.deviceId)
        assertEquals("$method $keyId", "Desktop A", entry.deviceName)
        val details = entry.details.orEmpty()
        listOf(data, peerKey, b64(aesMaterial), b64(RFC4231_KEY)).forEach { secret ->
            assertFalse("$method $keyId: the entry carries request or key bytes", details.contains(secret))
        }
    }

    /** A Keystore-key request and, where the method has one, a software-key request per method. */
    private fun gatedRequests(): List<Pair<String, String>> = listOf(
        MethodNames.LOCAL_DECRYPT to """{"keyId":"$HW_RSA","ciphertext":"${b64(ByteArray(256) { 5 })}"}""",
        MethodNames.LOCAL_SYMMETRIC_ENCRYPT to """{"keyId":"$HW_AES","plaintext":"$data","aad":"$data"}""",
        MethodNames.LOCAL_SYMMETRIC_ENCRYPT to """{"keyId":"$SW_AES","plaintext":"$data","aad":"$data"}""",
        MethodNames.LOCAL_SYMMETRIC_DECRYPT to """{"keyId":"$HW_AES","ciphertext":"${b64(hwCiphertext)}","aad":"$data"}""",
        MethodNames.LOCAL_SYMMETRIC_DECRYPT to """{"keyId":"$SW_AES","ciphertext":"${b64(swCiphertext(unb64(data)))}","aad":"$data"}""",
        MethodNames.LOCAL_HMAC to """{"keyId":"$HW_HMAC","data":"$data"}""",
        MethodNames.LOCAL_HMAC to """{"keyId":"$SW_HMAC_256","data":"$data"}""",
        MethodNames.LOCAL_ECDH to """{"keyId":"$HW_EC","peerPublicKey":"$peerKey"}"""
    )

    /** [gatedRequests] and local.getPublicKey. */
    private fun allRequests(): List<Pair<String, String>> =
        gatedRequests() + (MethodNames.LOCAL_GET_PUBLIC_KEY to """{"keyId":"$HW_EC","format":"der"}""")

    /** A software-key ciphertext of [plaintext] under [aesMaterial], bound to `data` as AAD. */
    private fun swCiphertext(plaintext: ByteArray): ByteArray {
        val iv = ByteArray(12) { 1 }
        return Cipher.getInstance("AES/GCM/NoPadding").run {
            init(Cipher.ENCRYPT_MODE, SecretKeySpec(aesMaterial, "AES"), GCMParameterSpec(128, iv))
            updateAAD(unb64(data))
            iv + doFinal(plaintext)
        }
    }

    private fun withField(params: String, field: String, value: String): String =
        JSONObject(params).apply { put(field, value) }.toString()

    /** [response] is an error with [code], and its message carries no exception text. */
    private fun assertCleanError(what: String, code: Int, response: JSONObject) {
        assertEquals("$what: $response", code, errorCode(response))
        val message = errorMessage(response)
        listOf("Internal error", "Exception", "Illegal", "javax.", "java.").forEach { text ->
            assertFalse("$what: the message carries exception text: $message", message.contains(text))
        }
    }

    /** No Keystore or software key was touched and no key use was audited. */
    private fun assertNoKeyOperation() {
        io.mockk.coVerify(exactly = 0) { keystore.rsaDecryptWithAlgorithm(any(), any()) }
        io.mockk.coVerify(exactly = 0) { keystore.symmetricEncrypt(any(), any(), any()) }
        io.mockk.coVerify(exactly = 0) { keystore.symmetricDecrypt(any(), any(), any()) }
        io.mockk.coVerify(exactly = 0) { keystore.computeHMACWithAlgorithm(any(), any()) }
        io.mockk.coVerify(exactly = 0) { keystore.performECDH(any(), any()) }
        io.mockk.coVerify(exactly = 0) { keystore.getPublicKeyDER(any(), any()) }
        io.mockk.verify(exactly = 0) { anyConstructed<SoftwareKeyStore>().get(any()) }
        assertTrue("no key-use entry: $inserted", inserted.none { it.success && it.keyId != null })
    }

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

    /** Whether a [servedBy] block is running, so [call] keeps its peer. */
    private var served = false

    private suspend fun <T> servedBy(peer: String, block: suspend () -> T): T =
        withContext(RequestHandler.servedConnection(binding, peer, "test:connection")) {
            val outer = served
            served = true
            try {
                block()
            } finally {
                served = outer
            }
        }

    private fun device(name: String, requireAttestation: Boolean, lastAttested: Long?): PairedDeviceData =
        mockk(relaxed = true) {
            every { deviceName } returns name
            every { requireAttestationForKeyUse } returns requireAttestation
            every { lastAttestationTime } returns lastAttested
            every { attestationGracePeriodMinutes } returns 5
        }

    /** Sends [method] from the paired [PEER_OK] unless a [servedBy] block names another peer. */
    private suspend fun call(method: String, params: String): JSONObject =
        if (served) rawCall(method, params) else servedBy(PEER_OK) { rawCall(method, params) }

    /** Sends [method] with no session, as a caller outside any desktop connection. */
    private suspend fun rawCall(method: String, params: String): JSONObject {
        val request = """{"id":1,"method":"$method","params":$params}"""
        return JSONObject(String(handler.handleRawRequest(request.toByteArray(Charsets.UTF_8)), Charsets.UTF_8))
    }

    private companion object {
        const val SW_AES = "sw-aes"
        const val SW_HMAC_256 = "sw-hmac-256"
        const val SW_HMAC_384 = "sw-hmac-384"
        const val SW_HMAC_512 = "sw-hmac-512"
        const val SW_ODD_AES = "sw-odd-aes"
        const val SW_ODD_HMAC = "sw-odd-hmac"
        const val SW_ODD_NAME = "sw-odd-name"
        const val SW_SHORT_AES = "sw-short-aes"
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

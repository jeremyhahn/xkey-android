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
import com.automatethethings.xkey.crypto.HmacResult
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.crypto.SoftwareKey
import com.automatethethings.xkey.crypto.SoftwareKeyStore
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
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * `local.hmac` and `local.ecdh` use a key, so each success leaves one audit
 * entry (HMAC_REQUEST / KEY_DERIVATION_REQUEST) naming the key, and no entry
 * carries the MAC, the shared secret, the input data or the peer key.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class HmacEcdhAuditTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private lateinit var handler: RequestHandler
    private lateinit var keystore: KeystoreManager
    private val inserted = mutableListOf<AuditLogEntity>()

    private val data = Base64.getEncoder().encodeToString("payload-to-mac".toByteArray())
    private val peerKey = Base64.getEncoder().encodeToString(ByteArray(91) { (it + 7).toByte() })
    private val keystoreMac = ByteArray(32) { 0x11 }
    private val sharedSecret = ByteArray(32) { 0x22 }
    private val swMaterial = ByteArray(32) { 0x33 }

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

        // Stored key types: ECDH runs on an EC key stored as signing, and the
        // Keystore HMAC key is stored as "secret"; neither matches the
        // operation, so a hardcoded keyType shows up as a mismatch.
        val keyDao = mockk<KeyDao>(relaxed = true)
        coEvery { keyDao.getByKeyId(any()) } returns null
        coEvery { keyDao.getByKeyId("hw-ecdh") } returns
            KeyEntity(keyId = "hw-ecdh", keyType = "signing", algorithm = "ES256", label = "ecdh", keySizeBits = 256, source = "local")
        coEvery { keyDao.getByKeyId("hw-hmac") } returns
            // The row says SHA-512; the Keystore key runs SHA-256 (below).
            KeyEntity(keyId = "hw-hmac", keyType = "secret", algorithm = "HMAC-SHA512", label = "hmac", keySizeBits = 256, source = "local")
        val database = mockk<XKeyDatabase>(relaxed = true)
        every { database.keyDao() } returns keyDao
        mockkObject(XKeyDatabase.Companion)
        every { XKeyDatabase.getInstance(any()) } returns database

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
        every { anyConstructed<SoftwareKeyStore>().get(any()) } returns null
        every { anyConstructed<SoftwareKeyStore>().get("sw-hmac") } returns SoftwareKey(
            keyId = "sw-hmac",
            algorithm = "HMAC-SHA256",
            keyType = "symmetric",
            keySize = 256,
            exportable = true,
            shareable = true,
            material = swMaterial
        )
        // Unvalidated stored name: SoftwareKeyOps runs SHA-256 for it.
        every { anyConstructed<SoftwareKeyStore>().get("sw-odd") } returns SoftwareKey(
            keyId = "sw-odd",
            algorithm = "HMAC-SHA384",
            keyType = "symmetric",
            keySize = 256,
            exportable = true,
            shareable = true,
            material = swMaterial
        )

        val context = mockk<Context>(relaxed = true)
        every { context.filesDir } returns tmp.root
        every { context.applicationContext } returns context
        every { context.getSystemService(Context.KEYGUARD_SERVICE) } returns
            mockk<KeyguardManager>(relaxed = true)
        every { context.getSystemService(NotificationManager::class.java) } returns
            mockk<NotificationManager>(relaxed = true)

        // Two paired desktops; neither requires attestation for key use.
        val pairedDevices = mockk<PairedDeviceRepository>()
        every { pairedDevices.getDevice(any()) } returns null
        every { pairedDevices.getDevice(PEER_A) } returns device("Desktop A")
        every { pairedDevices.getDevice(PEER_B) } returns device("Desktop B")

        keystore = mockk(relaxed = true)
        coEvery { keystore.computeHMAC("hw-hmac", any()) } returns keystoreMac
        coEvery { keystore.computeHMACWithAlgorithm("hw-hmac", any()) } returns
            HmacResult(keystoreMac, "HMAC-SHA256")
        coEvery { keystore.performECDH("hw-ecdh", any()) } returns sharedSecret

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

    @Test
    fun `hmac on a keystore key writes one HMAC_REQUEST naming the key`() = runTest {
        val response = call(MethodNames.LOCAL_HMAC, """{"keyId":"hw-hmac","data":"$data"}""")

        assertFalse(response.toString(), response.has("error"))
        val entries = inserted.filter { it.operationType == AuditOperationType.HMAC_REQUEST }
        assertEquals(1, entries.size)
        assertEquals("hw-hmac", entries[0].keyId)
        assertEquals("the key's stored type", "secret", entries[0].keyType)
        assertEquals("the algorithm the Keystore ran, not the row's", "HMAC-SHA256", algorithmOf(entries[0]))
        assertTrue(entries[0].success)
        assertNoSecrets(response.getJSONObject("result").getString("mac"))
    }

    @Test
    fun `hmac on a software key writes one HMAC_REQUEST naming the key`() = runTest {
        val response = call(MethodNames.LOCAL_HMAC, """{"keyId":"sw-hmac","data":"$data"}""")

        assertFalse(response.toString(), response.has("error"))
        val entries = inserted.filter { it.operationType == AuditOperationType.HMAC_REQUEST }
        assertEquals(1, entries.size)
        assertEquals("sw-hmac", entries[0].keyId)
        assertEquals("the software key's stored type", "symmetric", entries[0].keyType)
        assertTrue(entries[0].success)
        assertNoSecrets(response.getJSONObject("result").getString("mac"))
    }

    @Test
    fun `ecdh writes one KEY_DERIVATION_REQUEST naming the key`() = runTest {
        val response = call(
            MethodNames.LOCAL_ECDH,
            """{"keyId":"hw-ecdh","peerPublicKey":"$peerKey"}"""
        )

        assertFalse(response.toString(), response.has("error"))
        val entries = inserted.filter {
            it.operationType == AuditOperationType.KEY_DERIVATION_REQUEST
        }
        assertEquals(1, entries.size)
        assertEquals("hw-ecdh", entries[0].keyId)
        assertEquals("ECDH on a signing key is filed under signing", "signing", entries[0].keyType)
        assertEquals("ECDH", algorithmOf(entries[0]))
        assertTrue(entries[0].success)
        assertNoSecrets(response.getJSONObject("result").getString("sharedSecret"))
    }

    @Test
    fun `software hmac records the algorithm that ran, not the stored name`() = runTest {
        val response = call(MethodNames.LOCAL_HMAC, """{"keyId":"sw-odd","data":"$data"}""")

        assertFalse(response.toString(), response.has("error"))
        val expected = javax.crypto.Mac.getInstance("HmacSHA256").run {
            init(javax.crypto.spec.SecretKeySpec(swMaterial, "HmacSHA256"))
            doFinal(Base64.getDecoder().decode(data))
        }
        assertEquals(
            "the MAC is HMAC-SHA256",
            Base64.getEncoder().encodeToString(expected),
            response.getJSONObject("result").getString("mac")
        )
        val entry = inserted.single { it.operationType == AuditOperationType.HMAC_REQUEST }
        assertEquals("HMAC-SHA256", algorithmOf(entry))
    }

    @Test
    fun `rsa decrypt records the OAEP SHA-256 it runs`() = runTest {
        val ct = Base64.getEncoder().encodeToString(ByteArray(256) { 5 })
        coEvery { keystore.rsaDecrypt("hw-ecdh", any()) } returns ByteArray(16) { 6 }
        val response = call(MethodNames.LOCAL_DECRYPT, """{"keyId":"hw-ecdh","ciphertext":"$ct"}""")

        assertFalse(response.toString(), response.has("error"))
        val entry = inserted.single { it.operationType == AuditOperationType.DECRYPTION_REQUEST }
        assertEquals("RSA-OAEP-256", algorithmOf(entry))
    }

    @Test
    fun `a key with no stored metadata is recorded as unknown`() = runTest {
        coEvery { keystore.performECDH("hw-bare", any()) } returns sharedSecret
        val response = call(
            MethodNames.LOCAL_ECDH,
            """{"keyId":"hw-bare","peerPublicKey":"$peerKey"}"""
        )

        assertFalse(response.toString(), response.has("error"))
        val entry = inserted.single { it.operationType == AuditOperationType.KEY_DERIVATION_REQUEST }
        assertEquals("unknown", entry.keyType)
    }

    @Test
    fun `missing params write no success entry`() = runTest {
        val hmac = call(MethodNames.LOCAL_HMAC, """{"keyId":"hw-hmac"}""")
        val ecdh = call(MethodNames.LOCAL_ECDH, """{"keyId":"hw-ecdh"}""")

        assertTrue(hmac.has("error"))
        assertTrue(ecdh.has("error"))
        assertTrue(
            "no success entry for a refused request",
            inserted.none {
                it.success && (
                    it.operationType == AuditOperationType.HMAC_REQUEST ||
                        it.operationType == AuditOperationType.KEY_DERIVATION_REQUEST
                    )
            }
        )
    }

    @Test
    fun `entries name the caller of the session, not the transport connected last`() = runTest {
        // Desktop A is served over BLE; desktop B then confirms over USB, which
        // installs B as the handler-wide connected device.
        handler.setConnectedDevicePublicKeyHex(PEER_B)

        servedBy(PEER_A) {
            call(MethodNames.LOCAL_HMAC, """{"keyId":"hw-hmac","data":"$data"}""")
            call(MethodNames.LOCAL_ECDH, """{"keyId":"hw-ecdh","peerPublicKey":"$peerKey"}""")
        }

        // Another transport disconnects, clearing the handler-wide device.
        handler.setSessionId(null)
        servedBy(PEER_A) {
            call(MethodNames.LOCAL_HMAC, """{"keyId":"sw-hmac","data":"$data"}""")
        }

        val entries = inserted.filter {
            it.operationType == AuditOperationType.HMAC_REQUEST ||
                it.operationType == AuditOperationType.KEY_DERIVATION_REQUEST
        }
        assertEquals(3, entries.size)
        entries.forEach { entry ->
            assertEquals("${entry.operationType} ${entry.keyId}", PEER_A, entry.deviceId)
            assertEquals("${entry.operationType} ${entry.keyId}", "Desktop A", entry.deviceName)
        }
    }

    private fun algorithmOf(entry: AuditLogEntity): String? =
        entry.details?.let { JSONObject(it).optString("algorithm", "").ifEmpty { null } }

    private suspend fun <T> servedBy(peer: String, block: suspend () -> T): T =
        withContext(RequestHandler.servedConnection(binding, peer)) { block() }

    private fun device(name: String): PairedDeviceData = mockk(relaxed = true) {
        every { deviceName } returns name
        every { requireAttestationForKeyUse } returns false
    }

    /** No audit field may carry the output, the input data or the peer key. */
    private fun assertNoSecrets(output: String) {
        val forbidden = listOf(
            output,
            Base64.getEncoder().encodeToString(keystoreMac),
            Base64.getEncoder().encodeToString(sharedSecret),
            Base64.getEncoder().encodeToString(swMaterial),
            data,
            peerKey
        )
        inserted.forEach { entry ->
            val fields = listOfNotNull(
                entry.details, entry.errorMessage, entry.keyLabel, entry.deviceName
            )
            forbidden.forEach { secret ->
                fields.forEach { field ->
                    assertFalse("audit entry leaks secret material: $field", field.contains(secret))
                }
            }
        }
    }

    private suspend fun call(method: String, params: String): JSONObject {
        val request = """{"id":1,"method":"$method","params":$params}"""
        return JSONObject(String(handler.handleRawRequest(request.toByteArray(Charsets.UTF_8)), Charsets.UTF_8))
    }

    private companion object {
        const val PEER_A = "aa01"
        const val PEER_B = "bb02"
        val binding = SessionBindingProvider {
            SessionBinding(ByteArray(32) { 3 }, ByteArray(32) { 4 }, ByteArray(0))
        }
    }
}

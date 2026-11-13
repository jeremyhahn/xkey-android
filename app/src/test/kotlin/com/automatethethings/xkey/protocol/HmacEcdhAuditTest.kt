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
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.crypto.SoftwareKey
import com.automatethethings.xkey.crypto.SoftwareKeyStore
import com.automatethethings.xkey.storage.XKeyDatabase
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import java.util.Base64
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.CoroutineScope
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

        val database = mockk<XKeyDatabase>(relaxed = true)
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

        val context = mockk<Context>(relaxed = true)
        every { context.filesDir } returns tmp.root
        every { context.applicationContext } returns context
        every { context.getSystemService(Context.KEYGUARD_SERVICE) } returns
            mockk<KeyguardManager>(relaxed = true)
        every { context.getSystemService(NotificationManager::class.java) } returns
            mockk<NotificationManager>(relaxed = true)

        keystore = mockk(relaxed = true)
        coEvery { keystore.computeHMAC("hw-hmac", any()) } returns keystoreMac
        coEvery { keystore.performECDH("hw-ecdh", any()) } returns sharedSecret

        handler = RequestHandler(
            context = context,
            keystoreManager = keystore,
            biometricLauncher = null,
            sessionAuthManager = null,
            pairedDeviceRepository = null,
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

        assertFalse(response.has("error"))
        val entries = inserted.filter { it.operationType == AuditOperationType.HMAC_REQUEST }
        assertEquals(1, entries.size)
        assertEquals("hw-hmac", entries[0].keyId)
        assertTrue(entries[0].success)
        assertNoSecrets(response.getJSONObject("result").getString("mac"))
    }

    @Test
    fun `hmac on a software key writes one HMAC_REQUEST naming the key`() = runTest {
        val response = call(MethodNames.LOCAL_HMAC, """{"keyId":"sw-hmac","data":"$data"}""")

        assertFalse(response.has("error"))
        val entries = inserted.filter { it.operationType == AuditOperationType.HMAC_REQUEST }
        assertEquals(1, entries.size)
        assertEquals("sw-hmac", entries[0].keyId)
        assertTrue(entries[0].success)
        assertNoSecrets(response.getJSONObject("result").getString("mac"))
    }

    @Test
    fun `ecdh writes one KEY_DERIVATION_REQUEST naming the key`() = runTest {
        val response = call(
            MethodNames.LOCAL_ECDH,
            """{"keyId":"hw-ecdh","peerPublicKey":"$peerKey"}"""
        )

        assertFalse(response.has("error"))
        val entries = inserted.filter {
            it.operationType == AuditOperationType.KEY_DERIVATION_REQUEST
        }
        assertEquals(1, entries.size)
        assertEquals("hw-ecdh", entries[0].keyId)
        assertTrue(entries[0].success)
        assertNoSecrets(response.getJSONObject("result").getString("sharedSecret"))
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
}

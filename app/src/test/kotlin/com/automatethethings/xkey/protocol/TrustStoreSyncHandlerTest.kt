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
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.crypto.SyncCodec
import com.automatethethings.xkey.settings.DeviceLookup
import com.automatethethings.xkey.settings.PairedDeviceData
import com.automatethethings.xkey.settings.PairedDeviceRepository
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.sync.SyncEngine
import com.automatethethings.xkey.truststore.TestCertificates
import com.automatethethings.xkey.truststore.TrustStoreRepository
import com.automatethethings.xkey.truststore.VerificationResult
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import java.io.File
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.json.JSONArray
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * The inbound `local.syncTrustStore` handler against a real trust store: a
 * synced CA never anchors endorsement verification, each certificate merges
 * on its own, and every sync records one audit entry with counts and the
 * desktop that asked, never a certificate body.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class TrustStoreSyncHandlerTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    private lateinit var handler: RequestHandler
    private lateinit var context: Context
    private lateinit var storeDir: File
    private val audited = mutableListOf<AuditLogEntity>()

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

        // Only the sync time is stubbed: the certificate merge and gather run for real.
        mockkConstructor(SyncEngine::class)
        coEvery { anyConstructed<SyncEngine>().markSynced() } returns Unit

        Dispatchers.setMain(UnconfinedTestDispatcher())

        storeDir = tempFolder.newFolder("trust_store")
        context = mockk<Context>(relaxed = true)
        every { context.getDir("trust_store", Context.MODE_PRIVATE) } returns storeDir
        every { context.getSystemService(Context.KEYGUARD_SERVICE) } returns
            mockk<KeyguardManager>(relaxed = true)
        every { context.getSystemService(NotificationManager::class.java) } returns
            mockk<NotificationManager>(relaxed = true)

        val desk = mockk<PairedDeviceData>()
        every { desk.deviceName } returns DESK_NAME
        val pairedDevices = mockk<PairedDeviceRepository>(relaxed = true)
        every { pairedDevices.lookupDevice(any()) } returns DeviceLookup.NotPaired
        every { pairedDevices.lookupDevice(DESK_PEER) } returns DeviceLookup.Paired(desk)

        handler = RequestHandler(
            context = context,
            keystoreManager = mockk<KeystoreManager>(relaxed = true),
            biometricLauncher = mockk(relaxed = true),
            sessionAuthManager = null,
            pairedDeviceRepository = pairedDevices
        )
        handler.setConnectedDevicePublicKeyHex(DESK_PEER)
    }

    @After
    fun tearDown() {
        auditHolder<AuditLogDao>("daoRef").set(null)
        auditHolder<CoroutineScope>("scopeRef").set(null)
        Dispatchers.resetMain()
        unmockkAll()
    }

    @Suppress("UNCHECKED_CAST")
    private fun <T> auditHolder(name: String): AtomicReference<T?> =
        AuditLogger::class.java.getDeclaredField(name)
            .apply { isAccessible = true }
            .get(AuditLogger) as AtomicReference<T?>

    private fun captureAudit() {
        audited.clear()
        val dao = mockk<AuditLogDao>(relaxed = true)
        coEvery { dao.insert(any()) } answers {
            audited += firstArg<AuditLogEntity>()
            audited.size.toLong()
        }
        auditHolder<AuditLogDao>("daoRef").set(dao)
        auditHolder<CoroutineScope>("scopeRef").set(CoroutineScope(Dispatchers.Unconfined))
    }

    private fun syncEntries() = audited.filter { it.operationType.name == "TRUST_STORE_SYNC_PERFORMED" }

    private fun synced(pem: String) = JSONObject()
        .put("fingerprint", TestCertificates.fingerprint(pem))
        .put("pem", pem)

    private suspend fun call(vararg certificates: JSONObject): Response {
        val params = JSONObject().put("certificates", JSONArray().apply { certificates.forEach { put(it) } })
        val request = Request(id = 7, method = MethodNames.LOCAL_SYNC_TRUST_STORE, params = params)
        return Response.fromJson(handler.handleRawRequest(request.toJson()))
    }

    @Test
    fun `a CA merged through local syncTrustStore does not anchor a leaf it signed`() = runTest {
        val response = call(synced(TestCertificates.INTERMEDIATE_A_PEM))

        assertNull(response.error)
        assertEquals(1, response.result!!.getInt("added"))
        val result = TrustStoreRepository(context).verifyIDevIDChain(
            listOf(TestCertificates.der(TestCertificates.LEAF_VIA_INTERMEDIATE_PEM))
        )
        assertFalse("a synced CA must not anchor, got $result", result is VerificationResult.Valid)
    }

    @Test
    fun `a self-signed root and an unparsable entry are skipped and the sync succeeds`() = runTest {
        val garbage = JSONObject().put("pem", SyncCodec.derToPem(byteArrayOf(0x30, 0x03, 0x01, 0x02, 0x03)))

        val response = call(
            synced(TestCertificates.INTERMEDIATE_A_PEM),
            synced(TestCertificates.ROOT_CA_A_PEM),
            garbage,
            synced(TestCertificates.LEAF_B_PEM)
        )

        assertNull(response.error)
        val result = response.result!!
        assertEquals(2, result.getInt("added"))
        assertEquals(2, result.getInt("skipped"))
        assertEquals(2, result.getJSONArray("remote").length())
    }

    @Test
    fun `each local syncTrustStore records one entry with counts and the desktop`() = runTest {
        captureAudit()

        call(synced(TestCertificates.INTERMEDIATE_A_PEM), synced(TestCertificates.ROOT_CA_A_PEM))

        val entry = syncEntries().single()
        assertEquals(true, entry.success)
        assertEquals(DESK_PEER, entry.deviceId)
        assertEquals(DESK_NAME, entry.deviceName)
        val details = JSONObject(entry.details!!)
        assertEquals("inbound", details.getString("direction"))
        assertEquals(1, details.getInt("added"))
        assertEquals(1, details.getInt("skipped"))
        assertFalse("no certificate body in the entry", entry.details!!.contains("BEGIN CERTIFICATE"))
    }

    private companion object {
        const val DESK_PEER = "aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11"
        const val DESK_NAME = "desk.example.com"
    }
}

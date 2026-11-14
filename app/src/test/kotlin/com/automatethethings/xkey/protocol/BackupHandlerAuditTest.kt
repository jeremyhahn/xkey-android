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
import com.automatethethings.xkey.settings.PairedDeviceData
import com.automatethethings.xkey.settings.DeviceLookup
import com.automatethethings.xkey.settings.PairedDeviceRepository
import com.automatethethings.xkey.storage.XKeyDatabase
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import java.util.Base64
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.withContext
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
 * `local.createBackup` and `local.restoreBackup` each record one audit entry
 * on success (BACKUP_CREATED / BACKUP_RESTORED) naming the backup id, its size
 * and the requesting device, never the backup bytes. Failed calls record no
 * success entry.
 *
 * The [AuditLogger] singleton's private `daoRef`/`scopeRef` holders are
 * injected with a capturing DAO and an unconfined scope, as in
 * AuditLoggerDispatchTest, so every write is visible synchronously.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class BackupHandlerAuditTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private lateinit var handler: RequestHandler
    private lateinit var repository: PairedDeviceRepository
    private val inserted = mutableListOf<AuditLogEntity>()

    private val deviceKeyHex = "a1b2c3d4"
    private val deviceName = "Build Laptop"

    // 32 bytes whose base64 is long enough to be unmistakable in details.
    private val payload = ByteArray(32) { (it * 7 + 3).toByte() }
    private val payloadB64 = Base64.getEncoder().encodeToString(payload)

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

        val context = mockk<Context>(relaxed = true)
        every { context.filesDir } returns tmp.root
        every { context.applicationContext } returns context
        every { context.getSystemService(Context.KEYGUARD_SERVICE) } returns
            mockk<KeyguardManager>(relaxed = true)
        every { context.getSystemService(NotificationManager::class.java) } returns
            mockk<NotificationManager>(relaxed = true)

        val device = mockk<PairedDeviceData>(relaxed = true)
        every { device.deviceName } returns deviceName
        repository = mockk(relaxed = true)
        every { repository.lookupDevice(any()) } returns DeviceLookup.NotPaired
        every { repository.lookupDevice(deviceKeyHex) } returns DeviceLookup.Paired(device)

        handler = RequestHandler(
            context = context,
            keystoreManager = mockk<KeystoreManager>(relaxed = true),
            biometricLauncher = null,
            sessionAuthManager = null,
            pairedDeviceRepository = repository,
            pinManager = mockk(relaxed = true)
        )
        handler.setConnectedDevicePublicKeyHex(deviceKeyHex)
    }

    @After
    fun tearDown() {
        holder<AuditLogDao>("daoRef").set(null)
        holder<CoroutineScope>("scopeRef").set(null)
        Dispatchers.resetMain()
        unmockkAll()
    }

    // -----------------------------------------------------------------
    // local.createBackup
    // -----------------------------------------------------------------

    @Test
    fun `createBackup records one BACKUP_CREATED entry with the id and size`() = runTest {
        val response = call(
            MethodNames.LOCAL_CREATE_BACKUP,
            """{"backup_data":"$payloadB64","label":"nightly"}"""
        )
        val id = response.getJSONObject("result").getString("backup_id")

        val entries = entriesOf(AuditOperationType.BACKUP_CREATED)
        assertEquals(1, entries.size)
        val entry = entries[0]
        assertTrue(entry.success)
        assertEquals(deviceKeyHex, entry.deviceId)
        assertEquals(deviceName, entry.deviceName)
        val details = JSONObject(entry.details!!)
        assertEquals(id, details.getString("backupId"))
        assertEquals(payload.size, details.getInt("sizeBytes"))
        assertNoPayload()
    }

    @Test
    fun `createBackup without backup_data records no success entry`() = runTest {
        val response = call(MethodNames.LOCAL_CREATE_BACKUP, """{"label":"nightly"}""")
        assertTrue(response.has("error"))
        assertTrue(entriesOf(AuditOperationType.BACKUP_CREATED).isEmpty())
    }

    @Test
    fun `createBackup with invalid base64 records no success entry`() = runTest {
        val response = call(MethodNames.LOCAL_CREATE_BACKUP, """{"backup_data":"not base64!"}""")
        assertTrue(response.has("error"))
        assertTrue(entriesOf(AuditOperationType.BACKUP_CREATED).isEmpty())
    }

    // -----------------------------------------------------------------
    // local.restoreBackup
    // -----------------------------------------------------------------

    @Test
    fun `restoreBackup of the latest backup records one BACKUP_RESTORED entry`() = runTest {
        val id = createBackup()

        val response = call(MethodNames.LOCAL_RESTORE_BACKUP, "{}")
        assertEquals(id, response.getJSONObject("result").getString("backup_id"))

        assertRestored(id)
    }

    @Test
    fun `restoreBackup by id records one BACKUP_RESTORED entry`() = runTest {
        val first = createBackup()
        createBackup()

        val response = call(MethodNames.LOCAL_RESTORE_BACKUP, """{"backup_id":"$first"}""")
        assertEquals(first, response.getJSONObject("result").getString("backup_id"))

        assertRestored(first)
    }

    @Test
    fun `restoreBackup of an unknown id records no success entry`() = runTest {
        createBackup()

        val response = call(MethodNames.LOCAL_RESTORE_BACKUP, """{"backup_id":"backup-0-0"}""")
        assertTrue(response.has("error"))
        assertTrue(entriesOf(AuditOperationType.BACKUP_RESTORED).isEmpty())
    }

    @Test
    fun `restoreBackup with no backup stored records no success entry`() = runTest {
        val response = call(MethodNames.LOCAL_RESTORE_BACKUP, "{}")
        assertTrue(response.has("error"))
        assertTrue(entriesOf(AuditOperationType.BACKUP_RESTORED).isEmpty())
    }

    // -----------------------------------------------------------------
    // Requesting peer
    // -----------------------------------------------------------------

    /**
     * Desktop A is served over BLE while desktop B connects last over USB, so
     * the handler-wide connected key names B. A's backup calls -- served over
     * its BLE connection and over a session the phone opened to A -- must be
     * logged under A, the peer of the connection each request arrived on.
     */
    @Test
    fun `backup entries name the desktop whose connection the request arrived on`() = runTest {
        val keyA = "aa11aa11"
        val keyB = "bb22bb22"
        val deviceA = mockk<PairedDeviceData>(relaxed = true)
        every { deviceA.deviceName } returns "Desktop A"
        val deviceB = mockk<PairedDeviceData>(relaxed = true)
        every { deviceB.deviceName } returns "Desktop B"
        every { repository.lookupDevice(keyA) } returns DeviceLookup.Paired(deviceA)
        every { repository.lookupDevice(keyB) } returns DeviceLookup.Paired(deviceB)

        val bleA = mockk<SessionBindingProvider>(relaxed = true)
        // B (USB) is the connection made last.
        handler.setConnectedDevicePublicKeyHex(keyB)

        val id = withContext(RequestHandler.servedConnection(bleA, keyA, "ble-a")) {
            val created = call(MethodNames.LOCAL_CREATE_BACKUP, """{"backup_data":"$payloadB64"}""")
            val backupId = created.getJSONObject("result").getString("backup_id")
            call(MethodNames.LOCAL_RESTORE_BACKUP, """{"backup_id":"$backupId"}""")
            backupId
        }

        // A phone-initiated session to A.
        val request = """{"id":2,"method":"${MethodNames.LOCAL_RESTORE_BACKUP}","params":{"backup_id":"$id"}}"""
        val raw = handler.handleRawRequest(request.toByteArray(Charsets.UTF_8), bleA, keyA)
        assertFalse(JSONObject(String(raw, Charsets.UTF_8)).has("error"))

        val entries = entriesOf(AuditOperationType.BACKUP_CREATED) +
            entriesOf(AuditOperationType.BACKUP_RESTORED)
        assertEquals(3, entries.size)
        for (entry in entries) {
            assertEquals(keyA, entry.deviceId)
            assertEquals("Desktop A", entry.deviceName)
        }
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    private fun assertRestored(id: String) {
        val entries = entriesOf(AuditOperationType.BACKUP_RESTORED)
        assertEquals(1, entries.size)
        val entry = entries[0]
        assertTrue(entry.success)
        assertEquals(deviceKeyHex, entry.deviceId)
        assertEquals(deviceName, entry.deviceName)
        val details = JSONObject(entry.details!!)
        assertEquals(id, details.getString("backupId"))
        assertEquals(payload.size, details.getInt("sizeBytes"))
        assertNoPayload()
    }

    /** No entry may carry the backup bytes, as base64 or as raw text. */
    private fun assertNoPayload() {
        val raw = String(payload, Charsets.ISO_8859_1)
        for (entry in inserted) {
            val text = listOfNotNull(entry.details, entry.errorMessage, entry.keyLabel).joinToString("\n")
            assertFalse("entry holds the backup base64", text.contains(payloadB64))
            assertFalse("entry holds the backup bytes", text.contains(raw))
        }
    }

    private fun entriesOf(type: AuditOperationType) = inserted.filter { it.operationType == type }

    private suspend fun createBackup(): String {
        val response = call(MethodNames.LOCAL_CREATE_BACKUP, """{"backup_data":"$payloadB64"}""")
        return response.getJSONObject("result").getString("backup_id")
    }

    private suspend fun call(method: String, params: String): JSONObject {
        val request = """{"id":1,"method":"$method","params":$params}"""
        return JSONObject(String(handler.handleRawRequest(request.toByteArray(Charsets.UTF_8)), Charsets.UTF_8))
    }
}

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
package com.automatethethings.xkey.usb

import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import com.automatethethings.xkey.audit.AuditLogDao
import com.automatethethings.xkey.audit.AuditLogEntity
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.audit.AuditOperationType
import io.mockk.coEvery
import io.mockk.mockk
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.util.concurrent.atomic.AtomicReference

/**
 * Switching the loopback TCP pairing server or native USB accessory mode
 * opens a path to the pairing responder, so every change of either toggle
 * leaves a `SETTINGS_CHANGED` audit entry. Writing the value already stored
 * changes nothing and records nothing.
 *
 * The repository runs on a real file-backed Preferences DataStore; the
 * [AuditLogger] singleton gets a mock DAO and an unconfined scope, as in
 * `AuditLoggerDispatchTest`, so entries are captured synchronously.
 */
class UsbHsmSettingsAuditTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private val inserted = mutableListOf<AuditLogEntity>()
    private val job = Job()
    private lateinit var repository: UsbHsmSettingsRepository

    @Suppress("UNCHECKED_CAST")
    private fun <T> holder(name: String): AtomicReference<T?> =
        AuditLogger::class.java.getDeclaredField(name)
            .apply { isAccessible = true }
            .get(AuditLogger) as AtomicReference<T?>

    @Before
    fun setUp() {
        val dao = mockk<AuditLogDao>(relaxed = true)
        coEvery { dao.insert(any()) } answers {
            inserted += firstArg<AuditLogEntity>()
            inserted.size.toLong()
        }
        holder<AuditLogDao>("daoRef").set(dao)
        holder<CoroutineScope>("scopeRef").set(CoroutineScope(Dispatchers.Unconfined))
        val file = tmp.newFile("usb_hsm_settings.preferences_pb").apply { delete() }
        repository = UsbHsmSettingsRepository(
            PreferenceDataStoreFactory.create(scope = CoroutineScope(Dispatchers.IO + job)) { file }
        )
    }

    @After
    fun tearDown() {
        runBlocking { job.cancelAndJoin() }
        holder<AuditLogDao>("daoRef").set(null)
        holder<CoroutineScope>("scopeRef").set(null)
    }

    private fun assertChange(entry: AuditLogEntity, setting: String, old: String, new: String) {
        assertEquals(AuditOperationType.SETTINGS_CHANGED, entry.operationType)
        assertTrue(entry.success)
        val details = JSONObject(entry.details!!)
        assertEquals(setting, details.getString("setting"))
        assertEquals(old, details.getString("oldValue"))
        assertEquals(new, details.getString("newValue"))
    }

    @Test
    fun `enabling then disabling TCP pairing records both changes`() = runBlocking {
        repository.setTcpHsmEnabled(true)
        repository.setTcpHsmEnabled(false)

        assertEquals(2, inserted.size)
        assertChange(inserted[0], "tcpPairing", "false", "true")
        assertChange(inserted[1], "tcpPairing", "true", "false")
    }

    @Test
    fun `enabling then disabling native USB records both changes`() = runBlocking {
        repository.setNativeUsbEnabled(true)
        repository.setNativeUsbEnabled(false)

        assertEquals(2, inserted.size)
        assertChange(inserted[0], "nativeUsb", "false", "true")
        assertChange(inserted[1], "nativeUsb", "true", "false")
    }

    @Test
    fun `writing the stored value records nothing`() = runBlocking {
        repository.setTcpHsmEnabled(false)
        repository.setNativeUsbEnabled(false)
        repository.setTcpHsmEnabled(true)
        repository.setNativeUsbEnabled(true)
        inserted.clear()

        repository.setTcpHsmEnabled(true)
        repository.setNativeUsbEnabled(true)

        assertEquals(emptyList<AuditLogEntity>(), inserted)
    }

    @Test
    fun `one toggle's change does not audit the other`() = runBlocking {
        repository.setTcpHsmEnabled(true)

        assertEquals(1, inserted.size)
        assertChange(inserted[0], "tcpPairing", "false", "true")
        assertEquals(false, repository.getSettings().nativeUsbEnabled)
    }
}

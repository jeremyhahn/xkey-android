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
import android.content.SharedPreferences
import android.os.Looper
import android.util.Log
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.password.PasswordStoreLockedException
import com.automatethethings.xkey.settings.PairedDeviceData
import com.automatethethings.xkey.settings.PairedDeviceRepository
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.sync.SyncEngine
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import io.mockk.verify
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * The inbound `local.syncOATH` and `local.syncPasswords` handlers record one
 * audit entry per sync (issue #221), success or failure, naming the desktop
 * that asked and never a secret, password, site or user name.
 *
 * The real handler runs; [SyncEngine] is a constructor mock (it reads Room and
 * the Android Keystore) and [AuditLogger] is an object mock whose calls are
 * verified. With the logger left unmocked and not initialized, the handlers
 * answer exactly as before.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class SyncAuditTest {

    private lateinit var handler: RequestHandler
    private lateinit var context: Context

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

        mockkConstructor(SyncEngine::class)
        coEvery { anyConstructed<SyncEngine>().markSynced() } returns Unit
        coEvery { anyConstructed<SyncEngine>().mergeOath(any()) } returns
            SyncEngine.ItemCounts(added = 2, updated = 1, skipped = 3)
        coEvery { anyConstructed<SyncEngine>().gatherOath() } returns
            JSONArray().put(JSONObject().put("id", "o1").put("secret", SECRET))
        coEvery { anyConstructed<SyncEngine>().mergePasswords(any()) } returns
            SyncEngine.ItemCounts(added = 1, updated = 2, skipped = 0)
        coEvery { anyConstructed<SyncEngine>().gatherPasswords() } returns JSONArray()
            .put(JSONObject().put("id", "p1").put("site", SITE).put("username", USER).put("password", PASSWORD))
            .put(JSONObject().put("id", "p2").put("site", SITE).put("username", USER).put("password", PASSWORD))

        Dispatchers.setMain(UnconfinedTestDispatcher())

        context = mockk<Context>(relaxed = true)
        every { context.getSystemService(Context.KEYGUARD_SERVICE) } returns
            mockk<KeyguardManager>(relaxed = true)
        every { context.getSystemService(NotificationManager::class.java) } returns
            mockk<NotificationManager>(relaxed = true)

        val desk = mockk<PairedDeviceData>()
        every { desk.deviceName } returns DESK_NAME
        val pairedDevices = mockk<PairedDeviceRepository>(relaxed = true)
        every { pairedDevices.getDevice(DESK_PEER) } returns desk
        every { pairedDevices.getDevice(OTHER_PEER) } returns null

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
        Dispatchers.resetMain()
        unmockkAll()
    }

    // --- OATH ---------------------------------------------------------------

    @Test
    fun `syncOATH records one successful entry with the caller and counts`() = runTest {
        mockkObject(AuditLogger)

        val response = call(MethodNames.LOCAL_SYNC_OATH, "credentials")

        verify(exactly = 1) {
            AuditLogger.logOathSyncPerformed(
                deviceId = DESK_PEER,
                deviceName = DESK_NAME,
                count = 1,
                direction = AuditLogger.SYNC_INBOUND,
                added = 2,
                updated = 1,
                skipped = 3,
                success = true,
                errorMessage = null
            )
        }
        assertOathResponseUnchanged(response)
    }

    @Test
    fun `syncOATH on a served connection names that connection's peer`() = runTest {
        mockkObject(AuditLogger)

        withContext(RequestHandler.servedConnection(binding, OTHER_PEER)) {
            call(MethodNames.LOCAL_SYNC_OATH, "credentials")
        }

        verify(exactly = 1) {
            AuditLogger.logOathSyncPerformed(
                deviceId = OTHER_PEER, deviceName = null, count = any(), direction = any(),
                added = any(), updated = any(), skipped = any(), success = true, errorMessage = null
            )
        }
    }

    @Test
    fun `a failed syncOATH records one failed entry`() = runTest {
        mockkObject(AuditLogger)
        coEvery { anyConstructed<SyncEngine>().mergeOath(any()) } throws IllegalStateException("db closed")

        val response = call(MethodNames.LOCAL_SYNC_OATH, "credentials")

        assertEquals(ErrorCodes.INTERNAL_ERROR, response.error?.code)
        verify(exactly = 1) {
            AuditLogger.logOathSyncPerformed(
                deviceId = DESK_PEER, deviceName = DESK_NAME, count = 0, direction = AuditLogger.SYNC_INBOUND,
                added = 0, updated = 0, skipped = 0, success = false,
                errorMessage = "syncOATH failed: IllegalStateException"
            )
        }
    }

    @Test
    fun `syncOATH answers as before when the audit logger is not initialized`() = runTest {
        assertFalse(AuditLogger.isInitialized())

        assertOathResponseUnchanged(call(MethodNames.LOCAL_SYNC_OATH, "credentials"))
    }

    // --- Passwords ----------------------------------------------------------

    @Test
    fun `syncPasswords records one entry that names no password, site or user`() = runTest {
        mockkObject(AuditLogger)

        val response = call(MethodNames.LOCAL_SYNC_PASSWORDS, "passwords")

        verify(exactly = 1) {
            AuditLogger.logPasswordSyncPerformed(
                deviceId = DESK_PEER,
                deviceName = DESK_NAME,
                count = 2,
                direction = AuditLogger.SYNC_INBOUND,
                added = 1,
                updated = 2,
                skipped = 0,
                success = true,
                errorMessage = null
            )
        }
        verify(exactly = 0) { AuditLogger.logOathSyncPerformed(any(), any(), any(), any(), any(), any(), any(), any(), any()) }
        assertEquals(2, response.result!!.getJSONArray("remote").length())
    }

    @Test
    fun `the password sync entry's details hold no password, site or user name`() {
        val details = AuditLogger.passwordSyncDetails(
            direction = AuditLogger.SYNC_INBOUND, count = 2, added = 1, updated = 2, skipped = 0
        )

        for (secret in listOf(PASSWORD, SITE, USER)) {
            assertFalse("details leak $secret: $details", details.contains(secret))
        }
        val json = JSONObject(details)
        assertEquals(AuditLogger.SYNC_INBOUND, json.getString("direction"))
        assertEquals(2, json.getInt("passwordCount"))
        assertEquals(1, json.getInt("added"))
        assertEquals(2, json.getInt("updated"))
        assertEquals(0, json.getInt("skipped"))
    }

    @Test
    fun `a locked store answers PASSWORD_STORE_LOCKED and records one failed entry`() = runTest {
        mockkObject(AuditLogger)
        coEvery { anyConstructed<SyncEngine>().mergePasswords(any()) } throws PasswordStoreLockedException()

        val response = call(MethodNames.LOCAL_SYNC_PASSWORDS, "passwords")

        assertEquals(ErrorCodes.PASSWORD_STORE_LOCKED, response.error?.code)
        verify(exactly = 1) {
            AuditLogger.logPasswordSyncPerformed(
                deviceId = DESK_PEER, deviceName = DESK_NAME, count = 0, direction = AuditLogger.SYNC_INBOUND,
                added = 0, updated = 0, skipped = 0, success = false, errorMessage = "password store is locked"
            )
        }
    }

    @Test
    fun `syncPasswords answers as before when the audit logger is not initialized`() = runTest {
        assertFalse(AuditLogger.isInitialized())

        val response = call(MethodNames.LOCAL_SYNC_PASSWORDS, "passwords")

        assertNull(response.error)
        assertEquals(setOf("added", "updated", "skipped", "remote"), response.result!!.keys().asSequence().toSet())

        coEvery { anyConstructed<SyncEngine>().mergePasswords(any()) } throws PasswordStoreLockedException()
        assertEquals(
            ErrorCodes.PASSWORD_STORE_LOCKED,
            call(MethodNames.LOCAL_SYNC_PASSWORDS, "passwords").error?.code
        )
    }

    // --- Unreadable paired-device store -------------------------------------

    /**
     * Every inbound sync handler audits through one path: with the paired
     * device store unreadable (its encrypted preferences throw), each still
     * syncs and records its entry under the connection's peer id with no
     * name. A handler that looked the name up outside that path fails here.
     */
    @Test
    fun `every sync handler audits with the peer id and no name when the paired store is unreadable`() = runTest {
        mockkObject(AuditLogger)
        val prefs = mockk<SharedPreferences>()
        every { prefs.getString(any(), any()) } throws SecurityException("keystore unavailable")
        handler = RequestHandler(
            context = context,
            keystoreManager = mockk<KeystoreManager>(relaxed = true),
            biometricLauncher = mockk(relaxed = true),
            sessionAuthManager = null,
            pairedDeviceRepository = PairedDeviceRepository(prefs)
        )
        handler.setConnectedDevicePublicKeyHex(DESK_PEER)

        assertOathResponseUnchanged(call(MethodNames.LOCAL_SYNC_OATH, "credentials"))
        assertNull(call(MethodNames.LOCAL_SYNC_PASSWORDS, "passwords").error)

        verify(exactly = 1) {
            AuditLogger.logOathSyncPerformed(
                deviceId = DESK_PEER, deviceName = null, count = 1, direction = AuditLogger.SYNC_INBOUND,
                added = 2, updated = 1, skipped = 3, success = true, errorMessage = null
            )
        }
        verify(exactly = 1) {
            AuditLogger.logPasswordSyncPerformed(
                deviceId = DESK_PEER, deviceName = null, count = 2, direction = AuditLogger.SYNC_INBOUND,
                added = 1, updated = 2, skipped = 0, success = true, errorMessage = null
            )
        }
    }

    // --- Helpers ------------------------------------------------------------

    private suspend fun call(method: String, key: String): Response {
        val params = JSONObject().put(key, JSONArray())
        return Response.fromJson(handler.handleRawRequest(Request(id = 7, method = method, params = params).toJson()))
    }

    private fun assertOathResponseUnchanged(response: Response) {
        assertNull(response.error)
        val result = response.result!!
        assertEquals(setOf("added", "updated", "skipped", "remote"), result.keys().asSequence().toSet())
        assertEquals(2, result.getInt("added"))
        assertEquals(1, result.getInt("updated"))
        assertEquals(3, result.getInt("skipped"))
        assertEquals(SECRET, result.getJSONArray("remote").getJSONObject(0).getString("secret"))
        assertTrue(result.getJSONArray("remote").length() == 1)
    }

    private companion object {
        const val DESK_PEER = "aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11"
        const val OTHER_PEER = "bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22"
        const val DESK_NAME = "desk.example.com"
        const val SECRET = "JBSWY3DPEHPK3PXP"
        const val PASSWORD = "hunter2-correct-horse"
        const val SITE = "login.example.org"
        const val USER = "alice-at-example"

        val binding = SessionBindingProvider {
            SessionBinding(ByteArray(32) { 3 }, ByteArray(32) { 4 }, ByteArray(0))
        }
    }
}

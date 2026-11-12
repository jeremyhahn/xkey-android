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
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.storage.XKeyDatabase
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import java.time.Instant
import java.util.Base64
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * Pins the `local.createBackup` / `local.restoreBackup` wire shapes against the
 * go-xkms structs in `pkg/pairingproto/protocol_backup.go` (xkey/v0.64.2-alpha):
 *
 * - LocalCreateBackupParams {backup_data []byte, label}
 * - LocalCreateBackupResult {success, backup_id, message}
 * - LocalRestoreBackupParams {backup_id omitempty}
 * - LocalRestoreBackupResult {backup_data []byte, backup_id, created_at}
 *
 * Go's encoding/json writes a []byte as standard, padded base64.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class BackupHandlerWireTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private lateinit var handler: RequestHandler

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

        val context = mockk<Context>(relaxed = true)
        every { context.filesDir } returns tmp.root
        every { context.applicationContext } returns context
        every { context.getSystemService(Context.KEYGUARD_SERVICE) } returns
            mockk<KeyguardManager>(relaxed = true)
        every { context.getSystemService(NotificationManager::class.java) } returns
            mockk<NotificationManager>(relaxed = true)

        handler = RequestHandler(
            context = context,
            keystoreManager = mockk<KeystoreManager>(relaxed = true),
            biometricLauncher = null,
            sessionAuthManager = null,
            pairedDeviceRepository = null,
            pinManager = mockk(relaxed = true)
        )
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
        unmockkAll()
    }

    // -----------------------------------------------------------------
    // local.createBackup
    // -----------------------------------------------------------------

    @Test
    fun `createBackup with padded standard base64 returns success and a backup_id`() = runTest {
        // 4 bytes -> "AAEC/w==" exercises both padding and a '/' character.
        val data = Base64.getEncoder().encodeToString(byteArrayOf(0, 1, 2, -1))
        assertTrue(data.endsWith("=="))

        val response = call(
            MethodNames.LOCAL_CREATE_BACKUP,
            """{"backup_data":"$data","label":"nightly"}"""
        )

        val result = response.getJSONObject("result")
        assertTrue(result.getBoolean("success"))
        assertTrue(result.getString("backup_id").isNotEmpty())
        assertFalse(response.has("error"))
    }

    @Test
    fun `createBackup without a label still returns success and a backup_id`() = runTest {
        val response = call(MethodNames.LOCAL_CREATE_BACKUP, """{"backup_data":"AQID"}""")

        val result = response.getJSONObject("result")
        assertTrue(result.getBoolean("success"))
        assertTrue(result.getString("backup_id").isNotEmpty())
    }

    @Test
    fun `two createBackup calls return distinct ids`() = runTest {
        val a = createBackup(byteArrayOf(1))
        val b = createBackup(byteArrayOf(2))
        assertFalse(a == b)
    }

    @Test
    fun `createBackup without backup_data is INVALID_PARAMS`() = runTest {
        val response = call(MethodNames.LOCAL_CREATE_BACKUP, """{"label":"x"}""")
        assertEquals(ErrorCodes.INVALID_PARAMS, errorCode(response))
    }

    @Test
    fun `createBackup with null backup_data is INVALID_PARAMS`() = runTest {
        val response = call(MethodNames.LOCAL_CREATE_BACKUP, """{"backup_data":null}""")
        assertEquals(ErrorCodes.INVALID_PARAMS, errorCode(response))
    }

    @Test
    fun `createBackup with non-base64 backup_data is INVALID_PARAMS`() = runTest {
        val response = call(MethodNames.LOCAL_CREATE_BACKUP, """{"backup_data":"not base64!"}""")
        assertEquals(ErrorCodes.INVALID_PARAMS, errorCode(response))
    }

    // -----------------------------------------------------------------
    // local.restoreBackup
    // -----------------------------------------------------------------

    @Test
    fun `restoreBackup by id returns the same bytes, the id and an RFC 3339 created_at`() = runTest {
        val bytes = byteArrayOf(0, 1, 2, -1, 0x7f)
        val before = System.currentTimeMillis()
        val id = createBackup(bytes)
        val after = System.currentTimeMillis()

        val result = call(MethodNames.LOCAL_RESTORE_BACKUP, """{"backup_id":"$id"}""")
            .getJSONObject("result")

        val encoded = result.getString("backup_data")
        assertEquals(Base64.getEncoder().encodeToString(bytes), encoded)
        assertArrayEquals(bytes, Base64.getDecoder().decode(encoded))
        assertEquals(id, result.getString("backup_id"))
        val createdAt = Instant.parse(result.getString("created_at")).toEpochMilli()
        assertTrue("created_at $createdAt not in [$before, $after]", createdAt in before..after)
    }

    @Test
    fun `restoreBackup without an id returns the latest backup`() = runTest {
        createBackup(byteArrayOf(1))
        createBackup(byteArrayOf(2))
        val latest = createBackup(byteArrayOf(3))

        val result = call(MethodNames.LOCAL_RESTORE_BACKUP, "{}").getJSONObject("result")

        assertEquals(latest, result.getString("backup_id"))
        assertArrayEquals(byteArrayOf(3), Base64.getDecoder().decode(result.getString("backup_data")))
    }

    @Test
    fun `restoreBackup with an empty id returns the latest backup`() = runTest {
        createBackup(byteArrayOf(1))
        val latest = createBackup(byteArrayOf(2))

        val result = call(MethodNames.LOCAL_RESTORE_BACKUP, """{"backup_id":""}""")
            .getJSONObject("result")

        assertEquals(latest, result.getString("backup_id"))
    }

    @Test
    fun `restoreBackup of an unknown id is INVALID_PARAMS`() = runTest {
        createBackup(byteArrayOf(1))
        val response = call(MethodNames.LOCAL_RESTORE_BACKUP, """{"backup_id":"backup-unknown"}""")
        assertEquals(ErrorCodes.INVALID_PARAMS, errorCode(response))
    }

    @Test
    fun `restoreBackup with no backups stored is INVALID_PARAMS`() = runTest {
        val response = call(MethodNames.LOCAL_RESTORE_BACKUP, "{}")
        assertEquals(ErrorCodes.INVALID_PARAMS, errorCode(response))
    }

    // -----------------------------------------------------------------

    private suspend fun createBackup(bytes: ByteArray): String {
        val data = Base64.getEncoder().encodeToString(bytes)
        val response = call(MethodNames.LOCAL_CREATE_BACKUP, """{"backup_data":"$data"}""")
        return response.getJSONObject("result").getString("backup_id")
    }

    private suspend fun call(method: String, params: String): JSONObject {
        val request = """{"id":1,"method":"$method","params":$params}"""
        return JSONObject(String(handler.handleRawRequest(request.toByteArray(Charsets.UTF_8)), Charsets.UTF_8))
    }

    private fun errorCode(response: JSONObject): Int = response.getJSONObject("error").getInt("code")
}

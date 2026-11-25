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
import android.content.SharedPreferences
import android.os.Looper
import android.util.Log
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.crypto.FakeSharedPreferences
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.dao.KeyDao
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.spyk
import io.mockk.unmockkAll
import java.nio.file.Files
import java.security.KeyStore
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * `local.deleteKey` of a key whose material cannot be removed answers an
 * error and keeps the key's metadata row: a software Ed25519 key whose
 * removal does not commit is still on disk, so the desktop is never told it
 * was deleted.
 */
class LocalDeleteKeyFailureHandlerTest {

    private val context = mockk<Context>(relaxed = true)

    @Before
    fun setUp() {
        mockkStatic(Log::class)
        every { Log.d(any(), any<String>()) } returns 0
        every { Log.i(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>()) } returns 0
        every { Log.e(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>(), any()) } returns 0
        every { Log.e(any(), any<String>(), any()) } returns 0
        mockkObject(AuditLogger)
        every { AuditLogger.logKeyDeleted(any(), any(), any()) } returns Unit
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    @Test
    fun aRemovalThatDoesNotCommitKeepsTheRowAndAnswersAnError() = runBlocking<Unit> {
        val keyDao = mockk<KeyDao>(relaxed = true)
        coEvery { keyDao.exists("ed") } returns true
        coEvery { keyDao.deleteByKeyId(any()) } returns 1
        val handler = realHandler(keyDao)

        val request = JSONObject().put("jsonrpc", "2.0").put("id", 1).put("method", MethodNames.LOCAL_DELETE_KEY)
            .put("params", JSONObject().put("keyId", "ed"))
        val response = JSONObject(String(handler.handleRawRequest(request.toString().toByteArray())))

        assertTrue(
            "a failed removal must never answer deleted=true, got $response",
            response.optJSONObject("result")?.optBoolean("deleted") != true
        )
        assertNotNull("a failed removal must answer an error, got $response", response.optJSONObject("error"))
        coVerify(exactly = 0) { keyDao.deleteByKeyId(any()) }
    }

    @Test
    fun aRetryAfterARemovalThatDidNotCommitStillKeepsTheRow() = runBlocking<Unit> {
        val keyDao = mockk<KeyDao>(relaxed = true)
        coEvery { keyDao.exists("edretry") } returns true
        coEvery { keyDao.deleteByKeyId(any()) } returns 1
        // Like Android's, the fake drops the key from its in-memory map even
        // though the write to disk fails.
        val prefs = FakeSharedPreferences(mapOf("xkey_key_edretry" to "secret"))
        prefs.diskFails = true
        val handler = realHandler(keyDao, prefs)

        for (attempt in 1..2) {
            val request = JSONObject().put("jsonrpc", "2.0").put("id", attempt)
                .put("method", MethodNames.LOCAL_DELETE_KEY)
                .put("params", JSONObject().put("keyId", "edretry"))
            val response = JSONObject(String(handler.handleRawRequest(request.toString().toByteArray())))

            assertTrue(
                "attempt $attempt must never answer deleted=true, got $response",
                response.optJSONObject("result")?.optBoolean("deleted") != true
            )
            assertNotNull("attempt $attempt must answer an error, got $response", response.optJSONObject("error"))
        }
        coVerify(exactly = 0) { keyDao.deleteByKeyId(any()) }
        assertTrue("the key is still on disk", "xkey_key_edretry" in prefs.disk)
    }

    /**
     * The real [RequestHandler] and a real [KeystoreManager] on an API 33+
     * device, whose software Ed25519 key `xkey_key_ed` is stored and whose
     * removal does not commit (or whose store is [prefs]); only the Android
     * and storage edges are mocked.
     */
    private fun realHandler(keyDao: KeyDao, prefs: SharedPreferences = failingCommitPrefs()): RequestHandler {
        mockkStatic(Looper::class)
        every { Looper.getMainLooper() } returns mockk(relaxed = true)
        val database = mockk<XKeyDatabase>(relaxed = true)
        every { database.keyDao() } returns keyDao
        mockkObject(XKeyDatabase.Companion)
        every { XKeyDatabase.getInstance(any()) } returns database
        every { context.getSystemService(Context.KEYGUARD_SERVICE) } returns mockk<KeyguardManager>(relaxed = true)
        val keyStore = mockk<KeyStore>(relaxed = true)
        every { keyStore.containsAlias(any()) } returns false
        mockkStatic(KeyStore::class)
        every { KeyStore.getInstance("AndroidKeyStore") } returns keyStore
        every { context.filesDir } returns Files.createTempDirectory("xkey-files").toFile().apply { deleteOnExit() }
        every { context.getSystemService(NotificationManager::class.java) } returns
            mockk<NotificationManager>(relaxed = true)

        val keystore = spyk(KeystoreManager(context))
        every { keystore.softwareEd25519Supported() } returns true
        every { keystore.ed25519Prefs() } returns prefs

        return RequestHandler(context, keystore, biometricLauncher = null, sessionAuthManager = null)
    }

    /** Software Ed25519 key `xkey_key_ed` is stored, and removing it does not commit. */
    private fun failingCommitPrefs(): SharedPreferences {
        val editor = mockk<SharedPreferences.Editor>()
        every { editor.remove(any()) } returns editor
        every { editor.commit() } returns false
        val prefs = mockk<SharedPreferences>()
        every { prefs.contains(any()) } answers { firstArg<String>() == "xkey_key_ed" }
        every { prefs.edit() } returns editor
        return prefs
    }
}

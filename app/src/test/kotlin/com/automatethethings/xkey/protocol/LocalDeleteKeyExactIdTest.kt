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
import com.automatethethings.xkey.crypto.SoftwareKeyStore
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.dao.KeyDao
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.runs
import io.mockk.unmockkAll
import io.mockk.verify
import java.nio.file.Files
import java.security.KeyStore
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * `local.deleteKey` deletes the key the request names. An ID that is itself
 * a recorded or software key is that key, even when it also has the raw
 * alias form (`xkey_key_<id>`) of another key's Keystore entry.
 */
class LocalDeleteKeyExactIdTest {

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
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    /**
     * Software key `xkey_key_a` is generated, then hardware key `a`, whose
     * Keystore entry is `xkey_key_a`. Deleting `xkey_key_a` deletes the
     * software key only: hardware key `a`'s entry and row remain.
     */
    @Test
    fun deletingASoftwareKeyNamedLikeAHardwareAliasLeavesTheHardwareKey() = runBlocking<Unit> {
        val software = "xkey_key_a"
        val hardware = "a"
        val keyDao = mockk<KeyDao>(relaxed = true)
        coEvery { keyDao.exists(software) } returns true
        coEvery { keyDao.exists(hardware) } returns true
        val keystore = mockk<KeystoreManager>(relaxed = true)
        // Hardware key `a` lives at Keystore alias `xkey_key_a`.
        every { keystore.resolveKeystoreAlias(any()) } answers {
            when (firstArg<String>()) {
                hardware, software -> software
                else -> null
            }
        }
        mockkConstructor(SoftwareKeyStore::class)
        every { anyConstructed<SoftwareKeyStore>().contains(any()) } answers { firstArg<String>() == software }
        every { anyConstructed<SoftwareKeyStore>().delete(any()) } just runs

        val request = JSONObject().put("jsonrpc", "2.0").put("id", 1).put("method", MethodNames.LOCAL_DELETE_KEY)
            .put("params", JSONObject().put("keyId", software))
        val response = JSONObject(String(realHandler(keyDao, keystore).handleRawRequest(request.toString().toByteArray())))

        assertTrue(
            "the delete must succeed, got $response",
            response.optJSONObject("result")?.optBoolean("deleted") == true
        )
        verify { anyConstructed<SoftwareKeyStore>().delete(software) }
        coVerify { keyDao.deleteByKeyId(software) }
        verify(exactly = 0) { keystore.deleteGeneralKey(hardware) }
        verify(exactly = 0) { anyConstructed<SoftwareKeyStore>().delete(hardware) }
        coVerify(exactly = 0) { keyDao.deleteByKeyId(hardware) }
    }

    /**
     * The raw alias of a key with no record or software key of that ID still
     * names the key itself: deleting `xkey_key_b` deletes hardware key `b`.
     */
    @Test
    fun aRawAliasWithNoKeyOfItsOwnStillDeletesItsKey() = runBlocking<Unit> {
        val keyDao = mockk<KeyDao>(relaxed = true)
        coEvery { keyDao.exists("b") } returns true
        val keystore = mockk<KeystoreManager>(relaxed = true)
        every { keystore.resolveKeystoreAlias(any()) } answers {
            firstArg<String>().takeIf { it == "xkey_key_b" || it == "b" }?.let { "xkey_key_b" }
        }
        mockkConstructor(SoftwareKeyStore::class)
        every { anyConstructed<SoftwareKeyStore>().contains(any()) } returns false
        every { anyConstructed<SoftwareKeyStore>().delete(any()) } just runs

        val request = JSONObject().put("jsonrpc", "2.0").put("id", 2).put("method", MethodNames.LOCAL_DELETE_KEY)
            .put("params", JSONObject().put("keyId", "xkey_key_b"))
        realHandler(keyDao, keystore).handleRawRequest(request.toString().toByteArray())

        verify { keystore.deleteGeneralKey("b") }
        coVerify { keyDao.deleteByKeyId("b") }
        coVerify(exactly = 0) { keyDao.deleteByKeyId("xkey_key_b") }
    }

    /** The real [RequestHandler] with only its Android and storage edges mocked. */
    private fun realHandler(keyDao: KeyDao, keystore: KeystoreManager): RequestHandler {
        mockkStatic(Looper::class)
        every { Looper.getMainLooper() } returns mockk(relaxed = true)
        val database = mockk<XKeyDatabase>(relaxed = true)
        every { database.keyDao() } returns keyDao
        mockkObject(XKeyDatabase.Companion)
        every { XKeyDatabase.getInstance(any()) } returns database
        every { context.getSystemService(Context.KEYGUARD_SERVICE) } returns mockk<KeyguardManager>(relaxed = true)
        mockkStatic(KeyStore::class)
        every { KeyStore.getInstance("AndroidKeyStore") } returns mockk(relaxed = true)
        every { context.filesDir } returns Files.createTempDirectory("xkey-files").toFile().apply { deleteOnExit() }
        every { context.getSystemService(NotificationManager::class.java) } returns
            mockk<NotificationManager>(relaxed = true)
        return RequestHandler(context, keystore, biometricLauncher = null, sessionAuthManager = null)
    }
}

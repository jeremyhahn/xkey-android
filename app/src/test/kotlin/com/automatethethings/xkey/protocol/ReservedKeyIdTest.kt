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
import com.automatethethings.xkey.crypto.FileEncryptor
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
import java.io.File
import java.nio.file.Files
import java.security.KeyStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Key IDs starting with `ephemeral_` name xKey's own agreement keys only when
 * xKey made them (no key row). Key creation keeps main's contract: every ID
 * main accepts, `ephemeral_` ones included, is created as it would be under
 * any other ID, and only the delete guard reads the ephemeral rule.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class ReservedKeyIdTest {

    private val context = mockk<Context>(relaxed = true)
    private lateinit var keyDao: KeyDao
    private lateinit var keystore: KeystoreManager

    private val ephemeralId = "${FileEncryptor.EPHEMERAL_KEY_PREFIX}desktop"
    private val plainId = "desktop-key"

    @Before
    fun setUp() {
        Dispatchers.setMain(Dispatchers.Unconfined)
        mockkStatic(Log::class)
        every { Log.d(any(), any<String>()) } returns 0
        every { Log.i(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>()) } returns 0
        every { Log.e(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>(), any()) } returns 0
        every { Log.e(any(), any<String>(), any()) } returns 0

        keyDao = mockk(relaxed = true)
        coEvery { keyDao.exists(any()) } returns false
        keystore = mockk(relaxed = true)
        every { keystore.listAllKeystoreAliases() } returns emptyList()
        every { keystore.resolveKeystoreAlias(any()) } answers { firstArg() }
        every { keystore.keyExists(any()) } returns false
        every { keystore.generalKeyExists(any()) } returns false
        mockkConstructor(SoftwareKeyStore::class)
        every { anyConstructed<SoftwareKeyStore>().contains(any()) } returns false
        every { anyConstructed<SoftwareKeyStore>().put(any()) } just runs
    }

    @After
    fun tearDown() {
        unmockkAll()
        Dispatchers.resetMain()
    }

    private fun creations(id: String) = listOf(
        MethodNames.LOCAL_GENERATE_KEY to JSONObject().put("keyId", id).put("algorithm", "ES256")
            .put("requireUserVerification", false),
        MethodNames.LOCAL_GENERATE_KEY to JSONObject().put("keyId", id).put("algorithm", "AES-256")
            .put("requireUserVerification", false),
        MethodNames.GENERATE_KEY to JSONObject().put("credentialId", id).put("algorithm", CoseAlgorithms.ES256)
            .put("requireUserVerification", false)
    )

    @Test
    fun everyCreationRpcAcceptsAnEphemeralNamedIdAsMainDoes() = runBlocking<Unit> {
        val handler = realHandler()
        for ((n, creation) in creations(ephemeralId).withIndex()) {
            val response = send(handler, n, creation.first, creation.second)
            assertTrue(
                "${creation.first} of $ephemeralId must not be refused as reserved, got $response",
                response.optJSONObject("error")?.optString("message")?.contains("reserved") != true
            )
        }
        coVerify(exactly = 1) { keystore.generateKeyForAlgorithm(ephemeralId, any(), any(), any()) }
    }

    @Test
    fun anEphemeralNamedIdIsCreatedExactlyAsAnyOtherId() = runBlocking<Unit> {
        fun outcome(r: JSONObject) = r.optJSONObject("error")?.optInt("code")
        val handler = realHandler()
        val plain = creations(plainId).mapIndexed { n, c -> outcome(send(handler, n, c.first, c.second)) }
        val ephemeral = creations(ephemeralId).mapIndexed { n, c -> outcome(send(handler, n + 10, c.first, c.second)) }

        assertEquals("an ephemeral_ ID is created as any other ID is", plain, ephemeral)
    }

    /**
     * No creation path refuses an ID by the ephemeral rule (that would change
     * the desktop key-creation contract), and the delete guard is the one
     * place that reads it.
     */
    @Test
    fun onlyTheDeleteGuardReadsTheEphemeralIdRule() {
        val code = File("src/main/kotlin/com/automatethethings/xkey/protocol/Handler.kt").readText()
        val functions = Regex("""\n    (?:private |internal )?(?:suspend )?fun (?:<[^>]+> )?(\w+)\(""").findAll(code).toList()
        fun body(i: Int) = code.substring(functions[i].range.first, functions.getOrNull(i + 1)?.range?.first ?: code.length)

        val readers = functions.indices
            .filter { Regex("""(?<!fun )\bisReservedKeyId\(""").containsMatchIn(body(it)) }
            .map { functions[it].groupValues[1] }
            .filter { it != "isReservedKeyId" }
        assertEquals("only the delete guard reads the ephemeral ID rule", listOf("refuseInternalAlias"), readers)
        assertEquals(
            "Handler may spell the ephemeral prefix only in its ephemeral ID rule",
            1,
            Regex(Regex.escape("EPHEMERAL_KEY_PREFIX")).findAll(code).count()
        )
    }

    private suspend fun send(handler: RequestHandler, n: Int, method: String, params: JSONObject): JSONObject {
        val request = JSONObject().put("jsonrpc", "2.0").put("id", n + 1).put("method", method).put("params", params)
        return JSONObject(String(handler.handleRawRequest(request.toString().toByteArray())))
    }

    /** The real [RequestHandler] with only its Android and storage edges mocked. */
    private fun realHandler(): RequestHandler {
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

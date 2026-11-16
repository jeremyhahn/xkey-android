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
import io.mockk.verify
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
 * xKey reserves key IDs starting with `ephemeral_` for its own agreement
 * keys, and `local.deleteKey` refuses to delete them. No RPC may create a key
 * under such an ID either, or a paired desktop would make a key it can never
 * delete: every creation RPC refuses a reserved ID before any key is made.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class ReservedKeyIdTest {

    private val context = mockk<Context>(relaxed = true)
    private lateinit var keyDao: KeyDao
    private lateinit var keystore: KeystoreManager

    private val reservedId = "${FileEncryptor.EPHEMERAL_KEY_PREFIX}desktop"

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

    @Test
    fun everyCreationRpcRefusesAReservedKeyId() = runBlocking<Unit> {
        val creations = listOf(
            MethodNames.LOCAL_GENERATE_KEY to JSONObject().put("keyId", reservedId).put("algorithm", "ES256")
                .put("requireUserVerification", false),
            MethodNames.LOCAL_GENERATE_KEY to JSONObject().put("keyId", reservedId).put("algorithm", "AES-256")
                .put("requireUserVerification", false),
            MethodNames.GENERATE_KEY to JSONObject().put("credentialId", reservedId).put("algorithm", CoseAlgorithms.ES256)
                .put("requireUserVerification", false)
        )
        val handler = realHandler()
        for ((n, creation) in creations.withIndex()) {
            val response = send(handler, n, creation.first, creation.second)

            assertEquals(
                "${creation.first} of reserved ID $reservedId must be refused, got $response",
                ErrorCodes.INVALID_PARAMS,
                response.optJSONObject("error")?.optInt("code")
            )
        }
        coVerify(exactly = 0) { keystore.generateKeyForAlgorithm(any(), any(), any(), any()) }
        coVerify(exactly = 0) { keystore.generateKeyWithAuthDuration(any(), any(), any()) }
        coVerify(exactly = 0) { keystore.generateSymmetricKey(any(), any(), any()) }
        coVerify(exactly = 0) { keystore.generateHMACKey(any(), any()) }
        verify(exactly = 0) { anyConstructed<SoftwareKeyStore>().put(any()) }
    }

    @Test
    fun anUnreservedIdIsNotRefusedAsReserved() = runBlocking<Unit> {
        val response = send(
            realHandler(), 0, MethodNames.LOCAL_GENERATE_KEY,
            JSONObject().put("keyId", "desktop_ephemeral_").put("algorithm", "ES256").put("requireUserVerification", false)
        )

        assertTrue(
            "an ID that only contains the prefix is not reserved, got $response",
            response.optJSONObject("error")?.optString("message")?.contains("reserved") != true
        )
    }

    /**
     * Every Handler function that creates a key under a caller's ID refuses a
     * reserved ID first, and the delete guard reads the same rule.
     */
    @Test
    fun everyCreationPathAndTheDeleteGuardShareTheReservedIdRule() {
        val code = File("src/main/kotlin/com/automatethethings/xkey/protocol/Handler.kt").readText()
        val functions = Regex("""\n    (?:private |internal )?(?:suspend )?fun (?:<[^>]+> )?(\w+)\(""").findAll(code).toList()
        fun body(i: Int) = code.substring(functions[i].range.first, functions.getOrNull(i + 1)?.range?.first ?: code.length)

        val creators = listOf("createLocalKey", "createCredential")
        var callers = 0
        for (i in functions.indices) {
            val name = functions[i].groupValues[1]
            if (name in creators) continue
            val text = body(i)
            val call = creators.mapNotNull { c -> Regex("""\b$c\(""").find(text)?.range?.first }.minOrNull() ?: continue
            callers++
            val refusal = text.indexOf("refuseReservedKeyId(")
            assertTrue("$name creates a key and must refuse a reserved ID before it does", refusal in 0 until call)
        }
        assertTrue("the creation RPCs must be found", callers >= 2)

        val guard = functions.indexOfFirst { it.groupValues[1] == "refuseInternalAlias" }
        assertTrue("refuseInternalAlias must exist", guard >= 0)
        assertTrue("the delete guard must read the reserved ID rule", body(guard).contains("isReservedKeyId("))
        assertEquals(
            "Handler may spell the ephemeral prefix only in its reserved ID rule",
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

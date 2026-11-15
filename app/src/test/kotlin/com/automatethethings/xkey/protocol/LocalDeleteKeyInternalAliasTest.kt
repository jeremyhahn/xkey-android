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
import java.io.File
import java.nio.file.Files
import java.security.KeyStore
import java.util.Collections
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * `local.deleteKey` from a paired desktop deletes only user keys. Every
 * Keystore entry xKey keeps for itself (the stores' protection keys, the
 * device's identity and attestation keys, the CA, PIV slot keys and the
 * ephemeral agreement keys) is refused before any material is removed, by
 * whichever branch of the delete the ID reaches, and stays usable.
 */
class LocalDeleteKeyInternalAliasTest {

    private val context = mockk<Context>(relaxed = true)

    /** The Keystore entries a paired desktop may never delete. */
    private val internalAliases = listOf(
        "xkey_password_encryption_key",
        "xkey_oath_secret_encryption_key",
        "xkey_seal_store_key",
        "xkey_software_key_store",
        "xkey_user_verification_key",
        "xkey_device_attestation_key",
        "xkey_device_identity_0",
        "xkey_root_ca",
        "xkey_intermediate_ca",
        "xkey_piv_9a",
        "_androidx_security_master_key_",
        "xkey_key_ephemeral_0"
    )

    /** A user key `u` at its general alias. */
    private val userAlias = "xkey_key_u"

    private lateinit var aliases: MutableSet<String>
    private lateinit var keyDao: KeyDao
    private lateinit var keystore: KeystoreManager

    @Before
    fun setUp() {
        mockkStatic(Log::class)
        every { Log.d(any(), any<String>()) } returns 0
        every { Log.i(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>()) } returns 0
        every { Log.e(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>(), any()) } returns 0
        every { Log.e(any(), any<String>(), any()) } returns 0

        aliases = Collections.synchronizedSet((internalAliases + userAlias).toHashSet())
        keyDao = mockk(relaxed = true)
        // Discovery lists every unprefixed Keystore entry but PIV slot keys
        // as a key row of that ID; `xkey_key_u` is listed as key `u`.
        coEvery { keyDao.exists(any()) } answers {
            val id = firstArg<String>()
            id == "u" || (
                id in aliases && !id.startsWith("xkey_piv_") &&
                    !id.startsWith("xkey_key_") && !id.startsWith("xkey_credential_")
                )
        }
        keystore = mockk(relaxed = true)
        every { keystore.listAllKeystoreAliases() } answers { aliases.toList() }
        every { keystore.resolveKeystoreAlias(any()) } answers {
            val id = firstArg<String>()
            listOf("xkey_credential_$id", "xkey_key_$id", id).firstOrNull { it in aliases }
        }
        // Today's deleteByAlias, which protects only PIV slot keys.
        every { keystore.deleteByAlias(any()) } answers {
            val alias = firstArg<String>()
            !alias.startsWith("xkey_piv_") && aliases.remove(alias)
        }
        every { keystore.deleteGeneralKey(any()) } answers { aliases.remove("xkey_key_${firstArg<String>()}") }
        every { keystore.deleteKey(any()) } answers {
            keystore.resolveKeystoreAlias(firstArg())?.let { aliases.remove(it) } ?: false
        }
        mockkConstructor(SoftwareKeyStore::class)
        every { anyConstructed<SoftwareKeyStore>().contains(any()) } returns false
        every { anyConstructed<SoftwareKeyStore>().delete(any()) } just runs
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    @Test
    fun everyInternalAliasIsRefusedAndKeepsItsKey() = runBlocking<Unit> {
        val handler = realHandler()
        for ((n, alias) in internalAliases.withIndex()) {
            val response = delete(handler, n, alias)

            assertEquals(
                "deleting $alias must be refused, got $response",
                ErrorCodes.OPERATION_DENIED,
                response.optJSONObject("error")?.optInt("code")
            )
            assertTrue("$alias must keep its key, left $aliases", alias in aliases)
            coVerify(exactly = 0) { keyDao.deleteByKeyId(alias) }
        }
        assertTrue("the user key is untouched, left $aliases", userAlias in aliases)
    }

    @Test
    fun aStoreProtectionKeyStillDecryptsItsStoreAfterARefusedDelete() = runBlocking<Unit> {
        val handler = realHandler()
        for ((n, alias) in listOf("xkey_password_encryption_key", "xkey_oath_secret_encryption_key").withIndex()) {
            delete(handler, n, alias)
            // The store opens its cipher on this entry: it is still there.
            assertEquals("$alias must still resolve", alias, keystore.resolveKeystoreAlias(alias))
        }
    }

    @Test
    fun aUserKeyStillDeletes() = runBlocking<Unit> {
        val handler = realHandler()
        for ((n, id) in listOf("u", userAlias).withIndex()) {
            aliases.add(userAlias)
            val response = delete(handler, n, id)

            assertTrue(
                "deleting $id must succeed, got $response",
                response.optJSONObject("result")?.optBoolean("deleted") == true
            )
            assertTrue("$id's key must be gone, left $aliases", userAlias !in aliases)
        }
        coVerify(exactly = 2) { keyDao.deleteByKeyId("u") }
    }

    @Test
    fun aMissingKeyIsNotRefused() = runBlocking<Unit> {
        val response = delete(realHandler(), 0, "no-such-key")

        assertTrue("got $response", response.optJSONObject("error") == null)
        assertTrue("got $response", response.optJSONObject("result")?.optBoolean("deleted") == false)
    }

    @Test
    fun handlerDeletesKeystoreEntriesOnlyThroughTheRefusal() {
        val code = File("src/main/kotlin/com/automatethethings/xkey/protocol/Handler.kt").readText()
        val start = code.indexOf("private fun deleteKeystoreAlias(")
        assertTrue("deleteKeystoreAlias must exist", start >= 0)
        val body = code.substring(start, code.indexOf("\n    }\n", start).let { if (it < 0) code.length else it })
        val refusal = body.indexOf("refuseInternalAlias(")
        assertTrue("deleteKeystoreAlias must refuse internal aliases first", refusal >= 0)
        for (call in listOf("deleteByAlias(", "deleteGeneralKey(")) {
            assertTrue("$call must follow the refusal", body.indexOf(call) > refusal)
        }
        // A raw alias is deleted nowhere else; deleteGeneralKey elsewhere only
        // discards a key local.generateKey has just made.
        assertEquals(
            "Handler may delete a raw alias only in deleteKeystoreAlias",
            1,
            Regex(Regex.escape(".deleteByAlias(")).findAll(code).count()
        )
    }

    private suspend fun delete(handler: RequestHandler, n: Int, keyId: String): JSONObject {
        val request = JSONObject().put("jsonrpc", "2.0").put("id", n + 1).put("method", MethodNames.LOCAL_DELETE_KEY)
            .put("params", JSONObject().put("keyId", keyId))
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

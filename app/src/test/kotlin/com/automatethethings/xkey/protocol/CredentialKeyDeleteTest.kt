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
import com.automatethethings.xkey.storage.dao.CredentialMetadataDao
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.entity.CredentialMetadataEntity
import io.mockk.coEvery
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
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Deleting a FIDO2 credential key (`xkey_credential_<id>`) from a paired
 * desktop, by `local.deleteKey` or the legacy `deleteKey`, removes its
 * material only through [KeystoreManager.deleteCredentialKey], which writes the
 * audit record, and removes the passkey's Credential Provider metadata in the
 * same delete. A delete that cannot remove both keeps both.
 */
class CredentialKeyDeleteTest {

    private val context = mockk<Context>(relaxed = true)

    private val credentialAlias = "xkey_credential_c"

    private lateinit var aliases: MutableSet<String>
    private lateinit var metadata: MutableMap<String, CredentialMetadataEntity>
    private lateinit var keyDao: KeyDao
    private lateinit var credentialDao: CredentialMetadataDao
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

        aliases = Collections.synchronizedSet(hashSetOf(credentialAlias, "xkey_root_ca"))
        metadata = ConcurrentHashMap(mapOf("c" to passkey("c")))
        keyDao = mockk(relaxed = true)
        coEvery { keyDao.exists(any()) } returns false
        credentialDao = mockk(relaxed = true)
        coEvery { credentialDao.getByCredentialId(any()) } answers { metadata[firstArg()] }
        coEvery { credentialDao.deleteByCredentialId(any()) } answers {
            if (metadata.remove(firstArg<String>()) != null) 1 else 0
        }
        coEvery { credentialDao.insert(any()) } answers {
            val row = firstArg<CredentialMetadataEntity>()
            metadata[row.credentialId] = row
            1L
        }

        keystore = mockk(relaxed = true)
        every { keystore.listAllKeystoreAliases() } answers { aliases.toList() }
        every { keystore.resolveKeystoreAlias(any()) } answers {
            val id = firstArg<String>()
            listOf("xkey_credential_$id", "xkey_key_$id", id).firstOrNull { it in aliases }
        }
        every { keystore.keyExists(any()) } answers { keystore.resolveKeystoreAlias(firstArg()) != null }
        every { keystore.deleteByAlias(any()) } answers { aliases.remove(firstArg<String>()) }
        every { keystore.deleteGeneralKey(any()) } answers { aliases.remove("xkey_key_${firstArg<String>()}") }
        every { keystore.deleteKey(any()) } answers {
            keystore.resolveKeystoreAlias(firstArg())?.let { aliases.remove(it) } ?: false
        }
        // The audited delete of exactly one credential's Keystore entry.
        every { keystore.deleteCredentialKey(any<String>()) } answers {
            aliases.remove("xkey_credential_${firstArg<String>()}")
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
    fun aCredentialDeleteGoesThroughTheAuditedDeleteAndRemovesItsMetadata() = runBlocking<Unit> {
        for ((n, request) in listOf(
            localDelete("c"), localDelete(credentialAlias), legacyDelete("c"), legacyDelete(credentialAlias)
        ).withIndex()) {
            aliases.add(credentialAlias)
            metadata["c"] = passkey("c")

            val response = send(realHandler(), n, request)

            assertTrue("deleting must succeed, got $response", response.optJSONObject("error") == null)
            assertFalse("the credential's key must be gone, left $aliases", credentialAlias in aliases)
            assertFalse("the passkey's metadata must be gone", "c" in metadata)
        }
        verify(exactly = 4) { keystore.deleteCredentialKey("c") }
        verify(exactly = 0) { keystore.deleteByAlias(credentialAlias) }
        verify(exactly = 0) { keystore.deleteKey(any()) }
    }

    @Test
    fun aDeleteWhoseMetadataCannotBeRemovedKeepsBoth() = runBlocking<Unit> {
        coEvery { credentialDao.deleteByCredentialId(any()) } throws IllegalStateException("disk I/O error")
        for ((n, request) in listOf(localDelete("c"), legacyDelete("c")).withIndex()) {
            val response = send(realHandler(), n, request)

            assertNotNull("the delete must be refused, got $response", response.optJSONObject("error"))
            assertTrue("the key must be kept, left $aliases", credentialAlias in aliases)
            assertTrue("the metadata must be kept", "c" in metadata)
        }
    }

    @Test
    fun aFailedMaterialRemovalKeepsTheMetadata() = runBlocking<Unit> {
        every { keystore.deleteCredentialKey(any<String>()) } throws IllegalStateException("keystore busy")
        for ((n, request) in listOf(localDelete("c"), legacyDelete("c")).withIndex()) {
            val response = send(realHandler(), n, request)

            assertNotNull("the delete must fail, got $response", response.optJSONObject("error"))
            assertTrue("the key must be kept, left $aliases", credentialAlias in aliases)
            assertEquals("the metadata must be kept", passkey("c").rpId, metadata["c"]?.rpId)
        }
    }

    @Test
    fun deletingAGeneralKeyLeavesTheCredentialOfTheSameId() = runBlocking<Unit> {
        aliases.add("xkey_key_c")
        val response = send(realHandler(), 0, localDelete("xkey_key_c"))

        assertTrue("got $response", response.optJSONObject("result")?.optBoolean("deleted") == true)
        assertFalse("the general key must be gone", "xkey_key_c" in aliases)
        assertTrue("the credential must stay, left $aliases", credentialAlias in aliases)
        assertTrue("the credential's metadata must stay", "c" in metadata)
    }

    @Test
    fun theLegacyDeleteRefusesAnInternalAlias() = runBlocking<Unit> {
        val response = send(realHandler(), 0, legacyDelete("xkey_root_ca"))

        assertEquals(
            "got $response",
            ErrorCodes.OPERATION_DENIED,
            response.optJSONObject("error")?.optInt("code")
        )
        assertTrue("the CA key must be kept, left $aliases", "xkey_root_ca" in aliases)
    }

    @Test
    fun handlerRemovesCredentialMetadataAndKeystoreEntriesOnlyAtTheChokePoint() {
        val code = File("src/main/kotlin/com/automatethethings/xkey/protocol/Handler.kt").readText()
        assertEquals(
            "Handler may remove a passkey's metadata only in deleteCredentialKey",
            1,
            Regex(Regex.escape(".deleteByCredentialId(")).findAll(code).count()
        )
        assertEquals(
            "Handler may remove a credential's material only through deleteCredentialKey",
            1,
            Regex(Regex.escape("keystoreManager.deleteCredentialKey(")).findAll(code).count()
        )
        assertEquals("no unaudited raw-alias delete in Handler", 0, Regex(Regex.escape(".deleteByAlias(")).findAll(code).count())
    }

    @Test
    fun aDeleteCancelledMidwayKeepsBothOrNeither() = runBlocking<Unit> {
        for ((n, request) in listOf(localDelete("c"), legacyDelete("c")).withIndex()) {
            // Room has already removed the row when the cancelled caller resumes.
            val metadataRemoved = CompletableDeferred<Unit>()
            val release = CompletableDeferred<Unit>()
            coEvery { credentialDao.deleteByCredentialId(any()) } coAnswers {
                val removed = if (metadata.remove(firstArg<String>()) != null) 1 else 0
                metadataRemoved.complete(Unit)
                release.await()
                removed
            }
            aliases.add(credentialAlias)
            metadata["c"] = passkey("c")
            val handler = realHandler()

            val job = launch(Dispatchers.Default) { send(handler, n, request) }
            withTimeout(10_000) { metadataRemoved.await() }
            job.cancel()
            release.complete(Unit)
            withTimeout(10_000) { job.join() }

            assertEquals(
                "a cancelled delete must keep both or neither: key ${credentialAlias in aliases}, metadata ${"c" in metadata}",
                credentialAlias in aliases,
                "c" in metadata
            )
        }
    }

    @Test
    fun twoConcurrentDeletesOfOneCredentialLeaveNoMetadataAndOneAuditRecord() = runBlocking<Unit> {
        val removals = AtomicInteger()
        every { keystore.deleteCredentialKey(any<String>()) } answers {
            aliases.remove("xkey_credential_${firstArg<String>()}").also { if (it) removals.incrementAndGet() }
        }
        // Let both deletes read the passkey before either removes it, if they may.
        val readers = AtomicInteger()
        coEvery { credentialDao.getByCredentialId(any()) } coAnswers {
            readers.incrementAndGet()
            withTimeoutOrNull(500) { while (readers.get() < 2) delay(5) }
            metadata[firstArg()]
        }
        val handler = realHandler()

        listOf(localDelete("c"), legacyDelete("c")).mapIndexed { n, request ->
            async(Dispatchers.Default) { send(handler, n, request) }
        }.awaitAll()

        assertFalse("the credential's key must be gone, left $aliases", credentialAlias in aliases)
        assertFalse("no metadata may be written back for a deleted key", "c" in metadata)
        assertEquals("one delete removes the key and writes its audit record", 1, removals.get())
    }

    @Test
    fun deletesOfNonexistentCredentialsLeaveNoLockBehind() = runBlocking<Unit> {
        val handler = realHandler()
        for (n in 0 until 200) {
            val id = "xkey_credential_missing$n"
            val response = send(handler, n, if (n % 2 == 0) localDelete(id) else legacyDelete(id))
            assertFalse("nothing to delete, got $response", response.optJSONObject("result")?.optBoolean("deleted") == true)
        }
        assertTrue("no delete runs, so no lock may be kept, left ${credentialDeleteLocks()}", credentialDeleteLocks().isEmpty())

        // Deletes of one existing alias still run one at a time, and leave no lock.
        val inside = AtomicInteger()
        val overlapped = AtomicInteger()
        every { keystore.deleteCredentialKey(any<String>()) } answers {
            if (inside.incrementAndGet() > 1) overlapped.incrementAndGet()
            Thread.sleep(50)
            inside.decrementAndGet()
            aliases.remove("xkey_credential_${firstArg<String>()}")
        }
        // Keep the alias listed so every delete reaches the Keystore removal.
        every { keystore.listAllKeystoreAliases() } answers { (aliases + credentialAlias).toList() }
        (0 until 4).map { n ->
            async(Dispatchers.Default) { send(handler, n, if (n % 2 == 0) localDelete("c") else legacyDelete("c")) }
        }.awaitAll()

        assertEquals("deletes of one credential must not overlap", 0, overlapped.get())
        assertTrue("no delete runs, so no lock may be kept, left ${credentialDeleteLocks()}", credentialDeleteLocks().isEmpty())
    }

    @Test
    fun aFailedRemovalWithAnUnknownKeyStateKeepsTheMetadataAndFails() = runBlocking<Unit> {
        for ((n, request) in listOf(localDelete("c"), legacyDelete("c")).withIndex()) {
            metadata["c"] = passkey("c")
            val removalTried = java.util.concurrent.atomic.AtomicBoolean(false)
            every { keystore.listAllKeystoreAliases() } answers {
                if (removalTried.get()) throw IllegalStateException("keystore unavailable")
                aliases.toList()
            }
            every { keystore.deleteCredentialKey(any<String>()) } answers {
                removalTried.set(true)
                throw IllegalStateException("keystore busy")
            }

            val response = send(realHandler(), n, request)

            assertNotNull("the delete must fail, got $response", response.optJSONObject("error"))
            assertEquals("the metadata must be kept", passkey("c").rpId, metadata["c"]?.rpId)
        }
    }

    /** The handler's process-wide credential delete locks, by alias. */
    private fun credentialDeleteLocks(): Map<*, *> =
        RequestHandler::class.java.getDeclaredField("credentialDeleteLocks")
            .apply { isAccessible = true }
            .get(null) as Map<*, *>

    @Test
    fun noOtherMainSourceRemovesCredentialMetadataOrMaterial() {
        val sources = File("src/main/kotlin").walkTopDown().filter { it.isFile && it.extension == "kt" }
        for (file in sources) {
            val code = file.readText()
            val expected = if (file.name == "Handler.kt" && file.parentFile.name == "protocol") 1 else 0
            assertEquals(
                "${file.path} may remove a passkey's metadata only at Handler's choke point",
                expected,
                Regex(Regex.escape(".deleteByCredentialId(")).findAll(code).count()
            )
            assertEquals(
                "${file.path} may remove a credential's material only at Handler's choke point",
                expected,
                Regex(Regex.escape("keystoreManager.deleteCredentialKey(")).findAll(code).count()
            )
        }
    }

    private fun passkey(id: String) = CredentialMetadataEntity(
        credentialId = id,
        rpId = "example.com",
        rpName = "Example",
        userId = "user",
        userName = "user@example.com",
        userDisplayName = "User",
        publicKeyCose = byteArrayOf(1, 2, 3)
    )

    private fun localDelete(keyId: String) = MethodNames.LOCAL_DELETE_KEY to JSONObject().put("keyId", keyId)

    private fun legacyDelete(credentialId: String) = "deleteKey" to JSONObject().put("credentialId", credentialId)

    private suspend fun send(handler: RequestHandler, n: Int, request: Pair<String, JSONObject>): JSONObject {
        val raw = JSONObject().put("jsonrpc", "2.0").put("id", n + 1).put("method", request.first)
            .put("params", request.second)
        return JSONObject(String(handler.handleRawRequest(raw.toString().toByteArray())))
    }

    /** The real [RequestHandler] with only its Android and storage edges mocked. */
    private fun realHandler(): RequestHandler {
        mockkStatic(Looper::class)
        every { Looper.getMainLooper() } returns mockk(relaxed = true)
        val database = mockk<XKeyDatabase>(relaxed = true)
        every { database.keyDao() } returns keyDao
        every { database.credentialMetadataDao() } returns credentialDao
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

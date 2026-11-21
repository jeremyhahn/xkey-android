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
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.crypto.UserKeyKind
import com.automatethethings.xkey.storage.FakeKeyPolicyTables
import com.automatethethings.xkey.storage.KeyMaterial
import com.automatethethings.xkey.storage.KeyPolicyStore
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.entity.KeyDeletionEntity
import com.automatethethings.xkey.storage.keyMaterialDeleter
import io.mockk.coEvery
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.runs
import io.mockk.unmockkAll
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.IOException
import java.util.Collections

/**
 * A delete whose Keystore material delete failed answers deleted=true and
 * keeps its tombstone, so the old alias is still there. A generation of the
 * same id after the backend recovers settles that owed delete first and
 * then generates fresh material; it is never refused as an existing key.
 * While the material still cannot be deleted, the generation is refused as
 * a pending deletion, never as KEY_EXISTS. Both generators, `local.generateKey`
 * and the legacy `generateKey`, run through the real [RequestHandler] with
 * the Keystore, the key table and the material deleter as in-memory fakes.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class GenerateAfterFailedDeleteTest {

    private val peer = "ab".repeat(32)

    /** Ids whose material is in the fake Keystore. */
    private val present: MutableSet<String> = Collections.synchronizedSet(HashSet())

    /** How many times each id was generated. */
    private val generated = Collections.synchronizedList(ArrayList<String>())

    /** While true, every material delete throws, as a Keystore that is down. */
    @Volatile private var deleteFails = true

    private val tables = FakeKeyPolicyTables()
    private lateinit var context: Context
    private lateinit var keystore: KeystoreManager

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

        val keyDao = mockk<KeyDao>(relaxed = true)
        coEvery { keyDao.exists(any()) } returns false
        val database = mockk<XKeyDatabase>(relaxed = true)
        every { database.keyDao() } returns keyDao
        every { database.keyPolicyDao() } returns tables
        mockkObject(XKeyDatabase.Companion)
        every { XKeyDatabase.getInstance(any()) } returns database
        mockkObject(KeyPolicyStore.Companion)
        every { KeyPolicyStore.of(any(), any()) } answers { tables.store() }

        mockkObject(AuditLogger)
        every { AuditLogger.logFido2Registration(any(), any(), any(), any()) } just runs

        // The material deleter every write settles an owed delete with: it
        // deletes the id's material unless the Keystore is down.
        val deleter = object : KeyMaterial {
            override suspend fun generation(held: KeyPolicyStore.KeyMaterialHeld, source: String?) = "old"
            override suspend fun delete(held: KeyPolicyStore.KeyMaterialHeld, tombstone: KeyDeletionEntity): Boolean {
                if (deleteFails) throw IOException("Keystore unavailable")
                present.remove(held.keyId)
                return true
            }
        }
        mockkStatic("com.automatethethings.xkey.storage.KeyDeletionReplayKt")
        every { keyMaterialDeleter(any(), any(), any(), any()) } returns deleter

        keystore = mockk(relaxed = true)
        every { keystore.userKeyIdInUse(any()) } answers { firstArg<String>() in present }
        every { keystore.generalKeyExists(any()) } answers { firstArg<String>() in present }
        every { keystore.keyExists(any(), any()) } answers { firstArg<String>() in present }
        every { keystore.resolveKeystoreAlias(any(), UserKeyKind.CREDENTIAL) } answers {
            firstArg<String>().takeIf { it in present }?.let { "xkey_credential_$it" }
        }
        coEvery { keystore.generateKeyForAlgorithm(any(), any(), any(), any()) } answers {
            generate(firstArg())
            ByteArray(91) { 1 }
        }
        coEvery { keystore.generateKeyWithAuthDuration(any(), any(), any()) } answers {
            generate(firstArg())
            ByteArray(77) { 2 }
        }
        every { keystore.getAttestationChain(any(), any()) } returns null

        Dispatchers.setMain(UnconfinedTestDispatcher())
        context = mockk(relaxed = true)
        every { context.filesDir } returns kotlin.io.path.createTempDirectory("xkey-files").toFile()
        val keyguard = mockk<KeyguardManager>(relaxed = true)
        every { keyguard.isKeyguardLocked } returns false
        every { context.getSystemService(Context.KEYGUARD_SERVICE) } returns keyguard
        every { context.getSystemService(NotificationManager::class.java) } returns
            mockk<NotificationManager>(relaxed = true)
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
        unmockkAll()
    }

    private fun generate(keyId: String) {
        generated += keyId
        present += keyId
    }

    /**
     * What a delete of [keyId] whose material delete failed leaves: its row
     * gone, its tombstone kept, its material still in the Keystore; the
     * delete answered deleted=true.
     */
    private fun deletedWithMaterialLeft(keyId: String) {
        present += keyId
        tables.deletions.value = tables.deletions.value + (keyId to KeyDeletionEntity(keyId, 1L, "android", "old"))
    }

    private fun handler() = RequestHandler(context, keystore, biometricLauncher = null, sessionAuthManager = null)
        .also { it.setConnectedDevicePublicKeyHex(peer) }

    private suspend fun localGenerate(keyId: String): JSONObject = call(
        Request(1L, MethodNames.LOCAL_GENERATE_KEY, JSONObject().put("keyId", keyId).put("algorithm", "ES256"))
    )

    private suspend fun legacyGenerate(credentialId: String): JSONObject = call(
        Request(
            2L,
            MethodNames.GENERATE_KEY,
            JSONObject().put("credentialId", credentialId).put("algorithm", CoseAlgorithms.ES256)
                .put("requireUserVerification", false)
        )
    )

    private suspend fun call(request: Request): JSONObject = JSONObject(handler().handleRequest(request).toJsonString())

    @Test
    fun localGenerateKeyAfterTheBackendRecoversSettlesTheDeleteAndGenerates() = runBlocking<Unit> {
        deletedWithMaterialLeft("key-k")
        deleteFails = false

        val response = localGenerate("key-k")

        assertNotNull("generation after recovery must succeed, got $response", response.optJSONObject("result"))
        assertEquals(listOf("key-k"), generated)
        assertNull("the owed delete must be settled", tables.deletions.value["key-k"])
    }

    @Test
    fun legacyGenerateKeyAfterTheBackendRecoversSettlesTheDeleteAndGenerates() = runBlocking<Unit> {
        deletedWithMaterialLeft("cred-k")
        deleteFails = false

        val response = legacyGenerate("cred-k")

        assertNotNull("generation after recovery must succeed, got $response", response.optJSONObject("result"))
        assertEquals(listOf("cred-k"), generated)
        assertNull("the owed delete must be settled", tables.deletions.value["cred-k"])
    }

    @Test
    fun localGenerateKeyWhileTheDeleteIsStillOwedIsRefusedAsPendingNotExisting() = runBlocking<Unit> {
        deletedWithMaterialLeft("key-p")

        val error = localGenerate("key-p").optJSONObject("error")

        assertNotNull(error)
        assertNotEquals("refused as an existing key: $error", ErrorCodes.KEY_EXISTS, error!!.optInt("code"))
        assertTrue("refused as a pending deletion: $error", error.optString("message").contains("not finished"))
        assertTrue(generated.isEmpty())
        assertNotNull("the tombstone stays for the replay", tables.deletions.value["key-p"])
    }

    @Test
    fun legacyGenerateKeyWhileTheDeleteIsStillOwedIsRefusedAsPendingNotExisting() = runBlocking<Unit> {
        deletedWithMaterialLeft("cred-p")

        val error = legacyGenerate("cred-p").optJSONObject("error")

        assertNotNull(error)
        assertTrue("refused as a pending deletion: $error", error!!.optString("message").contains("not finished"))
        assertTrue(generated.isEmpty())
        assertNotNull("the tombstone stays for the replay", tables.deletions.value["cred-p"])
    }
}

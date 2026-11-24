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
package com.automatethethings.xkey.sync

import android.content.Context
import android.net.Uri
import android.util.Log
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.oath.OATH_KEPT_DELETED
import com.automatethethings.xkey.oath.OathCredentialDao
import com.automatethethings.xkey.oath.OathCredentialEntity
import com.automatethethings.xkey.oath.OathRepository
import com.automatethethings.xkey.oath.OathSecretManager
import com.automatethethings.xkey.storage.XKeyDatabase
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import io.mockk.verify
import kotlinx.coroutines.test.runTest
import org.json.JSONArray
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import java.net.URI
import java.net.URLDecoder
import java.security.KeyStore

/**
 * [SyncEngine.mergeOath] reads a synced credential's label on the structured
 * path: the issuer and account arrive as separate fields, so a `:` inside
 * either stays in it. On the external-import path an issuerless account
 * `host:user` would be stored as issuer `host`, account `user`.
 *
 * The DAO records what is inserted, the secret manager passes the secret
 * through, and `Uri.parse` is backed by [URI] (the JVM has no android.net).
 */
class SyncEngineMergeOathTest {

    private val inserted = mutableListOf<OathCredentialEntity>()

    /** The table, by `oath_id`, as the DAO's insert-if-absent and in-place update leave it. */
    private val rows = linkedMapOf<String, OathCredentialEntity>()

    /** The ids with a delete record (`oath_deletions`). */
    private val deleted = mutableSetOf<String>()
    private lateinit var engine: SyncEngine
    private lateinit var dao: OathCredentialDao

    @Before
    fun setUp() {
        dao = mockk<OathCredentialDao>()
        coEvery { dao.getByOathId(any()) } answers { rows[firstArg()] }
        coEvery { dao.deleteByOathId(any()) } answers { if (rows.remove(firstArg<String>()) != null) 1 else 0 }
        coEvery { dao.recordDeletion(any(), any()) } answers { deleted += firstArg<String>() }
        coEvery { dao.isDeleted(any()) } answers { firstArg<String>() in deleted }
        // The DAO's transactions, as their bodies leave the table (a mock does not run interface bodies).
        coEvery { dao.removeIfDeleted(any()) } answers {
            val oathId = firstArg<String>()
            if (oathId in deleted) rows.remove(oathId)
            oathId in deleted
        }
        coEvery { dao.deleteAndRecordDeletion(any(), any()) } answers {
            deleted += firstArg<String>()
            if (rows.remove(firstArg<String>()) != null) 1 else 0
        }
        coEvery { dao.insertIfAbsent(any()) } answers { insertIfAbsent(firstArg()) }
        coEvery { dao.insertIfAbsentUnlessDeleted(any()) } answers {
            val row = firstArg<OathCredentialEntity>()
            if (row.oathId in deleted) {
                rows.remove(row.oathId)
                OATH_KEPT_DELETED
            } else {
                insertIfAbsent(row)
            }
        }
        coEvery {
            dao.updateSynced(any(), any(), any(), any())
        } answers {
            val oathId = arg<String>(0)
            val row = rows[oathId]
            if (row == null) {
                0
            } else {
                // As the SQL does: the counter only moves forward.
                rows[oathId] = row.copy(
                    counter = maxOf(row.counter, arg<Long>(1)),
                    issuer = arg(2),
                    accountName = arg(3)
                )
                1
            }
        }
        val db = mockk<XKeyDatabase>()
        every { db.oathCredentialDao() } returns dao
        mockkObject(XKeyDatabase.Companion)
        every { XKeyDatabase.getInstance(any()) } returns db

        // The secret manager opens the Android Keystore as it is constructed.
        mockkStatic(KeyStore::class)
        every { KeyStore.getInstance("AndroidKeyStore") } returns mockk(relaxed = true)
        mockkConstructor(OathSecretManager::class)
        every { anyConstructed<OathSecretManager>().encryptSecret(any()) } answers { firstArg() }
        every { anyConstructed<OathSecretManager>().decryptSecret(any()) } answers { firstArg() }

        mockkStatic(Uri::class)
        every { Uri.parse(any()) } answers { jvmUri(firstArg()) }

        mockkStatic(Log::class)
        every { Log.w(any(), any<String>()) } returns 0

        // Every add, a synced one included, writes a created row from the
        // repository; the logger is not initialized on the JVM.
        mockkObject(AuditLogger)
        every { AuditLogger.logOathCredentialCreated(any(), any(), any(), any()) } returns Unit
        every { AuditLogger.logOathSyncConflict(any()) } returns Unit
        every { AuditLogger.logOathCredentialDeleted(any(), any(), any()) } returns Unit

        engine = SyncEngine(mockk<Context>())
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    /** What the DAO's `INSERT OR IGNORE` leaves: the new row id, or -1 if a row has the oath id. */
    private fun insertIfAbsent(row: OathCredentialEntity): Long {
        if (rows.containsKey(row.oathId)) return -1L
        val stored = row.copy(id = rows.size + 1L)
        rows[row.oathId] = stored
        inserted += stored
        return stored.id
    }

    /** An android [Uri] answering what `importFromUri` reads, from [URI]. */
    private fun jvmUri(uriString: String): Uri {
        val uri = URI(uriString)
        val params = uri.rawQuery.orEmpty().split("&").filter { it.isNotEmpty() }
            .map { it.split("=", limit = 2) }
            .associate { it[0] to URLDecoder.decode(it.getOrElse(1) { "" }, Charsets.UTF_8.name()) }
        return mockk {
            every { scheme } returns uri.scheme
            every { host } returns uri.host
            every { encodedPath } returns uri.rawPath
            every { getQueryParameter(any()) } answers { params[firstArg()] }
        }
    }

    private fun credential(
        id: String,
        issuer: String?,
        account: String,
        secret: String = "JBSWY3DPEHPK3PXP",
        type: String = "totp",
        counter: Long? = null
    ) = JSONObject().apply {
        put("id", id)
        put("secret", secret)
        put("account_name", account)
        if (issuer != null) put("issuer", issuer)
        put("type", type)
        if (counter != null) put("counter", counter)
    }

    @Test
    fun `merging the same id twice leaves one row under the incoming id`() = runTest {
        val payload = JSONArray().put(credential("desk-1", "Acme", "alice"))

        val first = engine.mergeOath(payload)
        val second = engine.mergeOath(payload)

        assertEquals(SyncEngine.ItemCounts(added = 1, updated = 0, skipped = 0), first)
        assertEquals(SyncEngine.ItemCounts(added = 0, updated = 1, skipped = 0), second)
        assertEquals(listOf("desk-1"), rows.keys.toList())
        assertEquals("desk-1", rows.getValue("desk-1").oathId)
    }

    @Test
    fun `a second merge with a higher HOTP counter updates the counter in place`() = runTest {
        engine.mergeOath(JSONArray().put(credential("h1", "Acme", "alice", type = "hotp", counter = 5)))
        val before = rows.getValue("h1")

        engine.mergeOath(JSONArray().put(credential("h1", "Acme", "alice", type = "hotp", counter = 9)))

        val after = rows.getValue("h1")
        assertEquals(1, rows.size)
        assertEquals(9L, after.counter)
        assertEquals(before.id, after.id)
        assertEquals(before.createdAt, after.createdAt)
    }

    @Test
    fun `a second merge with a lower HOTP counter leaves the counter unchanged`() = runTest {
        engine.mergeOath(JSONArray().put(credential("h2", "Acme", "alice", type = "hotp", counter = 12)))

        engine.mergeOath(JSONArray().put(credential("h2", "Acme", "alice", type = "hotp", counter = 3)))

        assertEquals(1, rows.size)
        assertEquals(12L, rows.getValue("h2").counter)
    }

    @Test
    fun `an item with an invalid Base32 secret is skipped and the rest merge`() = runTest {
        val payload = JSONArray()
            .put(credential("ok-1", "Acme", "alice"))
            .put(credential("bad", "Acme", "bob", secret = "ABC1!"))
            .put(credential("ok-2", "Acme", "carol"))

        val counts = engine.mergeOath(payload)

        assertEquals(SyncEngine.ItemCounts(added = 2, updated = 0, skipped = 1), counts)
        assertEquals(setOf("ok-1", "ok-2"), rows.keys)
    }

    @Test
    fun `mergeOath keeps an issuerless account with a colon whole`() = runTest {
        val counts = engine.mergeOath(JSONArray().put(credential("c1", null, "host:user")))

        assertEquals(SyncEngine.ItemCounts(added = 1, updated = 0, skipped = 0), counts)
        assertEquals(1, inserted.size)
        assertNull(inserted[0].issuer)
        assertEquals("host:user", inserted[0].accountName)
        verify(exactly = 1) { AuditLogger.logOathCredentialCreated(any(), null, "host:user", "TOTP") }
    }

    @Test
    fun `a credential deleted on the phone is not re-inserted by the next merge`() = runTest {
        val payload = JSONArray().put(credential("gone", "Acme", "alice"))
        engine.mergeOath(payload)
        OathRepository(dao, OathSecretManager()).deleteCredential("gone")
        assertNull(rows["gone"])

        val counts = engine.mergeOath(payload)

        assertNull("a deleted id stays deleted", rows["gone"])
        assertEquals(SyncEngine.ItemCounts(added = 0, updated = 0, skipped = 1), counts)
    }

    @Test
    fun `a stale copy with another secret never overwrites the stored secret`() = runTest {
        engine.mergeOath(JSONArray().put(credential("x", "Acme", "alice", secret = "GEZDGNBVGY3TQOJQ")))
        val rekeyed = rows.getValue("x").secretEncrypted

        val counts = engine.mergeOath(JSONArray().put(credential("x", "Acme", "alice", secret = "JBSWY3DPEHPK3PXP")))

        assertArrayEquals("the stored secret is kept", rekeyed, rows.getValue("x").secretEncrypted)
        assertEquals(SyncEngine.ItemCounts(added = 0, updated = 0, skipped = 1, conflicts = 1), counts)
        verify(exactly = 1) { AuditLogger.logOathSyncConflict("x") }
    }

    @Test
    fun `a copy with the same secret applies its label`() = runTest {
        engine.mergeOath(JSONArray().put(credential("y", "Acme", "alice")))

        val counts = engine.mergeOath(JSONArray().put(credential("y", "Acme Corp", "alice@example.com")))

        assertEquals(SyncEngine.ItemCounts(added = 0, updated = 1, skipped = 0), counts)
        assertEquals("Acme Corp", rows.getValue("y").issuer)
        assertEquals("alice@example.com", rows.getValue("y").accountName)
    }

    @Test
    fun `a copy with another digit count never overwrites the stored parameters`() = runTest {
        engine.mergeOath(JSONArray().put(credential("z", "Acme", "alice")))

        val counts = engine.mergeOath(JSONArray().put(credential("z", "Acme", "alice").put("digits", 8)))

        assertEquals(6, rows.getValue("z").digits)
        assertEquals(SyncEngine.ItemCounts(added = 0, updated = 0, skipped = 1, conflicts = 1), counts)
    }

    @Test
    fun `mergeOath keeps an issuer and account with colons whole`() = runTest {
        engine.mergeOath(JSONArray().put(credential("c2", "Corp:EU", "host:user")))

        assertEquals(1, inserted.size)
        assertEquals("Corp:EU", inserted[0].issuer)
        assertEquals("host:user", inserted[0].accountName)
    }
}

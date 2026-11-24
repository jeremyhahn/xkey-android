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

package com.automatethethings.xkey.oath

import android.net.Uri
import com.automatethethings.xkey.audit.AuditLogger
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import java.net.URI
import java.net.URLDecoder

/**
 * A HOTP code generated while something else moves the same credential's
 * counter (a sync merge raising it, or another code) is never computed from
 * a counter that is no longer the stored one, and never rewinds it.
 *
 * The DAO holds one row in memory and can pause a code generation right
 * after it reads the row; the secret manager passes the secret through
 * (as copies, since the merge zeroes what it decrypts), and `Uri.parse` is
 * backed by [URI] (the JVM has no android.net).
 */
class OathHotpCounterRaceTest {

    private class FakeOathDao(delegate: OathCredentialDao = mockk()) : OathCredentialDao by delegate {
        var row: OathCredentialEntity? = null

        /** Run once, after the next read has taken its copy of the row and before it returns. */
        var afterRead: (suspend () -> Unit)? = null

        override suspend fun getByOathId(oathId: String): OathCredentialEntity? {
            val read = row?.takeIf { it.oathId == oathId }
            afterRead?.let {
                afterRead = null
                it()
            }
            return read
        }

        override suspend fun insertIfAbsent(credential: OathCredentialEntity): Long {
            if (row?.oathId == credential.oathId) return -1
            row = credential.copy(id = 1)
            return 1
        }

        override suspend fun updateSynced(oathId: String, counter: Long, issuer: String?, accountName: String): Int {
            val current = row?.takeIf { it.oathId == oathId } ?: return 0
            row = current.copy(counter = maxOf(current.counter, counter), issuer = issuer, accountName = accountName)
            return 1
        }

        override suspend fun isDeleted(oathId: String): Boolean = false

        // Nothing here is ever deleted: the merge's transactions reduce to the plain insert.
        override suspend fun removeIfDeleted(oathId: String): Boolean = false

        override suspend fun insertIfAbsentUnlessDeleted(credential: OathCredentialEntity): Long =
            insertIfAbsent(credential)

        override suspend fun recordUsage(oathId: String, timestamp: Long) {
            val current = row?.takeIf { it.oathId == oathId } ?: return
            row = current.copy(lastUsedAt = timestamp, useCount = current.useCount + 1)
        }

        override suspend fun claimCounter(oathId: String, expected: Long): Int {
            val current = row?.takeIf { it.oathId == oathId && it.counter == expected && it.counter < Long.MAX_VALUE }
                ?: return 0
            row = current.copy(counter = expected.inc())
            return 1
        }
    }

    private lateinit var dao: FakeOathDao
    private lateinit var repository: OathRepository

    @Before
    fun setUp() {
        dao = FakeOathDao()
        val secretManager = mockk<OathSecretManager>()
        every { secretManager.encryptSecret(any()) } answers { firstArg<ByteArray>().copyOf() }
        every { secretManager.decryptSecret(any()) } answers { firstArg<ByteArray>().copyOf() }
        mockkStatic(Uri::class)
        every { Uri.parse(any()) } answers { jvmUri(firstArg()) }
        stubAuditLogger()
        repository = OathRepository(dao, secretManager)
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    private suspend fun merge(counter: Long): SyncMergeOutcome =
        repository.upsertStructured(ID, "hotp", "Example", "alice", SECRET, counter = counter)

    private fun codeAt(counter: Long): String =
        OathEngine.generateHotpCode(dao.row!!.secretEncrypted, counter, "SHA1", 6)

    @Test
    fun `a code generated while a sync raises the counter uses the raised counter`() = runTest {
        assertEquals(SyncMergeOutcome.ADDED, merge(counter = 5))
        val gate = CompletableDeferred<Unit>()
        dao.afterRead = { gate.await() }

        val generating = async { repository.generateCode(ID) }
        runCurrent()
        assertEquals(SyncMergeOutcome.UPDATED, merge(counter = 100))
        gate.complete(Unit)

        assertEquals(codeAt(100), generating.await())
        assertEquals(101L, dao.row!!.counter)
    }

    @Test
    fun `two codes generated at once use two counters`() = runTest {
        assertEquals(SyncMergeOutcome.ADDED, merge(counter = 5))
        val gate = CompletableDeferred<Unit>()
        dao.afterRead = { gate.await() }

        val first = async { repository.generateCode(ID) }
        runCurrent()
        val second = async { repository.generateCode(ID) }
        runCurrent()
        gate.complete(Unit)
        val codes = setOf(first.await(), second.await())

        assertEquals(setOf(codeAt(5), codeAt(6)), codes)
        assertNotEquals(codeAt(5), codeAt(6))
        assertEquals(7L, dao.row!!.counter)
    }

    private companion object {
        const val ID = "phone-1:hotp"
        const val SECRET = "JBSWY3DPEHPK3PXP"
    }
}

/** The repository audits every add, delete and generation; the logger is not initialized on the JVM. */
private fun stubAuditLogger() {
    mockkObject(AuditLogger)
    every { AuditLogger.logOathCredentialCreated(any(), any(), any(), any(), any(), any()) } returns Unit
    every { AuditLogger.logOathCredentialDeleted(any(), any(), any(), any(), any()) } returns Unit
    every { AuditLogger.logOathCodeGenerated(any(), any(), any(), any(), any()) } returns Unit
}

/** An android [Uri] answering what the importer reads, from [URI]. */
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

/**
 * A phone deletion of an OATH credential and a sync merge of the same id
 * never leave the credential stored, wherever one interrupts the other.
 *
 * The DAO keeps the table and the deletion records in memory. Each of its
 * methods is one committed statement or one transaction, and [afterCall]
 * runs after each, numbered from 1: there a test lands a phone deletion
 * between two of the repository's steps, or ends the merge as a
 * cancellation or process death would. Nothing runs inside a transaction.
 */
class OathSyncDeletionRaceTest {

    private class DeletionFakeOathDao(delegate: OathCredentialDao = mockk()) : OathCredentialDao by delegate {
        val rows = linkedMapOf<String, OathCredentialEntity>()
        val deletions = linkedMapOf<String, Long>()
        private var calls = 0

        /** Run after each DAO call returns its result, with the call's number. */
        var afterCall: (suspend (Int) -> Unit)? = null

        private suspend fun <T> call(block: () -> T): T {
            val result = block()
            afterCall?.invoke(++calls)
            return result
        }

        override suspend fun getByOathId(oathId: String): OathCredentialEntity? = call { rows[oathId] }

        override suspend fun insertIfAbsent(credential: OathCredentialEntity): Long = call {
            if (rows.containsKey(credential.oathId)) {
                -1L
            } else {
                rows[credential.oathId] = credential.copy(id = rows.size + 1L)
                rows.size.toLong()
            }
        }

        override suspend fun updateSynced(oathId: String, counter: Long, issuer: String?, accountName: String): Int = call {
            val current = rows[oathId]
            if (current == null) {
                0
            } else {
                rows[oathId] = current.copy(counter = maxOf(current.counter, counter), issuer = issuer, accountName = accountName)
                1
            }
        }

        override suspend fun isDeleted(oathId: String): Boolean = call { oathId in deletions }

        override suspend fun deleteByOathId(oathId: String): Int = call {
            if (rows.remove(oathId) != null) 1 else 0
        }

        override suspend fun recordDeletion(oathId: String, deletedAt: Long): Unit = call {
            deletions[oathId] = deletedAt
            Unit
        }

        /** One transaction: a deleted id's leftover row goes. Returns whether the id has a deletion record. */
        override suspend fun removeIfDeleted(oathId: String): Boolean = call {
            if (oathId in deletions) rows.remove(oathId)
            oathId in deletions
        }

        /** One transaction: a deleted id's leftover row goes, and nothing is added for it. */
        override suspend fun insertIfAbsentUnlessDeleted(credential: OathCredentialEntity): Long = call {
            if (credential.oathId in deletions) {
                rows.remove(credential.oathId)
                OATH_KEPT_DELETED
            } else if (rows.containsKey(credential.oathId)) {
                -1L
            } else {
                rows[credential.oathId] = credential.copy(id = rows.size + 1L)
                rows.size.toLong()
            }
        }

        /** One transaction: the record and the delete land together. */
        override suspend fun deleteAndRecordDeletion(oathId: String, deletedAt: Long): Int = call {
            deletions[oathId] = deletedAt
            if (rows.remove(oathId) != null) 1 else 0
        }

        /** What the phone's delete leaves, applied directly, outside any merge step. */
        fun phoneDeletes(oathId: String) {
            deletions[oathId] = 1L
            rows.remove(oathId)
        }
    }

    private lateinit var dao: DeletionFakeOathDao
    private lateinit var repository: OathRepository

    @Before
    fun setUp() {
        dao = DeletionFakeOathDao()
        val secretManager = mockk<OathSecretManager>()
        every { secretManager.encryptSecret(any()) } answers { firstArg<ByteArray>().copyOf() }
        every { secretManager.decryptSecret(any()) } answers { firstArg<ByteArray>().copyOf() }
        mockkStatic(Uri::class)
        every { Uri.parse(any()) } answers { jvmUri(firstArg()) }
        stubAuditLogger()
        repository = OathRepository(dao, secretManager)
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    private suspend fun merge(): SyncMergeOutcome =
        repository.upsertStructured(ID, "totp", "Example", "alice", SECRET)

    @Test
    fun `a phone deletion between the merge's steps leaves no row`() = runTest {
        dao.afterCall = { n -> if (n == 1) dao.phoneDeletes(ID) }

        assertEquals(SyncMergeOutcome.DELETED, merge())

        assertFalse(dao.rows.containsKey(ID))
    }

    @Test
    fun `a merge cancelled right after its insert leaves no deleted credential stored`() = runTest {
        dao.afterCall = { n ->
            if (n == 1) dao.phoneDeletes(ID)
            if (n == 2) throw CancellationException("process death")
        }

        try {
            merge()
            fail("expected the merge to be cancelled")
        } catch (e: CancellationException) {
            // expected
        }

        assertTrue(ID in dao.deletions)
        assertFalse("a deleted id is never stored", dao.rows.containsKey(ID))
    }

    @Test
    fun `a row left beside its deletion record is removed by the next merge`() = runTest {
        dao.rows[ID] = OathCredentialEntity(
            id = 1,
            oathId = ID,
            oathType = "totp",
            algorithm = "SHA1",
            digits = 6,
            periodSeconds = 30,
            counter = 0,
            issuer = "Example",
            accountName = "alice",
            secretEncrypted = byteArrayOf(1, 2, 3),
            source = "local",
            createdAt = 1L
        )
        dao.deletions[ID] = 1L

        assertEquals(SyncMergeOutcome.DELETED, merge())

        assertFalse(dao.rows.containsKey(ID))
    }

    @Test
    fun `a delete cancelled after its first step leaves the record and the row together or neither`() = runTest {
        assertEquals(SyncMergeOutcome.ADDED, merge())
        dao.afterCall = { throw CancellationException("process death") }

        try {
            repository.deleteCredential(ID)
        } catch (e: CancellationException) {
            // expected
        }

        assertEquals("deleted means recorded and gone", ID in dao.deletions, !dao.rows.containsKey(ID))
    }

    private companion object {
        const val ID = "desk-1:totp"
        const val SECRET = "JBSWY3DPEHPK3PXP"
    }
}

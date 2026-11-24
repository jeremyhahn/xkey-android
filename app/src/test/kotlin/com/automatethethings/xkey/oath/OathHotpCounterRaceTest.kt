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
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
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

        override suspend fun recordUsage(oathId: String, timestamp: Long) {
            val current = row?.takeIf { it.oathId == oathId } ?: return
            row = current.copy(lastUsedAt = timestamp, useCount = current.useCount + 1)
        }

        override suspend fun advanceCounter(oathId: String, expected: Long, next: Long): Int {
            val current = row?.takeIf { it.oathId == oathId && it.counter == expected } ?: return 0
            row = current.copy(counter = next)
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

    private companion object {
        const val ID = "phone-1:hotp"
        const val SECRET = "JBSWY3DPEHPK3PXP"
    }
}

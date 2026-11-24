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

import com.automatethethings.xkey.audit.AuditLogger
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.unmockkAll
import kotlinx.coroutines.async
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.yield
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Before
import org.junit.Test

/**
 * Two HOTP generations that overlap (two phone copies, or a phone copy during
 * a desktop generate) must each use their own counter value: an HOTP code is
 * a one-time value, and handing out the same one twice lets a verifier accept
 * one and reject the other, or lets a replay pass.
 */
class OathHotpConcurrentCopyTest {

    /**
     * One HOTP row. A read takes its snapshot, then yields, so a second
     * generation can read the same counter before the first one writes.
     */
    private class OneRowDao(
        var row: OathCredentialEntity,
        delegate: OathCredentialDao = mockk()
    ) : OathCredentialDao by delegate {

        override suspend fun getByOathId(oathId: String): OathCredentialEntity? {
            val snapshot = row.takeIf { it.oathId == oathId }
            yield()
            return snapshot
        }

        override suspend fun updateCounter(oathId: String, counter: Long) {
            if (row.oathId == oathId) row = row.copy(counter = counter)
        }

        override suspend fun advanceCounter(oathId: String, expected: Long, next: Long): Int {
            if (row.oathId != oathId || row.counter != expected) return 0
            row = row.copy(counter = next)
            return 1
        }

        override suspend fun recordUsage(oathId: String, timestamp: Long) = Unit
    }

    @Before
    fun setUp() {
        mockkObject(AuditLogger)
        every { AuditLogger.logOathCodeGenerated(any(), any(), any()) } returns Unit
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    @Test
    fun `two overlapping HOTP copies get two counters`() = runTest {
        val dao = OneRowDao(hotpRow(counter = 5L))
        val secretManager = mockk<OathSecretManager>()
        every { secretManager.decryptSecret(any()) } answers { firstArg() }
        val repository = OathRepository(dao, secretManager)

        val first = async { repository.generateCode(HOTP_ID) }
        val second = async { repository.generateCode(HOTP_ID) }
        val codes = listOf(first.await(), second.await())

        assertNotEquals("the same HOTP code was handed out twice", codes[0], codes[1])
        assertEquals(setOf(codeAt(5L), codeAt(6L)), codes.toSet())
        assertEquals(7L, dao.row.counter)
    }

    private fun codeAt(counter: Long) =
        OathEngine.generateHotpCode(secret = SECRET, counter = counter, algorithm = "SHA1", digits = 6)

    private fun hotpRow(counter: Long) = OathCredentialEntity(
        oathId = HOTP_ID,
        oathType = "HOTP",
        algorithm = "SHA1",
        digits = 6,
        periodSeconds = 30,
        counter = counter,
        issuer = "Acme",
        accountName = "alice",
        secretEncrypted = SECRET,
        source = "local",
        createdAt = 0L
    )

    private companion object {
        const val HOTP_ID = "hotp-1"

        /** The RFC 4226 test secret. */
        val SECRET = "12345678901234567890".toByteArray(Charsets.US_ASCII)
    }
}

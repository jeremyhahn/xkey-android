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

import android.app.Application
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import com.automatethethings.xkey.storage.XKeyDatabase
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.util.concurrent.atomic.AtomicInteger

/**
 * Input that [OathEngine] cannot compute a code from never reaches the
 * table, through either import path. The secret manager passes the secret
 * through (the JVM has no Android Keystore).
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = Application::class)
class OathRepositoryHardeningTest {

    private lateinit var database: XKeyDatabase
    private lateinit var dao: OathCredentialDao
    private lateinit var secretManager: OathSecretManager
    private lateinit var repository: OathRepository

    @Before
    fun setUp() {
        database = Room.inMemoryDatabaseBuilder(ApplicationProvider.getApplicationContext(), XKeyDatabase::class.java)
            .allowMainThreadQueries()
            .build()
        dao = database.oathCredentialDao()
        secretManager = mockk()
        every { secretManager.encryptSecret(any()) } answers { firstArg() }
        every { secretManager.decryptSecret(any()) } answers { firstArg() }
        val corrupt = javax.crypto.AEADBadTagException("tag mismatch")
        every { secretManager.decryptSecret(match { it.contentEquals(CORRUPT) }) } throws corrupt
        repository = OathRepository(dao, secretManager)
    }

    @After
    fun tearDown() {
        database.close()
    }

    @Test
    fun `an otpauth uri with fields no code can be computed from is rejected and nothing is stored`() {
        val bad = listOf(
            "otpauth://totp/x?secret=$SECRET&digits=10",
            "otpauth://totp/x?secret=$SECRET&digits=4",
            "otpauth://totp/x?secret=$SECRET&period=0",
            "otpauth://totp/x?secret=$SECRET&period=-30",
            "otpauth://totp/x?secret=$SECRET&period=301",
            "otpauth://totp/x?secret=$SECRET&algorithm=MD5",
            "otpauth://hotp/x?secret=$SECRET&digits=9",
            "otpauth://totp/x?secret=A",
            "otpauth://totp/x?secret==",
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PX"
        )
        for (uri in bad) {
            val error = runCatching { runBlocking { repository.importFromUri(uri) } }.exceptionOrNull()
            assertTrue("$uri: ${error?.javaClass}", error is IllegalArgumentException)
            assertFalse("$uri: the message must not carry the secret", error!!.message.orEmpty().contains(SECRET))
        }
        assertEquals(0, runBlocking { dao.count() })
    }

    @Test
    fun `a structured import with fields no code can be computed from is rejected and nothing is stored`() {
        val bad: List<suspend () -> String> = listOf(
            { repository.importStructured(type = "totp", issuer = null, accountName = "x", secret = SECRET, digits = 10) },
            { repository.importStructured(type = "totp", issuer = null, accountName = "x", secret = SECRET, digits = 4) },
            { repository.importStructured(type = "totp", issuer = null, accountName = "x", secret = SECRET, period = 0) },
            { repository.importStructured(type = "totp", issuer = null, accountName = "x", secret = SECRET, period = -30) },
            { repository.importStructured(type = "totp", issuer = null, accountName = "x", secret = SECRET, algorithm = "MD5") },
            { repository.importStructured(type = "hotp", issuer = null, accountName = "x", secret = "A") },
            { repository.importStructured(type = "totp", issuer = null, accountName = "x", secret = "=") }
        )
        bad.forEachIndexed { index, import ->
            val error = runCatching { runBlocking { import() } }.exceptionOrNull()
            assertTrue("case $index: ${error?.javaClass}", error is IllegalArgumentException)
            assertFalse("case $index: the message must not carry the secret", error!!.message.orEmpty().contains(SECRET))
        }
        assertEquals(0, runBlocking { dao.count() })
    }

    @Test
    fun `the supported ranges still import, algorithm in any case`() = runBlocking {
        repository.importFromUri("otpauth://totp/a?secret=$SECRET&digits=6&period=1&algorithm=sha1")
        repository.importFromUri("otpauth://totp/b?secret=$SECRET&digits=7&period=300&algorithm=Sha256")
        repository.importFromUri("otpauth://hotp/c?secret=$SECRET&digits=8&algorithm=SHA512")
        repository.importStructured(type = "totp", issuer = null, accountName = "d", secret = SECRET, period = 60)

        assertEquals(4, dao.count())
        assertEquals(setOf("SHA1", "SHA256", "SHA512"), dao.getAll().map { it.algorithm }.toSet())
    }

    @Test
    fun `a row whose secret cannot be decrypted is flagged and the rest of the list still has codes`() = runBlocking {
        val good = repository.addCredential(issuer = "A", accountName = "good", secret = RFC_SEED)
        val bad = repository.addCredential(issuer = "B", accountName = "bad", secret = CORRUPT)

        val rows = repository.observeAll().first().associateBy { it.credential.oathId }

        assertEquals(2, rows.size)
        assertFalse(rows.getValue(good).codeError)
        assertEquals(6, rows.getValue(good).code.length)
        assertTrue(rows.getValue(good).code.all { it.isDigit() })
        assertTrue(rows.getValue(bad).codeError)
        assertFalse(rows.getValue(bad).code.any { it.isDigit() })

        repository.deleteCredential(bad)
        assertEquals(listOf(good), repository.observeAll().first().map { it.credential.oathId })
    }

    @Test
    fun `two concurrent HOTP generations hand out two codes and advance the counter twice`() = runBlocking {
        val id = repository.addCredential(issuer = "A", accountName = "hotp", secret = RFC_SEED, type = "HOTP")
        // Both calls read the stored counter before either writes: the
        // interleaving of a desktop generate and a phone tap.
        val reads = AtomicInteger()
        val bothRead = CompletableDeferred<Unit>()
        val racing = OathRepository(
            object : OathCredentialDao by dao {
                override suspend fun getByOathId(oathId: String): OathCredentialEntity? {
                    val row = dao.getByOathId(oathId)
                    val n = reads.incrementAndGet()
                    if (n == 2) bothRead.complete(Unit)
                    if (n <= 2) bothRead.await()
                    return row
                }
            },
            secretManager
        )

        val codes = listOf(async { racing.generateCode(id) }, async { racing.generateCode(id) }).awaitAll()

        // RFC 4226 appendix D: counter 0 and counter 1.
        assertEquals(setOf("755224", "287082"), codes.toSet())
        assertEquals(2L, dao.getByOathId(id)!!.counter)
    }

    private companion object {
        /** The RFC 4226 appendix D seed. */
        val RFC_SEED = "12345678901234567890".toByteArray(Charsets.US_ASCII)

        /** A stored secret the secret manager cannot decrypt (an invalidated Keystore key). */
        val CORRUPT = ByteArray(16) { 0x5A }

        /** 16 Base32 characters: 10 bytes, the 80-bit minimum. */
        const val SECRET = "JBSWY3DPEHPK3PXP"
    }
}

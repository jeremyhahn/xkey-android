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
import android.util.Log
import com.automatethethings.xkey.audit.AuditLogger
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import io.mockk.verify
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.yield
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.net.URI
import java.net.URLDecoder

/**
 * OATH add, delete and code generation are audited in [OathRepository], so
 * the phone's own screens (QR scan, manual entry, delete, HOTP copy) and the
 * desktop's local.oath* requests write the same row, each exactly once. A
 * list refresh ([OathRepository.observeAll]) writes none.
 */
class OathRepositoryAuditTest {

    private val inserted = mutableListOf<OathCredentialEntity>()
    private lateinit var dao: OathCredentialDao
    private lateinit var repository: OathRepository

    @Before
    fun setUp() {
        mockkStatic(Log::class)
        every { Log.w(any(), any<String>()) } returns 0
        every { Log.e(any(), any<String>(), any()) } returns 0

        mockkObject(AuditLogger)
        every { AuditLogger.logOathCredentialCreated(any(), any(), any(), any(), any(), any()) } returns Unit
        every { AuditLogger.logOathCredentialDeleted(any(), any(), any(), any(), any()) } returns Unit
        every { AuditLogger.logOathCodeGenerated(any(), any(), any(), any(), any()) } returns Unit

        dao = mockk(relaxed = true)
        coEvery { dao.insert(any()) } answers { inserted += firstArg<OathCredentialEntity>(); 1L }
        coEvery { dao.getByOathId(any()) } returns null
        coEvery { dao.getByOathId(HOTP_ID) } returns stored(HOTP_ID, "HOTP")
        coEvery { dao.getByOathId(TOTP_ID) } returns stored(TOTP_ID, "TOTP")
        // A relaxed mock returns false, which reads as a lost counter race.
        coEvery { dao.claimAndRecordUsage(any(), any(), any(), any()) } returns true
        // Likewise a delete count of 0 reads as a delete that removed nothing.
        coEvery { dao.deleteAndRecordDeletion(any(), any()) } returns 1

        val secretManager = mockk<OathSecretManager>()
        every { secretManager.encryptSecret(any()) } answers { firstArg() }
        every { secretManager.decryptSecret(any()) } answers { firstArg() }
        mockkStatic(Uri::class)
        every { Uri.parse(any()) } answers { jvmUri(firstArg()) }
        repository = OathRepository(dao, secretManager)
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    @Test
    fun `a manual add writes one created row under the stored id`() = runTest {
        val id = repository.addCredential(issuer = "Acme", accountName = "alice", secret = SECRET_BYTES, type = "hotp")

        verify(exactly = 1) { AuditLogger.logOathCredentialCreated(id, "Acme", "alice", "HOTP", any(), any()) }
        verify(exactly = 1) { AuditLogger.logOathCredentialCreated(any(), any(), any(), any(), any(), any()) }
    }

    @Test
    fun `a scanned uri import writes one created row`() = runTest {
        val id = repository.importFromUri("otpauth://totp/GitHub:alice?secret=$SECRET&issuer=GitHub")

        verify(exactly = 1) { AuditLogger.logOathCredentialCreated(id, "GitHub", "alice", "TOTP", any(), any()) }
        verify(exactly = 1) { AuditLogger.logOathCredentialCreated(any(), any(), any(), any(), any(), any()) }
    }

    @Test
    fun `a structured import writes one created row`() = runTest {
        val id = repository.importStructured(type = "totp", issuer = null, accountName = "host:user", secret = SECRET)

        verify(exactly = 1) { AuditLogger.logOathCredentialCreated(id, null, "host:user", "TOTP", any(), any()) }
        verify(exactly = 1) { AuditLogger.logOathCredentialCreated(any(), any(), any(), any(), any(), any()) }
    }

    @Test
    fun `deleting a credential writes one deleted row`() = runTest {
        val deleted = repository.deleteCredential(HOTP_ID)

        assertTrue(deleted)
        coVerify(exactly = 1) { dao.deleteAndRecordDeletion(HOTP_ID, any()) }
        verify(exactly = 1) { AuditLogger.logOathCredentialDeleted(HOTP_ID, ISSUER, ACCOUNT, any(), any()) }
        verify(exactly = 1) { AuditLogger.logOathCredentialDeleted(any(), any(), any(), any(), any()) }
    }

    @Test
    fun `deleting an unknown credential deletes and logs nothing`() = runTest {
        val deleted = repository.deleteCredential("nope")

        assertFalse(deleted)
        coVerify(exactly = 0) { dao.deleteAndRecordDeletion(any(), any()) }
        verify(exactly = 0) { AuditLogger.logOathCredentialDeleted(any(), any(), any(), any(), any()) }
    }

    @Test
    fun `two deletes that both read the credential write one deleted row`() = runTest {
        // Both calls read the stored credential before either deletes it (a
        // phone delete racing local.oathRemove); the row is removed once.
        var rowsLeft = 1
        coEvery { dao.deleteAndRecordDeletion(HOTP_ID, any()) } coAnswers {
            yield()
            if (rowsLeft > 0) { rowsLeft--; 1 } else 0
        }

        var first: Boolean? = null
        var second: Boolean? = null
        launch { first = repository.deleteCredential(HOTP_ID) }
        launch { second = repository.deleteCredential(HOTP_ID) }
        advanceUntilIdle()

        coVerify(exactly = 2) { dao.getByOathId(HOTP_ID) }
        coVerify(exactly = 2) { dao.deleteAndRecordDeletion(HOTP_ID, any()) }
        assertEquals(true, first)
        assertEquals(false, second)
        verify(exactly = 1) { AuditLogger.logOathCredentialDeleted(HOTP_ID, ISSUER, ACCOUNT, any(), any()) }
        verify(exactly = 1) { AuditLogger.logOathCredentialDeleted(any(), any(), any(), any(), any()) }
    }

    @Test
    fun `an HOTP code generation writes one generated row`() = runTest {
        repository.generateCode(HOTP_ID)

        coVerify(exactly = 1) { dao.claimAndRecordUsage(HOTP_ID, 5L, true, any()) }
        verify(exactly = 1) { AuditLogger.logOathCodeGenerated(HOTP_ID, ISSUER, ACCOUNT, any(), any()) }
        verify(exactly = 1) { AuditLogger.logOathCodeGenerated(any(), any(), any(), any(), any()) }
    }

    @Test
    fun `a list refresh writes no generated row`() = runTest {
        every { dao.observeAll() } returns flowOf(listOf(stored(TOTP_ID, "TOTP"), stored(HOTP_ID, "HOTP")))

        assertEquals(2, repository.observeAll().first().size)

        verify(exactly = 0) { AuditLogger.logOathCodeGenerated(any(), any(), any(), any(), any()) }
    }

    // -----------------------------------------------------------------------
    // Cancellation between the commit and the audit
    // -----------------------------------------------------------------------

    /**
     * Cancels the caller once the DAO has committed, then suspends the way
     * Room does when it resumes the caller after a write, so a cancellable
     * caller sees the cancellation before its next line runs.
     */
    private suspend fun cancelAfterCommit(caller: () -> Job) {
        caller().cancel()
        yield()
    }

    @Test
    fun `an add cancelled after its commit is still audited`() = runTest {
        lateinit var job: Job
        coEvery { dao.insert(any()) } coAnswers {
            inserted += firstArg<OathCredentialEntity>()
            cancelAfterCommit { job }
            1L
        }

        job = launch {
            repository.addCredential(issuer = "Acme", accountName = "alice", secret = SECRET_BYTES, type = "hotp")
        }
        advanceUntilIdle()

        assertEquals("the add must have committed", 1, inserted.size)
        val id = inserted.single().oathId
        verify(exactly = 1) { AuditLogger.logOathCredentialCreated(id, "Acme", "alice", "HOTP", any(), any()) }
        verify(exactly = 1) { AuditLogger.logOathCredentialCreated(any(), any(), any(), any(), any(), any()) }
    }

    @Test
    fun `a delete cancelled after its commit is still audited`() = runTest {
        var committed = false
        lateinit var job: Job
        coEvery { dao.deleteAndRecordDeletion(HOTP_ID, any()) } coAnswers {
            committed = true
            cancelAfterCommit { job }
            1
        }

        job = launch { repository.deleteCredential(HOTP_ID) }
        advanceUntilIdle()

        assertTrue("the delete must have committed", committed)
        verify(exactly = 1) { AuditLogger.logOathCredentialDeleted(HOTP_ID, ISSUER, ACCOUNT, any(), any()) }
        verify(exactly = 1) { AuditLogger.logOathCredentialDeleted(any(), any(), any(), any(), any()) }
    }

    @Test
    fun `an HOTP generation cancelled after its counter commit is still audited`() = runTest {
        lateinit var job: Job
        coEvery { dao.claimAndRecordUsage(HOTP_ID, 5L, true, any()) } coAnswers {
            cancelAfterCommit { job }
            true
        }

        job = launch { repository.generateCode(HOTP_ID) }
        advanceUntilIdle()

        coVerify(exactly = 1) { dao.claimAndRecordUsage(HOTP_ID, 5L, true, any()) }
        verify(exactly = 1) { AuditLogger.logOathCodeGenerated(HOTP_ID, ISSUER, ACCOUNT, any(), any()) }
        verify(exactly = 1) { AuditLogger.logOathCodeGenerated(any(), any(), any(), any(), any()) }
    }

    // -----------------------------------------------------------------------
    // One choke point for the claim and the usage
    // -----------------------------------------------------------------------

    @Test
    fun `no main source outside the DAO claims an OATH counter or records an OATH usage directly`() {
        val root = listOf(java.io.File("src/main/kotlin"), java.io.File("app/src/main/kotlin")).first { it.isDirectory }
        val offenders = root.walkTopDown()
            .filter { it.isFile && it.name.endsWith(".kt") && it.name != "OathCredentialDao.kt" }
            .flatMap { file -> directOathWrites.findAll(file.readText()).map { "${file.name}: ${it.value}" } }
            .toList()
        assertTrue("direct OATH claim or usage writes: $offenders", offenders.isEmpty())
    }

    @Test
    fun `the scan catches each bypass form`() {
        listOf(
            "dao.claimCounter(id, 5L)",
            "dao.recordUsage(id, now)",
            "db.oathCredentialDao().recordUsage(id)",
            "oathDao.claimCounter(id, 1)",
            "oathCredentialDao.recordUsage(id)"
        ).forEach { assertTrue(it, directOathWrites.containsMatchIn(it)) }
        listOf("keyDao.recordUsage(id)", "pivSlotDao.recordUsage(slot)", "dao.claimAndRecordUsage(id, 5L, true, now)")
            .forEach { assertTrue(it, !directOathWrites.containsMatchIn(it)) }
    }

    /** A claimCounter call on any receiver, or recordUsage on an OATH DAO receiver. */
    private val directOathWrites =
        Regex("""\.claimCounter\(|(\bdao|oath\w*Dao(\(\))?)\.recordUsage\(""", RegexOption.IGNORE_CASE)

    private fun stored(id: String, type: String) = OathCredentialEntity(
        oathId = id,
        oathType = type,
        algorithm = "SHA1",
        digits = 6,
        periodSeconds = 30,
        counter = 5L,
        issuer = ISSUER,
        accountName = ACCOUNT,
        secretEncrypted = SECRET_BYTES,
        source = "local",
        createdAt = 0L
    )

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
        const val SECRET = "JBSWY3DPEHPK3PXP"
        val SECRET_BYTES = ByteArray(10) { it.toByte() }
        const val HOTP_ID = "hotp-1"
        const val TOTP_ID = "totp-1"
        const val ISSUER = "Acme"
        const val ACCOUNT = "alice"
    }
}

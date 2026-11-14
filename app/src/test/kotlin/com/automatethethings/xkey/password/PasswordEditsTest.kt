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
package com.automatethethings.xkey.password

import com.automatethethings.xkey.audit.AuditLogDao
import com.automatethethings.xkey.audit.AuditLogEntity
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.audit.AuditOperationType
import com.automatethethings.xkey.crypto.KeystoreAeadCipher
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.unmockkAll
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.yield
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import java.io.File
import java.lang.reflect.Modifier
import java.util.concurrent.atomic.AtomicReference

/**
 * Unit tests for [PasswordEdits], the phone screen's add and delete path.
 *
 * A real [PasswordRepository] runs over a mocked DAO and a stub cipher, so the
 * size limit refuses an oversized add exactly as it does on the device; the
 * [AuditLogger] singleton writes to a capturing DAO on an unconfined scope.
 */
class PasswordEditsTest {

    private lateinit var passwordDao: PasswordDao
    private lateinit var edits: PasswordEdits
    private val audited = mutableListOf<AuditLogEntity>()

    @Suppress("UNCHECKED_CAST")
    private fun <T> holder(name: String): AtomicReference<T?> =
        AuditLogger::class.java.getDeclaredField(name)
            .apply { isAccessible = true }
            .get(AuditLogger) as AtomicReference<T?>

    @Before
    fun setUp() {
        passwordDao = mockk(relaxed = true)
        coEvery { passwordDao.getByPasswordId(any()) } returns null
        val cipher = mockk<KeystoreAeadCipher>()
        every { cipher.encrypt(any()) } answers { byteArrayOf(0x7f) + firstArg<ByteArray>() }
        edits = PasswordEdits(PasswordRepository(passwordDao, cipher))

        audited.clear()
        val auditDao = mockk<AuditLogDao>(relaxed = true)
        coEvery { auditDao.insert(any()) } answers {
            audited += firstArg<AuditLogEntity>()
            audited.size.toLong()
        }
        holder<AuditLogDao>("daoRef").set(auditDao)
        holder<CoroutineScope>("scopeRef").set(CoroutineScope(Dispatchers.Unconfined))
    }

    @After
    fun tearDown() {
        holder<AuditLogDao>("daoRef").set(null)
        holder<CoroutineScope>("scopeRef").set(null)
        unmockkAll()
    }

    private fun record(
        passwordId: String = "pwd-1",
        // Built at run time so no credential-shaped literal sits in the source.
        password: String = listOf("plain", "marker", "1").joinToString("-")
    ) = PasswordRecord(
        passwordId = passwordId,
        name = "example",
        title = "Example Login",
        username = "user@example.com",
        password = password,
        url = "https://example.com/login",
        notes = "recovery code 0000",
        source = "local"
    )

    @Test
    fun `an add writes one PASSWORD_CREATED entry with the id and name`() = runTest {
        assertEquals("pwd-1", edits.add(record()))

        coVerify(exactly = 1) { passwordDao.insert(any()) }
        assertEquals(1, audited.size)
        val entry = audited.single()
        assertEquals(AuditOperationType.PASSWORD_CREATED, entry.operationType)
        assertEquals("pwd-1", entry.keyId)
        assertEquals("Example Login", entry.keyLabel)
    }

    @Test
    fun `each add writes its own entry`() = runTest {
        edits.add(record(passwordId = "pwd-1"))
        edits.add(record(passwordId = "pwd-2"))

        assertEquals(listOf("pwd-1", "pwd-2"), audited.map { it.keyId })
        assertTrue(audited.all { it.operationType == AuditOperationType.PASSWORD_CREATED })
    }

    @Test
    fun `an add without a title is named by its name`() = runTest {
        edits.add(record().copy(title = null))

        assertEquals("example", audited.single().keyLabel)
    }

    @Test
    fun `a refused add writes no entry and the refusal reaches the caller`() = runTest {
        val oversized = record(password = "x".repeat(PasswordEntryLimit.MAX_ENTRY_SIZE + 1))
        try {
            edits.add(oversized)
            fail("expected PasswordEntryTooLargeException")
        } catch (expected: PasswordEntryTooLargeException) {
            // reaches the caller
        }

        coVerify(exactly = 0) { passwordDao.insert(any()) }
        assertTrue("a refused add may not be audited", audited.isEmpty())
    }

    @Test
    fun `a delete writes one PASSWORD_DELETED entry with the id and name`() = runTest {
        coEvery { passwordDao.deleteByPasswordId("pwd-1") } returns 1

        assertTrue(edits.delete(record()))

        val entry = audited.single()
        assertEquals(AuditOperationType.PASSWORD_DELETED, entry.operationType)
        assertEquals("pwd-1", entry.keyId)
        assertEquals("Example Login", entry.keyLabel)
    }

    @Test
    fun `a delete that removed nothing writes no entry`() = runTest {
        coEvery { passwordDao.deleteByPasswordId("pwd-1") } returns 0

        assertFalse(edits.delete(record()))

        assertTrue(audited.isEmpty())
    }

    @Test
    fun `no entry holds the password, username, URL or notes`() = runTest {
        coEvery { passwordDao.deleteByPasswordId("pwd-1") } returns 1
        val r = record()

        edits.add(r)
        edits.delete(r)

        assertEquals(2, audited.size)
        val secrets = listOf(r.password, r.username!!, r.url!!, r.notes!!)
        for (entry in audited) {
            val written = listOfNotNull(
                entry.keyId, entry.keyLabel, entry.keyType, entry.deviceId,
                entry.deviceName, entry.errorMessage, entry.details
            ).joinToString("\n")
            for (secret in secrets) {
                assertFalse("${entry.operationType} holds \"$secret\"", written.contains(secret))
            }
        }
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
        var committed = false
        lateinit var job: Job
        coEvery { passwordDao.insert(any()) } coAnswers {
            committed = true
            cancelAfterCommit { job }
            1L
        }

        job = launch { edits.add(record()) }
        advanceUntilIdle()

        assertTrue("the add must have committed", committed)
        assertEquals(
            "a committed add must be audited even when its caller is cancelled",
            listOf(AuditOperationType.PASSWORD_CREATED),
            audited.map { it.operationType }
        )
    }

    @Test
    fun `a delete cancelled after its commit is still audited`() = runTest {
        lateinit var job: Job
        coEvery { passwordDao.deleteByPasswordId("pwd-1") } coAnswers {
            cancelAfterCommit { job }
            1
        }

        job = launch { edits.delete(record()) }
        advanceUntilIdle()

        assertEquals(
            "a committed delete must be audited even when its caller is cancelled",
            listOf(AuditOperationType.PASSWORD_DELETED),
            audited.map { it.operationType }
        )
    }

    @Test
    fun `every password write on PasswordEdits is one of the audited paths`() {
        // Each public method here is a vault write covered by the cancellation
        // tests above. A new write method fails this test until it runs through
        // the audited choke point and gains its own cancellation test.
        val writes = PasswordEdits::class.java.declaredMethods
            .filter { Modifier.isPublic(it.modifiers) && !it.isSynthetic }
            .map { it.name }
            .toSet()
        assertEquals(setOf("add", "delete"), writes)
    }

    @Test
    fun `no main source writes a password through the repository outside the audited paths`() {
        // The phone's password writes go through PasswordEdits. The desktop
        // paths (USB verbs, sync) write through the repository and are
        // audited by their own request handling.
        val allowed = setOf(
            "password/PasswordEdits.kt",
            "password/PasswordRepository.kt",
            "usb/PasswordStoreMethods.kt"
        )
        val root = File("src/main/kotlin/com/automatethethings/xkey")
        assertTrue("run from the app module: ${root.absolutePath}", root.isDirectory)
        val write = Regex("""\b\w*[rR]epository\??\.(upsert|delete)\(""")
        val offenders = root.walkTopDown()
            .filter { it.isFile && it.extension == "kt" }
            .filter { it.readText().contains("PasswordRepository") }
            .map { it.relativeTo(root).invariantSeparatorsPath }
            .filter { it !in allowed && !it.startsWith("sync/") }
            .filter { write.containsMatchIn(File(root, it).readText()) }
            .toList()
        assertEquals("password writes that bypass PasswordEdits", emptyList<String>(), offenders)
    }
}

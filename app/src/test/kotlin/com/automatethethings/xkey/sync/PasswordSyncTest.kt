// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Licensed under AGPL-3.0 (see LICENSE) or a commercial license.
// Contact licensing@automatethethings.com for commercial licensing options.

package com.automatethethings.xkey.sync

import android.util.Log
import com.automatethethings.xkey.crypto.KeystoreAeadCipher
import com.automatethethings.xkey.crypto.SyncCodec
import com.automatethethings.xkey.password.FakePasswordDao
import com.automatethethings.xkey.password.InMemoryPasswordDeletions
import com.automatethethings.xkey.password.PasswordDeletionQueries
import com.automatethethings.xkey.password.PassphraseHasher
import com.automatethethings.xkey.password.PasswordDao
import com.automatethethings.xkey.password.PasswordEntity
import com.automatethethings.xkey.password.PasswordPatch
import com.automatethethings.xkey.password.PasswordRecord
import com.automatethethings.xkey.password.PasswordRepository
import com.automatethethings.xkey.password.PasswordStoreLockedException
import com.automatethethings.xkey.password.PasswordVault
import com.automatethethings.xkey.password.PasswordVaultCredential
import com.automatethethings.xkey.password.PasswordVaultFactorRecord
import com.automatethethings.xkey.password.PasswordVaultFactorStore
import com.automatethethings.xkey.password.SessionPasswordVault
import com.automatethethings.xkey.password.VaultUnlockAttemptStore
import com.automatethethings.xkey.password.VaultUnlockLimits
import com.automatethethings.xkey.settings.PinSettingsData
import com.automatethethings.xkey.settings.VaultUnlockAttempts
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.slot
import io.mockk.unmockkAll
import io.mockk.verify
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.security.MessageDigest

/**
 * Unit tests for [PasswordSync]: password sync is refused while the password
 * vault is locked, writes nothing when refused, hashes nothing to refuse, and
 * syncs as before once the session's vault is unlocked or when no factor is
 * enrolled.
 *
 * The Keystore is stubbed with the reversible marker transform
 * [com.automatethethings.xkey.password.PasswordRepositoryTest] uses, the DAO
 * is an in-memory map, and the vault hashes with a counting SHA-256 because
 * Argon2 is native and absent on the JVM.
 */
class PasswordSyncTest {

    private val marker: Byte = 0x7f
    private val updatedAt = 1_700_000_000_000L
    private val updatedAtIso = "2023-11-14T22:13:20Z"
    private val passphrase = "correct horse battery staple"

    private lateinit var cipher: KeystoreAeadCipher
    private lateinit var dao: InMemoryPasswordDao
    private lateinit var repository: PasswordRepository
    private lateinit var factors: InMemoryFactorStore
    private lateinit var vault: PasswordVault
    private lateinit var sync: PasswordSync
    private var hashes = 0

    /** The phone's clock, read by both the repository and the sync: an hour after [updatedAt]. */
    private var now = updatedAt + 60 * MINUTE

    private fun iso(millis: Long): String = SyncCodec.toRfc3339(millis)

    private class InMemoryPasswordDao(
        val deletions: InMemoryPasswordDeletions = InMemoryPasswordDeletions()
    ) : PasswordDao, PasswordDeletionQueries by deletions {
        val rows = linkedMapOf<String, PasswordEntity>()
        private var rowId = 0L

        override suspend fun insert(password: PasswordEntity): Long {
            val id = if (password.id != 0L) password.id else ++rowId
            rows[password.passwordId] = password.copy(id = id)
            return id
        }
        override suspend fun insertIfAbsent(password: PasswordEntity): Long =
            if (rows.containsKey(password.passwordId)) -1 else insert(password.copy(id = 0))
        override suspend fun update(password: PasswordEntity): Int {
            if (rows[password.passwordId]?.id != password.id) return 0
            rows[password.passwordId] = password
            return 1
        }
        override suspend fun updateFieldsIfUnchanged(
            id: Long,
            expectedPasswordEncrypted: ByteArray,
            expectedName: String,
            expectedTitle: String?,
            expectedUsername: String?,
            expectedUrl: String?,
            expectedNotes: String?,
            expectedFolderPath: String?,
            expectedSource: String,
            expectedCreatedAt: Long,
            expectedUpdatedAt: Long,
            expectedExpiresAt: String?,
            expectedShared: Boolean,
            expectedTenantId: String,
            name: String,
            title: String?,
            username: String?,
            passwordEncrypted: ByteArray,
            url: String?,
            notes: String?,
            folderPath: String?,
            source: String,
            expiresAt: String?,
            updatedAt: Long
        ): Int {
            val current = rows.values.firstOrNull {
                it.id == id && it.passwordEncrypted.contentEquals(expectedPasswordEncrypted) &&
                    it.name == expectedName && it.title == expectedTitle && it.username == expectedUsername &&
                    it.url == expectedUrl && it.notes == expectedNotes && it.folderPath == expectedFolderPath &&
                    it.source == expectedSource && it.createdAt == expectedCreatedAt &&
                    it.updatedAt == expectedUpdatedAt && it.expiresAt == expectedExpiresAt &&
                    it.shared == expectedShared && it.tenantId == expectedTenantId
            } ?: return 0
            rows[current.passwordId] = current.copy(
                name = name, title = title, username = username, passwordEncrypted = passwordEncrypted,
                url = url, notes = notes, folderPath = folderPath, source = source, expiresAt = expiresAt,
                updatedAt = updatedAt
            )
            return 1
        }
        override fun observeAll(): Flow<List<PasswordEntity>> = flowOf(rows.values.toList())
        override suspend fun getAll(): List<PasswordEntity> = rows.values.sortedBy { it.name }
        override suspend fun getByPasswordId(passwordId: String): PasswordEntity? = rows[passwordId]
        override suspend fun getByPasswordIdInTenant(passwordId: String, tenantId: String): PasswordEntity? =
            rows[passwordId]?.takeIf { it.tenantId == tenantId }
        override suspend fun getForListing(tenantId: String, shared: Boolean?, folderPath: String?): List<PasswordEntity> =
            getAll().filter {
                it.tenantId == tenantId && (shared == null || it.shared == shared) &&
                    (folderPath == null || it.folderPath == folderPath)
            }
        override suspend fun getBySource(source: String): List<PasswordEntity> =
            rows.values.filter { it.source == source }
        override suspend fun deleteByPasswordId(passwordId: String): Int =
            if (rows.remove(passwordId) != null) 1 else 0
        override suspend fun deleteByPasswordIdInTenant(passwordId: String, tenantId: String): Int =
            if (rows[passwordId]?.tenantId == tenantId) deleteByPasswordId(passwordId) else 0
        override suspend fun count(): Int = rows.size
        override fun observeCount(): Flow<Int> = flowOf(rows.size)
    }

    private class InMemoryFactorStore : PasswordVaultFactorStore {
        val records = mutableListOf<PasswordVaultFactorRecord>()
        override suspend fun list(): List<PasswordVaultFactorRecord> = records.toList()
        override suspend fun add(record: PasswordVaultFactorRecord) {
            records += record
        }
    }

    private class InMemoryAttemptStore : VaultUnlockAttemptStore {
        var counter = VaultUnlockAttempts()
        override suspend fun limits(): VaultUnlockLimits =
            PinSettingsData().let { VaultUnlockLimits(it.maxPinAttempts, it.lockoutDurationSeconds) }
        override suspend fun read(): VaultUnlockAttempts = counter
        override suspend fun write(attempts: VaultUnlockAttempts) {
            counter = attempts
        }
    }

    @Before
    fun setUp() {
        cipher = mockk<KeystoreAeadCipher>()
        every { cipher.encrypt(any()) } answers { byteArrayOf(marker) + firstArg<ByteArray>() }
        every { cipher.decrypt(any()) } answers {
            firstArg<ByteArray>().copyOfRange(1, firstArg<ByteArray>().size)
        }
        dao = InMemoryPasswordDao()
        repository = PasswordRepository(dao, cipher, clock = { now })
        factors = InMemoryFactorStore()
        vault = PasswordVault(factors, InMemoryAttemptStore(), PassphraseHasher { phrase, salt ->
            hashes++
            MessageDigest.getInstance("SHA-256").run {
                update(salt)
                digest(phrase.toByteArray(Charsets.UTF_8))
            }
        })
        sync = PasswordSync(repository, factors, clock = { now })
        mockkStatic(Log::class)
        every { Log.w(any<String>(), any<String>()) } returns 0
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    private suspend fun storeLocal(id: String = "local-1", password: String = "hunter2") {
        repository.upsert(PasswordRecord(passwordId = id, name = "GitHub", password = password, updatedAt = updatedAt))
    }

    /** One minute after [updatedAt]: a peer copy newer than the local one. */
    private val newerIso = "2023-11-14T22:14:20Z"

    /** One minute before [updatedAt]: a peer copy older than the local one. */
    private val olderIso = "2023-11-14T22:12:20Z"

    private fun incoming(
        id: String = "remote-1",
        password: String = "s3cret",
        at: String? = updatedAtIso
    ): JSONArray =
        JSONArray().put(
            JSONObject()
                .put("id", id)
                .put("name", "Mail")
                .put("username", "octo")
                .put("password", password)
                .apply { if (at != null) put("updated_at", at) }
        )

    private suspend fun assertLocked(block: suspend () -> Unit) {
        try {
            block()
            throw AssertionError("expected PasswordStoreLockedException")
        } catch (e: PasswordStoreLockedException) {
            // expected
        }
    }

    // -------------------------------------------------------------------------
    // Locked
    // -------------------------------------------------------------------------

    @Test
    fun `a locked session vault refuses the sync read`() = runTest {
        storeLocal()
        vault.enrollPassphrase(passphrase)
        val hashesBefore = hashes

        withContext(SessionPasswordVault(vault)) {
            assertLocked { sync.gather() }
        }

        assertEquals("refusing must run no Argon2id", hashesBefore, hashes)
    }

    @Test
    fun `a locked session vault refuses the sync merge and writes nothing`() = runTest {
        storeLocal()
        vault.enrollPassphrase(passphrase)
        val before = dao.rows.toMap()

        withContext(SessionPasswordVault(vault)) {
            assertLocked { sync.merge(incoming()) }
        }

        assertEquals(before, dao.rows.toMap())
    }

    @Test
    fun `without a session vault an enrolled factor refuses sync even while another session is unlocked`() =
        runTest {
            storeLocal()
            vault.enrollPassphrase(passphrase)
            vault.unlock(PasswordVaultCredential.Passphrase(passphrase))
            val before = dao.rows.toMap()

            // A BLE or TCP request: the USB session's unlocked vault is not in its context.
            assertLocked { sync.gather() }
            assertLocked { sync.merge(incoming()) }

            assertEquals(before, dao.rows.toMap())
        }

    @Test
    fun `locking the session vault again refuses sync`() = runTest {
        vault.enrollPassphrase(passphrase)
        vault.unlock(PasswordVaultCredential.Passphrase(passphrase))
        vault.lock()

        withContext(SessionPasswordVault(vault)) {
            assertLocked { sync.gather() }
        }
    }

    // -------------------------------------------------------------------------
    // Unlocked or uninitialized: unchanged
    // -------------------------------------------------------------------------

    @Test
    fun `an unlocked session vault syncs as before`() = runTest {
        storeLocal()
        vault.enrollPassphrase(passphrase)
        vault.unlock(PasswordVaultCredential.Passphrase(passphrase))

        val (counts, out) = withContext(SessionPasswordVault(vault)) {
            sync.merge(incoming()) to sync.gather()
        }

        assertEquals(SyncEngine.ItemCounts(added = 1, updated = 0, skipped = 0), counts)
        assertEquals(2, out.length())
        val mail = (0 until out.length()).map { out.getJSONObject(it) }.single { it.getString("id") == "remote-1" }
        assertEquals("s3cret", mail.getString("password"))
        assertEquals("octo", mail.getString("username"))
        assertEquals(updatedAtIso, mail.getString("updated_at"))
        assertEquals("remote", dao.rows.getValue("remote-1").source)
    }

    @Test
    fun `with no factor enrolled sync is unchanged on every transport`() = runTest {
        storeLocal()

        val counts = sync.merge(incoming())
        val out = sync.gather()
        val sessionOut = withContext(SessionPasswordVault(vault)) { sync.gather() }

        assertEquals(SyncEngine.ItemCounts(added = 1, updated = 0, skipped = 0), counts)
        assertEquals(2, out.length())
        assertEquals(2, sessionOut.length())
        assertEquals("hunter2", out.getJSONObject(0).getString("password"))
    }

    @Test
    fun `merge still counts updates and skips entries without an id or password`() = runTest {
        storeLocal(id = "remote-1", password = "old")
        val batch = incoming(id = "remote-1", password = "new", at = newerIso)
            .put(JSONObject().put("id", "").put("password", "x"))
            .put(JSONObject().put("id", "no-password"))

        val counts = sync.merge(batch)

        assertEquals(SyncEngine.ItemCounts(added = 0, updated = 1, skipped = 2), counts)
        assertEquals("new", repository.get("remote-1")!!.password)
    }

    // -------------------------------------------------------------------------
    // Last writer wins by updated_at
    // -------------------------------------------------------------------------

    @Test
    fun `an incoming entry with a newer updated_at overwrites the local one`() = runTest {
        storeLocal(id = "remote-1", password = "old")

        val counts = sync.merge(incoming(id = "remote-1", password = "new", at = newerIso))

        assertEquals(SyncEngine.ItemCounts(added = 0, updated = 1, skipped = 0), counts)
        assertEquals("new", repository.get("remote-1")!!.password)
        assertEquals(SyncCodec.parseRfc3339(newerIso), dao.rows.getValue("remote-1").updatedAt)
    }

    @Test
    fun `an incoming entry with an older updated_at keeps the local one`() = runTest {
        assertKeptLocal(olderIso)
    }

    @Test
    fun `an incoming entry with an equal updated_at keeps the local one`() = runTest {
        assertKeptLocal(updatedAtIso)
    }

    @Test
    fun `an incoming entry with no updated_at keeps the local one`() = runTest {
        assertKeptLocal(null)
    }

    @Test
    fun `an incoming entry with an unparseable updated_at keeps the local one`() = runTest {
        assertKeptLocal("yesterday")
    }

    @Test
    fun `a new entry with a malformed updated_at is rejected and the rest still merge`() = runTest {
        val batch = incoming(id = "bad-time", password = "x", at = "yesterday")
            .put(incoming(id = "remote-2", password = "y", at = newerIso).getJSONObject(0))

        val counts = sync.merge(batch)

        assertEquals(SyncEngine.ItemCounts(added = 1, updated = 0, skipped = 1), counts)
        assertNull("a malformed timestamp must not be stored as zero", repository.get("bad-time"))
        assertEquals("y", repository.get("remote-2")!!.password)
        verify { Log.w(any<String>(), match<String> { !it.contains("yesterday") && !it.contains("bad-time") }) }
    }

    @Test
    fun `a new entry with a blank updated_at is still added`() = runTest {
        val counts = sync.merge(incoming(id = "no-time", password = "x", at = ""))

        assertEquals(SyncEngine.ItemCounts(added = 1, updated = 0, skipped = 0), counts)
        assertEquals("x", repository.get("no-time")!!.password)
    }

    private suspend fun assertKeptLocal(at: String?) {
        storeLocal(id = "remote-1", password = "old")
        val before = dao.rows.getValue("remote-1")

        val counts = sync.merge(incoming(id = "remote-1", password = "new", at = at))

        assertEquals(SyncEngine.ItemCounts(added = 0, updated = 0, skipped = 1), counts)
        assertEquals(before, dao.rows.getValue("remote-1"))
        assertEquals("old", repository.get("remote-1")!!.password)
    }

    // -------------------------------------------------------------------------
    // Policy fields: SyncPassword carries none, so a merge writes only default-policy entries
    // -------------------------------------------------------------------------

    @Test
    fun `merging leaves an entry of another tenant, a shared one and an expiring one unchanged`() = runTest {
        repository.upsert(
            PasswordRecord(passwordId = "work-1", name = "Work", password = "old", updatedAt = updatedAt, tenantId = "work")
        )
        repository.upsert(
            PasswordRecord(passwordId = "shared-1", name = "Team", password = "old", updatedAt = updatedAt, shared = true)
        )
        repository.upsert(
            PasswordRecord(
                passwordId = "expiring-1",
                name = "Temp",
                password = "old",
                updatedAt = updatedAt,
                expiresAt = "2030-01-01T00:00:00Z"
            )
        )
        val before = dao.rows.toMap()
        val incoming = JSONArray()
        for (id in listOf("work-1", "shared-1", "expiring-1")) {
            incoming.put(incoming(id = id, password = "new", at = newerIso).getJSONObject(0))
        }

        val result = sync.mergeWithDetail(incoming)

        // gather() never sends these, so a sync never writes them either: a default-tenant copy is not theirs.
        assertEquals(SyncEngine.ItemCounts(added = 0, updated = 0, skipped = 3), result.counts)
        assertEquals(3, result.notSyncable)
        assertEquals(before, dao.rows.toMap())
        assertEquals("old", repository.get("work-1", "work")!!.password)
        assertEquals("old", repository.get("shared-1")!!.password)
        assertEquals("old", repository.get("expiring-1")!!.password)
    }

    @Test
    fun `merging a new entry adds a personal one with no expiry in the default tenant`() = runTest {
        val counts = sync.merge(incoming())

        assertEquals(SyncEngine.ItemCounts(added = 1, updated = 0, skipped = 0), counts)
        val row = dao.rows.getValue("remote-1")
        assertEquals(null, row.expiresAt)
        assertFalse(row.shared)
        assertEquals(PasswordEntity.DEFAULT_TENANT, row.tenantId)
    }

    @Test
    fun `an entry added and given an expiry while a merge adds it keeps the expiry`() = runTest {
        val racingDao = FakePasswordDao()
        val racingRepository = PasswordRepository(racingDao, cipher)
        val racingSync = PasswordSync(racingRepository, factors)
        // Sync A reads the id absent; before A writes, sync B adds the entry and a PasswordUpdate sets its expiry.
        racingDao.afterRead = {
            racingDao.afterRead = null
            assertEquals(
                SyncEngine.ItemCounts(added = 1, updated = 0, skipped = 0),
                racingSync.merge(incoming(id = "remote-1", password = "from-b"))
            )
            assertTrue(
                racingRepository.updateFields(
                    "remote-1",
                    PasswordPatch(expiresAt = "2030-01-01T00:00:00Z", updatedAt = updatedAt + 1_000L)
                )
            )
        }

        // A's copy is newer than B's and the expiry edit, but the entry now expires, which no sync writes.
        val counts = racingSync.merge(incoming(id = "remote-1", password = "from-a", at = newerIso))

        // A neither replaces the entry B added nor patches it, so the expiry and B's password stay.
        assertEquals(SyncEngine.ItemCounts(added = 0, updated = 0, skipped = 1), counts)
        assertEquals("2030-01-01T00:00:00Z", racingDao.rows.getValue("remote-1").expiresAt)
        assertEquals("from-b", racingRepository.get("remote-1")!!.password)
    }

    @Test
    fun `exporting into an empty store withholds every entry whose policy SyncPassword cannot carry`() = runTest {
        mockkStatic(Log::class)
        val warning = slot<String>()
        every { Log.w(any<String>(), capture(warning)) } returns 0
        storeLocal(id = "plain")
        repository.upsert(PasswordRecord(passwordId = "tenant-entry", name = "T", password = "p", tenantId = "t1"))
        repository.upsert(PasswordRecord(passwordId = "shared-entry", name = "S", password = "p", shared = true))
        repository.upsert(
            PasswordRecord(passwordId = "expiring-entry", name = "E", password = "p", expiresAt = "2030-01-01T00:00:00Z")
        )
        assertEquals(4, dao.rows.size)

        val exported = sync.gather()
        val emptyDao = InMemoryPasswordDao()
        val counts = PasswordSync(PasswordRepository(emptyDao, cipher), factors).merge(exported)

        assertEquals(SyncEngine.ItemCounts(added = 1, updated = 0, skipped = 0), counts)
        assertEquals(setOf("plain"), emptyDao.rows.keys)
        val row = emptyDao.rows.getValue("plain")
        assertEquals(null, row.expiresAt)
        assertFalse(row.shared)
        assertEquals(PasswordEntity.DEFAULT_TENANT, row.tenantId)
        // Only the count is logged, never an id.
        assertTrue(warning.captured.contains("Withheld 3 "))
        for (id in listOf("tenant-entry", "shared-entry", "expiring-entry")) {
            assertFalse(warning.captured.contains(id))
        }
    }

    // -------------------------------------------------------------------------
    // Deletions: a peer that still holds a deleted entry does not bring it back
    // -------------------------------------------------------------------------

    @Test
    fun `an entry deleted on the phone is not restored by a peer copy older than the delete`() = runTest {
        storeLocal(id = "remote-1")
        val deletedAt = now
        assertTrue(repository.delete("remote-1"))
        now += MINUTE

        val result = sync.mergeWithDetail(incoming(id = "remote-1", at = iso(deletedAt - MINUTE)))

        assertEquals(SyncEngine.ItemCounts(added = 0, updated = 0, skipped = 1), result.counts)
        assertEquals(1, result.keptDeleted)
        assertFalse(dao.rows.containsKey("remote-1"))
    }

    @Test
    fun `a peer copy with the deletion time itself does not restore the entry`() = runTest {
        storeLocal(id = "remote-1")
        val deletedAt = now
        assertTrue(repository.delete("remote-1"))

        val counts = sync.merge(incoming(id = "remote-1", at = iso(deletedAt)))

        assertEquals(SyncEngine.ItemCounts(added = 0, updated = 0, skipped = 1), counts)
        assertFalse(dao.rows.containsKey("remote-1"))
    }

    @Test
    fun `a peer copy edited after the phone deleted the entry restores it`() = runTest {
        storeLocal(id = "remote-1")
        val deletedAt = now
        assertTrue(repository.delete("remote-1"))
        now += 2 * MINUTE

        val counts = sync.merge(incoming(id = "remote-1", password = "edited", at = iso(deletedAt + MINUTE)))

        assertEquals(SyncEngine.ItemCounts(added = 1, updated = 0, skipped = 0), counts)
        assertEquals("edited", repository.get("remote-1")!!.password)
    }

    @Test
    fun `a deletion record older than the retention no longer holds the entry back`() = runTest {
        storeLocal(id = "remote-1")
        val deletedAt = now
        assertTrue(repository.delete("remote-1"))
        now = deletedAt + PasswordRepository.DELETION_RETENTION_MS + MINUTE

        val counts = sync.merge(incoming(id = "remote-1", at = iso(deletedAt - MINUTE)))

        assertEquals(SyncEngine.ItemCounts(added = 1, updated = 0, skipped = 0), counts)
        assertTrue(dao.rows.containsKey("remote-1"))
        assertEquals(null, dao.deletions.deletedAt["remote-1"])
    }

    @Test
    fun `an id the phone never deleted is added as before`() = runTest {
        assertFalse(repository.delete("remote-1"))

        val counts = sync.merge(incoming(id = "remote-1"))

        assertEquals(SyncEngine.ItemCounts(added = 1, updated = 0, skipped = 0), counts)
    }

    // -------------------------------------------------------------------------
    // Clock skew: a peer clock far ahead does not pin an entry
    // -------------------------------------------------------------------------

    @Test
    fun `a peer copy dated a year ahead is stored at the phone's time and does not override a later phone edit`() = runTest {
        val yearAhead = iso(now + 365 * DAY)

        val first = sync.mergeWithDetail(incoming(id = "remote-1", password = "desk", at = yearAhead))

        assertEquals(SyncEngine.ItemCounts(added = 1, updated = 0, skipped = 0), first.counts)
        assertEquals(1, first.clamped)
        assertEquals(now, dao.rows.getValue("remote-1").updatedAt)

        now += MINUTE
        assertTrue(repository.updateFields("remote-1", PasswordPatch(password = "phone", updatedAt = now)))
        now += MINUTE

        val second = sync.mergeWithDetail(incoming(id = "remote-1", password = "desk", at = yearAhead))

        assertEquals(SyncEngine.ItemCounts(added = 0, updated = 0, skipped = 1), second.counts)
        assertEquals(1, second.clamped)
        assertEquals("phone", repository.get("remote-1")!!.password)
    }

    @Test
    fun `a peer copy dated a year ahead does not restore an entry the phone deleted`() = runTest {
        storeLocal(id = "remote-1")
        assertTrue(repository.delete("remote-1"))
        now += MINUTE

        val result = sync.mergeWithDetail(incoming(id = "remote-1", at = iso(now + 365 * DAY)))

        assertEquals(SyncEngine.ItemCounts(added = 0, updated = 0, skipped = 1), result.counts)
        assertEquals(1, result.clamped)
        assertFalse(dao.rows.containsKey("remote-1"))
    }

    @Test
    fun `a peer copy within the skew bound is compared as sent`() = runTest {
        storeLocal(id = "remote-1")

        val result = sync.mergeWithDetail(incoming(id = "remote-1", password = "desk", at = iso(now + 4 * MINUTE)))

        assertEquals(SyncEngine.ItemCounts(added = 0, updated = 1, skipped = 0), result.counts)
        assertEquals(0, result.clamped)
        assertEquals(now + 4 * MINUTE, dao.rows.getValue("remote-1").updatedAt)
    }

    private companion object {
        const val MINUTE = 60_000L
        const val DAY = 24 * 60 * MINUTE
    }
}

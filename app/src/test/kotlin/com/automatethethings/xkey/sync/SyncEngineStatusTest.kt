// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Licensed under AGPL-3.0 (see LICENSE) or a commercial license.
// Contact licensing@automatethethings.com for commercial licensing options.

package com.automatethethings.xkey.sync

import android.content.Context
import com.automatethethings.xkey.crypto.KeystoreAeadCipher
import com.automatethethings.xkey.crypto.SyncCodec
import com.automatethethings.xkey.oath.OathCredentialDao
import com.automatethethings.xkey.password.PasswordDao
import com.automatethethings.xkey.password.PasswordEntity
import com.automatethethings.xkey.password.PasswordRepository
import com.automatethethings.xkey.password.PasswordVaultFactorRecord
import com.automatethethings.xkey.password.PasswordVaultFactorStore
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.truststore.TrustStoreRepository
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.mockkObject
import io.mockk.slot
import io.mockk.unmockkAll
import io.mockk.verify
import kotlinx.coroutines.test.runTest
import org.json.JSONArray
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import javax.crypto.AEADBadTagException

/**
 * Unit tests for the password half of `local.syncStatus`
 * ([SyncEngine.storeChecksums]) and for the reads password sync makes that
 * need no secret.
 *
 * The status is answered while the password vault is locked, so its checksum
 * must come from entry IDs and update times alone: no password is decrypted,
 * and an entry that cannot be decrypted does not fail the status. The cipher
 * here counts or refuses decryption; the DAO, the OATH store and the trust
 * store are mocks.
 */
class SyncEngineStatusTest {

    private val marker: Byte = 0x7f
    private lateinit var dao: PasswordDao

    private fun entity(passwordId: String, name: String, updatedAt: Long) = PasswordEntity(
        id = updatedAt,
        passwordId = passwordId,
        name = name,
        passwordEncrypted = byteArrayOf(marker) + "secret-$passwordId".toByteArray(Charsets.UTF_8),
        createdAt = 1_000L,
        updatedAt = updatedAt
    )

    @Before
    fun setUp() {
        dao = mockk(relaxed = true)
        // As Room returns them: ordered by name.
        coEvery { dao.getAll() } returns listOf(entity("pw-a", "Alpha", 3_000L), entity("pw-b", "Beta", 2_000L))

        val oathDao = mockk<OathCredentialDao>()
        coEvery { oathDao.getAll() } returns emptyList()
        val db = mockk<XKeyDatabase>()
        every { db.oathCredentialDao() } returns oathDao
        mockkObject(XKeyDatabase.Companion)
        every { XKeyDatabase.getInstance(any()) } returns db
        mockkConstructor(TrustStoreRepository::class)
        coEvery { anyConstructed<TrustStoreRepository>().getAllCertificates() } returns emptyList()
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    /** A cipher that decrypts the marker transform, counted by MockK. */
    private fun decryptingCipher(): KeystoreAeadCipher = mockk<KeystoreAeadCipher>().also { cipher ->
        every { cipher.encrypt(any()) } answers { byteArrayOf(marker) + firstArg<ByteArray>() }
        every { cipher.decrypt(any()) } answers {
            firstArg<ByteArray>().copyOfRange(1, firstArg<ByteArray>().size)
        }
    }

    /** A cipher whose every decryption fails, as for an entry under a lost or rotated key. */
    private fun failingCipher(): KeystoreAeadCipher = mockk<KeystoreAeadCipher>().also { cipher ->
        every { cipher.encrypt(any()) } answers { byteArrayOf(marker) + firstArg<ByteArray>() }
        every { cipher.decrypt(any()) } throws AEADBadTagException("tag mismatch")
    }

    private fun engine(cipher: KeystoreAeadCipher) =
        SyncEngine(mockk<Context>(), passwordRepository = { PasswordRepository(dao, cipher) })

    @Test
    fun `the status password checksum is unchanged and decrypts nothing`() = runTest {
        // What the checksum was computed from before: every entry, decrypted.
        val before = SyncCodec.storeChecksum(
            PasswordRepository(dao, decryptingCipher()).list().map { "${it.passwordId}:${it.updatedAt}" }
        )
        val cipher = decryptingCipher()

        val checksums = engine(cipher).storeChecksums()

        assertEquals(before, checksums.getString("passwords"))
        assertEquals(SyncCodec.storeChecksum(listOf("pw-a:3000", "pw-b:2000")), checksums.getString("passwords"))
        verify(exactly = 0) { cipher.decrypt(any()) }
    }

    @Test
    fun `the status is answered when no password can be decrypted`() = runTest {
        val checksums = engine(failingCipher()).storeChecksums()

        assertEquals(SyncCodec.storeChecksum(listOf("pw-a:3000", "pw-b:2000")), checksums.getString("passwords"))
        assertEquals(SyncCodec.storeChecksum(emptyList()), checksums.getString("oath"))
        assertEquals(SyncCodec.storeChecksum(emptyList()), checksums.getString("trust_store"))
    }

    @Test
    fun `a merge over an entry that cannot be decrypted replaces its password without decrypting it`() = runTest {
        val stored = entity("pw-a", "Alpha", 3_000L)
        coEvery { dao.getByPasswordId("pw-a") } returns stored
        // The guarded in-place UPDATE finds the row as it was read, and writes it.
        val written = slot<ByteArray>()
        coEvery {
            dao.updateFieldsIfUnchanged(
                id = stored.id,
                expectedPasswordEncrypted = stored.passwordEncrypted,
                expectedName = stored.name,
                expectedTitle = any(),
                expectedUsername = any(),
                expectedUrl = any(),
                expectedNotes = any(),
                expectedFolderPath = any(),
                expectedSource = any(),
                expectedCreatedAt = stored.createdAt,
                expectedUpdatedAt = stored.updatedAt,
                expectedExpiresAt = any(),
                expectedShared = any(),
                expectedTenantId = any(),
                name = any(),
                title = any(),
                username = any(),
                passwordEncrypted = capture(written),
                url = any(),
                notes = any(),
                folderPath = any(),
                source = any(),
                expiresAt = any(),
                updatedAt = any()
            )
        } returns 1
        val noFactors = object : PasswordVaultFactorStore {
            override suspend fun list(): List<PasswordVaultFactorRecord> = emptyList()
            override suspend fun add(record: PasswordVaultFactorRecord) = Unit
        }
        val cipher = failingCipher()
        val sync = PasswordSync(PasswordRepository(dao, cipher), noFactors)
        val incoming = JSONArray().put(
            JSONObject().put("id", "pw-a").put("name", "Alpha").put("password", "rotated")
                .put("updated_at", "2023-11-14T22:13:20Z")
        )

        assertEquals(SyncEngine.ItemCounts(added = 0, updated = 1, skipped = 0), sync.merge(incoming))
        assertArrayEquals(byteArrayOf(marker) + "rotated".toByteArray(Charsets.UTF_8), written.captured)
        verify(exactly = 0) { cipher.decrypt(any()) }
    }
}

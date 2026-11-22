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

package com.automatethethings.xkey.storage

import android.app.Application
import androidx.room.Room
import androidx.room.withTransaction
import androidx.test.core.app.ApplicationProvider
import com.automatethethings.xkey.storage.dao.KeyPolicyDao
import com.automatethethings.xkey.storage.entity.CredentialMetadataEntity
import com.automatethethings.xkey.storage.entity.KeyEntity
import com.automatethethings.xkey.storage.entity.SharingPolicyType
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.IOException

/**
 * A passkey registration that read the passkey it replaces while that
 * passkey was shared with all peers commits its delete only while nothing
 * narrowed it since: a narrowing that failed but recorded its denial in the
 * policy row narrowed it as much as one that landed, so the replacement
 * leaves the old passkey's rows. Runs over a real Room database.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = Application::class)
class PasskeyReplacementDenialTest {

    private lateinit var database: XKeyDatabase
    private val oldKeyId = "old-passkey"
    private val newKeyId = "new-passkey"

    @Before
    fun setUp() {
        database = Room.inMemoryDatabaseBuilder(ApplicationProvider.getApplicationContext(), XKeyDatabase::class.java)
            .allowMainThreadQueries()
            .build()
        runBlocking {
            database.keyDao().insert(passkey(oldKeyId))
            database.credentialMetadataDao().insert(metadata(oldKeyId))
        }
    }

    @After
    fun tearDown() = database.close()

    private fun passkey(keyId: String) = KeyEntity(
        keyId = keyId,
        keyType = "fido2",
        algorithm = "ES256",
        label = "Example",
        keySizeBits = 256,
        source = "local",
        rpId = "example.com",
        userId = "dXNlcg",
        isDiscoverable = true,
        sharingPolicy = SharingPolicyType.ALL_PEERS
    )

    private fun metadata(credentialId: String) = CredentialMetadataEntity(
        credentialId = credentialId,
        rpId = "example.com",
        rpName = "Example",
        userId = "dXNlcg",
        userName = "alice",
        userDisplayName = "Alice",
        publicKeyCose = byteArrayOf(1),
        signCount = 0,
        isDiscoverable = true
    )

    /** The store over the real tables, except that the key row's policy write fails. */
    private fun storeWhoseKeyRowWriteFails(): KeyPolicyStore {
        val real = database.keyPolicyDao()
        val failing = object : KeyPolicyDao by real {
            override suspend fun setKeyPolicy(keyId: String, policy: SharingPolicyType): Int =
                throw IOException("disk full")
        }
        return KeyPolicyStore(
            failing,
            object : KeyPolicyStore.Transactor {
                override suspend fun <T> run(block: suspend () -> T): T = database.withTransaction { block() }
            },
            unrecorded = mutableMapOf()
        )
    }

    private fun narrowingFailsAfterRead(narrowing: SharingPolicyType) = runBlocking {
        val read = database.keyDao().getByKeyId(oldKeyId)!!
        val store = storeWhoseKeyRowWriteFails()
        val failure = runCatching { store.setPolicy(oldKeyId, read.id, narrowing) }.exceptionOrNull()
        assertNotNull("the narrowing's key row write must fail", failure)
        val row = database.keyPolicyDao().policyRow(oldKeyId)
        assertNotNull("the failed narrowing's denial must be recorded", row)
        assertEquals(narrowing, row!!.denial)

        val removed = database.keyDao().completePasskeyRegistration(passkey(newKeyId), metadata(newKeyId), listOf(read))

        assertEquals("a denied passkey is not the registration's to remove", emptyList<String>(), removed)
        assertNotNull("the old passkey's key row must stay", database.keyDao().getByKeyId(oldKeyId))
        assertNotNull("the old passkey's metadata row must stay", database.credentialMetadataDao().getByCredentialId(oldKeyId))
        assertNotNull("the new passkey still registers", database.keyDao().getByKeyId(newKeyId))
    }

    @Test
    fun `a denial to private recorded after the last read keeps the replaced passkey`() =
        narrowingFailsAfterRead(SharingPolicyType.PRIVATE)

    @Test
    fun `a denial to selected peers recorded after the last read keeps the replaced passkey`() =
        narrowingFailsAfterRead(SharingPolicyType.SELECTED_PEERS)

    @Test
    fun `a replacement with no denial recorded since its read removes the old passkey`() = runBlocking {
        val read = database.keyDao().getByKeyId(oldKeyId)!!

        val removed = database.keyDao().completePasskeyRegistration(passkey(newKeyId), metadata(newKeyId), listOf(read))

        assertEquals(listOf(oldKeyId), removed)
        assertNull(database.keyDao().getByKeyId(oldKeyId))
        assertNull(database.credentialMetadataDao().getByCredentialId(oldKeyId))
        assertNotNull(database.keyDao().getByKeyId(newKeyId))
    }
}

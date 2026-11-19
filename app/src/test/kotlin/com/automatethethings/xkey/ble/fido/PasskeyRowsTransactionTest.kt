/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
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

package com.automatethethings.xkey.ble.fido

import android.app.Application
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.entity.CredentialMetadataEntity
import com.automatethethings.xkey.storage.entity.KeyEntity
import com.automatethethings.xkey.storage.entity.SharingPolicyType
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * The passkey rows a BLE registration replaces go in one Room transaction:
 * each passkey's `credential_metadata` row and key row, all or none, and
 * only a passkey whose sharing policy is still the one its caller read.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = Application::class)
class PasskeyRowsTransactionTest {

    private lateinit var database: XKeyDatabase

    @Before
    fun setUp() {
        database = Room.inMemoryDatabaseBuilder(ApplicationProvider.getApplicationContext(), XKeyDatabase::class.java)
            .allowMainThreadQueries()
            .build()
        runBlocking {
            listOf("a", "b").forEach {
                database.keyDao().insert(
                    KeyEntity(
                        keyId = it,
                        keyType = "fido2",
                        algorithm = "ES256",
                        label = "Example",
                        keySizeBits = 256,
                        source = "local",
                        rpId = "example.com",
                        isDiscoverable = true,
                        sharingPolicy = SharingPolicyType.ALL_PEERS
                    )
                )
                database.credentialMetadataDao().insert(
                    CredentialMetadataEntity(
                        credentialId = it,
                        rpId = "example.com",
                        rpName = "Example",
                        userId = "CQ",
                        userName = "alice",
                        userDisplayName = "Alice",
                        publicKeyCose = byteArrayOf(1),
                        signCount = 0,
                        isDiscoverable = true
                    )
                )
            }
        }
    }

    @After
    fun tearDown() = database.close()

    private suspend fun read(vararg keyIds: String): List<KeyEntity> =
        keyIds.map { requireNotNull(database.keyDao().getByKeyId(it)) }

    @Test
    fun `deletePasskeyRows removes each passkey's metadata row and key row`() = runBlocking {
        val removed = database.keyDao().deletePasskeyRows(read("a", "b"))

        assertEquals(listOf("a", "b"), removed)
        listOf("a", "b").forEach {
            assertNull(database.keyDao().getByKeyId(it))
            assertNull(database.credentialMetadataDao().getByCredentialId(it))
        }
    }

    @Test
    fun `a delete that fails part way leaves every row in place`() = runBlocking {
        // The last delete of the transaction, b's key row, fails.
        database.openHelper.writableDatabase.execSQL(
            "CREATE TRIGGER refuse_b BEFORE DELETE ON keys WHEN old.key_id = 'b' " +
                "BEGIN SELECT RAISE(ABORT, 'disk I/O error'); END"
        )

        val thrown = runCatching { database.keyDao().deletePasskeyRows(read("a", "b")) }.exceptionOrNull()

        assertTrue("the delete must fail, got $thrown", thrown != null)
        listOf("a", "b").forEach {
            assertNotNull("key row $it must stay", database.keyDao().getByKeyId(it))
            assertNotNull("metadata row $it must stay", database.credentialMetadataDao().getByCredentialId(it))
        }
        assertEquals(2, database.keyDao().countAll())
    }

    @Test
    fun `a passkey whose policy changed since it was read keeps both its rows`() = runBlocking {
        val asRead = read("a", "b")
        database.keyDao().updateSharingPolicy("a", SharingPolicyType.PRIVATE)
        // Changed away and back: the same policy, but a later revision.
        database.keyDao().updateSharingPolicy("b", SharingPolicyType.SELECTED_PEERS)
        database.keyDao().updateSharingPolicy("b", SharingPolicyType.ALL_PEERS)

        val removed = database.keyDao().deletePasskeyRows(asRead)

        assertEquals(emptyList<String>(), removed)
        listOf("a", "b").forEach {
            assertNotNull("key row $it must stay", database.keyDao().getByKeyId(it))
            assertNotNull("metadata row $it must stay", database.credentialMetadataDao().getByCredentialId(it))
        }
    }

    @Test
    fun `only the passkeys still as read go`() = runBlocking {
        val asRead = read("a", "b")
        database.keyDao().updateSharingPolicy("a", SharingPolicyType.PRIVATE)

        val removed = database.keyDao().deletePasskeyRows(asRead)

        assertEquals(listOf("b"), removed)
        assertNotNull(database.keyDao().getByKeyId("a"))
        assertNotNull(database.credentialMetadataDao().getByCredentialId("a"))
        assertNull(database.keyDao().getByKeyId("b"))
        assertNull(database.credentialMetadataDao().getByCredentialId("b"))
    }
}

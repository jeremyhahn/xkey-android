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
package com.automatethethings.xkey.storage

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.entity.CredentialMetadataEntity
import com.automatethethings.xkey.storage.entity.KeyEntity
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyPairGenerator
import java.security.KeyStore

/**
 * Instrumented tests for what [KeyStoreSyncManager.syncAll] actually writes,
 * as opposed to what it ends up with.
 *
 * The end state was already correct: a credential whose Android Keystore key
 * does not exist is not a key, and it must not appear in Key Management. The
 * problem was the route taken to get there. `syncCredentialMetadata` ran first
 * and copied every untracked credential into the `keys` table, and
 * `removeStaleEntries` then deleted the ones with no Keystore key — in the same
 * pass. Each such credential was written and immediately swept, and the sync's
 * own report ("synced N credentials") counted rows that did not survive the
 * call that produced it. That report is what a developer reads when a key is
 * missing from the UI, so it has to describe what happened.
 *
 * These tests therefore observe the DAO, not just the final table: a delegating
 * [KeyDao] records every insert, so a row that is written and deleted again is
 * still visible to the assertions.
 *
 * The database is in-memory and every Keystore alias carries a per-run suffix
 * and is deleted in `@After`.
 */
@RunWith(AndroidJUnit4::class)
class KeyStoreSyncChurnTest {

    private lateinit var database: XKeyDatabase
    private lateinit var recordingDao: RecordingKeyDao
    private lateinit var manager: KeyStoreSyncManager
    private lateinit var keyStore: KeyStore

    private val createdAliases = mutableListOf<String>()

    /** Unique per run so a leftover alias can never be mistaken for a fresh one. */
    private val runId = System.nanoTime().toString()

    private val livingKeyId = "churn-live-$runId"
    private val ghostKeyId = "churn-ghost-$runId"

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        database = Room.inMemoryDatabaseBuilder(context, XKeyDatabase::class.java).build()
        recordingDao = RecordingKeyDao(database.keyDao())
        manager = KeyStoreSyncManager(
            keystoreManager = KeystoreManager(context),
            credentialDao = database.credentialMetadataDao(),
            keyDao = recordingDao,
            keyPolicyStore = KeyPolicyStore.of(database)
        )
        keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    }

    @After
    fun tearDown() {
        for (alias in createdAliases) {
            runCatching { keyStore.deleteEntry(alias) }
        }
        createdAliases.clear()
        database.close()
    }

    private fun generateCredentialKey(keyId: String) {
        val alias = "xkey_credential_$keyId"
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").apply {
            initialize(
                KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .build()
            )
        }.generateKeyPair()
        createdAliases += alias
    }

    private fun credential(credentialId: String) = CredentialMetadataEntity(
        credentialId = credentialId,
        rpId = "example.com",
        rpName = "Example Inc",
        userId = "dXNlci0x",
        userName = "user@example.com",
        userDisplayName = "A User",
        publicKeyCose = byteArrayOf(0xA5.toByte(), 0x01, 0x02),
        signCount = 1L,
        createdAt = 1_700_000_000_000L,
        lastUsedAt = 1_700_000_500_000L,
        isDiscoverable = true
    )

    // -------------------------------------------------------------------------

    @Test
    fun syncAll_neverWritesACredentialItIsAboutToDelete() = runBlocking {
        database.credentialMetadataDao().insert(credential(ghostKeyId))

        manager.syncAll()

        assertTrue(
            "a credential with no Keystore key must not be inserted at all, " +
                "since the same sync removes it again: ${recordingDao.inserted}",
            ghostKeyId !in recordingDao.inserted
        )
        assertNull(database.keyDao().getByKeyId(ghostKeyId))
    }

    @Test
    fun syncAll_writesEachSurvivingCredentialExactlyOnce() = runBlocking {
        generateCredentialKey(livingKeyId)
        database.credentialMetadataDao().insert(credential(livingKeyId))
        database.credentialMetadataDao().insert(credential(ghostKeyId))

        manager.syncAll()
        manager.syncAll()

        assertEquals(
            "the second pass has nothing left to do",
            1,
            recordingDao.inserted.count { it == livingKeyId }
        )
        assertEquals(0, recordingDao.inserted.count { it == ghostKeyId })
    }

    @Test
    fun syncAll_reportsATotalThatMatchesTheRowsItLeftBehind() = runBlocking {
        generateCredentialKey(livingKeyId)
        database.credentialMetadataDao().insert(credential(livingKeyId))
        database.credentialMetadataDao().insert(credential(ghostKeyId))

        val reported = manager.syncAll()

        assertEquals(database.keyDao().countAll(), reported)
    }

    /**
     * A [KeyDao] that remembers the id of every key inserted through it.
     *
     * Everything else is delegated to the real DAO, so the manager runs against
     * genuine Room persistence; only the insert is observed.
     */
    private class RecordingKeyDao(private val delegate: KeyDao) : KeyDao by delegate {

        val inserted = mutableListOf<String>()

        override suspend fun insert(key: KeyEntity): Long {
            inserted += key.keyId
            return delegate.insert(key)
        }
    }
}

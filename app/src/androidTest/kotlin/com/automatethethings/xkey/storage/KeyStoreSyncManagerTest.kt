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
import com.automatethethings.xkey.storage.entity.CredentialMetadataEntity
import com.automatethethings.xkey.storage.entity.KeyEntity
import com.automatethethings.xkey.storage.entity.SharingPolicyType
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyPairGenerator
import java.security.KeyStore
import javax.crypto.KeyGenerator

/**
 * Instrumented tests for [KeyStoreSyncManager].
 *
 * This is the reconciliation pass that makes every key on the device visible in
 * Key Management, and it reads the real Android Keystore, so it can only run on
 * a device. Two of its three phases are destructive in opposite directions —
 * one inserts rows for Keystore entries nobody tracked, the other deletes rows
 * whose Keystore entry has vanished — and the ordering between them matters:
 * a credential that was just synced in must survive the stale sweep only if its
 * key really exists. Those interactions are what is pinned here.
 *
 * The database is always **in-memory**, so the shared on-device `keys` table is
 * never touched. Keystore aliases are created under a per-run unique suffix and
 * deleted in `@After`, so no alias outlives the test.
 */
@RunWith(AndroidJUnit4::class)
class KeyStoreSyncManagerTest {

    private lateinit var database: XKeyDatabase
    private lateinit var manager: KeyStoreSyncManager

    private lateinit var keyStore: KeyStore
    private val createdAliases = mutableListOf<String>()

    /** Unique per run so a leftover alias can never be mistaken for a fresh one. */
    private val runId = System.nanoTime().toString()

    private val credentialKeyId = "sync-cred-$runId"
    private val generalKeyId = "sync-general-$runId"
    private val credentialAlias = "xkey_credential_$credentialKeyId"
    private val generalAlias = "xkey_key_$generalKeyId"

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        database = Room.inMemoryDatabaseBuilder(context, XKeyDatabase::class.java).build()
        manager = KeyStoreSyncManager(
            keystoreManager = KeystoreManager(context),
            credentialDao = database.credentialMetadataDao(),
            keyDao = database.keyDao()
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

    private fun generateEcKey(alias: String) {
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").apply {
            initialize(
                KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .build()
            )
        }.generateKeyPair()
        createdAliases += alias
    }

    private fun generateAesKey(alias: String) {
        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
            init(
                KeyGenParameterSpec.Builder(
                    alias,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .build()
            )
        }.generateKey()
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
        signCount = 7L,
        createdAt = 1_700_000_000_000L,
        lastUsedAt = 1_700_000_500_000L,
        isDiscoverable = true
    )

    // -------------------------------------------------------------------------
    // Credential metadata is copied into the unified keys table
    // -------------------------------------------------------------------------

    @Test
    fun syncAll_copiesAFido2CredentialIntoTheKeysTable() = runBlocking {
        generateEcKey(credentialAlias)
        database.credentialMetadataDao().insert(credential(credentialKeyId))

        manager.syncAll()

        val key = database.keyDao().getByKeyId(credentialKeyId)
        assertNotNull("the credential should have been mirrored into keys", key)
        assertEquals("fido2", key!!.keyType)
        assertEquals("ES256", key.algorithm)
        assertEquals(256, key.keySizeBits)
        assertEquals("local", key.source)
        assertEquals("example.com", key.rpId)
        assertEquals("Example Inc", key.rpName)
        assertEquals("dXNlci0x", key.userId)
        assertEquals("user@example.com", key.userName)
        assertEquals("A User", key.userDisplayName)
        assertTrue(key.isDiscoverable)
        assertEquals(7L, key.signCount)
        assertEquals(1_700_000_000_000L, key.createdAt)
        assertEquals(1_700_000_500_000L, key.lastUsedAt)
    }

    @Test
    fun syncAll_labelsACredentialWithItsRelyingPartyName() = runBlocking {
        generateEcKey(credentialAlias)
        database.credentialMetadataDao().insert(credential(credentialKeyId))

        manager.syncAll()

        assertEquals("Example Inc", database.keyDao().getByKeyId(credentialKeyId)!!.label)
    }

    @Test
    fun syncAll_fallsBackToTheRpIdWhenTheRelyingPartyHasNoName() = runBlocking {
        generateEcKey(credentialAlias)
        database.credentialMetadataDao().insert(credential(credentialKeyId).copy(rpName = ""))

        manager.syncAll()

        assertEquals("example.com", database.keyDao().getByKeyId(credentialKeyId)!!.label)
    }

    @Test
    fun syncAll_leavesAnAlreadyTrackedCredentialUntouched() = runBlocking {
        generateEcKey(credentialAlias)
        database.credentialMetadataDao().insert(credential(credentialKeyId))
        database.keyDao().insert(
            KeyEntity(
                keyId = credentialKeyId,
                keyType = "fido2",
                algorithm = "ES256",
                label = "Hand written label",
                keySizeBits = 256,
                source = "local",
                shareable = true,
                sharingPolicy = SharingPolicyType.ALL_PEERS
            )
        )

        manager.syncAll()

        val key = database.keyDao().getByKeyId(credentialKeyId)!!
        assertEquals("Hand written label", key.label)
        assertEquals(SharingPolicyType.ALL_PEERS, key.sharingPolicy)
    }

    @Test
    fun syncAll_isIdempotent() = runBlocking {
        generateEcKey(credentialAlias)
        database.credentialMetadataDao().insert(credential(credentialKeyId))

        val first = manager.syncAll()
        val second = manager.syncAll()

        assertEquals(first, second)
        assertEquals(1, database.keyDao().getAll().count { it.keyId == credentialKeyId })
    }

    // -------------------------------------------------------------------------
    // Orphaned Keystore entries are discovered
    // -------------------------------------------------------------------------

    @Test
    fun syncAll_discoversAGeneralPurposeKeystoreEntryAndStripsItsPrefix() = runBlocking {
        generateEcKey(generalAlias)

        manager.syncAll()

        val key = database.keyDao().getByKeyId(generalKeyId)
        assertNotNull("an xkey_key_ alias should be discovered under its bare id", key)
        assertEquals("signing", key!!.keyType)
        assertEquals("ES256", key.algorithm)
        assertEquals(256, key.keySizeBits)
        assertEquals("local", key.source)
        assertFalse(key.isSystemKey)
        assertNotNull(key.publicKeyDer)
    }

    @Test
    fun syncAll_labelsADiscoveredGeneralKeyWithItsBareId() = runBlocking {
        generateEcKey(generalAlias)

        manager.syncAll()

        assertEquals(generalKeyId, database.keyDao().getByKeyId(generalKeyId)!!.label)
    }

    @Test
    fun syncAll_classifiesASymmetricKeystoreEntryAsASecret() = runBlocking {
        val alias = "xkey_key_sync-aes-$runId"
        generateAesKey(alias)

        manager.syncAll()

        val key = database.keyDao().getByKeyId("sync-aes-$runId")
        assertNotNull("an AES alias should be discovered", key)
        assertEquals("secret", key!!.keyType)
        assertEquals("AES256", key.algorithm)
        assertEquals(256, key.keySizeBits)
        assertNull(key.publicKeyDer)
    }

    @Test
    fun syncAll_keepsANonXkeyAliasUnderItsFullName() = runBlocking {
        val alias = "sync-foreign-$runId"
        generateEcKey(alias)

        manager.syncAll()

        val key = database.keyDao().getByKeyId(alias)
        assertNotNull("a foreign alias should be tracked under its full alias", key)
        assertEquals(alias, key!!.label)
    }

    @Test
    fun syncAll_doesNotRediscoverAKeyThatIsAlreadyTracked() = runBlocking {
        generateEcKey(generalAlias)
        database.keyDao().insert(
            KeyEntity(
                keyId = generalKeyId,
                keyType = "signing",
                algorithm = "ES384",
                label = "Existing label",
                keySizeBits = 384,
                source = "local"
            )
        )

        manager.syncAll()

        val key = database.keyDao().getByKeyId(generalKeyId)!!
        assertEquals("Existing label", key.label)
        assertEquals("ES384", key.algorithm)
    }

    // -------------------------------------------------------------------------
    // Stale entries are removed
    // -------------------------------------------------------------------------

    @Test
    fun syncAll_removesALocalKeyWhoseKeystoreEntryIsGone() = runBlocking {
        val orphan = "sync-orphan-$runId"
        database.keyDao().insert(
            KeyEntity(
                keyId = orphan,
                keyType = "signing",
                algorithm = "ES256",
                label = "Orphan",
                keySizeBits = 256,
                source = "local"
            )
        )

        manager.syncAll()

        assertNull(
            "a keys row with no Keystore entry should not survive a sync",
            database.keyDao().getByKeyId(orphan)
        )
    }

    @Test
    fun syncAll_keepsAnXkmsdReferenceThatHasNoLocalKeystoreEntry() = runBlocking {
        val remote = "sync-remote-$runId"
        database.keyDao().insert(
            KeyEntity(
                keyId = remote,
                keyType = "signing",
                algorithm = "ES256",
                label = "On the laptop",
                keySizeBits = 256,
                source = "xkmsd",
                remoteBackend = "tpm2"
            )
        )

        manager.syncAll()

        val key = database.keyDao().getByKeyId(remote)
        assertNotNull("an xkmsd reference lives on the laptop and must survive", key)
        assertEquals("tpm2", key!!.remoteBackend)
    }

    @Test
    fun syncAll_dropsACredentialWhoseKeystoreKeyWasNeverCreated() = runBlocking {
        // The credential row is copied in first and swept out afterwards, which
        // is the intended outcome: metadata with no key behind it is not a key.
        database.credentialMetadataDao().insert(credential("sync-ghost-$runId"))

        manager.syncAll()

        assertNull(database.keyDao().getByKeyId("sync-ghost-$runId"))
    }

    // -------------------------------------------------------------------------
    // Reported total
    // -------------------------------------------------------------------------

    @Test
    fun syncAll_reportsTheTotalRowCountAfterReconciling() = runBlocking {
        generateEcKey(generalAlias)

        val reported = manager.syncAll()

        assertEquals(database.keyDao().countAll(), reported)
        assertTrue(reported >= 1)
    }
}

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
package com.automatethethings.xkey.storage.dao

import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.entity.KeyEntity
import com.automatethethings.xkey.storage.entity.SharingPolicyType
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented tests for [KeyDao].
 *
 * The unified `keys` table is what Key Management, the passkey picker and the
 * sharing bridge all read, and every one of those views is a SQL predicate
 * rather than a Kotlin filter. The `sharing_policy` column is the interesting
 * one: it is an enum stored as text, so a query like `sharing_policy != 'PRIVATE'`
 * only works if the converter and the literal agree — pinning that here means a
 * renamed enum constant fails a test instead of quietly emptying the shared-key
 * list.
 *
 * The invariant from [KeyEntity]'s own KDoc — that `shareable` and
 * `sharingPolicy` must agree — is preserved by every row this suite writes, and
 * the one mutator that can break it is called out explicitly.
 *
 * The database is always **in-memory**, so nothing touches the shared on-device
 * `keys` table, which other suites count.
 */
@RunWith(AndroidJUnit4::class)
class KeyDaoTest {

    private lateinit var database: XKeyDatabase
    private lateinit var dao: KeyDao

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        database = Room.inMemoryDatabaseBuilder(context, XKeyDatabase::class.java).build()
        dao = database.keyDao()
    }

    @After
    fun tearDown() {
        database.close()
    }

    private fun key(
        keyId: String,
        keyType: String = "signing",
        algorithm: String = "ES256",
        source: String = "local",
        policy: SharingPolicyType = SharingPolicyType.PRIVATE,
        rpId: String? = null,
        userId: String? = null,
        isDiscoverable: Boolean = false,
        createdAt: Long = 1_000L,
        lastUsedAt: Long = 0L,
        publicKeyDer: ByteArray? = null
    ) = KeyEntity(
        keyId = keyId,
        keyType = keyType,
        algorithm = algorithm,
        label = keyId,
        publicKeyDer = publicKeyDer,
        keySizeBits = 256,
        shareable = policy != SharingPolicyType.PRIVATE,
        sharingPolicy = policy,
        source = source,
        createdAt = createdAt,
        lastUsedAt = lastUsedAt,
        rpId = rpId,
        userId = userId,
        isDiscoverable = isDiscoverable
    )

    // -------------------------------------------------------------------------
    // Insert, update, delete
    // -------------------------------------------------------------------------

    @Test
    fun insert_roundTripsEveryColumnIncludingTheBlob() = runBlocking {
        val der = byteArrayOf(0x30, 0x59, 0x30, 0x13)
        dao.insert(key("k-1", publicKeyDer = der, policy = SharingPolicyType.ALL_PEERS))

        val stored = dao.getByKeyId("k-1")!!
        assertEquals("signing", stored.keyType)
        assertEquals("ES256", stored.algorithm)
        assertEquals(256, stored.keySizeBits)
        assertEquals("local", stored.source)
        assertEquals(SharingPolicyType.ALL_PEERS, stored.sharingPolicy)
        assertTrue(stored.shareable)
        assertTrue(stored.publicKeyDer!!.contentEquals(der))
    }

    @Test
    fun insert_replacesARowWithTheSameKeyId() = runBlocking {
        dao.insert(key("k-1", algorithm = "ES256"))
        dao.insert(key("k-1", algorithm = "RS256"))

        assertEquals(1, dao.countAll())
        assertEquals("RS256", dao.getByKeyId("k-1")!!.algorithm)
    }

    @Test
    fun update_writesTheWholeRowBack() = runBlocking {
        val rowId = dao.insert(key("k-1"))
        val stored = dao.getByKeyId("k-1")!!

        dao.update(stored.copy(label = "Renamed", useCount = 9L))

        val reread = dao.getByKeyId("k-1")!!
        assertEquals(rowId, reread.id)
        assertEquals("Renamed", reread.label)
        assertEquals(9L, reread.useCount)
    }

    @Test
    fun delete_removesTheGivenRow() = runBlocking {
        dao.insert(key("k-1"))
        val stored = dao.getByKeyId("k-1")!!

        dao.delete(stored)

        assertNull(dao.getByKeyId("k-1"))
    }

    @Test
    fun deleteByKeyId_reportsHowManyRowsWent() = runBlocking {
        dao.insert(key("k-1"))

        assertEquals(1, dao.deleteByKeyId("k-1"))
        assertEquals(0, dao.deleteByKeyId("k-1"))
    }

    @Test
    fun deleteFido2ByRpId_removesOnlyThatRelyingPartysPasskeys() = runBlocking {
        dao.insert(key("k-a", keyType = "fido2", rpId = "example.com"))
        dao.insert(key("k-b", keyType = "fido2", rpId = "example.com"))
        dao.insert(key("k-c", keyType = "fido2", rpId = "other.test"))
        dao.insert(key("k-d", keyType = "signing", rpId = "example.com"))

        assertEquals(2, dao.deleteFido2ByRpId("example.com"))
        assertEquals(listOf("k-c", "k-d"), dao.getAll().map { it.keyId }.sorted())
    }

    @Test
    fun deleteAll_emptiesTheTable() = runBlocking {
        dao.insert(key("k-1"))
        dao.insert(key("k-2"))

        dao.deleteAll()

        assertEquals(0, dao.countAll())
    }

    // -------------------------------------------------------------------------
    // Listing and ordering
    // -------------------------------------------------------------------------

    @Test
    fun getAll_ordersNewestFirst() = runBlocking {
        dao.insert(key("k-old", createdAt = 100L))
        dao.insert(key("k-new", createdAt = 300L))
        dao.insert(key("k-mid", createdAt = 200L))

        assertEquals(listOf("k-new", "k-mid", "k-old"), dao.getAll().map { it.keyId })
    }

    @Test
    fun observeAll_emitsTheSameOrdering() = runBlocking {
        dao.insert(key("k-old", createdAt = 100L))
        dao.insert(key("k-new", createdAt = 300L))

        assertEquals(listOf("k-new", "k-old"), dao.observeAll().first().map { it.keyId })
    }

    @Test
    fun getByType_andObserveByType_agree() = runBlocking {
        dao.insert(key("k-fido", keyType = "fido2"))
        dao.insert(key("k-secret", keyType = "secret"))

        assertEquals(listOf("k-fido"), dao.getByType("fido2").map { it.keyId })
        assertEquals(listOf("k-fido"), dao.observeByType("fido2").first().map { it.keyId })
        assertTrue(dao.getByType("attestation").isEmpty())
    }

    @Test
    fun getBySource_separatesLocalFromRemoteOrigins() = runBlocking {
        dao.insert(key("k-local", source = "local"))
        dao.insert(key("k-ble", source = "remote_ble"))
        dao.insert(key("k-xkmsd", source = "xkmsd"))

        assertEquals(listOf("k-local"), dao.getBySource("local").map { it.keyId })
        assertEquals(listOf("k-ble"), dao.getBySource("remote_ble").map { it.keyId })
        assertEquals(listOf("k-xkmsd"), dao.getBySource("xkmsd").map { it.keyId })
    }

    // -------------------------------------------------------------------------
    // FIDO2 lookups
    // -------------------------------------------------------------------------

    @Test
    fun getFido2ByRpId_excludesOtherKeyTypesAndRelyingParties() = runBlocking {
        dao.insert(key("k-passkey", keyType = "fido2", rpId = "example.com", lastUsedAt = 2L))
        dao.insert(key("k-older", keyType = "fido2", rpId = "example.com", lastUsedAt = 1L))
        dao.insert(key("k-other-rp", keyType = "fido2", rpId = "other.test"))
        dao.insert(key("k-signing", keyType = "signing", rpId = "example.com"))

        assertEquals(
            listOf("k-passkey", "k-older"),
            dao.getFido2ByRpId("example.com").map { it.keyId }
        )
    }

    @Test
    fun getShareableFido2ByRpId_honoursTheLegacyShareableFlag() = runBlocking {
        dao.insert(
            key("k-shared", keyType = "fido2", rpId = "example.com",
                policy = SharingPolicyType.ALL_PEERS)
        )
        dao.insert(key("k-private", keyType = "fido2", rpId = "example.com"))

        assertEquals(
            listOf("k-shared"),
            dao.getShareableFido2ByRpId("example.com").map { it.keyId }
        )
    }

    @Test
    fun getDiscoverableFido2ByRpId_excludesNonResidentCredentials() = runBlocking {
        dao.insert(
            key("k-resident", keyType = "fido2", rpId = "example.com", isDiscoverable = true)
        )
        dao.insert(
            key("k-server-side", keyType = "fido2", rpId = "example.com", isDiscoverable = false)
        )

        assertEquals(
            listOf("k-resident"),
            dao.getDiscoverableFido2ByRpId("example.com").map { it.keyId }
        )
    }

    @Test
    fun getFido2ByUserIdAndRpId_findsTheOneCredentialForThatAccount() = runBlocking {
        dao.insert(key("k-1", keyType = "fido2", rpId = "example.com", userId = "dXNlcjE"))
        dao.insert(key("k-2", keyType = "fido2", rpId = "example.com", userId = "dXNlcjI"))

        assertEquals("k-1", dao.getFido2ByUserIdAndRpId("dXNlcjE", "example.com")!!.keyId)
        assertNull(dao.getFido2ByUserIdAndRpId("dXNlcjE", "other.test"))
        assertNull(dao.getFido2ByUserIdAndRpId("unknown", "example.com"))
    }

    @Test
    fun getFido2RpIds_listsEachRelyingPartyOnceAndSkipsNulls() = runBlocking {
        dao.insert(key("k-1", keyType = "fido2", rpId = "example.com"))
        dao.insert(key("k-2", keyType = "fido2", rpId = "example.com"))
        dao.insert(key("k-3", keyType = "fido2", rpId = "alpha.test"))
        dao.insert(key("k-4", keyType = "fido2", rpId = null))
        dao.insert(key("k-5", keyType = "signing", rpId = "signing.test"))

        assertEquals(listOf("alpha.test", "example.com"), dao.getFido2RpIds())
    }

    @Test
    fun getKeyTypes_listsEachTypeOnce() = runBlocking {
        dao.insert(key("k-1", keyType = "fido2"))
        dao.insert(key("k-2", keyType = "fido2"))
        dao.insert(key("k-3", keyType = "secret"))

        assertEquals(listOf("fido2", "secret"), dao.getKeyTypes())
    }

    // -------------------------------------------------------------------------
    // Sharing policy queries
    // -------------------------------------------------------------------------

    @Test
    fun getBySharePolicy_selectsOnTheStoredEnumName() = runBlocking {
        dao.insert(key("k-private", policy = SharingPolicyType.PRIVATE))
        dao.insert(key("k-all", policy = SharingPolicyType.ALL_PEERS))
        dao.insert(key("k-selected", policy = SharingPolicyType.SELECTED_PEERS))

        assertEquals(
            listOf("k-all"),
            dao.getBySharePolicy(SharingPolicyType.ALL_PEERS).map { it.keyId }
        )
        assertEquals(
            listOf("k-selected"),
            dao.observeBySharePolicy(SharingPolicyType.SELECTED_PEERS).first().map { it.keyId }
        )
    }

    @Test
    fun getFido2BySharePolicy_narrowsToPasskeys() = runBlocking {
        dao.insert(key("k-fido", keyType = "fido2", policy = SharingPolicyType.ALL_PEERS))
        dao.insert(key("k-signing", keyType = "signing", policy = SharingPolicyType.ALL_PEERS))

        assertEquals(
            listOf("k-fido"),
            dao.getFido2BySharePolicy(SharingPolicyType.ALL_PEERS).map { it.keyId }
        )
    }

    @Test
    fun getSharedKeys_returnsEverythingThatIsNotPrivate() = runBlocking {
        dao.insert(key("k-private", policy = SharingPolicyType.PRIVATE, createdAt = 1L))
        dao.insert(key("k-all", policy = SharingPolicyType.ALL_PEERS, createdAt = 3L))
        dao.insert(key("k-selected", policy = SharingPolicyType.SELECTED_PEERS, createdAt = 2L))

        assertEquals(listOf("k-all", "k-selected"), dao.getSharedKeys().map { it.keyId })
    }

    @Test
    fun countBySharePolicy_countsTheSameSet() = runBlocking {
        dao.insert(key("k-1", policy = SharingPolicyType.ALL_PEERS))
        dao.insert(key("k-2", policy = SharingPolicyType.ALL_PEERS))
        dao.insert(key("k-3", policy = SharingPolicyType.PRIVATE))

        assertEquals(2, dao.countBySharePolicy(SharingPolicyType.ALL_PEERS))
        assertEquals(1, dao.countBySharePolicy(SharingPolicyType.PRIVATE))
        assertEquals(0, dao.countBySharePolicy(SharingPolicyType.SELECTED_PEERS))
    }

    @Test
    fun updateSharingPolicy_keepsTheLegacyFlagInStepForEveryPolicy() = runBlocking {
        // This is the mutator that upholds KeyEntity's documented invariant, so
        // both columns are checked for all three policies rather than just the
        // one being set.
        dao.insert(key("k-1", policy = SharingPolicyType.PRIVATE))

        dao.updateSharingPolicy("k-1", SharingPolicyType.SELECTED_PEERS)
        var stored = dao.getByKeyId("k-1")!!
        assertEquals(SharingPolicyType.SELECTED_PEERS, stored.sharingPolicy)
        assertTrue(stored.shareable)

        dao.updateSharingPolicy("k-1", SharingPolicyType.ALL_PEERS)
        stored = dao.getByKeyId("k-1")!!
        assertEquals(SharingPolicyType.ALL_PEERS, stored.sharingPolicy)
        assertTrue(stored.shareable)

        dao.updateSharingPolicy("k-1", SharingPolicyType.PRIVATE)
        stored = dao.getByKeyId("k-1")!!
        assertEquals(SharingPolicyType.PRIVATE, stored.sharingPolicy)
        assertFalse(stored.shareable)
    }

    // -------------------------------------------------------------------------
    // Usage tracking
    // -------------------------------------------------------------------------

    @Test
    fun recordUsage_incrementsTheCountAndStampsTheTime() = runBlocking {
        dao.insert(key("k-1"))

        dao.recordUsage("k-1", 1_700_000_000_000L)
        dao.recordUsage("k-1", 1_700_000_001_000L)

        val stored = dao.getByKeyId("k-1")!!
        assertEquals(2L, stored.useCount)
        assertEquals(1_700_000_001_000L, stored.lastUsedAt)
    }

    @Test
    fun recordUsage_defaultsTheTimestampToNow() = runBlocking {
        dao.insert(key("k-1"))

        val before = System.currentTimeMillis()
        dao.recordUsage("k-1")
        val after = System.currentTimeMillis()

        assertTrue(dao.getByKeyId("k-1")!!.lastUsedAt in before..after)
    }

    @Test
    fun updateSignCount_setsTheCounterRatherThanIncrementingIt() = runBlocking {
        dao.insert(key("k-1"))

        dao.updateSignCount("k-1", 42L, 1_700_000_000_000L)

        val stored = dao.getByKeyId("k-1")!!
        assertEquals(42L, stored.signCount)
        assertEquals(1_700_000_000_000L, stored.lastUsedAt)
        assertEquals(0L, stored.useCount)
    }

    // -------------------------------------------------------------------------
    // Counts and existence
    // -------------------------------------------------------------------------

    @Test
    fun countAll_andCountByType_trackTheTable() = runBlocking {
        assertEquals(0, dao.countAll())

        dao.insert(key("k-1", keyType = "fido2"))
        dao.insert(key("k-2", keyType = "secret"))

        assertEquals(2, dao.countAll())
        assertEquals(1, dao.countByType("fido2"))
        assertEquals(0, dao.countByType("attestation"))
    }

    @Test
    fun exists_reportsPresenceWithoutLoadingTheRow() = runBlocking {
        dao.insert(key("k-1"))

        assertTrue(dao.exists("k-1"))
        assertFalse(dao.exists("k-missing"))
    }
}

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
import com.automatethethings.xkey.storage.entity.KeySharingPolicy
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
 * Instrumented tests for [KeySharingPolicyDao].
 *
 * This DAO *is* the key-sharing access control: `isKeySharedWithPeer` is the
 * predicate consulted before a paired desktop is allowed to use a key, and it
 * resolves entirely in SQL — a `CASE` over the key's own policy with a
 * `COALESCE` fallback to the per-peer table. Nothing in Kotlin re-checks it, so
 * a wrong branch here is a silent authorisation bug rather than a crash. Each
 * branch is therefore exercised on its own, including the two that must deny:
 * an unknown key, and a `SELECTED_PEERS` key with no row for the asking peer.
 *
 * The foreign key onto `keys` cascades on delete, which is what stops a deleted
 * key from leaving grants behind that a recycled key id could inherit; that is
 * pinned too.
 *
 * The database is always **in-memory**, so nothing touches the shared on-device
 * tables.
 */
@RunWith(AndroidJUnit4::class)
class KeySharingPolicyDaoTest {

    private lateinit var database: XKeyDatabase
    private lateinit var dao: KeySharingPolicyDao
    private lateinit var keyDao: KeyDao

    private val peer = "04a1b2c3"
    private val otherPeer = "04ffeedd"

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        database = Room.inMemoryDatabaseBuilder(context, XKeyDatabase::class.java).build()
        dao = database.keySharingPolicyDao()
        keyDao = database.keyDao()
    }

    @After
    fun tearDown() {
        database.close()
    }

    private suspend fun insertKey(
        keyId: String,
        policy: SharingPolicyType,
        keyType: String = "fido2",
        lastUsedAt: Long = 0L
    ) {
        keyDao.insert(
            KeyEntity(
                keyId = keyId,
                keyType = keyType,
                algorithm = "ES256",
                label = keyId,
                keySizeBits = 256,
                shareable = policy != SharingPolicyType.PRIVATE,
                sharingPolicy = policy,
                source = "local",
                lastUsedAt = lastUsedAt
            )
        )
    }

    // -------------------------------------------------------------------------
    // isKeySharedWithPeer: the access control predicate
    // -------------------------------------------------------------------------

    @Test
    fun isKeySharedWithPeer_allowsAnyPeerForAnAllPeersKey() = runBlocking {
        insertKey("k-all", SharingPolicyType.ALL_PEERS)

        assertTrue(dao.isKeySharedWithPeer("k-all", peer))
        assertTrue(dao.isKeySharedWithPeer("k-all", otherPeer))
    }

    @Test
    fun isKeySharedWithPeer_deniesEveryPeerForAPrivateKey() = runBlocking {
        insertKey("k-private", SharingPolicyType.PRIVATE)
        dao.setPolicy(KeySharingPolicy("k-private", peer, allowed = true))

        // Even an explicit grant must not override a PRIVATE key.
        assertFalse(dao.isKeySharedWithPeer("k-private", peer))
    }

    @Test
    fun isKeySharedWithPeer_allowsOnlyTheListedPeerForASelectedPeersKey() = runBlocking {
        insertKey("k-selected", SharingPolicyType.SELECTED_PEERS)
        dao.setPolicy(KeySharingPolicy("k-selected", peer, allowed = true))

        assertTrue(dao.isKeySharedWithPeer("k-selected", peer))
        assertFalse(dao.isKeySharedWithPeer("k-selected", otherPeer))
    }

    @Test
    fun isKeySharedWithPeer_deniesASelectedPeersKeyWithNoPolicyAtAll() = runBlocking {
        insertKey("k-selected", SharingPolicyType.SELECTED_PEERS)

        assertFalse(dao.isKeySharedWithPeer("k-selected", peer))
    }

    @Test
    fun isKeySharedWithPeer_honoursARevokedPolicyRow() = runBlocking {
        insertKey("k-selected", SharingPolicyType.SELECTED_PEERS)
        dao.setPolicy(KeySharingPolicy("k-selected", peer, allowed = false))

        assertFalse(dao.isKeySharedWithPeer("k-selected", peer))
    }

    @Test
    fun isKeySharedWithPeer_deniesAnUnknownKey() = runBlocking {
        assertFalse(dao.isKeySharedWithPeer("k-missing", peer))
    }

    // -------------------------------------------------------------------------
    // isPeerGranted: the explicit grant row alone (#174)
    // -------------------------------------------------------------------------

    @Test
    fun isPeerGranted_ignoresAnAllPeersStoredPolicy() = runBlocking {
        insertKey("k-all", SharingPolicyType.ALL_PEERS)
        dao.setPolicy(KeySharingPolicy("k-all", peer, allowed = true))

        // A Selected Peers change not yet stored must not let every peer in.
        assertTrue(dao.isPeerGranted("k-all", peer))
        assertFalse(dao.isPeerGranted("k-all", otherPeer))
    }

    @Test
    fun isPeerGranted_honoursARevokedRowAndAMissingKey() = runBlocking {
        insertKey("k-selected", SharingPolicyType.SELECTED_PEERS)
        dao.setPolicy(KeySharingPolicy("k-selected", peer, allowed = false))

        assertFalse(dao.isPeerGranted("k-selected", peer))
        assertFalse(dao.isPeerGranted("k-missing", peer))
    }

    // -------------------------------------------------------------------------
    // Shareable key listings
    // -------------------------------------------------------------------------

    @Test
    fun getShareableFido2ForPeer_returnsAllPeersAndGrantedSelectedKeys() = runBlocking {
        insertKey("k-all", SharingPolicyType.ALL_PEERS, lastUsedAt = 3L)
        insertKey("k-selected", SharingPolicyType.SELECTED_PEERS, lastUsedAt = 2L)
        insertKey("k-private", SharingPolicyType.PRIVATE, lastUsedAt = 1L)
        dao.setPolicy(KeySharingPolicy("k-selected", peer, allowed = true))

        assertEquals(
            listOf("k-all", "k-selected"),
            dao.getShareableFido2ForPeer(peer).map { it.keyId }
        )
    }

    @Test
    fun getShareableFido2ForPeer_excludesNonFido2Keys() = runBlocking {
        insertKey("k-fido", SharingPolicyType.ALL_PEERS, keyType = "fido2")
        insertKey("k-signing", SharingPolicyType.ALL_PEERS, keyType = "signing")

        assertEquals(listOf("k-fido"), dao.getShareableFido2ForPeer(peer).map { it.keyId })
    }

    @Test
    fun getShareableFido2ForPeer_ordersByMostRecentlyUsed() = runBlocking {
        insertKey("k-old", SharingPolicyType.ALL_PEERS, lastUsedAt = 10L)
        insertKey("k-new", SharingPolicyType.ALL_PEERS, lastUsedAt = 20L)

        assertEquals(listOf("k-new", "k-old"), dao.getShareableFido2ForPeer(peer).map { it.keyId })
    }

    @Test
    fun getShareableFido2ForPeer_isEmptyWhenNothingIsShared() = runBlocking {
        insertKey("k-private", SharingPolicyType.PRIVATE)

        assertTrue(dao.getShareableFido2ForPeer(peer).isEmpty())
    }

    @Test
    fun getAllShareableForPeer_spansEveryKeyType() = runBlocking {
        insertKey("k-fido", SharingPolicyType.ALL_PEERS, keyType = "fido2", lastUsedAt = 2L)
        insertKey("k-signing", SharingPolicyType.ALL_PEERS, keyType = "signing", lastUsedAt = 1L)
        insertKey("k-private", SharingPolicyType.PRIVATE, keyType = "secret")

        assertEquals(
            listOf("k-fido", "k-signing"),
            dao.getAllShareableForPeer(peer).map { it.keyId }
        )
    }

    @Test
    fun getAllShareableForPeer_ignoresAGrantMadeToAnotherPeer() = runBlocking {
        insertKey("k-selected", SharingPolicyType.SELECTED_PEERS)
        dao.setPolicy(KeySharingPolicy("k-selected", otherPeer, allowed = true))

        assertTrue(dao.getAllShareableForPeer(peer).isEmpty())
        assertEquals(listOf("k-selected"), dao.getAllShareableForPeer(otherPeer).map { it.keyId })
    }

    @Test
    fun countKeysSharedWithPeer_countsTheSameSetTheListingReturns() = runBlocking {
        insertKey("k-all", SharingPolicyType.ALL_PEERS, keyType = "signing")
        insertKey("k-selected", SharingPolicyType.SELECTED_PEERS)
        insertKey("k-private", SharingPolicyType.PRIVATE)
        dao.setPolicy(KeySharingPolicy("k-selected", peer, allowed = true))

        assertEquals(2, dao.countKeysSharedWithPeer(peer))
        assertEquals(1, dao.countKeysSharedWithPeer(otherPeer))
    }

    // -------------------------------------------------------------------------
    // Policy CRUD
    // -------------------------------------------------------------------------

    @Test
    fun setPolicy_roundTripsTheRow() = runBlocking {
        insertKey("k-1", SharingPolicyType.SELECTED_PEERS)
        dao.setPolicy(KeySharingPolicy("k-1", peer, allowed = true, createdAt = 1234L))

        val stored = dao.getPolicy("k-1", peer)!!
        assertEquals("k-1", stored.keyId)
        assertEquals(peer, stored.peerPublicKeyHex)
        assertTrue(stored.allowed)
        assertEquals(1234L, stored.createdAt)
    }

    @Test
    fun setPolicy_replacesTheRowForTheSameKeyAndPeer() = runBlocking {
        insertKey("k-1", SharingPolicyType.SELECTED_PEERS)
        dao.setPolicy(KeySharingPolicy("k-1", peer, allowed = true))
        dao.setPolicy(KeySharingPolicy("k-1", peer, allowed = false))

        assertEquals(1, dao.getPoliciesForKeySync("k-1").size)
        assertFalse(dao.getPolicy("k-1", peer)!!.allowed)
    }

    @Test
    fun setPolicies_writesABatchInOneCall() = runBlocking {
        insertKey("k-1", SharingPolicyType.SELECTED_PEERS)
        dao.setPolicies(
            listOf(
                KeySharingPolicy("k-1", peer),
                KeySharingPolicy("k-1", otherPeer)
            )
        )

        assertEquals(2, dao.getPoliciesForKeySync("k-1").size)
    }

    @Test
    fun getPoliciesForKey_emitsTheRowsNewestFirst() = runBlocking {
        insertKey("k-1", SharingPolicyType.SELECTED_PEERS)
        dao.setPolicy(KeySharingPolicy("k-1", peer, createdAt = 100L))
        dao.setPolicy(KeySharingPolicy("k-1", otherPeer, createdAt = 200L))

        assertEquals(
            listOf(otherPeer, peer),
            dao.getPoliciesForKey("k-1").first().map { it.peerPublicKeyHex }
        )
    }

    @Test
    fun getAllowedPeersForKey_omitsRevokedPeers() = runBlocking {
        insertKey("k-1", SharingPolicyType.SELECTED_PEERS)
        dao.setPolicy(KeySharingPolicy("k-1", peer, allowed = true))
        dao.setPolicy(KeySharingPolicy("k-1", otherPeer, allowed = false))

        assertEquals(listOf(peer), dao.getAllowedPeersForKey("k-1"))
    }

    // -------------------------------------------------------------------------
    // Revocation
    // -------------------------------------------------------------------------

    @Test
    fun revokePolicy_keepsTheRowButFlipsTheFlag() = runBlocking {
        insertKey("k-1", SharingPolicyType.SELECTED_PEERS)
        dao.setPolicy(KeySharingPolicy("k-1", peer, allowed = true))

        dao.revokePolicy("k-1", peer)

        assertFalse(dao.getPolicy("k-1", peer)!!.allowed)
        assertFalse(dao.isKeySharedWithPeer("k-1", peer))
    }

    @Test
    fun grantPolicy_restoresARevokedPeer() = runBlocking {
        insertKey("k-1", SharingPolicyType.SELECTED_PEERS)
        dao.setPolicy(KeySharingPolicy("k-1", peer, allowed = false))

        dao.grantPolicy("k-1", peer)

        assertTrue(dao.getPolicy("k-1", peer)!!.allowed)
        assertTrue(dao.isKeySharedWithPeer("k-1", peer))
    }

    @Test
    fun removePolicy_deletesTheRowAndReportsOne() = runBlocking {
        insertKey("k-1", SharingPolicyType.SELECTED_PEERS)
        dao.setPolicy(KeySharingPolicy("k-1", peer))

        assertEquals(1, dao.removePolicy("k-1", peer))
        assertNull(dao.getPolicy("k-1", peer))
    }

    @Test
    fun clearPoliciesForKey_removesEveryPeerOfThatKeyOnly() = runBlocking {
        insertKey("k-1", SharingPolicyType.SELECTED_PEERS)
        insertKey("k-2", SharingPolicyType.SELECTED_PEERS)
        dao.setPolicy(KeySharingPolicy("k-1", peer))
        dao.setPolicy(KeySharingPolicy("k-1", otherPeer))
        dao.setPolicy(KeySharingPolicy("k-2", peer))

        assertEquals(2, dao.clearPoliciesForKey("k-1"))
        assertTrue(dao.getPoliciesForKeySync("k-1").isEmpty())
        assertEquals(1, dao.getPoliciesForKeySync("k-2").size)
    }

    @Test
    fun clearPoliciesForPeer_revokesThatPeerAcrossEveryKey() = runBlocking {
        insertKey("k-1", SharingPolicyType.SELECTED_PEERS)
        insertKey("k-2", SharingPolicyType.SELECTED_PEERS)
        dao.setPolicy(KeySharingPolicy("k-1", peer))
        dao.setPolicy(KeySharingPolicy("k-2", peer))
        dao.setPolicy(KeySharingPolicy("k-1", otherPeer))

        assertEquals(2, dao.clearPoliciesForPeer(peer))
        assertEquals(0, dao.countKeysSharedWithPeer(peer))
        assertEquals(1, dao.countKeysSharedWithPeer(otherPeer))
    }

    @Test
    fun deleteAll_emptiesThePolicyTable() = runBlocking {
        insertKey("k-1", SharingPolicyType.SELECTED_PEERS)
        dao.setPolicy(KeySharingPolicy("k-1", peer))

        dao.deleteAll()

        assertTrue(dao.getPoliciesForKeySync("k-1").isEmpty())
    }

    // -------------------------------------------------------------------------
    // Foreign key cascade
    // -------------------------------------------------------------------------

    @Test
    fun deletingAKeyCascadesAwayItsGrants() = runBlocking {
        insertKey("k-1", SharingPolicyType.SELECTED_PEERS)
        dao.setPolicy(KeySharingPolicy("k-1", peer))

        keyDao.deleteByKeyId("k-1")

        assertTrue(dao.getPoliciesForKeySync("k-1").isEmpty())
        assertNull(dao.getPolicy("k-1", peer))
    }
}

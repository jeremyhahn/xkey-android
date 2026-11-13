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

import com.automatethethings.xkey.storage.dao.KeyPolicyDao
import com.automatethethings.xkey.storage.entity.KeyEntity
import com.automatethethings.xkey.storage.entity.KeyPolicyEntity
import com.automatethethings.xkey.storage.entity.KeySharingPolicy
import com.automatethethings.xkey.storage.entity.SharingPolicyType
import com.automatethethings.xkey.storage.entity.SharingPolicyType.ALL_PEERS
import com.automatethethings.xkey.storage.entity.SharingPolicyType.PRIVATE
import com.automatethethings.xkey.storage.entity.SharingPolicyType.SELECTED_PEERS
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.IOException

/**
 * The four #193 findings, against the one-row store: each edit runs its
 * instance check and its writes in one transaction, and a failure is an
 * error, never a logged success. A "restart" is a new store over the same
 * tables: nothing it relies on is in memory.
 */
class KeyPolicyStoreTest {

    private val tables = FakeTables()

    private fun store() = KeyPolicyStore(tables, tables)

    /** (a) A key-instance lookup that throws fails the edit; no denial is lost. */
    @Test
    fun aThrowingInstanceLookupFailsTheEditAndKeepsTheDenial() = runBlocking {
        val instance = tables.addKey("k", SELECTED_PEERS)
        tables.grant("k", PEER)
        tables.failing += "deleteGrants"
        expectFailure { store().setPolicy("k", instance, PRIVATE) }
        tables.failing.clear()
        assertEquals(PRIVATE, tables.rows.value["k"]!!.enforced)

        tables.failing += "keyInstance"
        expectFailure { store().setPolicy("k", instance, ALL_PEERS) }
        tables.failing.clear()

        val row = store().policy("k")!!
        assertEquals("the stored policy did not change", SELECTED_PEERS, row.sharingPolicy)
        assertEquals("the denial is still enforced", PRIVATE, row.enforced)
        assertEquals(SELECTED_PEERS, tables.keyPolicy("k"))
    }

    /** (b) Failed Private clear, restart, Selected Peers: the surviving grants go first. */
    @Test
    fun aFailedPrivateClearIsOwedBeforeSelectedPeersApplies() = runBlocking {
        val instance = tables.addKey("k", SELECTED_PEERS)
        tables.grant("k", PEER)
        tables.failing += "deleteGrants"
        expectFailure { store().setPolicy("k", instance, PRIVATE) }
        tables.failing.clear()
        assertEquals("the failed clear left the grant", setOf(PEER), tables.grantsOf("k"))

        val restarted = store()
        restarted.setPolicy("k", instance, SELECTED_PEERS)

        assertEquals("the owed clear ran before Selected applied", emptySet<String>(), tables.grantsOf("k"))
        val row = restarted.policy("k")!!
        assertEquals(SELECTED_PEERS, row.enforced)
        assertEquals(false, row.clearGrants)
        assertEquals(null, row.denial)
        assertEquals(SELECTED_PEERS, tables.keyPolicy("k"))
    }

    /** (c) Key replaced between the check and the write: the old edit refuses and touches nothing. */
    @Test
    fun anEditBoundToAReplacedKeyRefusesAndLeavesTheNewKeysGrants() = runBlocking {
        val old = tables.addKey("k", SELECTED_PEERS)
        val store = store()
        store.deleteKey("k")
        val recreated = tables.addKey("k", SELECTED_PEERS)
        tables.grant("k", PEER)
        assertTrue(recreated != old)

        for (policy in SharingPolicyType.values()) {
            try {
                store.setPolicy("k", old, policy)
                fail("an edit bound to the deleted key landed: $policy")
            } catch (expected: KeyPolicyStore.KeyChangedException) {
            }
        }

        assertEquals("the new key's grants are not erased", setOf(PEER), tables.grantsOf("k"))
        val row = store.policy("k")!!
        assertEquals(recreated, row.keyInstance)
        assertEquals("the new key's policy is not exposed or narrowed", SELECTED_PEERS, row.enforced)
        assertEquals(SELECTED_PEERS, tables.keyPolicy("k"))
    }

    /** (d) A failed denial removal is an error, and after a restart policy and denial agree. */
    @Test
    fun aFailedDenialRemovalReportsFailureAndPolicyAndDenialAgreeAfterRestart() = runBlocking {
        val instance = tables.addKey("k", ALL_PEERS)
        tables.failing += "setKeyPolicy"
        expectFailure { store().setPolicy("k", instance, PRIVATE) }
        tables.failing.clear()
        assertEquals(PRIVATE, store().policy("k")!!.denial)

        tables.failing += "putPolicyRow"
        expectFailure { store().setPolicy("k", instance, ALL_PEERS) }
        tables.failing.clear()

        val row = store().policy("k")!!
        assertEquals("the key row and the policy row agree", tables.keyPolicy("k"), row.sharingPolicy)
        assertEquals("the denial still holds", PRIVATE, row.enforced)

        store().setPolicy("k", instance, ALL_PEERS)
        val landed = store().policy("k")!!
        assertEquals(null, landed.denial)
        assertEquals(ALL_PEERS, landed.enforced)
        assertEquals(ALL_PEERS, tables.keyPolicy("k"))
    }

    @Test
    fun aKeyInsertAndDeleteCarryItsPolicyRowAndGrants() = runBlocking {
        val store = store()
        val instance = store.insertKey(key("k", SELECTED_PEERS))
        assertEquals(KeyPolicyEntity("k", instance, SELECTED_PEERS), store.policy("k"))
        store.grant("k", PEER)
        assertEquals(setOf(PEER), tables.grantsOf("k"))

        assertTrue(store.deleteKey("k"))
        assertEquals(null, store.policy("k"))
        assertEquals(emptySet<String>(), tables.grantsOf("k"))
        assertEquals(null, tables.keyInstance("k"))
    }

    @Test
    fun aGrantIsRefusedWhileAClearIsOwed() = runBlocking {
        val instance = tables.addKey("k", SELECTED_PEERS)
        tables.grant("k", PEER)
        tables.failing += "deleteGrants"
        expectFailure { store().setPolicy("k", instance, PRIVATE) }
        tables.failing.clear()

        try {
            store().grant("k", OTHER)
            fail("a grant landed while a clear is owed")
        } catch (expected: KeyPolicyStore.GrantRefusedException) {
        }
        assertEquals(setOf(PEER), tables.grantsOf("k"))
    }

    private suspend fun expectFailure(edit: suspend () -> Unit) {
        try {
            edit()
            fail("a failed store write was reported as stored")
        } catch (expected: IOException) {
        }
    }

    private fun key(keyId: String, policy: SharingPolicyType) = KeyEntity(
        keyId = keyId,
        keyType = "signing",
        algorithm = "Ed25519",
        label = keyId,
        keySizeBits = 256,
        source = "local",
        sharingPolicy = policy
    )

    private companion object {
        const val PEER = "peer-a"
        const val OTHER = "peer-b"
    }
}

/**
 * The three tables the store writes, as a DAO and a transactor: a
 * transaction snapshots them and puts the snapshot back if its block throws.
 * Each name in [failing] makes that DAO call throw.
 */
private class FakeTables : KeyPolicyDao, KeyPolicyStore.Transactor {

    private data class Key(val instance: Long, val policy: SharingPolicyType)

    private val keys = MutableStateFlow(mapOf<String, Key>())
    val rows = MutableStateFlow(mapOf<String, KeyPolicyEntity>())
    private val grants = MutableStateFlow(setOf<Pair<String, String>>())
    private var nextInstance = 1L
    val failing = mutableSetOf<String>()

    /** A key row as an unrouted path would leave it, with the row the 12 -> 13 migration seeds. */
    fun addKey(keyId: String, policy: SharingPolicyType): Long {
        val instance = nextInstance++
        keys.value = keys.value + (keyId to Key(instance, policy))
        rows.value = rows.value + (keyId to KeyPolicyEntity(keyId, instance, policy))
        return instance
    }

    fun grant(keyId: String, peer: String) {
        grants.value = grants.value + (keyId to peer)
    }

    fun grantsOf(keyId: String) = grants.value.filter { it.first == keyId }.map { it.second }.toSet()

    fun keyPolicy(keyId: String) = keys.value[keyId]?.policy

    private fun check(call: String) {
        if (call in failing) throw IOException("$call failed")
    }

    override suspend fun <T> run(block: suspend () -> T): T {
        val snapshot = Triple(keys.value, rows.value, grants.value)
        val saved = nextInstance
        return try {
            block()
        } catch (e: Throwable) {
            keys.value = snapshot.first
            rows.value = snapshot.second
            grants.value = snapshot.third
            nextInstance = saved
            throw e
        }
    }

    override suspend fun keyInstance(keyId: String): Long? {
        check("keyInstance")
        return keys.value[keyId]?.instance
    }

    override suspend fun policyRow(keyId: String): KeyPolicyEntity? {
        check("policyRow")
        return rows.value[keyId]
    }

    override fun observePolicyRow(keyId: String): Flow<KeyPolicyEntity?> = rows.map { it[keyId] }

    override suspend fun putPolicyRow(row: KeyPolicyEntity) {
        check("putPolicyRow")
        if (keys.value[row.keyId]?.instance != row.keyInstance) throw IOException("FOREIGN KEY constraint failed")
        rows.value = rows.value + (row.keyId to row)
    }

    override suspend fun setKeyPolicy(keyId: String, policy: SharingPolicyType): Int {
        check("setKeyPolicy")
        val key = keys.value[keyId] ?: return 0
        keys.value = keys.value + (keyId to key.copy(policy = policy))
        return 1
    }

    override fun observeGrants(keyId: String): Flow<List<KeySharingPolicy>> =
        grants.map { all -> all.filter { it.first == keyId }.map { KeySharingPolicy(it.first, it.second) } }

    override suspend fun grants(keyId: String): List<KeySharingPolicy> {
        check("grants")
        return grantsOf(keyId).map { KeySharingPolicy(keyId, it) }
    }

    override suspend fun putGrant(grant: KeySharingPolicy) {
        check("putGrant")
        if (grant.keyId !in keys.value) throw IOException("FOREIGN KEY constraint failed")
        grant(grant.keyId, grant.peerPublicKeyHex)
    }

    override suspend fun deleteGrant(keyId: String, peerPublicKeyHex: String): Int {
        check("deleteGrant")
        val before = grants.value.size
        grants.value = grants.value - (keyId to peerPublicKeyHex)
        return before - grants.value.size
    }

    override suspend fun deleteGrants(keyId: String): Int {
        check("deleteGrants")
        val before = grants.value.size
        grants.value = grants.value.filterNot { it.first == keyId }.toSet()
        return before - grants.value.size
    }

    override suspend fun insertKey(key: KeyEntity): Long {
        check("insertKey")
        deleteCascading(key.keyId)
        val instance = nextInstance++
        keys.value = keys.value + (key.keyId to Key(instance, key.sharingPolicy))
        return instance
    }

    override suspend fun deleteKey(keyId: String): Int {
        check("deleteKey")
        return if (deleteCascading(keyId)) 1 else 0
    }

    /** The key row and, by ON DELETE CASCADE, its policy row and grant rows. */
    private fun deleteCascading(keyId: String): Boolean {
        if (keyId !in keys.value) return false
        keys.value = keys.value - keyId
        rows.value = rows.value - keyId
        grants.value = grants.value.filterNot { it.first == keyId }.toSet()
        return true
    }
}

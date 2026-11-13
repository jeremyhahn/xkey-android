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

import com.automatethethings.xkey.storage.entity.KeyPolicyEntity
import com.automatethethings.xkey.storage.entity.SharingPolicyType
import com.automatethethings.xkey.storage.entity.SharingPolicyType.ALL_PEERS
import com.automatethethings.xkey.storage.entity.SharingPolicyType.PRIVATE
import com.automatethethings.xkey.storage.entity.SharingPolicyType.SELECTED_PEERS
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

    private val tables = FakeKeyPolicyTables()

    private fun store() = tables.store()

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
        val instance = store.insertKey(FakeKeyPolicyTables.entity("k", SELECTED_PEERS))
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

    private companion object {
        const val PEER = "peer-a"
        const val OTHER = "peer-b"
    }
}


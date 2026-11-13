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
        assertTrue(store.deleteKey("k", old))
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
        store.grant("k", instance, PEER)
        assertEquals(setOf(PEER), tables.grantsOf("k"))

        assertTrue(store.deleteKey("k", instance))
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
            store().grant("k", instance, OTHER)
            fail("a grant landed while a clear is owed")
        } catch (expected: KeyPolicyStore.GrantRefusedException) {
        }
        assertEquals(setOf(PEER), tables.grantsOf("k"))
    }

    /**
     * (1) The narrowing and then its denial write both fail: the edit is
     * refused and every peer stays denied, never authorized by the old
     * policy, until a later policy write lands.
     */
    @Test
    fun aNarrowingWhoseDenialWriteAlsoFailsStillDeniesEveryPeer() = runBlocking {
        val instance = tables.addKey("k", ALL_PEERS)
        tables.failing += setOf("setKeyPolicy", "putPolicyRow")
        expectFailure { store().setPolicy("k", instance, PRIVATE) }
        tables.failing.clear()
        assertEquals(null, tables.rows.value["k"]!!.denial)

        assertEquals("a failed denial write left the peers authorized", PRIVATE, store().enforcedPolicy(tables.key("k")!!))
        try {
            store().grant("k", instance, PEER)
            fail("a grant landed while the denial is held")
        } catch (expected: KeyPolicyStore.GrantRefusedException) {
        }

        store().setPolicy("k", instance, ALL_PEERS)
        assertEquals(ALL_PEERS, store().enforcedPolicy(tables.key("k")!!))
    }

    /**
     * Finding (1): a Private whose write and denial write both fail is held
     * in the process; the grant clear it owes is held with it, so the later
     * Selected Peers write deletes the grants made before the Private.
     */
    @Test
    fun anUnrecordedPrivateDenialKeepsItsOwedGrantClear() = runBlocking {
        val instance = tables.addKey("k", SELECTED_PEERS)
        tables.grant("k", PEER)
        tables.failing += setOf("setKeyPolicy", "putPolicyRow")
        expectFailure { store().setPolicy("k", instance, PRIVATE) }
        tables.failing.clear()

        assertTrue("the owed clear was not reported", store().setPolicy("k", instance, SELECTED_PEERS))
        assertEquals("a grant from before the Private survived its owed clear", emptySet<String>(), tables.grantsOf("k"))
    }

    /** A withdrawal whose grant delete failed leaves the grant clear it owes in the policy row, after a restart too. */
    @Test
    fun aFailedWithdrawalOwesTheGrantClearDurably() = runBlocking {
        val instance = tables.addKey("k", SELECTED_PEERS)
        tables.grant("k", PEER)
        tables.failing += "deleteGrant"
        assertEquals(KeyPolicyStore.Withdrawal.OWED, store().withdraw("k", instance, PEER))
        tables.failing.clear()

        val restarted = KeyPolicyStore(tables, tables, java.util.concurrent.ConcurrentHashMap())
        assertTrue(restarted.policy("k")!!.clearGrants)
        assertEquals(PRIVATE, restarted.enforcedPolicy(tables.key("k")!!))
        assertTrue(restarted.setPolicy("k", instance, SELECTED_PEERS))
        assertEquals(emptySet<String>(), tables.grantsOf("k"))
    }

    /** A withdrawal whose obligation write fails too is held in the process with its clear. */
    @Test
    fun aWithdrawalWhoseObligationWriteFailsIsHeldWithItsClear() = runBlocking {
        val instance = tables.addKey("k", SELECTED_PEERS)
        tables.grant("k", PEER)
        tables.failing += setOf("deleteGrant", "putPolicyRow")
        assertEquals(KeyPolicyStore.Withdrawal.HELD, store().withdraw("k", instance, PEER))
        tables.failing.clear()

        assertEquals(PRIVATE, store().enforcedPolicy(tables.key("k")!!))
        assertTrue(store().setPolicy("k", instance, SELECTED_PEERS))
        assertEquals(emptySet<String>(), tables.grantsOf("k"))
        assertEquals(SELECTED_PEERS, store().enforcedPolicy(tables.key("k")!!))
    }

    /**
     * The bypass guard (#193, ruling 554): the denial and grant-clear
     * columns are written only by [KeyPolicyStore]'s obligation choke point.
     * A main source elsewhere that sets them (a Room entity argument, a
     * migration's SQL) is a path that acknowledges a denial, withdrawal or
     * fallback without it.
     */
    @Test
    fun onlyTheStoreWritesTheDenialAndGrantClearColumns() {
        val root = java.io.File("src/main/kotlin")
        assertTrue("main sources not found from ${java.io.File(".").absolutePath}", root.isDirectory)
        val writes = Regex("""clearGrants\s*=[^=]|`clear_grants`\s*=|`denial`\s*=|\bdenial\s*=[^=]""")
        val bypasses = root.walkTopDown()
            .filter { it.isFile && it.extension == "kt" && it.name != "KeyPolicyStore.kt" }
            .flatMap { file -> file.readLines().mapIndexedNotNull { i, line -> if (writes.containsMatchIn(line)) "${file.name}:${i + 1}" else null } }
            .toList()
        assertEquals("denial or grant-clear written outside the store's choke point", emptyList<String>(), bypasses)
    }

    /**
     * The bypass guard for withdrawals and RPC deletes (#193 r6, ruling 554):
     * a grant is deleted only by the store's [KeyPolicyStore.withdraw], which
     * reports a withdrawal done only once it, or its denial, is durable; and
     * every queued delete of a key from the protocol passes its key-material
     * delete into the queued edit ([KeySharingPeers.forgetKey]'s `material`),
     * so a cancelled caller never leaves the material behind.
     */
    @Test
    fun everyWithdrawalAndRpcDeleteGoesThroughTheStore() {
        val root = java.io.File("src/main/kotlin")
        assertTrue("main sources not found from ${java.io.File(".").absolutePath}", root.isDirectory)
        val sources = root.walkTopDown().filter { it.isFile && it.extension == "kt" }.toList()
        fun hits(files: List<java.io.File>, match: (String) -> Boolean) = files.flatMap { file ->
            file.readLines().mapIndexedNotNull { i, line -> if (match(line)) "${file.name}:${i + 1}" else null }
        }
        val grantDeletes = Regex("""\.deleteGrant\(|\bremoveGrant\(""")
        assertEquals(
            "a grant deleted outside the store's withdrawal",
            emptyList<String>(),
            hits(sources.filter { it.name != "KeyPolicyStore.kt" }) { grantDeletes.containsMatchIn(it) }
        )
        assertEquals(
            "a protocol key delete leaves its key material outside the queued edit",
            emptyList<String>(),
            hits(sources.filter { it.path.contains("/protocol/") }) { "forgetKey(" in it && "material =" !in it }
        )
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


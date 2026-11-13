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
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.yield
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

    /**
     * Round 8 (2): a key deleted and generated again under its id while the
     * delete's material step waits keeps the new key's material. The delete
     * deletes the material only for the key row it was bound to, inside the
     * serialisation the generation takes ([KeyPolicyStore.withKeyMaterial]).
     */
    @Test
    fun aKeyGeneratedAgainDuringTheDeleteWindowKeepsItsNewMaterial() = runBlocking {
        val old = tables.addKey("k", SELECTED_PEERS)
        val store = store()
        val material = mutableSetOf("k")
        val window = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()

        val delete = async {
            store.deleteKey("k", old, materialDelete {
                window.complete(Unit)
                release.await()
                material -= "k"
                true
            })
        }
        window.await()

        // The rows are gone; the key is generated again under its id.
        val regenerate = async {
            store.withKeyMaterial("k", tombstoneDelete { _, _ -> true }) {
                material += "k"
                store.insertKey(FakeKeyPolicyTables.entity("k", SELECTED_PEERS))
            }
        }
        yield()
        release.complete(Unit)

        assertTrue(delete.await())
        val recreated = regenerate.await()
        assertEquals(recreated, tables.keyInstance("k"))
        assertTrue("the new key's material was deleted by the old key's delete", "k" in material)
    }

    /**
     * Round 9 (2): a material delete that throws after the rows are gone
     * leaves a tombstone bound to the key instance, and the replay deletes
     * the material: no material is left without a record.
     */
    @Test
    fun aThrowingMaterialDeleteIsReplayed() = runBlocking {
        val key = tables.addKey("k", SELECTED_PEERS)
        tables.grant("k", PEER)
        val material = mutableSetOf("k")
        val store = store()

        assertTrue(store.deleteKey("k", key, materialDelete { throw IOException("keystore busy") }))
        assertEquals(null, tables.keyInstance("k"))
        assertTrue("the material lost its record", store.isDeletionPending("k"))

        store.replayDeletions(tombstoneDelete { held, _ -> material -= held.keyId; true })
        assertTrue("the replay left the material behind", "k" !in material)
        assertTrue("the tombstone outlived the material", !store.isDeletionPending("k"))
    }

    /** Round 9 (2): the process dies after the row commit, before the material delete. */
    @Test
    fun aRestartAfterTheRowDeleteReplaysTheMaterialDelete() = runBlocking {
        val key = tables.addKey("k", SELECTED_PEERS)
        val material = mutableSetOf("k")
        try {
            store().deleteKey("k", key, materialDelete { throw ProcessDeath() })
            fail("the process did not die")
        } catch (expected: ProcessDeath) {
        }
        assertEquals(null, tables.keyInstance("k"))

        val restarted = KeyPolicyStore(tables, tables, java.util.concurrent.ConcurrentHashMap())
        assertTrue("the material lost its record across the restart", restarted.isDeletionPending("k"))
        restarted.replayDeletions(tombstoneDelete { held, _ -> material -= held.keyId; true })
        assertTrue("the replay left the material behind", "k" !in material)
        assertTrue(!restarted.isDeletionPending("k"))
    }

    /** Round 9 (2): a key generated again under a tombstoned id keeps its material. */
    @Test
    fun theReplayKeepsTheMaterialOfAKeyGeneratedAgain() = runBlocking {
        val key = tables.addKey("k", SELECTED_PEERS)
        val material = mutableSetOf("k")
        val store = store()
        assertTrue(store.deleteKey("k", key, materialDelete { throw IOException("keystore busy") }))
        // The write settles the owed delete first, then writes its own material.
        store.withKeyMaterial("k", tombstoneDelete { held, _ -> material -= held.keyId; true }) {
            material += "k"
            store.insertKey(FakeKeyPolicyTables.entity("k", SELECTED_PEERS))
        }

        store.replayDeletions(tombstoneDelete { held, _ -> material -= held.keyId; true })
        assertTrue("the new key's material was deleted by the replay", "k" in material)
        assertTrue(!store.isDeletionPending("k"))
    }

    /**
     * Round 12 (2): the tombstone records the generation it deletes, and the
     * replay deletes only that generation: material written under the same
     * id since (a credential generated again under the alias) is left, even
     * by a writer that never settled the owed delete.
     */
    @Test
    fun theReplayDeletesOnlyTheGenerationItTombstoned() = runBlocking {
        val key = tables.addKey("k", SELECTED_PEERS)
        // id to generation: what the backend holds now.
        val material = mutableMapOf("k" to "first")
        var reachable = false
        val generations = object : KeyMaterial {
            override suspend fun generation(held: KeyPolicyStore.KeyMaterialHeld, source: String?) = material.getValue(held.keyId)
            override suspend fun delete(held: KeyPolicyStore.KeyMaterialHeld, tombstone: com.automatethethings.xkey.storage.entity.KeyDeletionEntity): Boolean {
                if (!reachable) throw IOException("keystore busy")
                // A generation matching delete; one recorded as nothing deletes nothing.
                if (tombstone.generation != null && material[held.keyId] == tombstone.generation) material -= held.keyId
                return true
            }
        }
        val store = store()
        assertTrue(store.deleteKey("k", key, generations))
        assertTrue(store.isDeletionPending("k"))

        // A credential generated again under the alias, outside the store.
        material["k"] = "second"
        reachable = true
        assertEquals(0, store.replayDeletions(generations))
        assertEquals("the replay deleted a generation written after its tombstone", "second", material["k"])

        // The generation it did tombstone is deleted.
        material["k"] = "first"
        tables.addKey("j", SELECTED_PEERS).let { reachable = false; material["j"] = "j1"; assertTrue(store.deleteKey("j", it, generations)) }
        reachable = true
        store.replayDeletions(generations)
        assertTrue("the replay left the tombstoned generation", "j" !in material)
    }

    /**
     * Round 10 (4): a material delete that returns with material still in a
     * backend (a refused Keystore delete, a software key left) keeps the
     * tombstone, and the replay deletes the rest before dropping it.
     */
    @Test
    fun aTombstoneStaysUntilEveryBackendConfirmsTheMaterialGone() = runBlocking {
        val key = tables.addKey("k", SELECTED_PEERS)
        val keystore = mutableSetOf("k")
        val software = mutableSetOf("k")
        val store = store()

        // The Keystore delete is refused; the software key is deleted.
        assertTrue(store.deleteKey("k", key, materialDelete { held -> software -= held.keyId; held.keyId !in keystore }))
        assertTrue("a tombstone dropped while the Keystore still holds the key", store.isDeletionPending("k"))

        assertEquals(0, store.replayDeletions(tombstoneDelete { held, _ -> keystore -= held.keyId; held.keyId !in keystore }))
        assertTrue(!store.isDeletionPending("k"))
    }

    /**
     * Round 10 (4) bypass guard: every key material delete handed to the
     * store is the app's one confirming deleter, [keyMaterialDeleter].
     */
    @Test
    fun everyMaterialDeleteIsTheConfirmingDeleter() {
        val root = java.io.File("src/main/kotlin")
        assertTrue(root.isDirectory)
        val callers = root.walkTopDown()
            .filter { it.isFile && it.extension == "kt" && it.name != "KeyPolicyStore.kt" && it.name != "KeySharingPeers.kt" }
            .filter { file -> file.readText().let { "forgetKey(" in it || ".deleteMaterial(" in it || ".replayDeletions" in it } }
            .toList()
        assertTrue("no material delete callers found", callers.size >= 3)
        assertEquals(
            "a material delete that does not confirm every backend",
            emptyList<String>(),
            callers.filter { "keyMaterialDeleter(" !in it.readText() }.map { it.name }
        )
    }

    /**
     * Round 11 (1) bypass guard: a key delete reaches Keystore aliases only
     * through [deleteKeyMaterial], which deletes through
     * [KeystoreManager.deleteUserKeyGeneration], bounded to the key's
     * user-key aliases; the one raw-alias delete is the rollback of a key
     * its own issuance just generated.
     */
    @Test
    fun aKeyDeleteTouchesOnlyUserKeyAliases() {
        val root = java.io.File("src/main/kotlin")
        assertTrue(root.isDirectory)
        val callers = root.walkTopDown()
            .filter { it.isFile && it.extension == "kt" && it.name != "KeystoreManager.kt" }
            .filter { ".deleteByAlias(" in it.readText() }
            .map { it.name }
            .toSet()
        assertEquals(setOf("CertificateManagementActivity.kt"), callers)
        val replay = java.io.File(root, "com/automatethethings/xkey/storage/KeyDeletionReplay.kt").readText()
        assertTrue(".deleteUserKeyGeneration(" in replay && "resolveKeystoreAlias(held.keyId) ?:" !in replay)
        val manager = java.io.File(root, "com/automatethethings/xkey/crypto/KeystoreManager.kt").readText()
        val body = manager.substringAfter("fun deleteUserKeyGeneration(").substringBefore("\n    /**")
        assertTrue("the generation delete is not bounded to userKeyAliases", "alias in namespace" in body && "userKeyAliases(keyId)" in body)
        assertTrue("the internal-key refusal left the deleter", "throw InternalKeyException(" in replay)
    }

    /** Round 11 (1): no internal Keystore alias lies in a user-key namespace. */
    @Test
    fun noInternalAliasIsAUserKeyAlias() {
        val internal = listOf(
            "xkey_root_ca", "xkey_intermediate_ca", "xkey_device_attestation_key", "xkey_software_key_store",
            "xkey_user_verification_key", "xkey_oath_secret_encryption_key", "xkey_password_encryption_key",
            "xkey_seal_store_key", "xkey_device_identity_0", "xkey_piv_9a"
        )
        val prefixes = com.automatethethings.xkey.crypto.KeystoreManager.userKeyAliases("")
        assertEquals(emptyList<String>(), internal.filter { alias -> prefixes.any { alias.startsWith(it) } })
    }

    /**
     * Round 11 (2): a write under an id whose earlier delete is owed settles
     * it first; one whose owed material cannot be deleted is refused, so no
     * write ever lands under a tombstone that a replay would act on.
     */
    @Test
    fun aWriteUnderATombstoneSettlesItFirstOrIsRefused() = runBlocking {
        val store = store()
        assertTrue(store.deleteMaterial("k", materialDelete { false }))
        val written = mutableSetOf<String>()

        try {
            store.withKeyMaterial("k", tombstoneDelete { _, _ -> false }) { written += "k" }
            fail("a write landed under an owed delete")
        } catch (expected: KeyPolicyStore.DeletionPendingException) {
        }
        assertTrue("the refused write ran", written.isEmpty())
        assertTrue(store.isDeletionPending("k"))

        // A rowless import, as local.shareSymmetric writes one.
        store.withKeyMaterial("k", tombstoneDelete { _, _ -> true }) { written += "k" }
        assertTrue(!store.isDeletionPending("k"))
        assertEquals(0, store.replayDeletions(tombstoneDelete { held, _ -> written -= held.keyId; true }))
        assertTrue("the replay deleted a write made after its tombstone", "k" in written)
    }

    /**
     * Round 11 (2) bypass guard: every key material write in the main
     * sources settles owed deletes with the app's one deleter.
     */
    @Test
    fun everyMaterialWriteSettlesWithTheAppsDeleter() {
        val root = java.io.File("src/main/kotlin")
        assertTrue(root.isDirectory)
        val calls = root.walkTopDown()
            .filter { it.isFile && it.extension == "kt" && it.name != "KeyPolicyStore.kt" }
            .flatMap { file -> file.readLines().mapIndexedNotNull { i, l -> if ("withKeyMaterial(" in l) "${file.name}:${i + 1}" to l else null } }
            .toList()
        assertTrue("no material writes found", calls.size >= 4)
        assertEquals(emptyList<String>(), calls.filter { "keyMaterialDeleter(" !in it.second }.map { it.first })
    }

    /** Round 9 (1): a withdrawal bound to a replaced key is stale, not REMOVED, and keeps the new grant. */
    @Test
    fun aWithdrawalBoundToAReplacedKeyIsStale() = runBlocking {
        val old = tables.addKey("k", SELECTED_PEERS)
        val store = store()
        assertTrue(store.deleteKey("k", old))
        tables.addKey("k", SELECTED_PEERS)
        tables.grant("k", PEER)

        assertEquals(KeyPolicyStore.Withdrawal.STALE, store.withdraw("k", old, PEER))
        assertEquals("the new key's grant was withdrawn", setOf(PEER), tables.grantsOf("k"))
    }

    /**
     * Round 9 (2) bypass guard: the only key-row delete in the main sources
     * is the store's, and it writes the tombstone in the same transaction.
     */
    @Test
    fun everyKeyRowDeleteWritesATombstone() {
        val root = java.io.File("src/main/kotlin")
        assertTrue(root.isDirectory)
        val rowDelete = Regex("""\bdao\.deleteKey\(""")
        val outside = root.walkTopDown()
            .filter { it.isFile && it.extension == "kt" && it.name != "KeyPolicyStore.kt" }
            .flatMap { file -> file.readLines().mapIndexedNotNull { i, l -> if (rowDelete.containsMatchIn(l)) "${file.name}:${i + 1}" else null } }
            .toList()
        assertEquals("a key-row delete outside the store", emptyList<String>(), outside)
        val store = java.io.File(root, "com/automatethethings/xkey/storage/KeyPolicyStore.kt").readText()
        val transactions = Regex("""transactor\.run \{(.*?)\n {12}\}""", RegexOption.DOT_MATCHES_ALL).findAll(store).map { it.groupValues[1] }
        val deletes = transactions.filter { rowDelete.containsMatchIn(it) }.toList()
        assertTrue("no key-row delete found", deletes.isNotEmpty())
        assertTrue("a key-row delete without its tombstone", deletes.all { "putDeletion(" in it })
    }

    private class ProcessDeath : Error("process died")

    /**
     * Round 8 (2) bypass guard (ruling 554): every keyId-scoped key-material
     * write or delete in the main sources runs inside the store's one
     * serialisation: a [KeyPolicyStore.withKeyMaterial] block, or a
     * `material` delete handed to [KeyPolicyStore.deleteKey] (through
     * `forgetKey`) or [KeyPolicyStore.deleteMaterial].
     */
    @Test
    fun everyKeyMaterialWriteAndDeleteIsSerialisedByTheStore() {
        val root = java.io.File("src/main/kotlin")
        assertTrue("main sources not found from ${java.io.File(".").absolutePath}", root.isDirectory)
        val materialCall = Regex(
            """\.(generateSymmetricKey|generateHMACKey|generateKeyForAlgorithm|generateRSAEncryptionKey|deleteGeneralKey|deleteByAlias)\(|SoftwareKeyStore\([^)]*\)\.(put|delete)\(|\bsoftwareStore\.(put|delete)\(|\bKeyMaterialHeld\("""
        )
        // A block, a material delete, or a helper taking the block's proof.
        val opener = Regex("""withKeyMaterial\(|material(: suspend \(\) -> Unit)? = \{|: KeyPolicyStore\.KeyMaterialHeld\b""")
        val bypasses = root.walkTopDown()
            .filter { it.isFile && it.extension == "kt" && it.name !in setOf("KeystoreManager.kt", "SoftwareKeyStore.kt", "KeyPolicyStore.kt") }
            .flatMap { file ->
                val lines = file.readLines()
                // Depth of the braces opened by a serialised block, line by line.
                var open = 0
                var depth = 0
                lines.mapIndexedNotNull { i, line ->
                    if (open == 0 && opener.containsMatchIn(line)) open = depth + 1
                    val inside = open != 0
                    depth += line.count { it == '{' } - line.count { it == '}' }
                    // Closed only by a brace: a helper's proof parameter
                    // opens on its signature, before its body's brace.
                    if (open != 0 && depth < open && '}' in line) open = 0
                    if (materialCall.containsMatchIn(line) && !inside) "${file.name}:${i + 1}" else null
                }
            }
            .toList()
        assertEquals("a key-material write or delete outside the store's serialisation", emptyList<String>(), bypasses)
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

    private fun decision(revision: Long, enforced: SharingPolicyType, approved: Boolean, audit: MutableList<SharingPolicyType> = mutableListOf()) =
        KeyPolicyStore.RemoteDecision(revision, enforced, approved) { audit += it }

    /** Round 10 (1): a remote change that lifts a failed narrowing's denial is refused without approval. */
    @Test
    fun `a remote lift of a denial without approval is refused in the transaction`() = runBlocking {
        val instance = tables.addKey("k", ALL_PEERS)
        tables.failing += "setKeyPolicy"
        expectFailure { store().setPolicy("k", instance, PRIVATE) }
        tables.failing.clear()
        assertEquals(PRIVATE, tables.enforced("k"))
        val revision = tables.key("k")!!.policyRevision

        try {
            store().setPolicy("k", instance, ALL_PEERS, decision(revision, ALL_PEERS, approved = false))
            fail("an unapproved lift landed")
        } catch (e: KeyPolicyStore.DecisionRefusedException) {
            // refused
        }
        assertEquals(PRIVATE, tables.enforced("k"))

        val audit = mutableListOf<SharingPolicyType>()
        store().setPolicy("k", instance, ALL_PEERS, decision(revision, PRIVATE, approved = true, audit))
        assertEquals(ALL_PEERS, tables.enforced("k"))
        assertEquals(listOf(PRIVATE), audit)
    }

    /** Round 10 (2): an approval taken at a revision the key has since left is refused inside the write's transaction. */
    @Test
    fun `an approval at an earlier revision is refused in the transaction`() = runBlocking {
        val instance = tables.addKey("k", PRIVATE)
        val approvedAt = tables.key("k")!!.policyRevision
        store().setPolicy("k", instance, ALL_PEERS)
        store().setPolicy("k", instance, PRIVATE)

        try {
            store().setPolicy("k", instance, ALL_PEERS, decision(approvedAt, PRIVATE, approved = true))
            fail("a stale approval landed")
        } catch (e: KeyPolicyStore.DecisionRefusedException) {
            // refused
        }
        assertEquals(PRIVATE, tables.keyPolicy("k"))

        // A narrowing always lands, whatever moved.
        store().setPolicy("k", instance, ALL_PEERS)
        store().setPolicy("k", instance, PRIVATE, decision(approvedAt, ALL_PEERS, approved = false))
        assertEquals(PRIVATE, tables.keyPolicy("k"))
    }

    /** Round 10 bypass guard: the remote decision is checked in setPolicy's transaction, before any write. */
    @Test
    fun `the remote decision is checked inside the policy transaction`() {
        val source = listOf(
            java.io.File("src/main/kotlin/com/automatethethings/xkey/storage/KeyPolicyStore.kt"),
            java.io.File("app/src/main/kotlin/com/automatethethings/xkey/storage/KeyPolicyStore.kt")
        ).first { it.isFile }.readText()
        val start = source.indexOf("suspend fun setPolicy(")
        val body = source.substring(start, source.indexOf("\n    suspend fun ", start + 1))
        val transaction = body.indexOf("transactor.run {")
        val check = body.indexOf("dao.policyRevision(keyId) != decision.revision")
        assertTrue(transaction in 0 until check)
        assertTrue(check < body.indexOf("dao.setKeyPolicy("))
    }
}

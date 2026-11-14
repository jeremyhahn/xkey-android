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

import com.automatethethings.xkey.audit.AuditLogger
import android.util.Log
import androidx.room.withTransaction
import androidx.sqlite.db.SupportSQLiteDatabase
import com.automatethethings.xkey.storage.dao.KeyPolicyDao
import com.automatethethings.xkey.storage.entity.KeyEntity
import com.automatethethings.xkey.storage.entity.KeyDeletionEntity
import com.automatethethings.xkey.storage.entity.KeyPolicyEntity
import com.automatethethings.xkey.storage.entity.KeySharingPolicy
import com.automatethethings.xkey.storage.entity.SharingPolicyType
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.io.IOException

/**
 * A key's material, as the store's deletes reach it (#193 r9-r12). The
 * app's one is [keyMaterialDeleter].
 *
 * Every delete reads the [generation] of the key's material under its
 * [KeyPolicyStore.withKeyMaterial] lock, records it in the deletion
 * tombstone in the row delete's transaction, and hands that tombstone to
 * [delete], directly and on every replay: what is deleted is the exact
 * material the delete saw, never whatever is stored under the id later.
 */
interface KeyMaterial {
    /**
     * The generation of [held]'s material now, the key row's `source`
     * being [source]. Throws if it cannot be read: the delete is then
     * refused with nothing changed, as a generation the replay could not
     * name would be owed for ever.
     */
    suspend fun generation(held: KeyPolicyStore.KeyMaterialHeld, source: String?): String

    /**
     * [generation] for a delete that follows an earlier delete of the id
     * just settled ([retry]): a retry deletes only the key its delete
     * names, never the other key of a shared id that the earlier delete
     * left (#255 verify).
     */
    suspend fun generation(held: KeyPolicyStore.KeyMaterialHeld, source: String?, retry: Boolean): String =
        generation(held, source)

    /**
     * Deletes what is left of [tombstone]'s generation and returns true
     * only once no backend holds any of it; material of another
     * generation is left. The store drops the tombstone on true alone.
     */
    suspend fun delete(held: KeyPolicyStore.KeyMaterialHeld, tombstone: KeyDeletionEntity): Boolean

    /** Whether [generation] names no material at all. */
    fun isEmpty(generation: String): Boolean = generation.isEmpty()

    companion object {
        /** No material: for a key whose material lives elsewhere. */
        val NONE: KeyMaterial = object : KeyMaterial {
            override suspend fun generation(held: KeyPolicyStore.KeyMaterialHeld, source: String?) = ""
            override suspend fun delete(held: KeyPolicyStore.KeyMaterialHeld, tombstone: KeyDeletionEntity) = true
        }
    }
}

/**
 * A key's sharing policy state and its grant rows, written only here (#193).
 *
 * Every write runs in one Room transaction ([Transactor]) together with the
 * check that the key row is the one the caller read ([KeyEntity.id], the
 * key's instance): an edit of a key deleted, or deleted and generated again
 * under its id, since it was read is refused with [KeyChangedException] and
 * writes nothing. A write that fails is rolled back and thrown to the caller:
 * nothing is logged and reported stored, and nothing is retried in memory.
 *
 * A narrowing (Private or Selected Peers) whose write fails leaves its
 * denial in the key's [KeyPolicyEntity] row, in a second transaction bound
 * to the same instance, so it is enforced from then on, a restart included,
 * until a later policy write lands. A Private change, or any change away from
 * Selected Peers, also leaves the grant clear it owes: the next policy write
 * deletes the key's grant rows first, and no grant is written meanwhile.
 * A withdrawal whose grant delete fails owes the same grant clear.
 *
 * Every such obligation, from a failed narrowing, a failed withdrawal
 * ([withdraw]) or the 12 -> 13 migration's fallback, is recorded through one
 * choke point, [owe] (or [owedAtMigration] inside the migration, by the same
 * rule [obligation]), before the failure is acknowledged; a withdrawal is
 * reported done only if its delete or its obligation is durable. If the row cannot be
 * written, the obligation is held in the process with its clear
 * ([unrecorded], by key id): every peer is denied, every grant refused, and
 * the next policy write for the key row deletes its grants first.
 */
class KeyPolicyStore(
    private val dao: KeyPolicyDao,
    private val transactor: Transactor,
    private val unrecorded: MutableMap<String, Held> = processObligations,
    private val audit: DeletionAudit = DeletionAudit.APP
) {

    /**
     * Records a key delete once it is committed (#193 r12): the one place a
     * user-key delete is audited, by [deleteKey] and [deleteMaterial], never
     * by a replay or settle of the same delete.
     */
    fun interface DeletionAudit {
        fun deleted(tombstone: KeyDeletionEntity)

        companion object {
            /** The app's audit log. */
            val APP = DeletionAudit { AuditLogger.logKeyDeleted(keyId = it.keyId, keyLabel = it.keyId, keyType = "general") }
        }
    }

    /** Audits [tombstone]'s committed delete; a failed audit never fails the delete. */
    private fun audited(tombstone: KeyDeletionEntity) {
        try {
            audit.deleted(tombstone)
        } catch (e: Exception) {
            // The delete is committed; its record is best effort, as every audit is.
        }
    }

    /**
     * An obligation held in the process because its write failed: the key
     * row [instance] it binds, whether it owes the grant clear, and the
     * [narrowing] that left it (null for a withdrawal), which [recordHeld]
     * writes again.
     */
    data class Held(val instance: Long, val clearGrants: Boolean, val narrowing: SharingPolicyType? = null)

    /** What an obligation leaves in a policy row: the [denial] enforced and whether the grant clear is owed. */
    data class Obligation(val denial: SharingPolicyType, val clearGrants: Boolean)

    /** Runs a block in one database transaction, rolled back if it throws. */
    interface Transactor {
        suspend fun <T> run(block: suspend () -> T): T
    }

    /** The key row an edit was bound to is gone, or was replaced. */
    class KeyChangedException(keyId: String) :
        IOException("Key $keyId was deleted or replaced; the edit was refused")

    /**
     * What a remote policy change (local.setKeyPolicy) was decided on
     * (#193 r10), checked inside its write's transaction ([setPolicy]): the
     * key's [revision] (`keys.policy_revision`) and [enforced] policy as the
     * request read them, and whether the owner [approved] the change on the
     * phone. [audit] is told the policy the committed write replaced.
     */
    class RemoteDecision(
        val revision: Long,
        val enforced: SharingPolicyType,
        val approved: Boolean,
        val audit: (replaced: SharingPolicyType) -> Unit
    )

    /**
     * A remote change refused inside its transaction: it widens what the key
     * enforces (lifting a denial included) without the owner's approval, or
     * the policy moved since the approval was taken.
     */
    class DecisionRefusedException(keyId: String, reason: String) :
        IOException("Sharing policy change of $keyId refused: $reason")

    /** A grant refused because the key's policy state forbids it. */
    class GrantRefusedException(keyId: String) :
        IOException("Key $keyId refuses grants until a policy write lands")

    /** [keyId]'s key row instance (`keys.id`), or null if there is none. Throws if it cannot be read. */
    suspend fun instance(keyId: String): Long? = dao.keyInstance(keyId)

    /** [keyId]'s policy row, or null if the key has none. */
    suspend fun policy(keyId: String): KeyPolicyEntity? = dao.policyRow(keyId)

    fun observePolicy(keyId: String): Flow<KeyPolicyEntity?> = dao.observePolicyRow(keyId)

    fun observeGrants(keyId: String): Flow<List<KeySharingPolicy>> = dao.observeGrants(keyId)

    /** [keyId]'s key row instance, observed: null while it has none. A sheet binds to one (#193 r9). */
    fun observeInstance(keyId: String): Flow<Long?> = dao.observeKeyInstance(keyId)

    /**
     * Stores [policy] for [keyId]'s key row [instance], in one transaction:
     * the grant rows are deleted first when leaving Selected Peers or when an
     * earlier change still owes their clear, then `keys.sharing_policy` and
     * the policy row, which drops any denial. Returns whether grant rows were
     * cleared.
     *
     * A remote change carries its [decision]: one that widens the policy
     * the key enforces in this transaction (a held or recorded denial
     * included) needs the owner's approval, taken at the revision and
     * enforced policy it still has; anything else is refused with
     * [DecisionRefusedException] and writes nothing. Once committed, the
     * decision's audit is told the policy the write replaced, as enforced. The sheet's
     * own changes carry none: the owner makes them on the phone.
     *
     * @throws KeyChangedException if [keyId]'s key row is not [instance].
     * @throws DecisionRefusedException if [decision] does not cover the change.
     * @throws Exception whatever the database threw; nothing was stored but
     *   the denial of a failed narrowing.
     */
    suspend fun setPolicy(
        keyId: String,
        instance: Long,
        policy: SharingPolicyType,
        decision: RemoteDecision? = null
    ): Boolean =
        try {
            var replaced: SharingPolicyType? = null
            transactor.run {
                val row = bound(keyId, instance)
                if (decision != null) {
                    val stored = dao.storedPolicy(keyId) ?: throw KeyChangedException(keyId)
                    val pending = held(keyId, instance)
                    val enforced = if (pending != null) SharingPolicyType.PRIVATE else row?.enforced ?: stored
                    // Already at it, read here in the edit's turn, not before
                    // it (#255 verify): nothing is written, nothing audited.
                    if (enforced == policy && stored == policy && pending == null && row?.clearGrants != true) {
                        return@run false
                    }
                    replaced = enforced
                    if (widens(enforced, policy)) {
                        if (!decision.approved) throw DecisionRefusedException(keyId, "it needs the owner's approval")
                        if (dao.policyRevision(keyId) != decision.revision || enforced != decision.enforced) {
                            throw DecisionRefusedException(keyId, "the policy changed after the approval")
                        }
                    }
                }
                val clear = policy != SharingPolicyType.SELECTED_PEERS || row?.clearGrants == true ||
                    held(keyId, instance)?.clearGrants == true
                if (clear) dao.deleteGrants(keyId)
                if (dao.setKeyPolicy(keyId, policy) != 1) throw KeyChangedException(keyId)
                dao.putPolicyRow(KeyPolicyEntity(keyId, instance, policy))
                clear
            }.also {
                unrecorded.computeIfPresent(keyId) { _, held -> held.takeUnless { it.instance == instance } }
                replaced?.let { old -> decision?.audit?.invoke(old) }
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: KeyChangedException) {
            throw e
        } catch (e: DecisionRefusedException) {
            throw e
        } catch (e: Exception) {
            if (policy != SharingPolicyType.ALL_PEERS) owe(keyId, instance, policy, e)
            throw e
        }

    /** How a [withdraw] ended. Only [REMOVED] and [OWED] may be reported done: both are durable. */
    enum class Withdrawal {
        /** The grant is deleted. */
        REMOVED,

        /**
         * Refused: the key row it was bound to is gone or replaced, so it
         * touched nothing; a replacement's grants are its own (#193 r9).
         */
        STALE,

        /** The delete failed; the grant clear it owes is in the policy row, so the peer stays denied after a restart too. */
        OWED,

        /** The delete failed and so did the obligation's write: it is held in the process only, which a restart loses. */
        HELD
    }

    /**
     * Withdraws [peerPublicKeyHex]'s grant of [keyId]'s key row [instance]:
     * deletes it, bound to the key row, or, if that fails, records the grant
     * clear it owes through the choke point ([owe]), which denies every peer
     * of the key until its next policy write. The caller reports the
     * withdrawal done only on a durable result (#193 r6, ruling 554). Never
     * throws but for cancellation.
     */
    suspend fun withdraw(keyId: String, instance: Long, peerPublicKeyHex: String): Withdrawal =
        try {
            transactor.run {
                if (dao.keyInstance(keyId) != instance) throw KeyChangedException(keyId)
                dao.deleteGrant(keyId, peerPublicKeyHex)
            }
            Withdrawal.REMOVED
        } catch (e: CancellationException) {
            throw e
        } catch (e: KeyChangedException) {
            Withdrawal.STALE
        } catch (e: Exception) {
            if (owe(keyId, instance, null, e)) Withdrawal.OWED else Withdrawal.HELD
        }

    /**
     * The choke point (#193, ruling 554): records the obligation of a failed
     * [narrowing] (Private or Selected Peers), or of a failed withdrawal
     * (null), in [keyId]'s policy row, if its key row is still [instance],
     * by [obligation]; an owed clear, recorded or held, is kept. If the row
     * cannot be written, or there is none, the obligation is held in the
     * process instead; the write's failure is added to [failure]. Returns
     * whether the obligation is durable: recorded in the row, or owed by no
     * key row (it is gone or replaced). Never throws but for cancellation.
     */
    private suspend fun owe(keyId: String, instance: Long, narrowing: SharingPolicyType?, failure: Exception?): Boolean {
        val heldClear = held(keyId, instance)?.clearGrants == true
        val heldNarrowing = held(keyId, instance)?.narrowing
        var owed = obligation(narrowing, heldClear)
        try {
            val recorded = transactor.run {
                val row = bound(keyId, instance) ?: return@run false
                owed = obligation(narrowing, heldClear || row.clearGrants)
                dao.putPolicyRow(
                    row.copy(pendingPolicy = narrowing ?: row.pendingPolicy, denial = owed.denial, clearGrants = owed.clearGrants)
                )
                true
            }
            if (!recorded) unrecorded[keyId] = Held(instance, owed.clearGrants, narrowing ?: heldNarrowing)
            return recorded
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (gone: KeyChangedException) {
            // The key row is gone or replaced: its grants went with it.
            return true
        } catch (write: Exception) {
            // Fail closed: denied in this process, clear owed, until a later write lands.
            unrecorded[keyId] = Held(instance, owed.clearGrants, narrowing ?: heldNarrowing)
            failure?.addSuppressed(write)
            return false
        }
    }

    /** The obligation held in the process for [keyId]'s key row [instance], if any. */
    private fun held(keyId: String, instance: Long): Held? = unrecorded[keyId]?.takeIf { it.instance == instance }

    /** Whether an obligation for [keyId]'s key row [instance] is held in the process only: not durable, which a restart loses. */
    fun isHeld(keyId: String, instance: Long): Boolean = held(keyId, instance) != null

    /**
     * Writes the obligation held in the process for [keyId]'s key row
     * [instance] to its policy row again, through [owe] (#193 r9): a policy
     * denial whose sheet is gone is retried like a withdrawal. Returns
     * whether nothing is held any more: the obligation is durable, or its
     * key row is gone or replaced. Never throws but for cancellation.
     */
    suspend fun recordHeld(keyId: String, instance: Long): Boolean {
        val held = held(keyId, instance) ?: return true
        if (!owe(keyId, instance, held.narrowing, null)) return false
        unrecorded.remove(keyId, held)
        return !isHeld(keyId, instance)
    }

    /**
     * Writes [peerPublicKeyHex]'s grant for [keyId]. Refused while the key's
     * policy row owes a grant clear or denies every peer: the clear would
     * delete it, or it would authorize nothing.
     *
     * @throws KeyChangedException if the key row is not [instance]: the key
     *   is gone, or was generated again under its id since the grant was made.
     * @throws GrantRefusedException if the key's policy state refuses grants.
     */
    suspend fun grant(keyId: String, instance: Long, peerPublicKeyHex: String) {
        transactor.run {
            if (dao.keyInstance(keyId) != instance) throw KeyChangedException(keyId)
            if (held(keyId, instance) != null || refusesGrants(dao.policyRow(keyId))) throw GrantRefusedException(keyId)
            dao.putGrant(KeySharingPolicy(keyId = keyId, peerPublicKeyHex = peerPublicKeyHex, allowed = true))
        }
    }

    /**
     * Inserts [key], replacing a key row under its id, with its policy row,
     * in one transaction. Returns the new row's instance.
     */
    suspend fun insertKey(key: KeyEntity): Long =
        transactor.run {
            val instance = dao.insertKey(key)
            dao.putPolicyRow(KeyPolicyEntity(key.keyId, instance, key.sharingPolicy))
            instance
        }

    /**
     * Deletes [keyId]'s grant rows, policy row and key row in one
     * transaction, if its key row is still [instance]. Returns false, with
     * nothing deleted, if the key is gone or was generated again under its id.
     * Once the rows are deleted, [material] deletes the key's material (the
     * generation read before the row delete, recorded in its tombstone) in
     * the same call: a caller that queues this and is cancelled meanwhile
     * never leaves the material of a deleted key behind (#193 r6). The row
     * check, the delete and [material] run in [withKeyMaterial], the
     * serialisation every generation takes: material is deleted only for
     * the key row [instance] whose rows were just deleted (#193 r8).
     */
    suspend fun deleteKey(keyId: String, instance: Long, material: KeyMaterial = KeyMaterial.NONE): Boolean =
        lockKeyMaterial(keyId) { held ->
            if (dao.keyInstance(keyId) != instance) return@lockKeyMaterial false
            // An earlier delete beside this row still owing material is
            // settled first: this tombstone never replaces it (#255 verify).
            val retry = noTombstoneOwed(held, material) ?: return@lockKeyMaterial false
            val source = dao.keySource(keyId)
            // Under the lock every write of the id's material takes, so this
            // is the generation of the row being deleted (#193 r12).
            val generation = material.generation(held, source, retry)
            val tombstone = KeyDeletionEntity(keyId, instance, source, generation)
            val deleted = transactor.run {
                if (dao.keyInstance(keyId) != instance) return@run false
                // The tombstone, in the row delete's transaction: the material
                // keeps a record until its delete succeeds (#193 r9).
                dao.putDeletion(tombstone)
                dao.deleteGrants(keyId)
                dao.deleteKey(keyId) > 0
            }
            if (deleted) {
                audited(tombstone)
                deleteMaterialOf(held, tombstone, material)
            }
            deleted
        }

    /**
     * Deletes the material of [keyId] when it has no key row ([material]),
     * inside [withKeyMaterial]: only if no key row appeared meanwhile, so a
     * key generated under the id while this waited keeps its material.
     * A tombstone is written first, so a failed delete is replayed. Returns
     * whether [material] was attempted.
     */
    suspend fun deleteMaterial(keyId: String, material: KeyMaterial, besideRow: Long? = null): Boolean =
        lockKeyMaterial(keyId) { held ->
            // [besideRow]: the id's key row is another key's (a credential
            // and a general key share the id) and stays, with its policy and
            // grants; [material] names only the deleted key's (#255 review).
            if (dao.keyInstance(keyId) != besideRow) return@lockKeyMaterial false
            val source = dao.deletion(keyId)?.source
            // A delete names one key's material, so its generation need not
            // hold what an earlier tombstone owes: that one is settled first.
            val retry = noTombstoneOwed(held, material) ?: return@lockKeyMaterial false
            val generation = material.generation(held, source, retry)
            // A delete beside a row records that row's instance: the one
            // tombstone whose row is still there, which [settleDeletion]
            // replays instead of dropping.
            val tombstone = KeyDeletionEntity(keyId, besideRow ?: NO_ROW, source, generation)
            val absent = transactor.run {
                if (dao.keyInstance(keyId) != besideRow) return@run false
                dao.putDeletion(tombstone)
                true
            }
            if (absent) {
                // A delete of an id that holds nothing deletes nothing to record.
                if (!material.isEmpty(generation)) audited(tombstone)
                deleteMaterialOf(held, tombstone, material)
            }
            absent
        }

    /**
     * The one guard before a delete writes its tombstone (#255 verify): the
     * id holds one tombstone, so a pending one is settled first
     * ([settleDeletion]), and while it still owes material no other replaces
     * it. A delete naming one key of a shared id, or a rowless second
     * delete, reads a generation that need not hold what the earlier one
     * owes. Null, with nothing written, if a tombstone is still owed; else
     * whether one was just settled: the new delete is then a retry, which
     * reads its generation with `retry` ([KeyMaterial.generation]) and so
     * never reaches the other key of a shared id that the settled delete
     * left beside its row.
     */
    private suspend fun noTombstoneOwed(held: KeyMaterialHeld, material: KeyMaterial): Boolean? {
        if (dao.deletion(held.keyId) == null) return false
        settleDeletion(held, material)
        return if (dao.deletion(held.keyId) == null) true else null
    }

    /**
     * Deletes [tombstone]'s generation with [material], the one place a
     * tombstone's material is deleted and the tombstone dropped: only once
     * [material] confirms every backend holds none of it (#193 r10, r12).
     * A [material] that throws or reports material left keeps the
     * tombstone: [replayDeletions] deletes the material later.
     */
    private suspend fun deleteMaterialOf(held: KeyMaterialHeld, tombstone: KeyDeletionEntity, material: KeyMaterial) {
        val keyId = held.keyId
        val instance = tombstone.keyInstance
        val removed = try {
            material.delete(held, tombstone)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            false
        }
        // Kept for the replay: the tombstone is the material's record.
        if (!removed) return
        try {
            dao.dropDeletion(keyId, instance)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            // The tombstone stays; replaying it deletes nothing that is there.
        }
    }

    /**
     * The key sync's one key row insert (#193 r10, r11): runs [insert] only
     * if [keyId] has no key row and no deletion tombstone, the check and the
     * insert in one step under [keyId]'s material lock, the lock every
     * delete and its replay hold from the row delete to the tombstone drop.
     * A sync racing a delete never lists the key again with default
     * metadata, and never makes the replay drop a tombstone it still owes.
     * Returns whether [insert] ran.
     */
    suspend fun insertDiscovered(keyId: String, insert: suspend () -> Unit): Boolean =
        lockKeyMaterial(keyId) {
            if (dao.deletion(keyId) != null || dao.keyInstance(keyId) != null) return@lockKeyMaterial false
            insert()
            true
        }

    /** Whether [keyId]'s material is owed a delete: its rows are gone, its material may not be. */
    suspend fun isDeletionPending(keyId: String): Boolean = dao.deletion(keyId) != null

    /**
     * The one gate every use of a key passes (#193 r12): a key whose delete
     * reported success refuses every operation from that moment, though its
     * material may not be deleted yet (its tombstone still owed). Throws
     * [KeyDeletedException] if [keyId] has a deletion tombstone. A write of
     * the id's material takes [withKeyMaterial] instead, which settles the
     * tombstone first.
     */
    suspend fun requireUsable(keyId: String) {
        if (isDeletionPending(keyId)) throw KeyDeletedException(keyId)
    }

    /** A use of a deleted key refused by [requireUsable]. */
    class KeyDeletedException(keyId: String) : IOException("Key $keyId was deleted")

    /**
     * Replays every deletion tombstone (#193 r9): at start-up and before a
     * key sync, so material whose delete failed, or whose process died after
     * the row commit, is deleted, never rediscovered with default metadata
     * or orphaned. Each runs in [withKeyMaterial]; a key generated again
     * under the id meanwhile keeps its material and the tombstone is
     * dropped. [deleter] deletes the generation the tombstone recorded. A
     * tombstone whose [deleter] throws stays for the next replay. Returns
     * how many are left.
     */
    suspend fun replayDeletions(deleter: KeyMaterial): Int {
        var left = 0
        for (tombstone in dao.deletions()) {
            lockKeyMaterial(tombstone.keyId) { held ->
                settleDeletion(held, deleter)
                if (dao.deletion(tombstone.keyId) != null) left++
            }
        }
        return left
    }

    /**
     * Settles [held]'s deletion tombstone, if it has one: deletes the
     * material of the key row it recorded ([deleteMaterialOf]) while no key
     * row is there, else drops it (a key generated again keeps its
     * material). The one place a tombstone is replayed: by
     * [replayDeletions], and by [withKeyMaterial] before any write, so no
     * tombstone outlives a later write under its id and a replay only ever
     * deletes the generation it recorded (#193 r11).
     */
    @PublishedApi
    internal suspend fun settleDeletion(held: KeyMaterialHeld, deleter: KeyMaterial) {
        val tombstone = dao.deletion(held.keyId) ?: return
        val row = dao.keyInstance(held.keyId)
        // A row under the tombstone's own instance is the other key of a
        // shared id (a delete beside it, [deleteMaterial]): a row delete
        // drops its row in the tombstone's transaction, so no other does.
        if (row == null || (tombstone.keyInstance != NO_ROW && row == tombstone.keyInstance)) {
            deleteMaterialOf(held, tombstone, deleter)
        } else {
            dao.dropDeletion(held.keyId, tombstone.keyInstance)
        }
    }

    /**
     * The one serialisation of a write of [keyId]'s key material (#193 r8,
     * r11, ruling 554): every write of it (a generation with its row insert,
     * an import) runs in [block] under [keyId]'s lock, the lock every
     * delete takes, so a delete never removes the material of a key
     * generated again under its id between its row delete and its material
     * delete. Before [block], an earlier delete still owed under the id is
     * settled with [settle] (the app's [keyMaterialDeleter]); if its
     * material cannot be deleted, [block] does not run and
     * [DeletionPendingException] is thrown: a write never lands under a
     * tombstone, so no replay deletes it. Not reentrant: [block] must not
     * call [deleteKey], [deleteMaterial] or this for the same id. A helper
     * that writes material for its caller takes the [KeyMaterialHeld]
     * handed to [block], so it is callable only from inside one.
     */
    suspend inline fun <T> withKeyMaterial(keyId: String, settle: KeyMaterial, block: (KeyMaterialHeld) -> T): T =
        lockKeyMaterial(keyId) { held ->
            settleDeletion(held, settle)
            if (isDeletionPending(keyId)) throw DeletionPendingException(keyId)
            block(held)
        }

    /**
     * The one gate every crypto use of a user key passes (#255 review,
     * ruling 554): [requireUsable] rechecks the key under [keyId]'s material
     * lock, the lock every delete takes, and [block] runs as a shared use of
     * the key that the lock's exclusive holders (deletes, [withKeyMaterial])
     * wait out. A request that waited in an approval prompt while a delete
     * reported success is refused here, before any crypto, never run with
     * the deleted key; a delete that starts while a use runs waits until it
     * ends. Uses of one key by two desktops run side by side. The dispatch
     * gate's earlier [requireUsable] refuses early; this one refuses late.
     * [block] must not take [keyId]'s exclusive lock.
     */
    suspend inline fun <T> withUsableKey(keyId: String, block: () -> T): T {
        val lock = acquireMaterialLock(keyId)
        try {
            lock.mutex.withLock {
                requireUsable(keyId)
                lock.beginUse()
            }
            try {
                return block()
            } finally {
                lock.endUse()
            }
        } finally {
            releaseMaterialLock(keyId, lock)
        }
    }

    /**
     * [keyId]'s exclusive material lock, for the store's deletes and
     * [withKeyMaterial]: [block] runs once no [withUsableKey] use of the key
     * is running, and none starts until it ends.
     */
    @PublishedApi
    internal suspend inline fun <T> lockKeyMaterial(keyId: String, block: (KeyMaterialHeld) -> T): T {
        val lock = acquireMaterialLock(keyId)
        try {
            return lock.mutex.withLock {
                // Uses start only under the mutex, so none starts meanwhile.
                lock.awaitNoUse()
                block(KeyMaterialHeld(keyId))
            }
        } finally {
            releaseMaterialLock(keyId, lock)
        }
    }

    /**
     * A key material write refused: an earlier delete under the id still
     * owes material it could not delete yet (#193 r11).
     */
    class DeletionPendingException(keyId: String) :
        IOException("An earlier delete of key $keyId is not finished; try again")

    /**
     * Proof that [keyId]'s [withKeyMaterial] lock is held: only that block
     * makes one.
     */
    class KeyMaterialHeld @PublishedApi internal constructor(val keyId: String)

    /**
     * One key id's material lock and how many callers hold or wait on it.
     * Key ids can be chosen by a peer, so a lock lives only while it has a
     * holder or a waiter, the way [com.automatethethings.xkey.protocol.KeyIdReservations]
     * keeps its locks: the map never grows with ids no one is using.
     */
    @PublishedApi
    internal class MaterialLock {
        val mutex = Mutex()
        var users = 0
        private var uses = 0
        private var idle: CompletableDeferred<Unit>? = null

        /** One more running [withUsableKey] use; called under [mutex]. */
        fun beginUse() = synchronized(this) { uses++ }

        fun endUse() {
            val done = synchronized(this) {
                if (--uses == 0) idle.also { idle = null } else null
            }
            done?.complete(Unit)
        }

        /** Waits until no use runs; called under [mutex]. */
        suspend fun awaitNoUse() {
            while (true) {
                val wait = synchronized(this) {
                    if (uses == 0) null else idle ?: CompletableDeferred<Unit>().also { idle = it }
                } ?: return
                wait.await()
            }
        }
    }

    /** [keyId]'s lock for [withKeyMaterial], counted as one more user until [releaseMaterialLock]. */
    @PublishedApi
    internal fun acquireMaterialLock(keyId: String): MaterialLock =
        synchronized(materialLocks) { materialLocks.getOrPut(keyId) { MaterialLock() }.also { it.users++ } }

    /** Ends one use of [lock]; the last user removes it from the map. */
    @PublishedApi
    internal fun releaseMaterialLock(keyId: String, lock: MaterialLock) {
        synchronized(materialLocks) {
            if (--lock.users == 0) materialLocks.remove(keyId)
        }
    }

    /**
     * The policy to enforce for [key]: its policy row's, which carries a
     * denial left by a failed narrowing, or the stored one if the row is
     * missing or belongs to another key row.
     */
    suspend fun enforcedPolicy(key: KeyEntity): SharingPolicyType =
        if (held(key.keyId, key.id) != null) SharingPolicyType.PRIVATE
        else dao.policyRow(key.keyId)?.takeIf { it.keyInstance == key.id }?.enforced ?: key.sharingPolicy

    /** [policy] lets more peers use the key than [from] does. */
    private fun widens(from: SharingPolicyType, policy: SharingPolicyType): Boolean = reach(policy) > reach(from)

    /** How many peers [policy] lets use the key, in order: none, the selected ones, every one. */
    private fun reach(policy: SharingPolicyType): Int = when (policy) {
        SharingPolicyType.PRIVATE -> 0
        SharingPolicyType.SELECTED_PEERS -> 1
        SharingPolicyType.ALL_PEERS -> 2
    }

    /** [keyId]'s policy row, after checking its key row is [instance]. */
    private suspend fun bound(keyId: String, instance: Long): KeyPolicyEntity? {
        if (dao.keyInstance(keyId) != instance) throw KeyChangedException(keyId)
        return dao.policyRow(keyId)?.takeIf { it.keyInstance == instance }
    }

    companion object {
        /** A tombstone's instance when the material it deletes had no key row ([deleteMaterial]). */
        const val NO_ROW = 0L

        /** Obligations whose write failed, by key id, for the life of the process. */
        private val processObligations: MutableMap<String, Held> = java.util.concurrent.ConcurrentHashMap()

        /** Each key id's material lock ([withKeyMaterial]), shared by every store in the process. */
        private val materialLocks = HashMap<String, MaterialLock>()

        /** How many key ids have a live material lock (tests: the map never outgrows its users). */
        internal fun liveMaterialLocks(): Int = synchronized(materialLocks) { materialLocks.size }

        /** [keyId]'s live material lock users, 0 when it has none. */
        internal fun materialLockUsers(keyId: String): Int = synchronized(materialLocks) { materialLocks[keyId]?.users ?: 0 }

        /**
         * The rule every obligation is recorded by: a failed withdrawal
         * (null [narrowing]) or Private, or any narrowing once a clear is
         * already owed ([owedClear]), denies every peer and owes the grant
         * clear; a failed Selected Peers alone denies by Selected Peers.
         */
        fun obligation(narrowing: SharingPolicyType?, owedClear: Boolean): Obligation {
            val clear = owedClear || narrowing != SharingPolicyType.SELECTED_PEERS
            return Obligation(if (clear) SharingPolicyType.PRIVATE else SharingPolicyType.SELECTED_PEERS, clear)
        }

        /**
         * The choke point inside the 12 -> 13 migration, over the policy
         * rows it has just seeded from `keys` (none owes a clear yet):
         * records each "instance@POLICY" of [denials] on its key row by
         * [obligation], dropping a record for another key row. If the
         * records cannot be read, every key may owe a Private's clear, so
         * every row gets the obligation of a failed withdrawal, deny-all and
         * the clear, and the records stay where they were.
         */
        fun owedAtMigration(db: SupportSQLiteDatabase, denials: () -> Map<String, String>) {
            val recorded = try {
                denials()
            } catch (e: Exception) {
                Log.e("KeyPolicyStore", "Reading recorded key policy denials failed; every key denied and its grants owed a clear", e)
                val owed = obligation(null, false)
                db.execSQL(
                    "UPDATE `key_policies` SET `denial` = ?, `clear_grants` = ?",
                    arrayOf<Any>(owed.denial.name, if (owed.clearGrants) 1 else 0)
                )
                return
            }
            for ((keyId, record) in recorded) {
                val instance = record.substringBefore('@', "").toLongOrNull() ?: continue
                val narrowing = when (record.substringAfter('@')) {
                    "PRIVATE" -> SharingPolicyType.PRIVATE
                    "SELECTED_PEERS" -> SharingPolicyType.SELECTED_PEERS
                    else -> continue
                }
                val owed = obligation(narrowing, false)
                db.execSQL(
                    "UPDATE `key_policies` SET `pending_policy` = ?, `denial` = ?, `clear_grants` = ? " +
                        "WHERE `key_id` = ? AND `key_instance` = ?",
                    arrayOf<Any>(narrowing.name, owed.denial.name, if (owed.clearGrants) 1 else 0, keyId, instance)
                )
            }
        }

        /** A grant written under [row] would be deleted by its owed clear, or deny-all would hide it. */
        fun refusesGrants(row: KeyPolicyEntity?): Boolean =
            row != null && (row.clearGrants || row.denial == SharingPolicyType.PRIVATE)

        /** The store over [database], each write in a Room transaction. */
        fun of(database: XKeyDatabase): KeyPolicyStore =
            KeyPolicyStore(
                database.keyPolicyDao(),
                object : Transactor {
                    override suspend fun <T> run(block: suspend () -> T): T = database.withTransaction { block() }
                }
            )
    }
}

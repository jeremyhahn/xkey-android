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

import android.util.Log
import androidx.room.withTransaction
import androidx.sqlite.db.SupportSQLiteDatabase
import com.automatethethings.xkey.storage.dao.KeyPolicyDao
import com.automatethethings.xkey.storage.entity.KeyEntity
import com.automatethethings.xkey.storage.entity.KeyPolicyEntity
import com.automatethethings.xkey.storage.entity.KeySharingPolicy
import com.automatethethings.xkey.storage.entity.SharingPolicyType
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.io.IOException

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
    private val unrecorded: MutableMap<String, Held> = processObligations
) {

    /** An obligation held in the process because its write failed: the key row [instance] it binds, and whether it owes the grant clear. */
    data class Held(val instance: Long, val clearGrants: Boolean)

    /** What an obligation leaves in a policy row: the [denial] enforced and whether the grant clear is owed. */
    data class Obligation(val denial: SharingPolicyType, val clearGrants: Boolean)

    /** Runs a block in one database transaction, rolled back if it throws. */
    interface Transactor {
        suspend fun <T> run(block: suspend () -> T): T
    }

    /** The key row an edit was bound to is gone, or was replaced. */
    class KeyChangedException(keyId: String) :
        IOException("Key $keyId was deleted or replaced; the edit was refused")

    /** A grant refused because the key's policy state forbids it. */
    class GrantRefusedException(keyId: String) :
        IOException("Key $keyId refuses grants until a policy write lands")

    /** [keyId]'s key row instance (`keys.id`), or null if there is none. Throws if it cannot be read. */
    suspend fun instance(keyId: String): Long? = dao.keyInstance(keyId)

    /** [keyId]'s policy row, or null if the key has none. */
    suspend fun policy(keyId: String): KeyPolicyEntity? = dao.policyRow(keyId)

    fun observePolicy(keyId: String): Flow<KeyPolicyEntity?> = dao.observePolicyRow(keyId)

    fun observeGrants(keyId: String): Flow<List<KeySharingPolicy>> = dao.observeGrants(keyId)

    /**
     * Stores [policy] for [keyId]'s key row [instance], in one transaction:
     * the grant rows are deleted first when leaving Selected Peers or when an
     * earlier change still owes their clear, then `keys.sharing_policy` and
     * the policy row, which drops any denial. Returns whether grant rows were
     * cleared.
     *
     * @throws KeyChangedException if [keyId]'s key row is not [instance].
     * @throws Exception whatever the database threw; nothing was stored but
     *   the denial of a failed narrowing.
     */
    suspend fun setPolicy(keyId: String, instance: Long, policy: SharingPolicyType): Boolean =
        try {
            transactor.run {
                val row = bound(keyId, instance)
                val clear = policy != SharingPolicyType.SELECTED_PEERS || row?.clearGrants == true ||
                    held(keyId, instance)?.clearGrants == true
                if (clear) dao.deleteGrants(keyId)
                if (dao.setKeyPolicy(keyId, policy) != 1) throw KeyChangedException(keyId)
                dao.putPolicyRow(KeyPolicyEntity(keyId, instance, policy))
                clear
            }.also { unrecorded.computeIfPresent(keyId) { _, held -> held.takeUnless { it.instance == instance } } }
        } catch (e: CancellationException) {
            throw e
        } catch (e: KeyChangedException) {
            throw e
        } catch (e: Exception) {
            if (policy != SharingPolicyType.ALL_PEERS) owe(keyId, instance, policy, e)
            throw e
        }

    /** How a [withdraw] ended. Only [REMOVED] and [OWED] may be reported done: both are durable. */
    enum class Withdrawal {
        /** The grant is deleted, or its key row is gone or replaced, its grants with it. */
        REMOVED,

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
            Withdrawal.REMOVED
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
            if (!recorded) unrecorded[keyId] = Held(instance, owed.clearGrants)
            return recorded
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (gone: KeyChangedException) {
            // The key row is gone or replaced: its grants went with it.
            return true
        } catch (write: Exception) {
            // Fail closed: denied in this process, clear owed, until a later write lands.
            unrecorded[keyId] = Held(instance, owed.clearGrants)
            failure?.addSuppressed(write)
            return false
        }
    }

    /** The obligation held in the process for [keyId]'s key row [instance], if any. */
    private fun held(keyId: String, instance: Long): Held? = unrecorded[keyId]?.takeIf { it.instance == instance }

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
     * Once the rows are deleted, [material] deletes the key's material in
     * the same call: a caller that queues this and is cancelled meanwhile
     * never leaves the material of a deleted key behind (#193 r6). The row
     * check, the delete and [material] run in [withKeyMaterial], the
     * serialisation every generation takes: material is deleted only for
     * the key row [instance] whose rows were just deleted (#193 r8).
     */
    suspend fun deleteKey(keyId: String, instance: Long, material: suspend () -> Unit = {}): Boolean =
        withKeyMaterial(keyId) {
            transactor.run {
                if (dao.keyInstance(keyId) != instance) return@run false
                dao.deleteGrants(keyId)
                dao.deleteKey(keyId) > 0
            }.also { if (it) material() }
        }

    /**
     * Deletes the material of [keyId] when it has no key row ([material]),
     * inside [withKeyMaterial]: only if no key row appeared meanwhile, so a
     * key generated under the id while this waited keeps its material.
     * Returns whether [material] ran.
     */
    suspend fun deleteMaterial(keyId: String, material: suspend () -> Unit): Boolean =
        withKeyMaterial(keyId) {
            if (dao.keyInstance(keyId) != null) return@withKeyMaterial false
            material()
            true
        }

    /**
     * The one serialisation of [keyId]'s key material (#193 r8, ruling 554):
     * every write of it (a generation with its row insert, an import) and
     * every delete of it ([deleteKey], [deleteMaterial]) runs in [block]
     * under [keyId]'s lock, one at a time, so a delete never removes the
     * material of a key generated again under its id between its row delete
     * and its material delete. Not reentrant: [block] must not call
     * [deleteKey], [deleteMaterial] or this for the same id. A helper that
     * writes material for its caller takes the [KeyMaterialHeld] handed to
     * [block], so it is callable only from inside one.
     */
    suspend inline fun <T> withKeyMaterial(keyId: String, block: (KeyMaterialHeld) -> T): T =
        materialLock(keyId).withLock { block(KeyMaterialHeld(keyId)) }

    /**
     * Proof that [keyId]'s [withKeyMaterial] lock is held: only that block
     * makes one.
     */
    class KeyMaterialHeld @PublishedApi internal constructor(val keyId: String)

    /** [keyId]'s lock for [withKeyMaterial]. */
    @PublishedApi
    internal fun materialLock(keyId: String): Mutex = materialLocks.computeIfAbsent(keyId) { Mutex() }

    /**
     * The policy to enforce for [key]: its policy row's, which carries a
     * denial left by a failed narrowing, or the stored one if the row is
     * missing or belongs to another key row.
     */
    suspend fun enforcedPolicy(key: KeyEntity): SharingPolicyType =
        if (held(key.keyId, key.id) != null) SharingPolicyType.PRIVATE
        else dao.policyRow(key.keyId)?.takeIf { it.keyInstance == key.id }?.enforced ?: key.sharingPolicy

    /** [keyId]'s policy row, after checking its key row is [instance]. */
    private suspend fun bound(keyId: String, instance: Long): KeyPolicyEntity? {
        if (dao.keyInstance(keyId) != instance) throw KeyChangedException(keyId)
        return dao.policyRow(keyId)?.takeIf { it.keyInstance == instance }
    }

    companion object {
        /** Obligations whose write failed, by key id, for the life of the process. */
        private val processObligations: MutableMap<String, Held> = java.util.concurrent.ConcurrentHashMap()

        /** Each key id's material lock ([withKeyMaterial]), shared by every store in the process. */
        private val materialLocks = java.util.concurrent.ConcurrentHashMap<String, Mutex>()

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

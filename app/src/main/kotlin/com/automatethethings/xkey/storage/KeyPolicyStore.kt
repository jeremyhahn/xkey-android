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

import androidx.room.withTransaction
import com.automatethethings.xkey.storage.dao.KeyPolicyDao
import com.automatethethings.xkey.storage.entity.KeyEntity
import com.automatethethings.xkey.storage.entity.KeyPolicyEntity
import com.automatethethings.xkey.storage.entity.KeySharingPolicy
import com.automatethethings.xkey.storage.entity.SharingPolicyType
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.Flow
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
 */
class KeyPolicyStore(
    private val dao: KeyPolicyDao,
    private val transactor: Transactor
) {

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
                val clear = policy != SharingPolicyType.SELECTED_PEERS || row?.clearGrants == true
                if (clear) dao.deleteGrants(keyId)
                if (dao.setKeyPolicy(keyId, policy) != 1) throw KeyChangedException(keyId)
                dao.putPolicyRow(KeyPolicyEntity(keyId, instance, policy))
                clear
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: KeyChangedException) {
            throw e
        } catch (e: Exception) {
            if (policy != SharingPolicyType.ALL_PEERS) {
                try {
                    recordDenial(keyId, instance, policy)
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (denial: Exception) {
                    e.addSuppressed(denial)
                }
            }
            throw e
        }

    /**
     * Leaves the denial of [policy], a narrowing whose write failed, in
     * [keyId]'s policy row, if that row is still [instance]'s. A clear an
     * older failure owed is kept.
     */
    private suspend fun recordDenial(keyId: String, instance: Long, policy: SharingPolicyType) {
        transactor.run {
            val row = bound(keyId, instance) ?: return@run
            val clear = row.clearGrants || policy != SharingPolicyType.SELECTED_PEERS
            dao.putPolicyRow(
                row.copy(
                    pendingPolicy = policy,
                    denial = if (clear) SharingPolicyType.PRIVATE else policy,
                    clearGrants = clear
                )
            )
        }
    }

    /**
     * Writes [peerPublicKeyHex]'s grant for [keyId]. Refused while the key's
     * policy row owes a grant clear or denies every peer: the clear would
     * delete it, or it would authorize nothing.
     *
     * @throws KeyChangedException if the key does not exist.
     * @throws GrantRefusedException if the key's policy state refuses grants.
     */
    suspend fun grant(keyId: String, instance: Long, peerPublicKeyHex: String) {
        transactor.run {
            if (dao.keyInstance(keyId) == null) throw KeyChangedException(keyId)
            if (refusesGrants(dao.policyRow(keyId))) throw GrantRefusedException(keyId)
            dao.putGrant(KeySharingPolicy(keyId = keyId, peerPublicKeyHex = peerPublicKeyHex, allowed = true))
        }
    }

    /** Deletes [peerPublicKeyHex]'s grant for [keyId], if any. */
    suspend fun removeGrant(keyId: String, peerPublicKeyHex: String) {
        transactor.run { dao.deleteGrant(keyId, peerPublicKeyHex) }
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

    /** Deletes [keyId]'s grant rows, policy row and key row in one transaction. Returns whether a key was deleted. */
    suspend fun deleteKey(keyId: String): Boolean =
        transactor.run {
            dao.deleteGrants(keyId)
            dao.deleteKey(keyId) > 0
        }

    /**
     * The policy to enforce for [key]: its policy row's, which carries a
     * denial left by a failed narrowing, or the stored one if the row is
     * missing or belongs to another key row.
     */
    suspend fun enforcedPolicy(key: KeyEntity): SharingPolicyType =
        dao.policyRow(key.keyId)?.takeIf { it.keyInstance == key.id }?.enforced ?: key.sharingPolicy

    /** [keyId]'s policy row, after checking its key row is [instance]. */
    private suspend fun bound(keyId: String, instance: Long): KeyPolicyEntity? {
        if (dao.keyInstance(keyId) != instance) throw KeyChangedException(keyId)
        return dao.policyRow(keyId)?.takeIf { it.keyInstance == instance }
    }

    companion object {
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

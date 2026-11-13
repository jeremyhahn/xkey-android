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
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.map
import java.io.IOException

/**
 * The three tables [KeyPolicyStore] writes, as its DAO and its transactor: a
 * transaction snapshots them and puts the snapshot back if its block throws.
 * Each name in [failing] makes that DAO call throw. A "restart" is a new
 * store over the same tables: nothing the store relies on is in memory.
 */
class FakeKeyPolicyTables : KeyPolicyDao, KeyPolicyStore.Transactor {

    val keys = MutableStateFlow(mapOf<String, KeyEntity>())
    val rows = MutableStateFlow(mapOf<String, KeyPolicyEntity>())
    val grants = MutableStateFlow(setOf<Pair<String, String>>())
    private var nextInstance = 1L
    val failing = mutableSetOf<String>()

    /** Runs at the start of every grant write, before [failing] is checked: a test holds or counts writes here. */
    var onPutGrant: suspend (KeySharingPolicy) -> Unit = {}

    /** Runs at the start of every single-grant delete, before [failing] is checked. */
    var onDeleteGrant: suspend (keyId: String, peer: String) -> Unit = { _, _ -> }

    fun store() = KeyPolicyStore(this, this)

    /** A key row as an unrouted path would leave it, with the row the 12 -> 13 migration seeds. */
    fun addKey(keyId: String, policy: SharingPolicyType): Long {
        val instance = nextInstance++
        keys.value = keys.value + (keyId to entity(keyId, policy, instance))
        rows.value = rows.value + (keyId to KeyPolicyEntity(keyId, instance, policy))
        return instance
    }

    fun grant(keyId: String, peer: String) {
        grants.value = grants.value + (keyId to peer)
    }

    fun grantsOf(keyId: String) = grants.value.filter { it.first == keyId }.map { it.second }.toSet()

    fun isGranted(keyId: String, peer: String) = (keyId to peer) in grants.value

    /** What the grant cleanup's `clearPoliciesForPeer` deletes: every grant row of [peer]. */
    fun clearPeer(peer: String) {
        grants.value = grants.value.filterNot { it.second == peer }.toSet()
    }

    /** The policy the request handler enforces for [keyId] ([KeyPolicyStore.enforcedPolicy]). */
    fun enforced(keyId: String): SharingPolicyType? {
        val key = keys.value[keyId] ?: return null
        return rows.value[keyId]?.takeIf { it.keyInstance == key.id }?.enforced ?: key.sharingPolicy
    }

    fun key(keyId: String): KeyEntity? = keys.value[keyId]

    fun keyPolicy(keyId: String) = keys.value[keyId]?.sharingPolicy

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
        return keys.value[keyId]?.id
    }

    override suspend fun policyRow(keyId: String): KeyPolicyEntity? {
        check("policyRow")
        return rows.value[keyId]
    }

    override fun observePolicyRow(keyId: String): Flow<KeyPolicyEntity?> = rows.map { it[keyId] }

    override suspend fun putPolicyRow(row: KeyPolicyEntity) {
        check("putPolicyRow")
        if (keys.value[row.keyId]?.id != row.keyInstance) throw IOException("FOREIGN KEY constraint failed")
        rows.value = rows.value + (row.keyId to row)
    }

    override suspend fun setKeyPolicy(keyId: String, policy: SharingPolicyType): Int {
        check("setKeyPolicy")
        val key = keys.value[keyId] ?: return 0
        keys.value = keys.value + (keyId to key.copy(sharingPolicy = policy, shareable = policy != SharingPolicyType.PRIVATE))
        return 1
    }

    override fun observeGrants(keyId: String): Flow<List<KeySharingPolicy>> =
        grants.map { all -> all.filter { it.first == keyId }.map { KeySharingPolicy(it.first, it.second) } }

    override suspend fun grants(keyId: String): List<KeySharingPolicy> {
        check("grants")
        return grantsOf(keyId).map { KeySharingPolicy(keyId, it) }
    }

    override suspend fun putGrant(grant: KeySharingPolicy) {
        onPutGrant(grant)
        check("putGrant")
        if (grant.keyId !in keys.value) throw IOException("FOREIGN KEY constraint failed")
        grant(grant.keyId, grant.peerPublicKeyHex)
    }

    override suspend fun deleteGrant(keyId: String, peerPublicKeyHex: String): Int {
        onDeleteGrant(keyId, peerPublicKeyHex)
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
        keys.value = keys.value + (key.keyId to key.copy(id = instance))
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

    companion object {
        fun entity(keyId: String, policy: SharingPolicyType, id: Long = 0) = KeyEntity(
            id = id,
            keyId = keyId,
            keyType = "signing",
            algorithm = "Ed25519",
            label = keyId,
            keySizeBits = 256,
            source = "local",
            sharingPolicy = policy,
            shareable = policy != SharingPolicyType.PRIVATE
        )
    }
}

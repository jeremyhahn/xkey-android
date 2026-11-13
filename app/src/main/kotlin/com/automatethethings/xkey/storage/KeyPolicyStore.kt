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
import java.io.IOException

/**
 * A key's sharing policy state and its grant rows, written only here (#193).
 * Skeleton: see the tests.
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

    suspend fun instance(keyId: String): Long? = TODO()

    suspend fun policy(keyId: String): KeyPolicyEntity? = TODO()

    fun observePolicy(keyId: String): Flow<KeyPolicyEntity?> = TODO()

    fun observeGrants(keyId: String): Flow<List<KeySharingPolicy>> = TODO()

    suspend fun setPolicy(keyId: String, instance: Long, policy: SharingPolicyType): Unit = TODO()

    suspend fun grant(keyId: String, peerPublicKeyHex: String): Unit = TODO()

    suspend fun removeGrant(keyId: String, peerPublicKeyHex: String): Unit = TODO()

    suspend fun insertKey(key: KeyEntity): Long = TODO()

    suspend fun deleteKey(keyId: String): Boolean = TODO()

    suspend fun enforcedPolicy(key: KeyEntity): SharingPolicyType = TODO()
}

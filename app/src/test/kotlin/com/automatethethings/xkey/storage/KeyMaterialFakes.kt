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

import com.automatethethings.xkey.storage.entity.KeyDeletionEntity

/** A [KeyMaterial] of one generation ("g") whose delete is [delete]. */
fun materialDelete(delete: suspend (KeyPolicyStore.KeyMaterialHeld) -> Boolean): KeyMaterial =
    tombstoneDelete { held, _ -> delete(held) }

/** A [KeyMaterial] of one generation ("g") whose delete of a tombstone is [delete]. */
fun tombstoneDelete(delete: suspend (KeyPolicyStore.KeyMaterialHeld, KeyDeletionEntity) -> Boolean): KeyMaterial =
    object : KeyMaterial {
        override suspend fun generation(held: KeyPolicyStore.KeyMaterialHeld, source: String?): String = "g"

        override suspend fun delete(held: KeyPolicyStore.KeyMaterialHeld, tombstone: KeyDeletionEntity): Boolean =
            delete(held, tombstone)
    }

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
package com.automatethethings.xkey.ui

import com.automatethethings.xkey.storage.KeyMaterial
import com.automatethethings.xkey.storage.KeyPolicyStore
import com.automatethethings.xkey.storage.dao.CredentialMetadataDao
import com.automatethethings.xkey.storage.entity.KeyEntity

/**
 * The passkey screens' one delete. The passkey is deleted as every other
 * user key is, through [deleteUserKey] and [KeyPolicyStore.deleteKey]:
 * its key_deletions tombstone is written in the row delete's transaction
 * and its material is deleted, so the next key sync cannot copy it back.
 * Only once the key is [UserKeyDelete.DELETED] is its credential_metadata
 * row deleted, so the credential provider stops offering it; a passkey
 * gone, refused or still blocked keeps its row.
 */
internal suspend fun deletePasskey(
    key: KeyEntity,
    store: KeyPolicyStore,
    material: KeyMaterial,
    credentials: CredentialMetadataDao
): UserKeyDelete =
    deleteUserKey(key, store, material).also { outcome ->
        if (outcome == UserKeyDelete.DELETED) credentials.deleteByCredentialId(key.keyId)
    }

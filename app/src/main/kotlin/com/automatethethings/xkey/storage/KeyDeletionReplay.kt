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

import android.content.Context
import android.util.Log
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.crypto.SoftwareKeyStore

/**
 * The app's one [MaterialDelete] (#193 r9, r10): deletes [held]'s key
 * material wherever it lives, the Android Keystore (every alias its id
 * resolves to) and the software key store, and returns true only once
 * neither holds any of it. A key from the KMS daemon (`xkmsd`) holds no
 * local material. Callable only under the key's
 * [KeyPolicyStore.withKeyMaterial] lock.
 */
fun deleteKeyMaterial(
    context: Context,
    held: KeyPolicyStore.KeyMaterialHeld,
    source: String?,
    keystore: KeystoreManager = KeystoreManager(context)
): Boolean {
    if (source == "xkmsd") return true
    // Each backend is tried whatever the other does: one that fails leaves
    // its material, reported below, and never stops the other's delete.
    // A key id resolves to one alias at a time; a refused or failed delete
    // leaves it resolving.
    val keystoreGone = try {
        repeat(MAX_ALIASES) {
            val alias = keystore.resolveKeystoreAlias(held.keyId) ?: return@repeat
            keystore.deleteByAlias(alias)
        }
        keystore.resolveKeystoreAlias(held.keyId) == null
    } catch (e: Exception) {
        false
    }
    val softwareGone = try {
        val software = SoftwareKeyStore(context)
        software.delete(held.keyId)
        !software.contains(held.keyId)
    } catch (e: Exception) {
        false
    }
    return keystoreGone && softwareGone
}

/** The aliases one key id can resolve to (credential, general, legacy). */
private const val MAX_ALIASES = 4

/**
 * Replays every deletion tombstone of [store] ([KeyPolicyStore.replayDeletions]):
 * at start-up and before a key sync, so no key material is left without a
 * record. Never throws but for cancellation; a tombstone left is replayed
 * next time.
 */
suspend fun replayKeyDeletions(context: Context, store: KeyPolicyStore) {
    try {
        val left = store.replayDeletions { held, source -> deleteKeyMaterial(context, held, source) }
        if (left > 0) Log.w("KeyDeletionReplay", "$left key material deletes are still owed; replayed next time")
    } catch (e: kotlinx.coroutines.CancellationException) {
        throw e
    } catch (e: Exception) {
        Log.e("KeyDeletionReplay", "Replaying key material deletes failed; replayed next time", e)
    }
}

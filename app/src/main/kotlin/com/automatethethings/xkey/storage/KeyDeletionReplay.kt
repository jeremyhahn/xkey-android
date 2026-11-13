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
 * Deletes the material of a tombstoned key ([KeyPolicyStore.replayDeletions],
 * #193 r9), wherever it lives: the Android Keystore or the software key
 * store. A key from the KMS daemon (`xkmsd`) holds no local material.
 * Callable only under the key's [KeyPolicyStore.withKeyMaterial] lock.
 */
fun deleteKeyMaterial(context: Context, held: KeyPolicyStore.KeyMaterialHeld, source: String?) {
    if (source == "xkmsd") return
    val keystore = KeystoreManager(context)
    keystore.resolveKeystoreAlias(held.keyId)?.let { keystore.deleteByAlias(it) }
    SoftwareKeyStore(context).delete(held.keyId)
}

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

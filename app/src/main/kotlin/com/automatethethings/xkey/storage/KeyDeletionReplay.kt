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
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext

/**
 * The app's one [MaterialDelete] (#193 r9, r10): deletes [held]'s key
 * material wherever it lives, the Android Keystore (the key's user-key
 * aliases, [KeystoreManager.userKeyAliases]) and the software key store,
 * and returns true only once neither holds any of it. A key from the KMS
 * daemon (`xkmsd`) holds no local material. Callable only under the key's
 * [KeyPolicyStore.withKeyMaterial] lock.
 *
 * Every key delete, direct or replayed, reaches material only here, so
 * this is where an internal key is refused (#193 r11): an id that resolves
 * to an alias outside its user-key namespace ([isInternalKey]) throws
 * [InternalKeyException] with nothing deleted, and no alias outside that
 * namespace is ever deleted.
 */
fun deleteKeyMaterial(
    context: Context,
    held: KeyPolicyStore.KeyMaterialHeld,
    source: String?,
    keystore: KeystoreManager = KeystoreManager(context)
): Boolean {
    if (source == "xkmsd") return true
    if (isInternalKey(held.keyId, keystore)) throw InternalKeyException(held.keyId)
    // Each backend is tried whatever the other does: one that fails leaves
    // its material, reported below, and never stops the other's delete.
    val keystoreGone = try {
        val aliases = KeystoreManager.userKeyAliases(held.keyId)
        aliases.forEach { keystore.deleteByAlias(it) }
        keystore.resolveKeystoreAlias(held.keyId) !in aliases
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

/**
 * True if [keyId] resolves to a Keystore alias outside its user-key
 * namespace ([KeystoreManager.userKeyAliases]): an internal key of the
 * app, which no key delete may touch (#193 r11).
 */
fun isInternalKey(keyId: String, keystore: KeystoreManager): Boolean {
    val alias = keystore.resolveKeystoreAlias(keyId) ?: return false
    return alias !in KeystoreManager.userKeyAliases(keyId)
}

/**
 * The app's one [TombstoneDelete]: [deleteKeyMaterial] for a deletion
 * tombstone, replayed ([replayKeyDeletions]) or settled before a write
 * under its id ([KeyPolicyStore.withKeyMaterial]). A tombstone of an
 * internal key is refused with nothing deleted and dropped: no user
 * material is owed (#193 r11).
 */
fun keyMaterialDeleter(context: Context, keystore: KeystoreManager? = null): TombstoneDelete {
    val manager by lazy { keystore ?: KeystoreManager(context) }
    return { held, source ->
        try {
            deleteKeyMaterial(context, held, source, manager)
        } catch (e: InternalKeyException) {
            Log.w("KeyDeletionReplay", "Refused deleting internal key ${e.keyId}; its tombstone is dropped")
            true
        }
    }
}

/** A delete refused: [keyId] names an internal key ([isInternalKey]). */
class InternalKeyException(val keyId: String) :
    SecurityException("Key $keyId is not a user key; not deleted")

/**
 * Replays every deletion tombstone of [store] ([KeyPolicyStore.replayDeletions]):
 * at start-up and before a key sync, so no key material is left without a
 * record. Never throws but for cancellation; a tombstone left is replayed
 * next time.
 */
suspend fun replayKeyDeletions(context: Context, store: KeyPolicyStore, keystore: KeystoreManager? = null) {
    try {
        // Out of the caller's cancellation (#193 r11): a screen closed or a
        // sync cancelled mid-replay never stops a delete between its lock
        // and its tombstone drop.
        val left = withContext(NonCancellable) { store.replayDeletions(keyMaterialDeleter(context, keystore)) }
        if (left > 0) Log.w("KeyDeletionReplay", "$left key material deletes are still owed; replayed next time")
    } catch (e: kotlinx.coroutines.CancellationException) {
        throw e
    } catch (e: Exception) {
        Log.e("KeyDeletionReplay", "Replaying key material deletes failed; replayed next time", e)
    }
}

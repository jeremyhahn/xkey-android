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
 * material wherever it lives, of every type the app stores: the Android
 * Keystore entries (EC, RSA, AES, HMAC) and the Ed25519 software keys of
 * the key's user-key namespace ([KeystoreManager.userKeyAliases]), and the
 * software key store; it returns true only once none holds any of it. A key from the KMS
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
    return deleteKeyMaterialGeneration(context, held.keyId, keyMaterialGeneration(context, held.keyId, keystore), keystore)
}

/**
 * The generation of [keyId]'s key material in every backend that holds a
 * user key's material: the Android Keystore entries and Ed25519 software
 * keys of its user-key namespace ([KeystoreManager.userKeyGeneration]) and
 * its software key store record ([SoftwareKeyStore.generation], entry
 * [SOFTWARE_ENTRY]). Each entry's tag changes when its material is
 * replaced, so a delete of this generation never reaches material written
 * under the id since. Empty when nothing is held.
 */
fun keyMaterialGeneration(context: Context, keyId: String, keystore: KeystoreManager): Map<String, String> {
    val generation = LinkedHashMap<String, String>()
    // A backend that cannot be read is owed as a whole ([UNREAD]): its
    // delete is reported failed, and never stops the other's.
    try {
        generation.putAll(keystore.userKeyGeneration(keyId))
    } catch (e: Exception) {
        generation[KEYSTORE_UNREAD] = UNREAD
    }
    try {
        SoftwareKeyStore(context).generation(keyId)?.let { generation[SOFTWARE_ENTRY] = it }
    } catch (e: Exception) {
        generation[SOFTWARE_ENTRY] = UNREAD
    }
    return generation
}

/**
 * Deletes what is still in place of [generation] ([keyMaterialGeneration])
 * and returns true only once no backend holds any of it. Material replaced
 * since under the id carries another tag and is left. Each backend is tried
 * whatever the other does: one that fails leaves its material, reported in
 * the result, and never stops the other's delete.
 */
fun deleteKeyMaterialGeneration(
    context: Context,
    keyId: String,
    generation: Map<String, String>,
    keystore: KeystoreManager
): Boolean {
    val keystoreGone = try {
        val held = generation - SOFTWARE_ENTRY
        when {
            KEYSTORE_UNREAD in held -> false
            held.isEmpty() -> true
            else -> keystore.deleteUserKeyGeneration(keyId, held).isEmpty()
        }
    } catch (e: Exception) {
        false
    }
    val softwareGone = try {
        when (val tag = generation[SOFTWARE_ENTRY]) {
            null -> true
            UNREAD -> false
            else -> SoftwareKeyStore(context).deleteGeneration(keyId, tag)
        }
    } catch (e: Exception) {
        false
    }
    return keystoreGone && softwareGone
}

/** [keyMaterialGeneration] entry of a software key store record. */
const val SOFTWARE_ENTRY = "software"

/** [keyMaterialGeneration] entry of a Keystore backend that could not be read. */
private const val KEYSTORE_UNREAD = "keystore-unread"

/** The tag of a backend whose generation could not be read. */
private const val UNREAD = "unread"

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

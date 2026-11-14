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
import com.automatethethings.xkey.crypto.UserKeyKind
import com.automatethethings.xkey.storage.entity.KeyDeletionEntity
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext

/**
 * The app's one material delete (#193 r9, r10, r12): deletes the material
 * generation [tombstone] recorded for [held]'s key wherever it lives, of
 * every type the app stores: the Android Keystore entries (EC, RSA, AES,
 * HMAC) and the Ed25519 software keys of the key's user-key namespace
 * ([KeystoreManager.userKeyAliases]), and the software key store; it
 * returns true only once none holds any of that generation. Material
 * written under the id since carries another generation and is left. A
 * key from the KMS daemon (`xkmsd`) holds no local material. Callable only
 * under the key's [KeyPolicyStore.withKeyMaterial] lock.
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
    tombstone: KeyDeletionEntity,
    keystore: KeystoreManager = KeystoreManager(context)
): Boolean {
    if (tombstone.source == "xkmsd") return true
    if (isInternalKey(held.keyId, keystore)) throw InternalKeyException(held.keyId)
    val generation = tombstone.generation ?: run {
        // Written before generations were recorded: it names no material,
        // and deleting whatever is under the id now could be a later key's.
        Log.w(TAG, "Deletion of ${held.keyId} recorded no material generation; nothing deleted")
        return true
    }
    return deleteKeyMaterialGeneration(context, held.keyId, decodeGeneration(generation), keystore)
}

/**
 * The encoded [keyMaterialGeneration] of [held]'s key, for its tombstone:
 * read under the key's material lock. Throws [InternalKeyException] for an
 * internal key, and any backend's read failure: the delete is refused.
 */
fun readKeyMaterialGeneration(
    context: Context,
    held: KeyPolicyStore.KeyMaterialHeld,
    source: String?,
    keystore: KeystoreManager = KeystoreManager(context),
    kind: UserKeyKind? = null,
    retry: Boolean = false
): String {
    if (source == "xkmsd") return encodeGeneration(emptyMap())
    if (isInternalKey(held.keyId, keystore)) throw InternalKeyException(held.keyId)
    return encodeGeneration(keyMaterialGeneration(context, held.keyId, keystore, kind, retry))
}

private fun encodeGeneration(generation: Map<String, String>): String =
    org.json.JSONObject(generation as Map<*, *>).toString()

private fun decodeGeneration(encoded: String): Map<String, String> {
    val json = org.json.JSONObject(encoded)
    return json.keys().asSequence().associateWith { json.getString(it) }
}

/**
 * The generation of [keyId]'s key material in every backend that holds a
 * user key's material: the Android Keystore entries and Ed25519 software
 * keys of its user-key namespace ([KeystoreManager.userKeyGeneration]) and
 * its software key store record ([SoftwareKeyStore.generation], entry
 * [SOFTWARE_ENTRY]). Each entry's tag changes when its material is
 * replaced, so a delete of this generation never reaches material written
 * under the id since. Empty when nothing is held; throws if a backend
 * cannot be read. With [kind], only that user key's material: a
 * credential and a general key can share an id, and the delete of one
 * records (in its tombstone) and deletes none of the other's (#255 review).
 *
 * The one place a delete's namespace is chosen (#255 verify): [kind], or
 * the other kind when only that one holds material under the id
 * ([KeystoreManager.presentKind]), as for a fido2 row's general-alias key.
 * A [retry], whose earlier delete of the id was just settled, never
 * switches: what is left under the id is the other key, which that delete
 * left on purpose.
 */
fun keyMaterialGeneration(
    context: Context,
    keyId: String,
    keystore: KeystoreManager,
    kind: UserKeyKind? = null,
    retry: Boolean = false
): Map<String, String> {
    val all = keystore.userKeyGeneration(keyId)
    val software = SoftwareKeyStore(context).generation(keyId)
    val present = if (software != null) all.keys + SOFTWARE_ENTRY else all.keys
    val target = kind?.let { if (retry) it else KeystoreManager.presentKind(keyId, present, it) }
    val generation = LinkedHashMap(if (target == null) all else all.filterKeys { KeystoreManager.isEntryOf(it, keyId, target) })
    if (target != UserKeyKind.CREDENTIAL && software != null) generation[SOFTWARE_ENTRY] = software
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
        held.isEmpty() || keystore.deleteUserKeyGeneration(keyId, held).isEmpty()
    } catch (e: Exception) {
        false
    }
    val softwareGone = try {
        val tag = generation[SOFTWARE_ENTRY]
        tag == null || SoftwareKeyStore(context).deleteGeneration(keyId, tag)
    } catch (e: Exception) {
        false
    }
    return keystoreGone && softwareGone
}

/** [keyMaterialGeneration] entry of a software key store record. */
const val SOFTWARE_ENTRY = "software"

private const val TAG = "KeyDeletionReplay"

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
 * The app's one [KeyMaterial]: [readKeyMaterialGeneration] for a delete's
 * tombstone and [deleteKeyMaterial] for it, direct, replayed
 * ([replayKeyDeletions]) or settled before a write under its id
 * ([KeyPolicyStore.withKeyMaterial]). A tombstone of an internal key is
 * refused with nothing deleted and dropped: no user material is owed
 * (#193 r11).
 */
fun keyMaterialDeleter(context: Context, keystore: KeystoreManager? = null, kind: UserKeyKind? = null): KeyMaterial {
    val manager by lazy { keystore ?: KeystoreManager(context) }
    return object : KeyMaterial {
        // A user delete names its [kind]; replays and settles delete what
        // the tombstone recorded, so they need none.
        override suspend fun generation(held: KeyPolicyStore.KeyMaterialHeld, source: String?): String =
            readKeyMaterialGeneration(context, held, source, manager, kind)

        override suspend fun generation(held: KeyPolicyStore.KeyMaterialHeld, source: String?, retry: Boolean): String =
            readKeyMaterialGeneration(context, held, source, manager, kind, retry)

        override fun isEmpty(generation: String): Boolean = decodeGeneration(generation).isEmpty()

        override suspend fun delete(held: KeyPolicyStore.KeyMaterialHeld, tombstone: KeyDeletionEntity): Boolean =
            try {
                deleteKeyMaterial(context, held, tombstone, manager)
            } catch (e: InternalKeyException) {
                Log.w(TAG, "Refused deleting internal key ${e.keyId}; its tombstone is dropped")
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
        if (left > 0) Log.w(TAG, "$left key material deletes are still owed; replayed next time")
    } catch (e: kotlinx.coroutines.CancellationException) {
        throw e
    } catch (e: Exception) {
        Log.e(TAG, "Replaying key material deletes failed; replayed next time", e)
    }
}

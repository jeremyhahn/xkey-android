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
package com.automatethethings.xkey.media

import android.util.Log

/**
 * The per-signer decision both verification screens share: the file-operation
 * screen and the verified-media viewer each look up the contact and the local
 * keys, then hand them here, so the two cannot drift apart again.
 *
 * Pure apart from `android.util.Log` and `android.util.Base64` (through
 * [SignatureVerifier]), so it is unit-testable off-device.
 */
object SignerVerification {

    private const val TAG = "SignerVerification"

    enum class Status { VERIFIED, FAILED, UNKNOWN }

    /** A contact whose fingerprint equals the entry's. */
    data class Contact(val name: String, val publicKeyDer: ByteArray) {
        override fun equals(other: Any?): Boolean =
            other is Contact && name == other.name && publicKeyDer.contentEquals(other.publicKeyDer)

        override fun hashCode(): Int = 31 * name.hashCode() + publicKeyDer.contentHashCode()
    }

    /** A row of the local key store, reduced to what the decision reads. */
    data class LocalKey(val keyId: String, val label: String, val publicKeyDer: ByteArray?) {
        override fun equals(other: Any?): Boolean =
            other is LocalKey && keyId == other.keyId && label == other.label &&
                publicKeyDer.contentEquals(other.publicKeyDer)

        override fun hashCode(): Int =
            31 * (31 * keyId.hashCode() + label.hashCode()) + (publicKeyDer?.contentHashCode() ?: 0)
    }

    data class Result(val status: Status, val displayName: String)

    /**
     * Decides the status of one signer.
     *
     * @param entry the signature entry read from the file.
     * @param storedContentHash the content hash recorded with the signatures;
     *        this is what each signer signed.
     * @param contentHashMatches whether [storedContentHash] matches the file;
     *        when it does not, the signer fails before any lookup.
     * @param contact the contact whose fingerprint equals the entry's, if any.
     * @param localKeys the local key store.
     */
    fun verify(
        entry: SignatureEntry,
        storedContentHash: String,
        contentHashMatches: Boolean,
        contact: Contact?,
        localKeys: List<LocalKey>
    ): Result {
        val fallbackName = entry.signerName ?: (entry.keyFingerprint.take(16) + "...")
        // The content hash comes first: on a mismatch the signatures cover
        // other content, so every signer fails, known or not. Returning
        // UNKNOWN here would let a copied block read as merely unrecognised.
        if (!contentHashMatches) {
            Log.w(TAG, "Content hash mismatch: stored=$storedContentHash")
            return Result(Status.FAILED, entry.signerName ?: contact?.name ?: fallbackName)
        }
        return try {
            if (contact != null) {
                val ok = checkSignature(contact.publicKeyDer, entry, storedContentHash, contentHashMatches)
                return Result(if (ok) Status.VERIFIED else Status.FAILED, entry.signerName ?: contact.name)
            }

            // Only a key we hold the public key of can match. A row without
            // one says nothing about the signature: matching it by keyId
            // would trust a fingerprint the file itself supplies.
            val matchedKey = localKeys.firstOrNull { key ->
                val pubDer = key.publicKeyDer
                pubDer != null && MediaHasher.hashBytes(pubDer) == entry.keyFingerprint
            } ?: return Result(Status.UNKNOWN, fallbackName)
            val pubDer = matchedKey.publicKeyDer ?: return Result(Status.UNKNOWN, fallbackName)

            val ok = checkSignature(pubDer, entry, storedContentHash, contentHashMatches)
            Result(if (ok) Status.VERIFIED else Status.FAILED, entry.signerName ?: matchedKey.label)
        } catch (e: Exception) {
            Log.e(TAG, "Error verifying entry for ${entry.keyFingerprint}", e)
            Result(Status.FAILED, fallbackName)
        }
    }

    private fun checkSignature(
        publicKeyDer: ByteArray,
        entry: SignatureEntry,
        storedContentHash: String,
        contentHashMatches: Boolean
    ): Boolean {
        if (!contentHashMatches) {
            Log.w(TAG, "Content hash mismatch: stored=$storedContentHash")
            return false
        }
        return SignatureVerifier.verifyEntry(publicKeyDer, entry, storedContentHash)
    }
}

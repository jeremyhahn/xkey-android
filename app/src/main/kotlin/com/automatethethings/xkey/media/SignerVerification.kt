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

    /**
     * @property displayName the name beside the badge: the matched contact's
     *           name or local key's label when a key matched, otherwise the
     *           name the file embeds or a fingerprint prefix.
     * @property claimedName the name the file embeds, set only when a key
     *           matched and the embedded name differs from [displayName]. It
     *           is a claim, never the badge name.
     */
    data class Result(val status: Status, val displayName: String, val claimedName: String? = null)

    fun verify(
        entry: SignatureEntry,
        storedContentHash: String,
        contentHashMatches: Boolean,
        contact: Contact?,
        localKeys: List<LocalKey>
    ): Result {
        // With no matching key the embedded name is all there is, and the
        // status (unknown, or failed) already says it is not vouched for.
        val fallbackName = entry.signerName ?: (entry.keyFingerprint.take(16) + "...")
        // Only a key we hold the public key of can match. A row without
        // one says nothing about the signature: matching it by keyId
        // would trust a fingerprint the file itself supplies.
        val matchedKey = if (contact == null) {
            localKeys.firstOrNull { key ->
                val pubDer = key.publicKeyDer
                pubDer != null && MediaHasher.hashBytes(pubDer) == entry.keyFingerprint
            }
        } else {
            null
        }
        val matchedName = contact?.name ?: matchedKey?.label
        val matchedPublicKey = contact?.publicKeyDer ?: matchedKey?.publicKeyDer

        // A matched signer is named by the contact or key the signature is
        // checked against; the name the file embeds is only a claim.
        fun result(status: Status): Result {
            if (matchedName == null) return Result(status, fallbackName)
            val claimed = entry.signerName?.takeIf { it != matchedName }
            return Result(status, matchedName, claimed)
        }

        // The content hash comes first: on a mismatch the signatures cover
        // other content, so every signer fails, known or not. Returning
        // UNKNOWN here would let a copied block read as merely unrecognised.
        if (!contentHashMatches) {
            Log.w(TAG, "Content hash mismatch: stored=$storedContentHash")
            return result(Status.FAILED)
        }
        if (matchedPublicKey == null) return result(Status.UNKNOWN)
        return try {
            val ok = checkSignature(matchedPublicKey, entry, storedContentHash, contentHashMatches)
            result(if (ok) Status.VERIFIED else Status.FAILED)
        } catch (e: Exception) {
            Log.e(TAG, "Error verifying entry for ${entry.keyFingerprint}", e)
            result(Status.FAILED)
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

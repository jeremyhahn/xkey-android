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

import android.util.Base64
import android.util.Log
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

/**
 * Cryptographic verification of a [SignatureEntry] against a signer's public key.
 *
 * This is the single place that decides whether a signature is genuine. Both the
 * file-operation screen and the verified-media viewer route through it: having
 * two implementations is how one of them came to report "Verified" after
 * resolving the signer's identity without ever checking the signature bytes.
 *
 * Nothing here touches the UI, so it is unit-testable off-device apart from
 * `android.util.Base64`.
 */
object SignatureVerifier {

    private const val TAG = "SignatureVerifier"

    /**
     * Verifies [entry] against [publicKeyDer].
     *
     * @param publicKeyDer the signer's public key, DER/SPKI encoded.
     * @param entry the signature entry read from the media's metadata.
     * @param storedContentHash the hash recorded alongside the signature; this is
     *        what was signed.
     * @return true only when the signature verifies over [storedContentHash].
     */
    fun verifyEntry(
        publicKeyDer: ByteArray,
        entry: SignatureEntry,
        storedContentHash: String
    ): Boolean {
        val signatureBytes = try {
            Base64.decode(entry.value, Base64.NO_WRAP)
        } catch (e: Exception) {
            Log.w(TAG, "Failed to decode signature Base64", e)
            return false
        }

        val hashBytes = try {
            hexToBytes(storedContentHash)
        } catch (e: Exception) {
            Log.w(TAG, "Recorded content hash is not valid hex", e)
            return false
        }

        return verify(publicKeyDer, hashBytes, signatureBytes, entry.algorithm)
    }

    /**
     * Verifies a signature over [data].
     *
     * Supports the EC (ES256/384/512) and RSA (RS256/384/512) algorithms xKey
     * issues. An unrecognised algorithm fails rather than being waved through.
     */
    fun verify(
        publicKeyDer: ByteArray,
        data: ByteArray,
        signature: ByteArray,
        algorithm: String
    ): Boolean {
        return try {
            val keyFactory = if (algorithm.startsWith("RS")) {
                KeyFactory.getInstance("RSA")
            } else {
                KeyFactory.getInstance("EC")
            }
            val publicKey = keyFactory.generatePublic(X509EncodedKeySpec(publicKeyDer))
            val sigAlgorithm = when (algorithm) {
                "ES256" -> "SHA256withECDSA"
                "ES384" -> "SHA384withECDSA"
                "ES512" -> "SHA512withECDSA"
                "RS256" -> "SHA256withRSA"
                "RS384" -> "SHA384withRSA"
                "RS512" -> "SHA512withRSA"
                else -> return false
            }
            Signature.getInstance(sigAlgorithm).apply {
                initVerify(publicKey)
                update(data)
            }.verify(signature)
        } catch (e: Exception) {
            Log.w(TAG, "Signature verification failed for algorithm $algorithm", e)
            false
        }
    }

    /** Decodes a hex string. Throws if [hex] is not valid hex. */
    fun hexToBytes(hex: String): ByteArray =
        hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}

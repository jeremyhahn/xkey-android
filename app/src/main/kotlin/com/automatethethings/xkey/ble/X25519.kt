/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
 *
 * This file is part of xkey-android.
 *
 * xkey-android is dual-licensed:
 *
 * 1. GNU Affero General Public License v3.0 (AGPL-3.0)
 *    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
 *
 * 2. Commercial License
 *    Contact licensing@automatethethings.com for commercial licensing options.
 */

package com.automatethethings.xkey.ble

import java.security.KeyFactory
import java.security.NoSuchAlgorithmException
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.KeyAgreement
import org.bouncycastle.math.ec.rfc7748.X25519 as BcX25519

/**
 * The one X25519 implementation every Noise handshake in the app uses
 * (RFC 7748), for the responder ([NoiseSession]), the initiator
 * ([NoiseInitiatorSession]) and the bootstrap client.
 *
 * The platform provider is used when it offers `X25519`. A device without one
 * (older API levels) gets Bouncy Castle's constant-time implementation. Only
 * a missing provider selects the fallback: any other failure (a key the
 * provider refuses, a small-order point) is a [NoiseException], never a
 * silent second attempt.
 *
 * [dh] refuses an all-zero result on both paths (RFC 7748 §6.1): a peer that
 * sends a small-order point cannot force a known shared secret into the
 * handshake.
 */
internal object X25519 {
    const val KEY_SIZE = 32

    private const val ALGORITHM = "X25519"

    private val BASE_POINT = ByteArray(KEY_SIZE).also { it[0] = 9 }

    /** PKCS#8 header for a raw X25519 private key (RFC 8410). */
    private val PKCS8_HEADER = byteArrayOf(
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20
    )

    /** X.509 SubjectPublicKeyInfo header for a raw X25519 public key (RFC 8410). */
    private val X509_HEADER = byteArrayOf(
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00
    )

    /**
     * Test seam: makes every call take the Bouncy Castle path, as on a device
     * whose platform has no X25519 provider. Production code must not set it.
     */
    @Volatile
    internal var forceFallbackForTest: Boolean = false

    /** The public key of the private scalar [k]: X25519(k, 9). */
    fun scalarMultBase(k: ByteArray): ByteArray {
        requireKey(k, "private key")
        val platform = platformOrNull()
        if (platform != null) return platform.compute(k, BASE_POINT)
        val result = ByteArray(KEY_SIZE)
        BcX25519.scalarMultBase(k, 0, result, 0)
        return result
    }

    /**
     * The shared secret X25519(k, u). Throws [NoiseException] when the result
     * is all zeros (u is a small-order point) or the computation fails.
     */
    fun dh(k: ByteArray, u: ByteArray): ByteArray {
        requireKey(k, "private key")
        requireKey(u, "public key")
        val platform = platformOrNull()
        val result = if (platform != null) {
            platform.compute(k, u)
        } else {
            val out = ByteArray(KEY_SIZE)
            if (!BcX25519.calculateAgreement(k, 0, u, 0, out, 0)) {
                out.fill(0)
                throw NoiseException("X25519 refused a small-order public key")
            }
            out
        }
        if (isAllZero(result)) {
            throw NoiseException("X25519 refused a small-order public key")
        }
        return result
    }

    /**
     * The platform's X25519 objects, or null when the platform has no X25519
     * provider at all (the only case the fallback covers).
     */
    private fun platformOrNull(): Platform? {
        if (forceFallbackForTest) return null
        return try {
            Platform(KeyFactory.getInstance(ALGORITHM), KeyAgreement.getInstance(ALGORITHM))
        } catch (e: NoSuchAlgorithmException) {
            null
        }
    }

    private class Platform(private val keyFactory: KeyFactory, private val agreement: KeyAgreement) {
        fun compute(k: ByteArray, u: ByteArray): ByteArray {
            try {
                // The key spec keeps its own copy of the encoding
                val encoded = PKCS8_HEADER + k
                val privateSpec = try {
                    PKCS8EncodedKeySpec(encoded)
                } finally {
                    encoded.fill(0)
                }
                val privateKey = keyFactory.generatePrivate(privateSpec)
                val publicKey = keyFactory.generatePublic(X509EncodedKeySpec(X509_HEADER + u))
                agreement.init(privateKey)
                agreement.doPhase(publicKey, true)
                val secret = agreement.generateSecret()
                if (secret.size != KEY_SIZE) {
                    secret.fill(0)
                    throw NoiseException("X25519 returned ${secret.size} bytes")
                }
                return secret
            } catch (e: NoiseException) {
                throw e
            } catch (e: Exception) {
                throw NoiseException("X25519 failed: ${e.message}", e)
            }
        }
    }

    private fun requireKey(key: ByteArray, what: String) {
        if (key.size != KEY_SIZE) throw NoiseException("X25519 $what must be $KEY_SIZE bytes, got ${key.size}")
    }

    /** Constant-time all-zero check. */
    private fun isAllZero(bytes: ByteArray): Boolean {
        var acc = 0
        for (b in bytes) acc = acc or b.toInt()
        return acc == 0
    }
}

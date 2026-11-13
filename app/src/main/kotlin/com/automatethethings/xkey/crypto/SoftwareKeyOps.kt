// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Licensed under AGPL-3.0 (see LICENSE) or a commercial license.
// Contact licensing@automatethethings.com for commercial licensing options.

package com.automatethethings.xkey.crypto

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Software (non-Keystore) symmetric operations for exportable software-backed
 * keys held in [SoftwareKeyStore].
 *
 * Hardware-backed keys are operated on via [KeystoreManager] and never expose
 * their material. This path exists only for keys whose raw material is
 * intentionally exportable (shared/synced symmetric keys). The AES-GCM
 * ciphertext layout matches the Keystore symmetric path: a random 12-byte IV
 * prepended to the AES-GCM output (ciphertext followed by the 16-byte tag).
 */
object SoftwareKeyOps {
    private const val GCM_IV_BYTES = 12
    private const val GCM_TAG_BITS = 128

    /** AES-GCM encrypt; returns iv(12) || ciphertext || tag(16). */
    fun aesGcmEncrypt(keyMaterial: ByteArray, plaintext: ByteArray, aad: ByteArray?): ByteArray {
        val iv = ByteArray(GCM_IV_BYTES).also { SecureRandom().nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(keyMaterial, "AES"), GCMParameterSpec(GCM_TAG_BITS, iv))
        aad?.takeIf { it.isNotEmpty() }?.let { cipher.updateAAD(it) }
        return iv + cipher.doFinal(plaintext)
    }

    /** AES-GCM decrypt of iv(12) || ciphertext || tag(16). */
    fun aesGcmDecrypt(keyMaterial: ByteArray, ivAndCiphertext: ByteArray, aad: ByteArray?): ByteArray {
        require(ivAndCiphertext.size > GCM_IV_BYTES) { "ciphertext too short" }
        val iv = ivAndCiphertext.copyOfRange(0, GCM_IV_BYTES)
        val ct = ivAndCiphertext.copyOfRange(GCM_IV_BYTES, ivAndCiphertext.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(keyMaterial, "AES"), GCMParameterSpec(GCM_TAG_BITS, iv))
        aad?.takeIf { it.isNotEmpty() }?.let { cipher.updateAAD(it) }
        return cipher.doFinal(ct)
    }

    /**
     * The HMAC [hmac] runs for a key stored with [algorithm]: "HMAC-SHA512"
     * when the name says 512, else "HMAC-SHA256". The stored name is not
     * validated, so an audit entry records this, never [algorithm] itself.
     */
    fun hmacAlgorithm(algorithm: String): String =
        if (algorithm.contains("512")) "HMAC-SHA512" else "HMAC-SHA256"

    /** HMAC over [data] using [algorithm] ("HMAC-SHA256" or "HMAC-SHA512"). */
    fun hmac(keyMaterial: ByteArray, data: ByteArray, algorithm: String): ByteArray {
        val javaAlg = if (hmacAlgorithm(algorithm) == "HMAC-SHA512") "HmacSHA512" else "HmacSHA256"
        val mac = Mac.getInstance(javaAlg)
        mac.init(SecretKeySpec(keyMaterial, javaAlg))
        return mac.doFinal(data)
    }
}

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
package com.automatethethings.xkey.oath

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Pure computation engine for OATH one-time password generation.
 *
 * Implements HOTP (RFC 4226) and TOTP (RFC 6238) algorithms using
 * HMAC-based dynamic truncation. This object is stateless and safe
 * for concurrent use from any thread.
 *
 * Supported HMAC algorithms:
 * - "SHA1" (mapped to HmacSHA1) -- default per RFC 4226/6238
 * - "SHA256" (mapped to HmacSHA256)
 * - "SHA512" (mapped to HmacSHA512)
 *
 * Supported digit lengths: 6, 7, or 8.
 *
 * Usage:
 * ```kotlin
 * // HOTP
 * val code = OathEngine.generateHotpCode(secret, counter = 0L, algorithm = "SHA1", digits = 6)
 *
 * // TOTP (current time)
 * val totp = OathEngine.generateTotpCode(secret, algorithm = "SHA256", digits = 6, periodSeconds = 30)
 *
 * // TOTP (specific time for testing)
 * val totp2 = OathEngine.generateTotpCode(secret, algorithm = "SHA1", digits = 8, periodSeconds = 30, timeMs = 1234567890000L)
 * ```
 */
object OathEngine {

    /** Supported digit lengths for OTP codes. */
    private val SUPPORTED_DIGITS = setOf(6, 7, 8)

    /** Powers of 10 for digit truncation, indexed by digit count. */
    private val DIGITS_POWER = intArrayOf(
        1,          // 0 (unused)
        10,         // 1 (unused)
        100,        // 2 (unused)
        1_000,      // 3 (unused)
        10_000,     // 4 (unused)
        100_000,    // 5 (unused)
        1_000_000,  // 6
        10_000_000, // 7
        100_000_000 // 8
    )

    /**
     * Generate an HOTP code per RFC 4226.
     *
     * Computes HMAC over the 8-byte big-endian counter value, then applies
     * dynamic truncation (RFC 4226 section 5.4) to produce a numeric OTP.
     *
     * @param secret The shared secret key bytes.
     * @param counter The moving factor (8-byte counter value).
     * @param algorithm HMAC algorithm name: "SHA1", "SHA256", or "SHA512".
     * @param digits Number of digits in the output code: 6, 7, or 8.
     * @return Zero-padded OTP string of the requested length.
     * @throws IllegalArgumentException if [digits] is not 6, 7, or 8,
     *         or if [algorithm] is not a supported HMAC algorithm.
     */
    fun generateHotpCode(
        secret: ByteArray,
        counter: Long,
        algorithm: String,
        digits: Int
    ): String {
        require(digits in SUPPORTED_DIGITS) {
            "Digits must be 6, 7, or 8, got $digits"
        }

        val macAlgorithm = mapAlgorithm(algorithm)

        // RFC 4226 Step 1: Generate HMAC value
        val mac = Mac.getInstance(macAlgorithm)
        mac.init(SecretKeySpec(secret, macAlgorithm))

        // Counter as 8-byte big-endian
        val counterBytes = ByteArray(8)
        var value = counter
        for (i in 7 downTo 0) {
            counterBytes[i] = (value and 0xFF).toByte()
            value = value shr 8
        }

        val hmac = mac.doFinal(counterBytes)

        // RFC 4226 Step 2: Dynamic Truncation (section 5.4)
        val offset = (hmac[hmac.size - 1].toInt() and 0x0F)
        val binary =
            ((hmac[offset].toInt() and 0x7F) shl 24) or
            ((hmac[offset + 1].toInt() and 0xFF) shl 16) or
            ((hmac[offset + 2].toInt() and 0xFF) shl 8) or
            (hmac[offset + 3].toInt() and 0xFF)

        // RFC 4226 Step 3: Compute OTP value
        val otp = binary % DIGITS_POWER[digits]

        return otp.toString().padStart(digits, '0')
    }

    /**
     * Generate a TOTP code per RFC 6238.
     *
     * Computes the time step T = floor(timeMs / 1000 / periodSeconds) and
     * delegates to [generateHotpCode] with T as the counter value.
     *
     * @param secret The shared secret key bytes.
     * @param algorithm HMAC algorithm name: "SHA1", "SHA256", or "SHA512".
     * @param digits Number of digits in the output code: 6, 7, or 8.
     * @param periodSeconds Time step duration in seconds (typically 30).
     * @param timeMs Unix time in milliseconds. Defaults to [System.currentTimeMillis].
     * @return Zero-padded TOTP string of the requested length.
     * @throws IllegalArgumentException if [digits] is not 6, 7, or 8,
     *         if [algorithm] is not supported, or if [periodSeconds] is not positive.
     */
    fun generateTotpCode(
        secret: ByteArray,
        algorithm: String,
        digits: Int,
        periodSeconds: Int,
        timeMs: Long = System.currentTimeMillis()
    ): String {
        require(periodSeconds > 0) {
            "Period must be positive, got $periodSeconds"
        }

        // RFC 6238: T = floor((Current Unix time) / X)
        val timeStep = timeMs / 1000L / periodSeconds.toLong()

        return generateHotpCode(secret, timeStep, algorithm, digits)
    }

    /**
     * Map a short algorithm name to a JCA HMAC algorithm identifier.
     *
     * @param algorithm "SHA1", "SHA256", or "SHA512".
     * @return JCA algorithm name (e.g., "HmacSHA1").
     * @throws IllegalArgumentException if the algorithm is not supported.
     */
    private fun mapAlgorithm(algorithm: String): String = when (algorithm) {
        "SHA1" -> "HmacSHA1"
        "SHA256" -> "HmacSHA256"
        "SHA512" -> "HmacSHA512"
        else -> throw IllegalArgumentException(
            "Unsupported HMAC algorithm: $algorithm. Expected SHA1, SHA256, or SHA512."
        )
    }
}

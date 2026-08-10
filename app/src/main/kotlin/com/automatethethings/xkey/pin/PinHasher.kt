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
package com.automatethethings.xkey.pin

import org.signal.argon2.Argon2
import org.signal.argon2.MemoryCost
import org.signal.argon2.Type
import org.signal.argon2.Version
import java.security.SecureRandom

/**
 * Argon2id password hashing utility for PIN management.
 *
 * Uses parameters matching the desktop xKey implementation:
 * - Memory: 64 MiB (65536 KiB)
 * - Time cost: 3 iterations
 * - Parallelism: 4 lanes
 * - Hash length: 32 bytes
 * - Salt length: 16 bytes
 *
 * This object uses the Signal Argon2 library (`org.signal:argon2`) which provides
 * a native implementation of Argon2id, the recommended variant for password hashing
 * per RFC 9106.
 */
object PinHasher {

    /** Memory cost in KiB (64 MiB). */
    private const val MEMORY_COST_KIB = 65536

    /** Number of iterations (time cost). */
    private const val TIME_COST = 3

    /** Degree of parallelism (number of lanes). */
    private const val PARALLELISM = 4

    /** Output hash length in bytes. */
    private const val HASH_LENGTH = 32

    /** Salt length in bytes. */
    private const val SALT_LENGTH = 16

    /** Minimum PIN length in UTF-8 bytes. */
    const val MIN_PIN_LENGTH = 6

    /** Maximum PIN length in UTF-8 bytes. */
    const val MAX_PIN_LENGTH = 63

    /**
     * Generate a cryptographically secure random salt.
     *
     * @return A [SALT_LENGTH]-byte random salt suitable for Argon2id hashing.
     */
    fun generateSalt(): ByteArray {
        val salt = ByteArray(SALT_LENGTH)
        SecureRandom().nextBytes(salt)
        return salt
    }

    /**
     * Hash a PIN using Argon2id with the provided salt.
     *
     * The PIN is validated for length before hashing. The resulting hash
     * is deterministic for the same PIN and salt combination, enabling
     * verification without storing the plaintext PIN.
     *
     * @param pin The plaintext PIN string to hash.
     * @param salt The salt bytes to use (must be [SALT_LENGTH] bytes).
     * @return A [HASH_LENGTH]-byte Argon2id hash.
     * @throws IllegalArgumentException if the PIN length is outside the
     *         allowed range of [MIN_PIN_LENGTH]..[MAX_PIN_LENGTH] UTF-8 bytes.
     */
    fun hashPin(pin: String, salt: ByteArray): ByteArray {
        validatePinLength(pin)
        val argon2 = Argon2.Builder(Version.V13)
            .type(Type.Argon2id)
            .memoryCost(MemoryCost.KiB(MEMORY_COST_KIB))
            .parallelism(PARALLELISM)
            .iterations(TIME_COST)
            .hashLength(HASH_LENGTH)
            .build()
        val result = argon2.hash(pin.toByteArray(Charsets.UTF_8), salt)
        return result.hash
    }

    /**
     * Verify a PIN against a previously computed hash.
     *
     * Computes the Argon2id hash of the provided PIN with the given salt
     * and compares it to the expected hash using constant-time comparison
     * via [ByteArray.contentEquals].
     *
     * @param pin The plaintext PIN to verify.
     * @param salt The salt that was used when the hash was originally computed.
     * @param expectedHash The expected hash to compare against.
     * @return `true` if the PIN matches the expected hash, `false` otherwise.
     * @throws IllegalArgumentException if the PIN length is outside the allowed range.
     */
    fun verifyPin(pin: String, salt: ByteArray, expectedHash: ByteArray): Boolean {
        val hash = hashPin(pin, salt)
        return hash.contentEquals(expectedHash)
    }

    /**
     * Validate that a PIN's UTF-8 byte length is within the allowed range.
     *
     * @param pin The PIN string to validate.
     * @throws IllegalArgumentException if the PIN length is outside
     *         [MIN_PIN_LENGTH]..[MAX_PIN_LENGTH] UTF-8 bytes.
     */
    fun validatePinLength(pin: String) {
        val byteLength = pin.toByteArray(Charsets.UTF_8).size
        require(byteLength in MIN_PIN_LENGTH..MAX_PIN_LENGTH) {
            "PIN must be $MIN_PIN_LENGTH-$MAX_PIN_LENGTH UTF-8 bytes, got $byteLength"
        }
    }
}

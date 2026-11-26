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

package com.automatethethings.xkey.crypto

/**
 * Which Keystore operations the running Android release can perform.
 *
 * Every function takes the SDK level explicitly so JVM tests can cover both
 * sides of each API floor; callers pass `Build.VERSION.SDK_INT`.
 */
object KeystoreCapabilities {

    /**
     * Algorithms every supported release (minSdk 28) can generate. Each RS*
     * name takes any modulus of 2048, 3072 or 4096 bits through
     * local.generateKey's keySizeBits; ES512, RS3072/4096, AES192 and
     * HMAC-SHA384 are TEE keys (StrongBox guarantees none of them).
     */
    val BASE_ALGORITHMS: List<String> = listOf(
        "ES256", "ES384", "ES512",
        "RS256", "RS384", "RS512",
        "AES128", "AES192", "AES256",
        "HMAC-SHA256", "HMAC-SHA384", "HMAC-SHA512",
        // Software keys on every release; hardwareAlgorithms() names the sets
        // the device also makes in the Keystore.
        "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"
    )

    /** The ML-DSA sets this device makes in hardware, in FIPS 204 order. */
    fun hardwareAlgorithms(): List<String> {
        val supported = PqcHardware.supported()
        return MlDsaParameterSet.entries.filter { it in supported }.map { it.wireName }
    }

    /** Keystore key agreement (`KeyProperties.PURPOSE_AGREE_KEY`) is API 31. */
    const val ECDH_MIN_SDK = 31

    /** True when local.ecdh can run on [sdk]. */
    fun supportsEcdh(sdk: Int): Boolean = sdk >= ECDH_MIN_SDK

    /** Keystore Ed25519 keys (`ECGenParameterSpec("ed25519")`) are API 33. */
    const val ED25519_MIN_SDK = 33

    /** Algorithms local.generateKey can create on [sdk]; EdDSA is a Keystore Ed25519 key from API 33. */
    fun supportedAlgorithms(sdk: Int): List<String> =
        if (sdk >= ED25519_MIN_SDK) BASE_ALGORITHMS + "EdDSA" else BASE_ALGORITHMS

    /** Why local.ecdh is refused on [sdk]. */
    fun ecdhUnsupportedReason(sdk: Int): String =
        "local.ecdh requires Android 12 (API $ECDH_MIN_SDK); this device runs API $sdk"
}

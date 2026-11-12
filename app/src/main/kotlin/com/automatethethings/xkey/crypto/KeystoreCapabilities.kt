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

    /** Algorithms every supported release (minSdk 28) can generate. */
    val BASE_ALGORITHMS: List<String> = listOf(
        "ES256", "ES384", "ES512",
        "RS256", "RS384", "RS512",
        "AES128", "AES256",
        "HMAC-SHA256", "HMAC-SHA512"
    )

    /** Keystore key agreement (`KeyProperties.PURPOSE_AGREE_KEY`) is API 31. */
    const val ECDH_MIN_SDK = 31

    /** [KeystoreManager.generateKeyForAlgorithm] refuses Ed25519 below API 33. */
    const val ED25519_MIN_SDK = 33

    /** True when local.ecdh can run on [sdk]. */
    fun supportsEcdh(sdk: Int): Boolean = sdk >= ECDH_MIN_SDK

    /** Algorithms local.generateKey can create on [sdk]. */
    fun supportedAlgorithms(sdk: Int): List<String> =
        if (sdk >= ED25519_MIN_SDK) BASE_ALGORITHMS + "Ed25519" else BASE_ALGORITHMS

    /** Why local.ecdh is refused on [sdk]. */
    fun ecdhUnsupportedReason(sdk: Int): String =
        "local.ecdh requires Android 12 (API $ECDH_MIN_SDK); this device runs API $sdk"
}

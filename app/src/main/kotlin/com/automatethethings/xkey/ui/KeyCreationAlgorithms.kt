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
package com.automatethethings.xkey.ui

/**
 * The algorithms the Key Management create dialog offers, per purpose, and
 * the key size each name stands for. Every entry is one the Android Keystore
 * generates on the given API level: P-521 and RSA above 2048 bits are made
 * in the TEE (StrongBox guarantees P-256 and RSA 2048 only), AES-192 and
 * HMAC-SHA384 exist since API 23, Ed25519 since API 33.
 */
internal object KeyCreationAlgorithms {

    /** One dialog entry: [display] in the spinner, [internal] to the Keystore. */
    data class Option(val display: String, val internal: String)

    /** Ed25519 Keystore keys exist from API 33 (Android 13). */
    const val ED25519_MIN_SDK = 33

    fun signing(@Suppress("UNUSED_PARAMETER") sdk: Int): List<Option> = listOf(
        Option("ECDSA P-256", "ES256"),
        Option("ECDSA P-384", "ES384"),
        Option("ECDSA P-521", "ES512"),
        Option("RSA 2048", "RS256"),
        Option("RSA 3072", "RS384")
    )

    fun tls(sdk: Int): List<Option> = buildList {
        add(Option("ECDSA P-256", "ES256"))
        add(Option("ECDSA P-384", "ES384"))
        add(Option("ECDSA P-521", "ES512"))
        add(Option("RSA 2048", "RS256"))
        add(Option("RSA 3072", "RS384"))
        add(Option("RSA 4096", "RS512"))
        if (sdk >= ED25519_MIN_SDK) add(Option("Ed25519", "Ed25519"))
    }

    fun encryption(): List<Option> = listOf(
        Option("RSA-OAEP 2048", "RSA-OAEP-2048"),
        Option("RSA-OAEP 3072", "RSA-OAEP-3072"),
        Option("RSA-OAEP 4096", "RSA-OAEP-4096")
    )

    fun secret(): List<Option> = listOf(
        Option("AES-128", "AES-128"),
        Option("AES-192", "AES-192"),
        Option("AES-256", "AES-256")
    )

    fun hmac(): List<Option> = listOf(
        Option("HMAC-SHA256", "HMAC-SHA256"),
        Option("HMAC-SHA384", "HMAC-SHA384"),
        Option("HMAC-SHA512", "HMAC-SHA512")
    )

    /** The modulus an encryption entry asks for. */
    fun oaepModulusBits(internal: String): Int = when (internal) {
        "RSA-OAEP-3072" -> 3072
        "RSA-OAEP-4096" -> 4096
        else -> 2048
    }

    /** The key length a secret entry asks for. */
    fun aesKeyBits(internal: String): Int = when (internal) {
        "AES-128" -> 128
        "AES-192" -> 192
        else -> 256
    }

    /** The key length of an HMAC entry: its digest length. */
    fun hmacKeyBits(internal: String): Int = when {
        internal.contains("512") -> 512
        internal.contains("384") -> 384
        else -> 256
    }
}

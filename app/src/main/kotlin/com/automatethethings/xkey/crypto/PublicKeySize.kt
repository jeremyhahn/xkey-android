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

package com.automatethethings.xkey.crypto

import java.security.KeyFactory
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.X509EncodedKeySpec

/** Key-factory algorithms tried when decoding a generated SPKI public key. */
private val KEY_FACTORY_ALGORITHMS = listOf("EC", "RSA")

/**
 * The real size of an SPKI-encoded public key: the modulus bit length for
 * RSA, the field size of the curve for EC (521 for P-521).
 *
 * The size stored against a key must describe the key that was produced, not
 * the one that was asked for, so every generator reads it back here.
 *
 * @param der The DER/SPKI public key returned by the keystore, or null.
 * @return The key size in bits, or null when [der] is absent or undecodable
 *   (which is the case for Ed25519, whose strength is fixed anyway).
 */
fun publicKeySizeBits(der: ByteArray?): Int? {
    if (der == null || der.isEmpty()) return null
    val spec = X509EncodedKeySpec(der)
    // A KeyFactory is selected by key algorithm and SPKI does not name it
    // without decoding the AlgorithmIdentifier, so try both families and let
    // the other one reject the encoding.
    val publicKey = KEY_FACTORY_ALGORITHMS.firstNotNullOfOrNull { name ->
        runCatching { KeyFactory.getInstance(name).generatePublic(spec) }.getOrNull()
    }
    return when (publicKey) {
        is RSAPublicKey -> publicKey.modulus.bitLength()
        is ECPublicKey -> publicKey.params.curve.field.fieldSize
        else -> null
    }
}

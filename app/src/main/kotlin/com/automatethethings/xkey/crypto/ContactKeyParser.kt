/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
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

import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.PublicKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

/**
 * Parses a contact's public key (X.509 SubjectPublicKeyInfo, DER or PEM) and
 * names the algorithm the app verifies it with.
 *
 * EC keys map by curve: P-256 to ES256, P-384 to ES384, P-521 to ES512. The
 * curve is identified by comparing the key's full [ECParameterSpec] (field,
 * coefficients, generator, order, cofactor) to the named curves, so a curve
 * that only shares a field size, such as secp256k1, is refused. RSA keys map
 * to RS256. Anything else is refused.
 *
 * Pure JVM: no Android imports, so it runs under the unit tests.
 */
object ContactKeyParser {

    /**
     * A parsed contact key.
     *
     * @property der The key's DER encoding (`PublicKey.encoded`).
     * @property algorithm The detected algorithm: ES256, ES384, ES512 or RS256.
     * @property fingerprint Lowercase hex SHA-256 of [der].
     */
    class ParsedContactKey(val der: ByteArray, val algorithm: String, val fingerprint: String)

    private val BASE64_BODY = Regex("^[A-Za-z0-9+/]+={0,2}$")
    private val WHITESPACE = Regex("\\s+")

    private val NAMED_CURVES: List<Pair<String, ECParameterSpec>> by lazy {
        listOf("secp256r1" to "ES256", "secp384r1" to "ES384", "secp521r1" to "ES512")
            .mapNotNull { (curve, algorithm) -> namedCurveSpec(curve)?.let { algorithm to it } }
    }

    /**
     * Parses [bytes] as a DER public key, or else as PEM text.
     *
     * @return The parsed key, or null when it is neither, or is on an unsupported curve.
     */
    fun parse(bytes: ByteArray): ParsedContactKey? {
        if (bytes.isEmpty()) return null
        return parseDer(bytes)
            ?: decodePem(String(bytes, Charsets.UTF_8))?.let { parseDer(it) }
    }

    /**
     * Strips PEM header and footer lines and decodes the Base64 body, which may
     * hold line breaks.
     *
     * @return The decoded bytes, or null when the body is empty or not Base64.
     */
    fun decodePem(text: String): ByteArray? {
        val body = text.lines().filter { !it.trim().startsWith("-----") }.joinToString("\n")
        if (!BASE64_BODY.matches(body.replace(WHITESPACE, ""))) return null
        return try {
            Base64.getMimeDecoder().decode(body).takeIf { it.isNotEmpty() }
        } catch (_: IllegalArgumentException) {
            null
        }
    }

    /** Lowercase hex SHA-256 of [der]. */
    fun fingerprint(der: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(der).joinToString("") { "%02x".format(it) }

    /**
     * The algorithm a contact is stored with: the one detected from the key.
     * A payload's [hint] that disagrees with it is ignored.
     */
    @Suppress("UNUSED_PARAMETER")
    fun resolveAlgorithm(hint: String?, detected: String): String = detected

    /** The JWS algorithm of a named curve, or null for any other curve. */
    internal fun curveAlgorithm(params: ECParameterSpec): String? =
        NAMED_CURVES.firstOrNull { (_, spec) -> sameCurve(spec, params) }?.first

    private fun parseDer(der: ByteArray): ParsedContactKey? {
        val key = decodeKey("EC", der) ?: decodeKey("RSA", der) ?: return null
        val algorithm = when (key) {
            is ECPublicKey -> curveAlgorithm(key.params)
            is RSAPublicKey -> "RS256"
            else -> null
        } ?: return null
        val encoded = key.encoded ?: return null
        return ParsedContactKey(encoded, algorithm, fingerprint(encoded))
    }

    private fun decodeKey(type: String, der: ByteArray): PublicKey? = try {
        KeyFactory.getInstance(type).generatePublic(X509EncodedKeySpec(der))
    } catch (_: Exception) {
        null
    }

    private fun namedCurveSpec(curve: String): ECParameterSpec? = try {
        AlgorithmParameters.getInstance("EC").run {
            init(ECGenParameterSpec(curve))
            getParameterSpec(ECParameterSpec::class.java)
        }
    } catch (_: Exception) {
        null
    }

    private fun sameCurve(a: ECParameterSpec, b: ECParameterSpec): Boolean =
        a.curve.field == b.curve.field &&
            a.curve.a == b.curve.a &&
            a.curve.b == b.curve.b &&
            a.generator == b.generator &&
            a.order == b.order &&
            a.cofactor == b.cofactor
}

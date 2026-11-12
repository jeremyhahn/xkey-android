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

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PublicKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECFieldFp
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.EllipticCurve
import java.util.Base64

class ContactKeyParserTest {

    private fun ecKey(curve: String): PublicKey =
        KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec(curve)) }
            .generateKeyPair().public

    private fun rsaKey(): PublicKey =
        KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }
            .generateKeyPair().public

    private fun pem(der: ByteArray): String =
        "-----BEGIN PUBLIC KEY-----\n" +
            Base64.getEncoder().encodeToString(der).chunked(64).joinToString("\n") +
            "\n-----END PUBLIC KEY-----\n"

    private fun sha256Hex(der: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(der).joinToString("") { "%02x".format(it) }

    @Test
    fun p256DerGivesEs256AndTheDerFingerprint() {
        val der = ecKey("secp256r1").encoded
        val parsed = assertParsed(ContactKeyParser.parse(der))
        assertEquals("ES256", parsed.algorithm)
        assertArrayEquals(der, parsed.der)
        assertEquals(sha256Hex(der), parsed.fingerprint)
    }

    @Test
    fun p256PemGivesEs256AndTheDerFingerprint() {
        val der = ecKey("secp256r1").encoded
        val parsed = assertParsed(ContactKeyParser.parse(pem(der).toByteArray(Charsets.UTF_8)))
        assertEquals("ES256", parsed.algorithm)
        assertArrayEquals(der, parsed.der)
        assertEquals(sha256Hex(der), parsed.fingerprint)
    }

    @Test
    fun decodePemReadsABodyWithLineBreaks() {
        val der = ecKey("secp256r1").encoded
        assertArrayEquals(der, ContactKeyParser.decodePem(pem(der).replace("\n", "\r\n")))
    }

    @Test
    fun p384GivesEs384() {
        assertEquals("ES384", assertParsed(ContactKeyParser.parse(ecKey("secp384r1").encoded)).algorithm)
    }

    @Test
    fun p521GivesEs512() {
        assertEquals("ES512", assertParsed(ContactKeyParser.parse(ecKey("secp521r1").encoded)).algorithm)
    }

    @Test
    fun rsa2048GivesRs256() {
        val der = rsaKey().encoded
        val parsed = assertParsed(ContactKeyParser.parse(der))
        assertEquals("RS256", parsed.algorithm)
        assertEquals(sha256Hex(der), parsed.fingerprint)
    }

    @Test
    fun secp256k1KeyIsRefused() {
        val der = Base64.getDecoder().decode(SECP256K1_SPKI)
        assertNull(ContactKeyParser.parse(der))
        assertNull(ContactKeyParser.parse(pem(der).toByteArray(Charsets.UTF_8)))
    }

    @Test
    fun secp256k1ParametersAreRefusedThoughTheFieldIs256Bits() {
        assertNull(ContactKeyParser.curveAlgorithm(SECP256K1_SPEC))
    }

    @Test
    fun namedCurveParametersMapToTheirAlgorithm() {
        assertEquals("ES256", ContactKeyParser.curveAlgorithm(ecParams("secp256r1")))
        assertEquals("ES384", ContactKeyParser.curveAlgorithm(ecParams("secp384r1")))
        assertEquals("ES512", ContactKeyParser.curveAlgorithm(ecParams("secp521r1")))
    }

    @Test
    fun garbageIsRefused() {
        assertNull(ContactKeyParser.parse(byteArrayOf(0x30, 0x03, 0x01, 0x02, 0x03)))
        assertNull(ContactKeyParser.parse("not a key at all".toByteArray(Charsets.UTF_8)))
    }

    @Test
    fun emptyInputIsRefused() {
        assertNull(ContactKeyParser.parse(ByteArray(0)))
        assertNull(ContactKeyParser.decodePem(""))
    }

    @Test
    fun nonBase64PemBodyIsRefused() {
        val text = "-----BEGIN PUBLIC KEY-----\n!!not*base64~~\n-----END PUBLIC KEY-----\n"
        assertNull(ContactKeyParser.decodePem(text))
        assertNull(ContactKeyParser.parse(text.toByteArray(Charsets.UTF_8)))
    }

    @Test
    fun es256HintOnAP384KeyGivesEs384() {
        val parsed = assertParsed(ContactKeyParser.parse(ecKey("secp384r1").encoded))
        assertEquals("ES384", ContactKeyParser.resolveAlgorithm("ES256", parsed.algorithm))
    }

    @Test
    fun matchingHintIsKept() {
        val parsed = assertParsed(ContactKeyParser.parse(ecKey("secp384r1").encoded))
        assertEquals("ES384", ContactKeyParser.resolveAlgorithm("ES384", parsed.algorithm))
        assertEquals("ES384", ContactKeyParser.resolveAlgorithm(null, parsed.algorithm))
    }

    private fun ecParams(curve: String): ECParameterSpec = (ecKey(curve) as ECPublicKey).params

    private fun assertParsed(parsed: ContactKeyParser.ParsedContactKey?): ContactKeyParser.ParsedContactKey {
        assertNotNull("key was refused", parsed)
        return parsed!!
    }

    private companion object {
        /** A secp256k1 SubjectPublicKeyInfo (named curve 1.3.132.0.10). */
        const val SECP256K1_SPKI =
            "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEKskKwE4FKICXNeVzVVjQlBdlGujiqCNZBOIU/R89rXvR" +
                "ukfVunp4UzYeIl66SnrHOZDcakRq3LwqIuQKXJxlCQ=="

        private fun hex(s: String) = BigInteger(s, 16)

        /** secp256k1 (SEC 2): a 256-bit prime field like P-256, but another curve. */
        val SECP256K1_SPEC = ECParameterSpec(
            EllipticCurve(
                ECFieldFp(hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F")),
                BigInteger.ZERO,
                BigInteger.valueOf(7)
            ),
            ECPoint(
                hex("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"),
                hex("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")
            ),
            hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"),
            1
        )
    }
}

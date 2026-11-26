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

import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.crypto.MlDsaParameterSet
import com.automatethethings.xkey.crypto.PqcBacking
import com.automatethethings.xkey.crypto.SoftwareKeyOps
import com.automatethethings.xkey.storage.entity.KeyEntity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** The algorithms the Key Management create dialog offers per purpose. */
class KeyCreationAlgorithmsTest {

    private fun internals(options: List<KeyCreationAlgorithms.Option>) = options.map { it.internal }

    @Test
    fun `signing offers P-521 and RSA 3072 next to the earlier types`() {
        for (sdk in 28..37) {
            val signing = internals(KeyCreationAlgorithms.signing(sdk))
            assertTrue(signing.containsAll(listOf("ES256", "ES384", "ES512", "RS256", "RS384")))
        }
    }

    @Test
    fun `TLS and SSH offer P-521, RSA 3072 and RSA 4096`() {
        for (sdk in 28..37) {
            assertTrue(
                internals(KeyCreationAlgorithms.tls(sdk))
                    .containsAll(listOf("ES256", "ES384", "ES512", "RS256", "RS384", "RS512"))
            )
        }
    }

    @Test
    fun `Ed25519 is offered from API 33 only`() {
        assertFalse(internals(KeyCreationAlgorithms.tls(32)).contains("Ed25519"))
        assertTrue(internals(KeyCreationAlgorithms.tls(33)).contains("Ed25519"))
    }

    @Test
    fun `encryption offers RSA-OAEP 3072`() {
        assertEquals(
            listOf("RSA-OAEP-2048", "RSA-OAEP-3072", "RSA-OAEP-4096"),
            internals(KeyCreationAlgorithms.encryption())
        )
        assertEquals(3072, KeyCreationAlgorithms.oaepModulusBits("RSA-OAEP-3072"))
        assertEquals(4096, KeyCreationAlgorithms.oaepModulusBits("RSA-OAEP-4096"))
        assertEquals(2048, KeyCreationAlgorithms.oaepModulusBits("RSA-OAEP-2048"))
    }

    @Test
    fun `secret offers AES-192 at its own size`() {
        assertEquals(listOf("AES-128", "AES-192", "AES-256"), internals(KeyCreationAlgorithms.secret()))
        assertEquals(128, KeyCreationAlgorithms.aesKeyBits("AES-128"))
        assertEquals(192, KeyCreationAlgorithms.aesKeyBits("AES-192"))
        assertEquals(256, KeyCreationAlgorithms.aesKeyBits("AES-256"))
    }

    @Test
    fun `HMAC offers SHA-384 at its own size`() {
        assertEquals(listOf("HMAC-SHA256", "HMAC-SHA384", "HMAC-SHA512"), internals(KeyCreationAlgorithms.hmac()))
        assertEquals(256, KeyCreationAlgorithms.hmacKeyBits("HMAC-SHA256"))
        assertEquals(384, KeyCreationAlgorithms.hmacKeyBits("HMAC-SHA384"))
        assertEquals(512, KeyCreationAlgorithms.hmacKeyBits("HMAC-SHA512"))
    }

    @Test
    fun `a software HMAC-SHA384 key computes HMAC-SHA384`() {
        assertEquals("HMAC-SHA384", SoftwareKeyOps.hmacAlgorithm("HMAC-SHA384"))
        val mac = SoftwareKeyOps.hmac(ByteArray(48) { 1 }, byteArrayOf(1, 2, 3), "HMAC-SHA384")
        assertEquals(48, mac.size)
    }

    @Test
    fun `signing and tls offer the three ML-DSA parameter sets on every release`() {
        val names = listOf("ML-DSA-44", "ML-DSA-65", "ML-DSA-87")
        for (sdk in 28..37) {
            assertTrue(internals(KeyCreationAlgorithms.signing(sdk)).containsAll(names))
            assertTrue(internals(KeyCreationAlgorithms.tls(sdk)).containsAll(names))
        }
    }

    @Test
    fun `an ML-DSA entry names its parameter set and no other entry does`() {
        assertEquals(MlDsaParameterSet.ML_DSA_65, KeyCreationAlgorithms.mlDsaSet("ML-DSA-65"))
        assertEquals(null, KeyCreationAlgorithms.mlDsaSet("ES256"))
        assertEquals(null, KeyCreationAlgorithms.mlDsaSet("RSA-OAEP-2048"))
    }

    @Test
    fun `storage offers hardware first only for a set the device makes, and software always`() {
        val set = MlDsaParameterSet.ML_DSA_65
        assertEquals(
            listOf(PqcBacking.HARDWARE, PqcBacking.SOFTWARE),
            KeyCreationAlgorithms.storageOptions(set, setOf(MlDsaParameterSet.ML_DSA_65))
        )
        assertEquals(
            listOf(PqcBacking.SOFTWARE),
            KeyCreationAlgorithms.storageOptions(set, setOf(MlDsaParameterSet.ML_DSA_44))
        )
        assertEquals(listOf(PqcBacking.SOFTWARE), KeyCreationAlgorithms.storageOptions(set, emptySet()))
    }

    private fun row(keyId: String, algorithm: String, keyType: String = "signing") = KeyEntity(
        keyId = keyId, keyType = keyType, algorithm = algorithm, label = keyId, keySizeBits = 256, source = "local"
    )

    @Test
    fun `the media and file signing pickers drop ML-DSA keys`() {
        val keys = listOf(row("ec", "ES256"), row("rsa", "RS256", "fido2")) +
            MlDsaParameterSet.entries.map { row(it.wireName, it.wireName) }

        assertEquals(listOf("ec", "rsa"), mediaSigningKeys(keys).map { it.keyId })
        assertEquals(listOf("ec", "rsa"), fileSigningKeys(keys).map { it.keyId })
    }

    /** PR #400 review: the media verifier checks ES and RS signatures only, so no picker offers an Ed25519 key. */
    @Test
    fun `the media and file signing pickers drop EdDSA and Ed25519 keys`() {
        val keys = listOf(row("ec", "ES256"), row("ed", "EdDSA"), row("rsa", "RS256", "fido2"), row("ed-ui", "Ed25519"))

        assertEquals(listOf("ec", "rsa"), mediaSigningKeys(keys).map { it.keyId })
        assertEquals(listOf("ec", "rsa"), fileSigningKeys(keys).map { it.keyId })
        // A co-signature is a media signature: co-signing selection drops them too.
        assertEquals(listOf("ec", "rsa"), KeystoreManager.jcaSigningKeys(keys, listOf("signing", "fido2")).map { it.keyId })
    }

    /** Every algorithm a signing picker offers makes signatures SignatureVerifier accepts. */
    @Test
    fun `every algorithm the signing pickers offer is one the media verifier verifies`() {
        io.mockk.mockkStatic(android.util.Log::class)
        io.mockk.every { android.util.Log.w(any(), any<String>(), any()) } returns 0
        try {
            val candidates = listOf("ES256", "ES384", "ES512", "RS256", "RS384", "RS512", "EdDSA", "Ed25519") +
                MlDsaParameterSet.entries.map { it.wireName }
            val offered = candidates.filter { algorithm ->
                val keys = listOf(row(algorithm, algorithm))
                fileSigningKeys(keys).isNotEmpty() || mediaSigningKeys(keys).isNotEmpty()
            }
            assertTrue("the pickers offer no ES256 key", "ES256" in offered)
            val data = "media content hash".toByteArray()
            for (algorithm in offered) {
                val pair = keyPairFor(algorithm)
                val signature = java.security.Signature.getInstance(KeystoreManager.jcaSignatureAlgorithm(algorithm)).run {
                    initSign(pair.private)
                    update(data)
                    sign()
                }
                assertTrue(
                    "$algorithm is offered but SignatureVerifier cannot verify it",
                    com.automatethethings.xkey.media.SignatureVerifier.verify(pair.public.encoded, data, signature, algorithm)
                )
            }
        } finally {
            io.mockk.unmockkStatic(android.util.Log::class)
        }
    }

    private fun keyPairFor(algorithm: String): java.security.KeyPair = when {
        algorithm.startsWith("ES") -> java.security.KeyPairGenerator.getInstance("EC").apply {
            initialize(java.security.spec.ECGenParameterSpec(mapOf("ES256" to "secp256r1", "ES384" to "secp384r1", "ES512" to "secp521r1").getValue(algorithm)))
        }.generateKeyPair()
        algorithm.startsWith("RS") -> java.security.KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        else -> java.security.KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
    }

    @Test
    fun `every algorithm with a JCA signature maps to one and no ML-DSA name has one`() {
        val candidates = listOf("ES256", "ES384", "ES512", "RS256", "RS384", "RS512", "Ed25519", "EdDSA") +
            MlDsaParameterSet.entries.map { it.wireName } + listOf("ML-DSA", "AES-256", "HMAC-SHA256", "")
        for (algorithm in candidates.filter { KeystoreManager.hasJcaSignature(it) }) {
            assertTrue(algorithm, KeystoreManager.jcaSignatureAlgorithm(algorithm).isNotEmpty())
        }
        for (set in MlDsaParameterSet.entries) {
            assertFalse(set.wireName, KeystoreManager.hasJcaSignature(set.wireName))
        }
        assertFalse(KeystoreManager.hasJcaSignature("ML-DSA"))
        assertTrue(KeystoreManager.hasJcaSignature("ES256"))
    }
}

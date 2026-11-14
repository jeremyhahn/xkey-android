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

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Security
import java.security.spec.MGF1ParameterSpec
import javax.crypto.Cipher
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The RSA decrypt step names the OAEP parameterisation its cipher ran with.
 * `OAEPWithSHA-256AndMGF1Padding` leaves the MGF1 digest to the provider
 * (SHA-1 in SunJCE and AndroidKeyStore, SHA-256 in Conscrypt and Bouncy
 * Castle), so the decrypt passes `KeystoreManager.rsaOaepSpec` (SHA-1 MGF1)
 * explicitly and the audit name must not claim JOSE "RSA-OAEP-256".
 */
class RsaOaepAuditNameTest {

    private val pair: KeyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.genKeyPair()

    private fun encrypt(plaintext: ByteArray, mgf1: MGF1ParameterSpec): ByteArray =
        Cipher.getInstance("RSA/ECB/OAEPPadding").run {
            init(
                Cipher.ENCRYPT_MODE, pair.public,
                OAEPParameterSpec("SHA-256", "MGF1", mgf1, PSource.PSpecified.DEFAULT)
            )
            doFinal(plaintext)
        }

    @Test
    fun `a SHA-1 MGF1 decrypt is named for the SHA-1 MGF1 it ran`() {
        val plaintext = "payload from a peer".toByteArray()
        val result = KeystoreManager.rsaOaepDecrypt(pair.private, encrypt(plaintext, MGF1ParameterSpec.SHA1))

        assertArrayEquals(plaintext, result.plaintext)
        assertEquals("RSA-OAEP-SHA-256-MGF1-SHA-1", result.algorithm)
    }

    @Test
    fun `the decrypt runs SHA-1 MGF1 whichever provider is first`() {
        // Conscrypt (Robolectric installs it) and Bouncy Castle default the
        // MGF1 digest of OAEPWithSHA-256AndMGF1Padding to SHA-256, unlike
        // SunJCE and AndroidKeyStore; the decrypt must not inherit that.
        val bc = BouncyCastleProvider()
        Security.removeProvider(bc.name)
        Security.insertProviderAt(bc, 1)
        try {
            val providerDefault = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding").run {
                init(Cipher.DECRYPT_MODE, pair.private)
                (parameters.getParameterSpec(OAEPParameterSpec::class.java).mgfParameters as MGF1ParameterSpec)
                    .digestAlgorithm
            }
            assertEquals("precondition: the first provider defaults MGF1 to SHA-256", "SHA-256", providerDefault)

            val plaintext = "payload from a peer".toByteArray()
            val result = KeystoreManager.rsaOaepDecrypt(pair.private, encrypt(plaintext, MGF1ParameterSpec.SHA1))

            assertArrayEquals(plaintext, result.plaintext)
            assertEquals("RSA-OAEP-SHA-256-MGF1-SHA-1", result.algorithm)
        } finally {
            Security.removeProvider(bc.name)
        }
    }

    @Test
    fun `the decrypt and its name follow the one explicit spec`() {
        val spec = KeystoreManager.rsaOaepSpec()
        assertEquals("SHA-256", spec.digestAlgorithm)
        assertEquals("SHA-1", (spec.mgfParameters as MGF1ParameterSpec).digestAlgorithm)

        val plaintext = "payload".toByteArray()
        val ct = Cipher.getInstance("RSA/ECB/OAEPPadding").run {
            init(Cipher.ENCRYPT_MODE, pair.public, spec)
            doFinal(plaintext)
        }
        val result = KeystoreManager.rsaOaepDecrypt(pair.private, ct)
        assertArrayEquals(plaintext, result.plaintext)
        assertEquals(KeystoreManager.rsaOaepAlgorithm(spec), result.algorithm)
    }

    @Test
    fun `the name follows both digests of the spec`() {
        fun spec(digest: String, mgf1: MGF1ParameterSpec) =
            OAEPParameterSpec(digest, "MGF1", mgf1, PSource.PSpecified.DEFAULT)

        assertEquals("RSA-OAEP-256", KeystoreManager.rsaOaepAlgorithm(spec("SHA-256", MGF1ParameterSpec.SHA256)))
        assertEquals("RSA-OAEP", KeystoreManager.rsaOaepAlgorithm(spec("SHA-1", MGF1ParameterSpec.SHA1)))
        assertEquals(
            "RSA-OAEP-SHA-256-MGF1-SHA-1",
            KeystoreManager.rsaOaepAlgorithm(spec("SHA256", MGF1ParameterSpec.SHA1))
        )
        assertEquals("RSA-OAEP-SHA-256-MGF1-unknown", KeystoreManager.rsaOaepAlgorithm(null))
    }
}

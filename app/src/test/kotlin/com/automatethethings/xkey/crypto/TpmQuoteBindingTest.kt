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

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import java.security.KeyPair
import java.security.Security
import java.security.Signature

/**
 * Covers the PCR selection inside a quote, the signature schemes a real IAK
 * uses beyond P-256, and the binding between the PCR values the desktop
 * reports and the pcrDigest the TPM signed.
 */
class TpmQuoteBindingTest {

    private val nonce = ByteArray(32) { (it * 7 + 3).toByte() }

    private var addedProvider = false

    @Before
    fun registerBouncyCastle() {
        // Android resolves SHA256withRSA/PSS through its own providers; the
        // host JDK has no such name, so the verifier finds it in Bouncy Castle.
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleProvider())
            addedProvider = true
        }
    }

    @After
    fun removeBouncyCastle() {
        if (addedProvider) Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
    }

    private fun ecdsa(keys: KeyPair, data: ByteArray, alg: String = "SHA256withECDSA"): ByteArray =
        Signature.getInstance(alg).apply {
            initSign(keys.private)
            update(data)
        }.sign()

    /** Runs [block] and insists it throws exactly [TpmQuoteException]. */
    private fun refused(block: () -> Unit): TpmQuoteException {
        try {
            block()
        } catch (e: Throwable) {
            assertEquals("exception type", TpmQuoteException::class.java, e.javaClass)
            return e as TpmQuoteException
        }
        fail("expected TpmQuoteException")
        throw AssertionError("unreachable")
    }

    // ---------------------------------------------------------------
    // Signature schemes
    // ---------------------------------------------------------------

    @Test
    fun `an RSA-PSS IAK quote verifies`() {
        val keys = TpmTestStructures.generateRsaKeyPair()
        val iak = TpmTestStructures.rsaPssIak(keys)
        val quoted = TpmTestStructures.quoteAttest(iak.name(), nonce)
        val signature = TpmTestStructures.signRsaPss(keys.private, quoted)

        val attest = TpmQuoteVerifier.verify(iak, quoted, signature, nonce)
        assertArrayEquals(nonce, attest.extraData)
    }

    @Test
    fun `a PSS signature with the maximum salt length is refused (recorded)`() {
        // Salt = modulus bytes - hash length - 2. The verifier fixes the salt
        // at the hash length, so a TPM that signs with the maximum salt fails.
        val keys = TpmTestStructures.generateRsaKeyPair()
        val iak = TpmTestStructures.rsaPssIak(keys)
        val quoted = TpmTestStructures.quoteAttest(iak.name(), nonce)
        val signature = TpmTestStructures.signRsaPss(keys.private, quoted, saltLength = 256 - 32 - 2)

        val e = refused { TpmQuoteVerifier.verify(iak, quoted, signature, nonce) }
        assertTrue(e.message!!.contains("does not verify"))
    }

    @Test
    fun `a P-384 IAK with a SHA-384 scheme verifies`() {
        val keys = TpmTestStructures.generateEcKeyPair("secp384r1")
        val iak = TpmTestStructures.p384Iak(keys)
        assertEquals(TpmAlg.SHA384, iak.nameAlg)
        val quoted = TpmTestStructures.quoteAttest(iak.name(), nonce)
        val signature = ecdsa(keys, quoted, "SHA384withECDSA")

        TpmQuoteVerifier.verify(iak, quoted, signature, nonce)
    }

    @Test
    fun `a P-384 quote signed over SHA-256 is refused`() {
        val keys = TpmTestStructures.generateEcKeyPair("secp384r1")
        val iak = TpmTestStructures.p384Iak(keys)
        val quoted = TpmTestStructures.quoteAttest(iak.name(), nonce)
        val signature = ecdsa(keys, quoted, "SHA256withECDSA")

        refused { TpmQuoteVerifier.verify(iak, quoted, signature, nonce) }
    }

    // ---------------------------------------------------------------
    // PCR selection structure
    // ---------------------------------------------------------------

    private fun quoteWithSelection(selection: ByteArray) = TpmTestStructures.quoteAttestWithSelection(
        qualifiedSigner = ByteArray(34),
        extraData = nonce,
        selection = selection,
        pcrDigest = ByteArray(32)
    )

    @Test
    fun `refuses a selection count of 17`() {
        val selection = TpmTestStructures.pcrSelection(List(17) { TpmAlg.SHA256 to setOf(0) })
        val e = refused { TpmAttest.parse(quoteWithSelection(selection)) }
        assertTrue(e.message!!.contains("17"))
    }

    @Test
    fun `refuses a sizeOfSelect that runs past the end`() {
        // One SHA-256 selection declaring a 255-byte bitmap; only the 34-byte
        // pcrDigest follows it.
        val selection = byteArrayOf(0, 0, 0, 1, 0, TpmAlg.SHA256.toByte(), 0xFF.toByte())
        val e = refused { TpmAttest.parse(quoteWithSelection(selection)) }
        assertTrue(e.message!!.contains("past the end"))
    }

    @Test
    fun `every prefix of a quote is refused as a quote error`() {
        val quoted = TpmTestStructures.quoteAttest(ByteArray(34), nonce)
        TpmAttest.parse(quoted)
        for (n in 0 until quoted.size) {
            refused { TpmAttest.parse(quoted.copyOf(n)) }
        }
    }
}
